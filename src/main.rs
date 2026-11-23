//! Concurrent server log analyzer.
//!
//! Architecture (bounded memory, all cores busy during the CPU-heavy part):
//!
//! ```text
//!  file --BufReader--> Vec<String> (<= chunk_size lines)
//!                          |
//!                  rayon par_iter: fold (per-task Metrics) -> reduce (merge)
//!                          |
//!                   chunk Metrics --merge--> global Metrics
//!                          |
//!                  chunk.clear(); read next chunk
//! ```
//!
//! Peak RAM ~ one chunk of lines + the maps of *distinct* IPs/endpoints.
//! It does NOT depend on file size.

mod metrics;
mod parser;

use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use clap::Parser;
use rayon::prelude::*;

use metrics::{Metrics, top_n};

#[derive(Parser, Debug)]
#[command(version, about = "Fast, fault-tolerant analyzer for huge access logs")]
struct Args {
    /// Path to an Nginx/Apache combined-format access log
    #[arg(short, long, value_name = "PATH")]
    file: PathBuf,

    /// Lines held in memory per batch before handing them to rayon
    #[arg(short, long, value_name = "SIZE", default_value_t = 50_000,
          value_parser = parse_chunk_size)]
    chunk_size: usize,
}

fn parse_chunk_size(s: &str) -> Result<usize, String> {
    match s.parse::<usize>() {
        Ok(0) => Err("chunk size must be at least 1".into()),
        Ok(n) => Ok(n),
        Err(e) => Err(format!("invalid chunk size: {e}")),
    }
}

/// Parse one chunk on all cores and return its combined `Metrics`.
///
/// BORROWING: `lines: &[String]` is a *shared* borrow. Rayon requires the
/// closure and items to be `Send + Sync`; `&String` is `Sync` because
/// shared references to immutable data are safe to read from many threads.
/// Rust proves there are no writers: the caller owns the `Vec` and cannot
/// mutate or `clear()` it until this function returns and the borrow ends.
/// Rayon's parallel iterators are fork-join: they block until every task
/// has finished, so no thread can still be reading when the caller clears
/// the `Vec`. No `Arc`, no `Mutex`.
fn process_chunk(lines: &[String]) -> Metrics {
    lines
        .par_iter()
        // `fold`: rayon splits the slice into pieces (work stealing) and
        // each piece gets its OWN accumulator from `Metrics::default`.
        // Accumulators are moved through the closure by value, so each is
        // only ever touched by one thread at a time: no locks.
        .fold(Metrics::default, |mut acc, line| {
            acc.record_line(line);
            acc
        })
        // `reduce`: combine the per-piece accumulators pairwise in a tree.
        // Valid because `merge` is associative; `default` is the identity.
        .reduce(Metrics::default, |mut a, b| {
            a.merge(b);
            a
        })
}

/// Turn raw bytes into a `String` without ever failing: invalid UTF-8 is
/// replaced with U+FFFD (such lines then simply fail to parse), and the
/// trailing `\n` / `\r\n` is removed.
fn decode_line(buf: &[u8]) -> String {
    let text = String::from_utf8_lossy(buf); // borrows if valid, else allocates
    text.trim_end_matches(['\n', '\r']).to_owned()
}

fn run(args: &Args) -> io::Result<(Metrics, u64)> {
    let file = File::open(&args.file)?;
    let file_len = file.metadata()?.len();
    let mut reader = BufReader::with_capacity(1 << 20, file);

    // Reserve once, capped so a huge `--chunk-size` doesn't pre-allocate GBs.
    let mut chunk: Vec<String> = Vec::with_capacity(args.chunk_size.min(1 << 20));
    let mut raw = Vec::with_capacity(4096); // reused byte buffer
    let mut global = Metrics::default();

    loop {
        raw.clear();
        // Read bytes, not `String`s: `BufRead::lines()` would abort the
        // whole run with an error on the first invalid-UTF-8 line.
        // Real I/O errors still propagate via `?`; those are not bad data.
        if reader.read_until(b'\n', &mut raw)? == 0 {
            break; // EOF
        }
        chunk.push(decode_line(&raw));

        if chunk.len() >= args.chunk_size {
            // `&chunk` borrows the Vec immutably for the call only.
            global.merge(process_chunk(&chunk));
            // The borrow has ended, so mutation is allowed again. `clear`
            // drops the Strings but keeps the Vec's capacity.
            chunk.clear();
        }
    }
    if !chunk.is_empty() {
        global.merge(process_chunk(&chunk)); // final partial chunk
    }
    Ok((global, file_len))
}

/// Peak resident memory from the kernel (Linux only; `None` elsewhere).
fn peak_rss_mib() -> Option<f64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let kb: f64 = status
        .lines()
        .find_map(|l| l.strip_prefix("VmHWM:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    Some(kb / 1024.0)
}

fn print_report(m: &Metrics, file_len: u64, secs: f64) {
    let line = "=".repeat(52);
    println!("{line}\n LOG ANALYSIS REPORT\n{line}");
    println!(" Total lines processed : {}", m.total_lines);
    println!(" Malformed lines       : {}", m.malformed_lines);
    println!(" Rescued by regex      : {}", m.regex_rescued);

    println!("\n Requests by status code");
    let mut statuses: Vec<_> = m.status_counts.iter().collect();
    statuses.sort_unstable();
    for (code, count) in statuses {
        println!("   {code}: {count}");
    }

    println!("\n Top 5 IP addresses");
    for (i, (ip, c)) in top_n(&m.ip_counts, 5).iter().enumerate() {
        println!("   {}. {ip:<40} {c}", i + 1);
    }
    println!("\n Top 5 endpoints");
    for (i, (ep, c)) in top_n(&m.endpoint_counts, 5).iter().enumerate() {
        println!("   {}. {ep:<40} {c}", i + 1);
    }

    println!("\n{line}");
    println!(" Execution time        : {secs:.3} s");
    if secs > 0.0 {
        println!(" Throughput            : {:.0} lines/s, {:.1} MiB/s",
            m.total_lines as f64 / secs, file_len as f64 / secs / (1024.0 * 1024.0));
    }
    if let Some(rss) = peak_rss_mib() {
        println!(" Peak memory (RSS)     : {rss:.1} MiB");
    }
    println!("{line}");
}

fn main() -> ExitCode {
    let args = Args::parse();
    let start = Instant::now();
    match run(&args) {
        Ok((metrics, file_len)) => {
            print_report(&metrics, file_len, start.elapsed().as_secs_f64());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {}: {e}", args.file.display());
            ExitCode::FAILURE
        }
    }
}
