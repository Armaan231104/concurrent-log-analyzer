//! Concurrent server log analyzer.
//!
//! Architecture (bounded memory, all cores busy during the CPU-heavy part):
//!
//! ```text
//!  reader thread: file --BufReader--> byte buffer (<= chunk_size lines)
//!                          | bounded channel (1 chunk)
//!  main thread: rayon par_split: fold (per-task Metrics) -> reduce (merge)
//!                          |
//!                   chunk Metrics --merge--> global Metrics
//!                          |
//!                  drop buffer; receive next chunk
//! ```
//!
//! Peak RAM ~ one chunk of lines + the maps of *distinct* IPs/endpoints.
//! It does NOT depend on file size.

mod metrics;
mod parser;

use std::fs::File;
use std::fmt::Write as _;
use std::io::{self, BufRead, BufReader, Write as _};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::mpsc::{SyncSender, sync_channel};
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
/// `chunk` is one contiguous byte buffer holding up to `chunk_size` lines.
/// One big allocation per chunk replaces one `String` per line, which is
/// where most of the old time went.
///
/// BORROWING: `&[u8]` is a shared borrow. `par_split` hands rayon tasks
/// sub-slices (`&[u8]`) of that one buffer; `&[u8]` is `Send + Sync` since
/// many threads can safely read immutable data. Rust proves nobody mutates
/// the buffer while it is borrowed. Rayon is fork-join: this call blocks
/// until every task is done, so the buffer cannot be freed or reused while
/// a worker still reads it. No `Arc`, no `Mutex`.
fn process_chunk(chunk: &[u8]) -> Metrics {
    // The buffer ends with the last line's '\n'; drop it so the split does
    // not produce a phantom empty line at the end.
    let body = chunk.strip_suffix(b"\n").unwrap_or(chunk);
    body.par_split(|&b| b == b'\n')
        // `fold`: each piece of the work gets its OWN accumulator from
        // `Metrics::default`. Accumulators move through the closure by
        // value, so each is touched by one thread at a time: no locks.
        .fold(Metrics::default, |mut acc, line| {
            acc.record_bytes(line);
            acc
        })
        // `reduce`: combine accumulators pairwise in a tree. Valid because
        // `merge` is associative and `default` is the identity.
        .reduce(Metrics::default, |mut a, b| {
            a.merge(b);
            a
        })
}

/// Reader side of the pipeline: fill byte buffers of `chunk_size` lines and
/// send them to the processing side.
///
/// Raw bytes (`read_until`) instead of `BufRead::lines()` so one invalid
/// UTF-8 line cannot abort the run. Real I/O errors are sent through the
/// channel and stop the run; those are not bad data.
fn read_chunks(file: File, chunk_size: usize, tx: SyncSender<io::Result<Vec<u8>>>) {
    let mut reader = BufReader::with_capacity(1 << 20, file);
    loop {
        let mut chunk = Vec::with_capacity(chunk_size.min(1 << 20) * 128);
        let mut lines = 0;
        while lines < chunk_size {
            match reader.read_until(b'\n', &mut chunk) {
                Ok(0) => break, // EOF
                Ok(_) => lines += 1,
                Err(e) => {
                    let _ = tx.send(Err(e));
                    return;
                }
            }
        }
        if lines == 0 {
            return;
        }
        // `send` moves ownership of the buffer to the other thread, so the
        // compiler guarantees this thread cannot touch it afterwards.
        // The channel holds at most 1 chunk, so the reader runs ahead by a
        // bounded amount: memory stays at ~3 chunks (reading, queued,
        // processing) regardless of file size.
        if tx.send(Ok(chunk)).is_err() {
            return; // consumer stopped
        }
        if lines < chunk_size {
            return; // EOF reached mid-chunk
        }
    }
}

fn run(args: &Args) -> io::Result<(Metrics, u64)> {
    let file = File::open(&args.file)?;
    let file_len = file.metadata()?.len();
    let chunk_size = args.chunk_size;
    let mut global = Metrics::default();

    // Bounded channel: reader thread fills chunk N+1 while rayon parses
    // chunk N. `scope` lets the thread borrow locals and guarantees it is
    // joined before `run` returns.
    let (tx, rx) = sync_channel::<io::Result<Vec<u8>>>(1);
    std::thread::scope(|scope| {
        scope.spawn(move || read_chunks(file, chunk_size, tx));
        for msg in rx {
            let chunk = msg?;
            global.merge(process_chunk(&chunk));
            // `chunk` is dropped here, freeing the buffer.
        }
        Ok::<(), io::Error>(())
    })?;
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
    // Build the report in memory, then write once and ignore a closed pipe
    // (e.g. `| head`) instead of letting `println!` panic.
    let mut out = String::new();
    macro_rules! p {
        ($($arg:tt)*) => {{ let _ = writeln!(out, $($arg)*); }};
    }
    let line = "=".repeat(52);
    p!("{line}\n LOG ANALYSIS REPORT\n{line}");
    p!(" Total lines processed : {}", m.total_lines);
    p!(" Malformed lines       : {}", m.malformed_lines);
    p!(" Rescued by regex      : {}", m.regex_rescued);

    p!("\n Requests by status code");
    let mut statuses: Vec<_> = m.status_counts.iter().collect();
    statuses.sort_unstable();
    for (code, count) in statuses {
        p!("   {code}: {count}");
    }

    p!("\n Top 5 IP addresses");
    for (i, (ip, c)) in top_n(&m.ip_counts, 5).iter().enumerate() {
        p!("   {}. {ip:<40} {c}", i + 1);
    }
    p!("\n Top 5 endpoints");
    for (i, (ep, c)) in top_n(&m.endpoint_counts, 5).iter().enumerate() {
        p!("   {}. {ep:<40} {c}", i + 1);
    }

    p!("\n{line}");
    p!(" Execution time        : {secs:.3} s");
    if secs > 0.0 {
        p!(" Throughput            : {:.0} lines/s, {:.1} MiB/s",
            m.total_lines as f64 / secs, file_len as f64 / secs / (1024.0 * 1024.0));
    }
    if let Some(rss) = peak_rss_mib() {
        p!(" Peak memory (RSS)     : {rss:.1} MiB");
    }
    p!("{line}");
    let _ = io::stdout().write_all(out.as_bytes());
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
