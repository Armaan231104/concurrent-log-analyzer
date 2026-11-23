# Log Analyzer

A command line tool written in Rust that reads large web server access logs (Nginx or Apache combined format) and prints a summary. It uses a fixed amount of memory no matter how big the file is, and it keeps going when it hits bad lines.

## What it reports

- Total lines processed and total malformed lines skipped
- Request count for each HTTP status code
- Top 5 IP addresses
- Top 5 requested endpoints
- Run time, throughput and peak memory

## Usage

```bash
cargo build --release
./target/release/log_analyzer -f access.log
./target/release/log_analyzer -f access.log -c 100000
```

| Flag | Meaning | Default |
|---|---|---|
| `-f, --file` | Path to the log file | required |
| `-c, --chunk-size` | Lines held in memory per batch | 50000 |

## How it works

1. The file is read line by line with a buffered reader, never loaded whole.
2. Lines are collected into batches of `--chunk-size`.
3. Each batch is parsed in parallel with Rayon. Every worker keeps its own counters, so no locks are needed.
4. The batch results are merged into one running total, the batch is cleared, and the next one is read.

Memory use depends on the batch size and the number of distinct IPs and endpoints, not on the file size.

Each line is parsed with plain string splitting first. If that fails, a regex is tried. If that fails too, the line is counted as malformed and skipped. Invalid UTF-8 is handled the same way, so bad data cannot crash the run.

## Benchmark

Test file: 5.2 million lines (0.5 GB), generated with `scripts/gen_log.py`, about 0.4% malformed. Machine: 4 cores.

| | Time | Peak memory |
|---|---|---|
| Rust (this tool) | 2.6 s | 22 MB |
| Plain Python script with the same regex | 6.1 s | 14 MB |

Both report the same line and malformed counts. To try it yourself:

```bash
python3 scripts/gen_log.py big.log 5
./target/release/log_analyzer -f big.log
```

## Tests

```bash
cargo test
```

## Project layout

- `src/main.rs`: command line, batch loop, Rayon, report
- `src/parser.rs`: string split parser and regex fallback
- `src/metrics.rs`: counters and the merge step
- `scripts/gen_log.py`: test log generator
