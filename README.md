# log_analyzer

Fast, fault-tolerant CLI that aggregates huge Nginx/Apache combined-format access logs
with bounded memory.

```bash
cargo build --release
./target/release/log_analyzer -f access.log            # default 50,000-line chunks
./target/release/log_analyzer -f access.log -c 200000  # bigger chunks
```

## How it works
1. `BufReader` reads raw lines (invalid UTF-8 is replaced, never an error) into a `Vec<String>` of at most `--chunk-size` lines.
2. The chunk is parsed with rayon `par_iter().fold(..).reduce(..)`; each task owns its own `Metrics`, so there are no locks.
3. The chunk's `Metrics` is merged into a global accumulator, the `Vec` is cleared, and the next chunk is read.
4. Per line: string splitting first, regex fallback second, otherwise counted as malformed. Neither path can panic.

Memory is roughly one chunk plus the maps of *distinct* IPs and endpoints, so it does not grow with file size.

## Benchmark
```bash
python3 scripts/gen_log.py big.log 5     # ~5 GiB synthetic log (~0.5% bad lines)
./target/release/log_analyzer -f big.log # report includes time, throughput, peak RSS
/usr/bin/time -v ./target/release/log_analyzer -f big.log   # independent peak-memory check
```

## Tests
```bash
cargo test
```
