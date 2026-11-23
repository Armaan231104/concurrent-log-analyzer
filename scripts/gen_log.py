#!/usr/bin/env python3
"""Generate a large synthetic access log for benchmarking.

    python3 scripts/gen_log.py big.log 5        # ~5 GiB
    python3 scripts/gen_log.py small.log 0.01   # ~10 MiB

Skewed IP/URL popularity (a few heavy hitters), a realistic status mix, and
~0.5% deliberately broken lines to exercise the fault-tolerant parser.
Fast because it builds a pool of lines once and writes shuffled batches.
"""
import random
import sys

POOL = 200_000          # distinct pre-built lines
BATCH = 100_000         # lines per write
BAD_RATE = 0.005

METHODS = ["GET"] * 8 + ["POST", "PUT", "DELETE"]
STATUS = [200] * 80 + [301] * 4 + [304] * 6 + [404] * 6 + [500, 502, 503]
PATHS = [f"/page/{i}" for i in range(2000)] + ["/index.html", "/api/v1/users", "/login"] * 300
UAS = ['"Mozilla/5.0 (X11; Linux x86_64)"', '"curl/8.4.0"', '"Googlebot/2.1"']
BAD = [
    "", "-", "garbage line with no structure",
    '127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /truncated',
    '1.2.3.4 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.1" xyz 12',
    "\x00\x01\x02 binary \xff junk",
    '1.2.3.4 - - [10/Oct/2000:13:55:36 -0700] "GET /old" 404 12',  # regex rescues
]


def make_ip(rng):
    # Zipf-ish skew: low-numbered hosts are far more common.
    return f"10.{rng.randint(0, 3)}.{int(rng.paretovariate(1.2)) % 256}.{rng.randint(1, 254)}"


def main():
    out = sys.argv[1]
    target = int(float(sys.argv[2]) * 1024**3)
    rng = random.Random(42)
    pool = []
    for _ in range(POOL):
        if rng.random() < BAD_RATE:
            pool.append(rng.choice(BAD))
        else:
            pool.append(
                f'{make_ip(rng)} - - [10/Oct/2023:13:55:{rng.randint(0, 59):02d} +0000] '
                f'"{rng.choice(METHODS)} {rng.choice(PATHS)} HTTP/1.1" '
                f'{rng.choice(STATUS)} {rng.randint(100, 50000)} "-" {rng.choice(UAS)}'
            )
    written = 0
    with open(out, "w", encoding="utf-8", errors="replace", newline="\n") as f:
        while written < target:
            data = "\n".join(rng.choices(pool, k=BATCH)) + "\n"
            f.write(data)
            written += len(data)
    print(f"wrote ~{written / 1024**3:.2f} GiB to {out}")


if __name__ == "__main__":
    main()
