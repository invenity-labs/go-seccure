#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later
"""
Python (py-seccure) side of the go-seccure ↔ py-seccure benchmark.

Mirrors bench_test.go: same curves, same operations, same input shapes.
Each operation is timed in a tight Python loop using time.perf_counter_ns().

Output: one CSV line per (op, curve) measurement, written to stdout, with
columns: impl,op,curve,ns_per_op,iters

The companion script bench/compare.sh runs `go test -bench .` and merges
both outputs into a side-by-side comparison table.

Usage:
    .venv/bin/python bench/bench_py.py [seconds-per-op]    # default: 2.0
"""

from __future__ import annotations

import sys
import time
from typing import Callable

import seccure

CURVES = [
    ("p160", "secp160r1"),
    ("p256", "secp256r1/nistp256"),
    ("p521", "secp521r1/nistp521"),
]

PASSPHRASE = b"benchmark passphrase that's reasonably long"
MESSAGE = b"payload-" * 32  # 256 bytes — same shape as bench_test.go

DEFAULT_SECONDS_PER_OP = 2.0
WARMUP_ITERS = 3


def bench(name: str, curve_label: str, fn: Callable[[], None], seconds: float) -> None:
    # Warmup so JIT-y caches / curve loading settle.
    for _ in range(WARMUP_ITERS):
        fn()

    # Calibrate iteration count to hit roughly `seconds` total.
    t0 = time.perf_counter_ns()
    fn()
    one_call = max(time.perf_counter_ns() - t0, 1)
    target_ns = int(seconds * 1e9)
    iters = max(1, target_ns // one_call)
    if iters > 100_000:
        iters = 100_000  # cap so a bad curve doesn't run forever

    t0 = time.perf_counter_ns()
    for _ in range(iters):
        fn()
    elapsed = time.perf_counter_ns() - t0
    ns_per_op = elapsed // iters
    print(f"py,{name},{curve_label},{ns_per_op},{iters}", flush=True)


def main(argv: list[str]) -> int:
    seconds = DEFAULT_SECONDS_PER_OP
    if len(argv) > 1:
        seconds = float(argv[1])

    for curve_label, py_curve in CURVES:
        # Precompute artefacts for verify/decrypt benches so we time only the
        # operation, matching what bench_test.go does in its setup.
        pub = str(seccure.passphrase_to_pubkey(PASSPHRASE, curve=py_curve))
        sig = seccure.sign(MESSAGE, PASSPHRASE, curve=py_curve).decode("ascii")
        ct = seccure.encrypt(MESSAGE, pub, mac_bytes=10, curve=py_curve)

        bench("PassphraseToPubkey", curve_label,
              lambda c=py_curve: seccure.passphrase_to_pubkey(PASSPHRASE, curve=c),
              seconds)

        bench("Sign", curve_label,
              lambda c=py_curve: seccure.sign(MESSAGE, PASSPHRASE, curve=c),
              seconds)

        bench("Verify", curve_label,
              lambda c=py_curve, p=pub, s=sig: seccure.verify(MESSAGE, s, p, curve=c),
              seconds)

        bench("Encrypt", curve_label,
              lambda c=py_curve, p=pub: seccure.encrypt(MESSAGE, p, mac_bytes=10, curve=c),
              seconds)

        bench("Decrypt", curve_label,
              lambda c=py_curve, x=ct: seccure.decrypt(x, PASSPHRASE, mac_bytes=10, curve=c),
              seconds)

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
