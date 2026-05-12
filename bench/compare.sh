#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-or-later
#
# Run the Go and Python sides of the benchmark, then merge the two outputs
# into a side-by-side comparison table.
#
# Usage:  bench/compare.sh [seconds-per-op]   # default: 2
set -euo pipefail

cd "$(dirname "$0")/.."   # repo root

SECONDS_PER_OP="${1:-2}"

if [[ ! -x .venv/bin/python ]]; then
  echo "error: .venv/bin/python not found. Run:" >&2
  echo "  python -m venv .venv && .venv/bin/pip install seccure" >&2
  exit 1
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# --- Go side ----------------------------------------------------------------
# Parse "BenchmarkSign/p256-8   12345    81234 ns/op   ..." into our CSV
# schema (impl,op,curve,ns_per_op,iters). The trailing "-8" is GOMAXPROCS;
# strip it.
echo "running go benchmarks (${SECONDS_PER_OP}s/op) ..." >&2
go test -bench . -benchtime="${SECONDS_PER_OP}s" -run '^$' ./... 2>/dev/null \
| awk -v OFS=',' '
    /^Benchmark/ {
      name = $1
      sub(/^Benchmark/, "", name)
      sub(/-[0-9]+$/, "", name)               # strip "-8" GOMAXPROCS suffix
      split(name, parts, "/")
      op = parts[1]; curve = parts[2]
      iters = $2; nsop = $3
      print "go", op, curve, int(nsop), iters
    }' > "$TMP/go.csv"

# --- Python side ------------------------------------------------------------
echo "running python benchmarks (${SECONDS_PER_OP}s/op) ..." >&2
.venv/bin/python bench/bench_py.py "$SECONDS_PER_OP" > "$TMP/py.csv"

# --- Merge and print --------------------------------------------------------
python3 - "$TMP/go.csv" "$TMP/py.csv" <<'PY'
import csv, sys
from collections import defaultdict

results = defaultdict(dict)   # (op, curve) -> {impl: ns}
for path in sys.argv[1:]:
    with open(path) as f:
        for row in csv.reader(f):
            if not row: continue
            impl, op, curve, ns, _iters = row
            results[(op, curve)][impl] = int(ns)

# Stable ordering: ops in the order they appear in bench_test.go, curves in
# size order.
op_order = ["PassphraseToPubkey", "Sign", "Verify", "Encrypt", "Decrypt"]
curve_order = ["p160", "p256", "p521"]

print()
print(f"{'op':<22} {'curve':<6} {'go (µs)':>12} {'py (µs)':>12} {'py/go':>10}")
print("-" * 66)
for op in op_order:
    for curve in curve_order:
        d = results.get((op, curve))
        if not d: continue
        g = d.get("go"); p = d.get("py")
        if g is None or p is None:
            print(f"{op:<22} {curve:<6} {('—' if g is None else f'{g/1000:.1f}'): >12} "
                  f"{('—' if p is None else f'{p/1000:.1f}'): >12} {'—': >10}")
            continue
        ratio = p / g
        print(f"{op:<22} {curve:<6} {g/1000:>12.1f} {p/1000:>12.1f} {ratio:>10.1f}x")
print()
PY
