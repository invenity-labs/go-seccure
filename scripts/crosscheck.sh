#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-or-later
#
# Cross-check the go-seccure CLI binaries against the C `seccure` tools and
# the Python `py-seccure` library:
#
#   * Python encrypts → Go decrypts (round-trip plaintext).
#   * Go encrypts     → Python decrypts (round-trip plaintext).
#   * Python signs    → Go verifies.
#   * Go signs        → Python verifies.
#   * `seccure-key`   → diff against `go run ./cmd/seccure-key`.
#
# Run from the repo root after `go install ./cmd/...` and `pip install seccure`.
#
# Stub — implementation gated on the CLI binaries (§8 day 5).

set -euo pipefail

echo "scripts/crosscheck.sh: not yet implemented" >&2
exit 1
