#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later
"""
Generate cross-implementation test vectors for go-seccure by driving py-seccure.

Output is JSON on stdout in the schema expected by go-seccure's tests. The Go
test driver reads this file and asserts byte-for-byte parity for every entry.

Usage:
    pip install seccure
    python scripts/gen_vectors.py > testdata/vectors.json

See §7.2 for the design intent and §4 for the canary tests
that MUST appear in the pubkey grid below.
"""

from __future__ import annotations

import json
import sys

import seccure  # py-seccure: https://github.com/bwesterb/py-seccure

CURVES = [
    "secp112r1", "secp128r1", "secp160r1", "secp192r1", "secp224r1",
    "secp256r1", "secp384r1", "secp521r1",
    "brainpoolp160r1", "brainpoolp192r1", "brainpoolp224r1",
    "brainpoolp256r1", "brainpoolp320r1", "brainpoolp384r1",
    "brainpoolp512r1",
]

# py-seccure registers NIST-equivalent curves under a slash-aliased name
# (e.g. "secp192r1/nistp192"). The JSON keeps the short Go-friendly name;
# this map is only used when calling into py-seccure.
_PYSECCURE_CURVE_NAME = {
    "secp192r1": "secp192r1/nistp192",
    "secp224r1": "secp224r1/nistp224",
    "secp256r1": "secp256r1/nistp256",
    "secp384r1": "secp384r1/nistp384",
    "secp521r1": "secp521r1/nistp521",
}


def _py_curve(name: str) -> str:
    return _PYSECCURE_CURVE_NAME.get(name, name)

# Canary inputs from §4 plus edge cases. Every prior porting
# attempt failed on at least one of these.
PASSPHRASES: list[bytes] = [
    b"",
    b"a",
    b"Test1234",
    b"my private key",
    b"test",
    b"seccure is secure",
    b"\x00\xff",
    b"a" * 1000,
    b"with\nnewline",
    b"with trailing space ",
    "café".encode("utf-8"),
    b"\xff" * 32,
]

MESSAGES: list[bytes] = [
    b"",
    b"hello",
    b"the quick brown fox jumps over the lazy dog",
    b"\x00" * 64,
    b"\xff" * 1024,
]


def gen_pubkeys() -> list[dict]:
    out = []
    for curve in CURVES:
        for pw in PASSPHRASES:
            pk = str(seccure.passphrase_to_pubkey(pw, curve=_py_curve(curve)))
            out.append({"curve": curve, "passphrase_hex": pw.hex(), "pubkey": pk})
    return out


def gen_signatures() -> list[dict]:
    out = []
    for curve in CURVES:
        for pw in PASSPHRASES[:4]:  # bound the matrix
            for msg in MESSAGES:
                # seccure.sign returns bytes (compact-formatted ASCII when
                # the default sig_format=SER_COMPACT is in effect). str(bytes)
                # would give the Python "b'...'" repr — use decode() so the
                # JSON carries the actual signature string.
                sig = seccure.sign(msg, pw, curve=_py_curve(curve)).decode("ascii")
                out.append({
                    "curve": curve,
                    "passphrase_hex": pw.hex(),
                    "message_hex": msg.hex(),
                    "signature": sig,
                })
    return out


# Note: ECIES encrypt cross-impl vectors require deterministic R, which is not
# exposed by py-seccure's high-level API. The cross-impl strategy is therefore
# "Python encrypts, Go decrypts" and vice versa, executed in scripts/crosscheck.sh
# rather than as static vectors.

def main() -> int:
    out = {
        "pubkeys": gen_pubkeys(),
        "signatures": gen_signatures(),
    }
    json.dump(out, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
