# go-seccure

A pure-Go port of [SECCURE](http://point-at-infinity.org/seccure/) (B. Poettering, v0.5) that is
**bit-for-bit wire-compatible** with the C reference implementation and with
[`bwesterb/py-seccure`](https://github.com/bwesterb/py-seccure). The same passphrase on the same
curve produces the same compact public key, the same ciphertext, and the same signature byte
stream as both reference implementations.

> **Status:** v0.1.0. Two earlier porting attempts failed because passphrases produced
> different public keys in Go than in Python. The root cause is documented in the
> [Footguns](#footguns) section below.

- **Module:** `github.com/invenity-labs/go-seccure`
- **License:** [LGPL-3.0](LICENSE) (matches py-seccure)
- **Owner:** Invenity Labs LLC
- **Build target:** Go 1.26.3

## What this package provides

A library:

```go
import "github.com/invenity-labs/go-seccure"

pub, _ := seccure.PassphraseToPubkey([]byte("Test1234"), seccure.CurveP160)
ct,  _ := seccure.Encrypt(plaintext, pub, seccure.CurveP160, 10)
pt,  _ := seccure.Decrypt(ct, []byte("Test1234"), seccure.CurveP160, 10)
sig, _ := seccure.Sign(msg, []byte("Test1234"), seccure.CurveP160)
err   := seccure.Verify(msg, sig, pub, seccure.CurveP160)
```

Plus eight CLI binaries matching the C tool's command-line surface:

```
seccure-key   seccure-encrypt    seccure-sign     seccure-dh
              seccure-decrypt    seccure-verify   seccure-signcrypt   seccure-veridec
```

See `go doc github.com/invenity-labs/go-seccure` for the full API.

## Non-goals

- **No constant-time / side-channel resistance.** `py-seccure` itself warns against use where
  timing attacks apply; we match its threat model.
- **No new curves.** Only the 15 curves supported by SECCURE 0.5 (`p112`–`p521`,
  `bp160`–`bp512`).
- **No wrappers around the C tool.** This is a clean reimplementation.

## Footguns

SECCURE diverges from "textbook ECC" in several small but load-bearing ways. Each item below
broke a prior porting attempt. If you change the crypto code, re-read these first and
cross-check against `reference/c/` and `reference/py/`.

1. **Passphrase → private scalar is not `SHA-256(pw) mod n`.** SHA-256 produces a 32-byte AES-256
   key for an all-zero-IV AES-256-CTR keystream; the keystream's first `order_len_bin` bytes are
   read as a big-endian unsigned integer `a`, and the scalar is `d = (a mod (n-1)) + 1`. Skipping
   the AES-CTR step, reducing `mod n` instead of `mod (n-1)+1`, or truncating to
   `⌈log2(n)/8⌉` bytes all produce a different — and silently wrong — public key.
2. **The compact string encoding is base-90.** Not base-85, base-64, or base-94. SECCURE
   picks every printable ASCII char in `0x21..0x7E` *except* `"`, `'`, `\`, and `` ` ``,
   leaving 90 digits. The alphabet is non-contiguous so `c - 0x21` is wrong — use a lookup
   table on both sides. Encode the binary serialization as a big-endian unsigned integer,
   take repeated `mod 90`, reverse, then left-pad with `!` (digit zero) to the fixed
   per-curve length. The byte-for-byte alphabet table lives in `encoding.go` and matches
   `reference/c/serialize.c::compact_digits` and
   `reference/py/__init__.py::COMPACT_DIGITS` exactly.
3. **Point compression uses an x-coordinate plus a "y is odd" top sign bit, not SEC1
   `0x02`/`0x03`.** The high bit of byte 0 of the binary serialization carries `y & 1`.
4. **Signatures serialize as a single MPI, not `(r, s)`.** `sig_int = r * n + (s - 1)`, written
   big-endian as exactly `2 * order_len_bin` bytes. Always left-pad the compact form to
   `sig_len_compact` — py-seccure once shipped a bug that didn't and produced signatures the C
   tool would reject.
5. **ECDSA `k` is deterministic**, derived from the same AES-256-CTR-as-CPRNG construction as the
   passphrase, seeded from the private scalar and the message hash. Signatures are reproducible;
   that property is also the easiest cross-implementation parity check.
6. **ECIES message layout is `R || ciphertext || HMAC`.** Key material is
   `SHA-512(z_x_bytes)`; first 32 bytes are the AES-256 key, next 32 bytes are the HMAC-SHA-256
   key. AES-256-CTR with an all-zero 16-byte counter starting at 0. HMAC is computed over the
   ciphertext and then truncated to `maclen` bytes.
7. **The library API takes `[]byte`, never `string`, for the passphrase.** A Python 3 `str`
   would silently UTF-8-encode in a way that drifts from the C tool's raw `read(2)` byte stream;
   py-seccure explicitly raises `ValueError` on `str` input. Don't reintroduce the bug in Go.

## Repository layout

```
go-seccure/
├── seccure.go          # public API
├── curves.go           # curve parameter table (15 curves)
├── encoding.go         # base-94 codec
├── ec.go               # affine point ops, scalar mul, sqrt
├── compress.go         # point compression / decompression
├── kdf.go              # SHA-256 → AES-256-CTR CPRNG → hash_to_exponent
├── ecies.go            # ECIES encrypt/decrypt
├── ecdsa.go            # deterministic ECDSA sign/verify
├── dh.go               # DH token / establish
├── internal/ctrprng/   # AES-256-CTR keystream generator
├── cmd/                # eight CLI binaries
├── testdata/           # vectors.json (generated from py-seccure)
├── scripts/            # gen_vectors.py, crosscheck.sh
└── reference/          # local copies of C and Python sources for diffing
```

## Building

```sh
go build ./...
go test  ./...
```

Every CLI:

```sh
go install ./cmd/...
```

## Fuzzing

Six Go fuzz targets cover the main input-handling surfaces — base-90 codec,
public-key derivation, decryption, signature verification, and curve-name
lookup. Each is an "input X must never panic" target rather than a
cryptographic-property check; the cryptographic-correctness gate is the
cross-impl vector suite below.

```sh
# Smoke-run each target for 30 seconds:
for t in FuzzDecodeCompactNeverPanics FuzzEncodeDecodeCompactRoundTrip \
         FuzzPassphraseToPubkeyNeverPanics FuzzDecryptNeverPanics \
         FuzzVerifyBinaryNeverPanics FuzzCurveByNameNeverPanics; do
  go test -run '^$' -fuzz="^${t}$" -fuzztime=30s .
done
```

## Cross-implementation testing

Test vectors are generated from the Python reference:

```sh
python -m venv .venv && . .venv/bin/activate
pip install seccure
python scripts/gen_vectors.py > testdata/vectors.json
go test ./...
```

CI regenerates `testdata/vectors.json` from py-seccure on every run so upstream drift surfaces
immediately.

## Performance vs py-seccure

Measured on Apple M2 (`bench/compare.sh 2`). Go wins on small curves, ties
around p256, loses on p521 — py-seccure uses `gmpy2` (GMP-backed
multi-precision arithmetic), which outperforms Go's `math/big` once the
field elements get large. All numbers are well below the 100ms-per-op
threshold the brief calls out in §7.4.

```
op                     curve       go (µs)      py (µs)      py/go
------------------------------------------------------------------
PassphraseToPubkey     p160          432.0        521.2        1.2x
PassphraseToPubkey     p256          960.9        861.0        0.9x
PassphraseToPubkey     p521         4585.7       2777.0        0.6x
Sign                   p160          498.4        639.3        1.3x
Sign                   p256         1006.6        960.5        1.0x
Sign                   p521         4203.6       2849.3        0.7x
Verify                 p160          930.3       1103.5        1.2x
Verify                 p256         1971.5       1788.1        0.9x
Verify                 p521         8390.5       5827.1        0.7x
Encrypt                p160          944.5       1115.2        1.2x
Encrypt                p256         1997.8       1890.3        0.9x
Encrypt                p521         9150.2       5822.2        0.6x
Decrypt                p160          436.5        558.7        1.3x
Decrypt                p256         1127.6        945.7        0.8x
Decrypt                p521         4108.2       3068.5        0.7x
```

If p521 throughput matters for a future workload, the easiest wins are
(a) switching the EC arithmetic from affine to Jacobian coordinates (one
modular inverse per scalar mult instead of one per add) and (b) using a
sliding-window or wNAF scalar-mult algorithm. Today neither is implemented
because the canary parity comes first — the affine code mirrors py-seccure
line-for-line which makes byte-equality bisection trivial.

Run the benchmark yourself: `bench/compare.sh [seconds-per-op]`.

## See also

- B. Poettering, **SECCURE** (C reference): http://point-at-infinity.org/seccure/
- Bas Westerbaan, **py-seccure** (Python port): https://github.com/bwesterb/py-seccure
- SEC 1 v2.0 (SECP/NIST curves): https://www.secg.org/sec1-v2.pdf
- RFC 5639 (Brainpool curves): https://www.rfc-editor.org/rfc/rfc5639
