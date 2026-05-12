# go-seccure

A pure-Go port of [SECCURE](http://point-at-infinity.org/seccure/) (B. Poettering, v0.5) that is
**bit-for-bit wire-compatible** with the C reference implementation and with
[`bwesterb/py-seccure`](https://github.com/bwesterb/py-seccure). The same passphrase on the same
curve produces the same compact public key, the same ciphertext, and the same signature byte
stream as both reference implementations.

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

## Install

### As a Go library

```sh
go get github.com/invenity-labs/go-seccure
```

### CLI tools

**Homebrew** (macOS and Linux):

```sh
brew tap invenity-labs/tap
brew install go-seccure
```

This installs all eight `seccure-*` binaries.

**Pre-built binaries** for Linux (amd64/arm64), macOS (amd64/arm64), and
Windows (amd64) are attached to every
[GitHub Release](https://github.com/invenity-labs/go-seccure/releases),
along with SHA-256 checksums and SPDX SBOMs. Each archive contains all
eight CLI binaries.

**From source**:

```sh
go install github.com/invenity-labs/go-seccure/cmd/...@latest
```

## Non-goals

- **No constant-time / side-channel resistance.** `py-seccure` itself warns against use where
  timing attacks apply; we match its threat model.
- **No new curves.** Only the 15 curves supported by SECCURE 0.5 (`p112`–`p521`,
  `bp160`–`bp512`).
- **No wrappers around the C tool.** This is a clean reimplementation.

## Wire-format notes

SECCURE diverges from "textbook ECC" in several small but load-bearing ways.
Each of these is something a reviewer or anyone porting SECCURE to another
language needs to know — the canonical source is the C reference; this is
a Go-friendly summary, cross-referenced against `reference/c/` and
`reference/py/`.

1. **Passphrase → private scalar is not `SHA-256(pw) mod n`.** SHA-256(pw)
   produces a 32-byte AES-256 key for an all-zero-IV AES-256-CTR keystream;
   the keystream's first `order_len_bin` bytes are read as a big-endian
   unsigned integer `a`, and the scalar is `d = (a mod (n-1)) + 1`.
   Skipping the AES-CTR step, reducing `mod n` instead of `mod (n-1) + 1`,
   or truncating to `⌈log2(n)/8⌉` bytes all produce a different — and
   silently wrong — public key.

2. **The compact string encoding is base-90.** Not base-85, base-64, or
   base-94. The alphabet is every printable ASCII char in `0x21..0x7E`
   *except* `"`, `'`, `\`, and `` ` `` — 90 digits in total. The alphabet
   is non-contiguous so `c - 0x21` is wrong; both encoder and decoder need
   a lookup table. Encode the binary serialization as a big-endian unsigned
   integer, take repeated `mod 90`, reverse, then left-pad with `!`
   (digit zero) to the fixed per-curve length. The alphabet table in
   `encoding.go` matches `reference/c/serialize.c::compact_digits` and
   `reference/py/__init__.py::COMPACT_DIGITS` byte-for-byte.

3. **Point compression encodes `x` if `y` is even, `x + m` if `y` is
   odd.** Then write the result big-endian as exactly `pk_len_bin` bytes.
   This is equivalent to "x with the y-parity bit OR-ed into the top of
   byte 0" only when `bit_len(m) < 8 * pk_len_bin`; for curves where the
   prime fills its bytes exactly (notably `secp521r1`) it isn't. Decoding
   reverses by comparing the recovered integer against `m`.

4. **Signatures serialize as a single MPI**, not `(r, s)`. The packing is
   `sig_int = s * n + r`, written big-endian as exactly `2 * order_len_bin`
   bytes. On decode: `s = sig_int / n`, `r = sig_int mod n`; reject if
   either falls outside `[1, n-1]`. Always left-pad the compact form to
   `sig_len_compact` characters.

5. **ECDSA `k` is deterministic**. It's derived via the same AES-256-CTR-
   as-CPRNG construction as the passphrase scalar, but seeded from
   `HMAC-SHA-256(key = d_padded, msg = SHA-512(message))` where `d_padded`
   is the private scalar serialized as `order_len_bin` big-endian bytes.
   Signatures are reproducible byte-for-byte — that property is also the
   easiest cross-implementation parity check.

6. **ECIES message layout is `R_compressed || ciphertext || HMAC`.** Key
   material is `SHA-512(Z.x_bytes || R.x_bytes || R.y_bytes)` where `Z`
   is the shared secret point and `R` is the ephemeral public key; each
   coordinate is serialized as exactly `elem_len_bin` big-endian bytes.
   The first 32 bytes of the digest are the AES-256-CTR key, the next 32
   are the HMAC-SHA-256 key. AES-256-CTR uses an all-zero 16-byte counter
   starting at 0. HMAC is computed over the ciphertext (post-encryption)
   and then truncated to `maclen` bytes.

7. **The library API takes `[]byte`, never `string`, for the passphrase.**
   A Python 3 `str` would silently UTF-8-encode in a way that drifts from
   the C tool's raw `read(2)` byte stream; py-seccure explicitly raises
   `ValueError` on `str` input. The Go API enforces the same discipline
   by typing the parameter as `[]byte`.

## Repository layout

```
go-seccure/
├── seccure.go          # public API
├── curves.go           # curve parameter table (15 curves)
├── encoding.go         # base-90 codec
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
field elements get large. All numbers are well within the latency budget
of a typical encryption pipeline.

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

If p521 throughput ever becomes a bottleneck, the two unlanded wins are
(a) switching the EC arithmetic from affine to Jacobian coordinates (one
modular inverse per scalar mult instead of one per add) and (b) using a
sliding-window or wNAF scalar-mult algorithm. Neither is implemented today
— the affine code intentionally mirrors py-seccure's so byte-level parity
bisection stays simple.

Run the benchmark yourself: `bench/compare.sh [seconds-per-op]`.

## See also

- B. Poettering, **SECCURE** (C reference): http://point-at-infinity.org/seccure/
- Bas Westerbaan, **py-seccure** (Python port): https://github.com/bwesterb/py-seccure
- SEC 1 v2.0 (SECP/NIST curves): https://www.secg.org/sec1-v2.pdf
- RFC 5639 (Brainpool curves): https://www.rfc-editor.org/rfc/rfc5639
