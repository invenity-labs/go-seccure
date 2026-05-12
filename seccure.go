// SPDX-License-Identifier: LGPL-3.0-or-later

// Package seccure is a pure-Go port of SECCURE (B. Poettering, v0.5) that is
// bit-for-bit wire-compatible with the C reference and with
// github.com/bwesterb/py-seccure. The same passphrase on the same curve
// produces the same compact public key, the same ciphertext, and the same
// signature byte stream as both upstreams.
//
// # Quick start
//
//	pub, _ := seccure.PassphraseToPubkey([]byte("Test1234"), seccure.CurveP256)
//	ct,  _ := seccure.Encrypt(plaintext, pub, seccure.CurveP256, 10)
//	pt,  _ := seccure.Decrypt(ct, []byte("Test1234"), seccure.CurveP256, 10)
//	sig, _ := seccure.Sign(msg, []byte("Test1234"), seccure.CurveP256)
//	err   := seccure.Verify(msg, sig, pub, seccure.CurveP256)
//
// # Threat model
//
// This package does NOT attempt constant-time / side-channel resistance —
// py-seccure itself warns against use where timing attacks apply, and we
// match its threat model. Don't use on attacker-co-resident hardware
// without an additional layer (e.g. TPM-backed key custody).
//
// # Passphrase encoding
//
// All passphrase arguments are raw []byte. No Unicode normalisation is
// applied; a Python 3 str.encode() drift was one of the reasons earlier
// porting attempts produced different public keys. If a caller wants to
// accept user input, encode it to bytes deliberately (typically UTF-8)
// before passing in.
//
// # Curves
//
// Fifteen curves are supported, matching SECCURE 0.5: the eight SECP/NIST
// curves p112–p521 and the seven Brainpool curves bp160–bp512. See the
// CurveLengths struct for per-curve wire sizes; CurveByName resolves both
// canonical names ("secp160r1") and short aliases ("p160", "bp256",
// "nistp192").
//
// # References
//
//   - README "Footguns" section — the wire-format spots that broke prior
//     porting attempts (base-90 alphabet, point compression, deterministic
//     ECDSA, ECIES KDF, etc).
//   - reference/c/ — the C source (GPL-2.0-or-later upstream; see NOTICE
//     for the licensing rationale).
//   - reference/py/ — py-seccure (LGPL-3.0-or-later).
package seccure

import (
	"errors"
	"strings"
)

// Curve identifies one of the fifteen curves supported by SECCURE 0.5.
//
// The enum order is internal; do not rely on the integer values across
// versions. Use CurveByName or CurveByCompactPubkeyLen to resolve curves from
// user input.
type Curve int

const (
	CurveP112 Curve = iota
	CurveP128
	CurveP160
	CurveP192
	CurveP224
	CurveP256
	CurveP384
	CurveP521
	CurveBP160
	CurveBP192
	CurveBP224
	CurveBP256
	CurveBP320
	CurveBP384
	CurveBP512
)

// Sentinel errors. Callers may switch on these with errors.Is.
var (
	ErrUnknownCurve      = errors.New("seccure: unknown curve")
	ErrAmbiguousCurve    = errors.New("seccure: ambiguous curve")
	ErrCurveMismatch     = errors.New("seccure: curve mismatch")
	ErrInvalidPubkey     = errors.New("seccure: invalid public key")
	ErrInvalidSignature  = errors.New("seccure: invalid signature")
	ErrSignatureMismatch = errors.New("seccure: signature does not verify")
	ErrHMACMismatch      = errors.New("seccure: HMAC verification failed")
	ErrInvalidCiphertext = errors.New("seccure: invalid ciphertext")
	ErrInvalidMACLen    = errors.New("seccure: invalid MAC length (must be 0..32 bytes)")
)

// CurveByName resolves a textual curve name to a Curve value. The C tool
// accepts canonical names ("secp160r1"), short aliases ("p160", "bp256"), and
// alternate names ("nistp192"). We match the upstream's non-ambiguous
// substring rule: if `name` is contained in exactly one registered curve
// name, that curve wins; otherwise we return ErrAmbiguousCurve or
// ErrUnknownCurve as appropriate.
func CurveByName(name string) (Curve, error) {
	if name == "" {
		return 0, ErrUnknownCurve
	}
	if c, ok := byNameTable[name]; ok {
		return c, nil
	}

	// Fall back to substring matching against canonical names + aliases,
	// mirroring curves.c::curve_by_name (which uses strstr).
	var matched Curve
	var matchCount int
	for fullName, c := range byNameTable {
		if strings.Contains(fullName, name) {
			if matchCount == 0 {
				matched = c
			} else if matched != c {
				return 0, ErrAmbiguousCurve
			}
			matchCount++
		}
	}
	if matchCount == 0 {
		return 0, ErrUnknownCurve
	}
	return matched, nil
}

// CurveLengths returns the on-the-wire byte/character lengths for a curve.
// Useful to callers that need to peel sig-suffixed payloads (seccure-veridec)
// or size buffers without going through the internal curve table.
type CurveLengths struct {
	PubkeyBin       int // pk_len_bin
	PubkeyCompact   int // pk_len_compact
	SignatureBin    int // sig_len_bin
	SignatureCompact int // sig_len_compact
	DHBin           int // dh_len_bin
	DHCompact       int // dh_len_compact
	ElementBin      int // elem_len_bin
	OrderBin        int // order_len_bin
}

// CurveByteLengths returns the per-curve wire lengths. See CurveLengths.
func CurveByteLengths(curve Curve) (CurveLengths, error) {
	cp := lookupCurve(curve)
	if cp == nil {
		return CurveLengths{}, ErrUnknownCurve
	}
	return CurveLengths{
		PubkeyBin:        cp.pkLenBin,
		PubkeyCompact:    cp.pkLenCompact,
		SignatureBin:     cp.sigLenBin,
		SignatureCompact: cp.sigLenCompact,
		DHBin:            cp.dhLenBin,
		DHCompact:        cp.dhLenCompact,
		ElementBin:       cp.elemLenBin,
		OrderBin:         cp.orderLenBin,
	}, nil
}

// CurveByCompactPubkeyLen returns the unique curve whose compact public-key
// length equals n. Returns ErrAmbiguousCurve when multiple curves share that
// length (notably the Brainpool / SECP collisions at 25, 30, 35, 40, 60
// chars) and ErrUnknownCurve when no curve matches.
func CurveByCompactPubkeyLen(n int) (Curve, error) {
	var matched Curve
	var matchCount int
	for _, cp := range curves {
		if cp == nil {
			continue
		}
		if cp.pkLenCompact == n {
			if matchCount == 0 {
				matched = cp.id
			} else {
				return 0, ErrAmbiguousCurve
			}
			matchCount++
		}
	}
	if matchCount == 0 {
		return 0, ErrUnknownCurve
	}
	return matched, nil
}

// PassphraseToPubkey deterministically derives the compact public key for the
// given passphrase on the given curve.
//
// The passphrase is treated as a raw byte string; no Unicode normalisation is
// applied. The output MUST byte-equal py-seccure's
// passphrase_to_pubkey(passphrase, curve=...) for every input — this is the
// canary check documented in §4.
//
// Derivation chain (see §3.1):
//
//   d         := hashToExponent(passphrase, curve)   // (SHA-256 → AES-CTR → mod (n-1) + 1)
//   P         := d * G                                // scalar mult on the base point
//   bin       := compress(P)                          // pkLenBin bytes, y-parity-as-(x+m)
//   compact   := encodeCompact(bin, pkLenCompact)     // base-90, left-padded
func PassphraseToPubkey(passphrase []byte, curve Curve) (string, error) {
	cp := lookupCurve(curve)
	if cp == nil {
		return "", ErrUnknownCurve
	}
	d := hashToExponent(passphrase, cp)
	p := scalarBaseMult(d, cp)
	if p.isInfinity() {
		// d ∈ [1, n-1] and gcd(d, n) = 1 since n is prime (cofactor 1 on
		// every SECCURE curve), so this branch is unreachable for any
		// valid curve. Belt-and-braces: return an error rather than
		// panicking, so a future curve with cofactor > 1 surfaces the
		// problem rather than crashing.
		return "", ErrInvalidPubkey
	}
	bin, err := compress(p, cp)
	if err != nil {
		return "", err
	}
	return encodeCompact(bin, cp.pkLenCompact)
}

// Encrypt, Decrypt are implemented in ecies.go.
// Sign, SignBinary, Verify, and VerifyBinary are implemented in ecdsa.go.

// DHToken and DHEstablish are implemented in dh.go.
