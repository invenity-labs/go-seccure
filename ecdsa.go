// SPDX-License-Identifier: LGPL-3.0-or-later

package seccure

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"io"
	"math/big"

	"github.com/invenity-labs/go-seccure/internal/ctrprng"
)

// Deterministic ECDSA — see §3.4 and §3.5.
//
// Two SECCURE-specific quirks make this code different from "textbook" ECDSA:
//
// 1. Signature serialisation is a single big integer
//      sig_int = s * n + r                  (NOT r * n + (s - 1))
//    where s, r in [1, n-1]. Written big-endian as exactly sig_len_bin
//    bytes (= 2 * orderLenBin), left-padded with zeros, then base-90 encoded
//    to exactly sig_len_compact characters.
//
//    On decode: s = sig_int / n; r = sig_int mod n; reject if either is
//    outside [1, n-1].
//
//    (The brief originally said "r * n + (s - 1)"; that's wrong. Both
//    reference/c/protocol.c:208-209 and reference/py/__init__.py:692-693
//    produce s * n + r.)
//
// 2. k is deterministic, seeded from the private scalar AND the message
//    digest (NOT random):
//
//      hmk  := d as big-endian, padded to orderLenBin bytes
//      seed := HMAC-SHA-256(key=hmk, msg=md)              // 32 bytes
//      k    := first orderLenBin bytes of AES-256-CTR(seed) → (mod (n-1)) + 1
//
//    where md is the SHA-512 digest of the user-supplied message (the C
//    reference and py-seccure both SHA-512 the message before signing).
//
//    Deterministic k means signatures are reproducible byte-for-byte, which
//    is what makes cross-implementation parity testing tractable.
//
// References: reference/c/protocol.c::ECDSA_sign / ecdsa_cprng_init
//             reference/py/__init__.py::PrivKey._ECDSA_sign

// SignBinary produces a deterministic ECDSA signature in raw binary form,
// exactly sig_len_bin bytes long.
func SignBinary(message, passphrase []byte, curve Curve) ([]byte, error) {
	cp := lookupCurve(curve)
	if cp == nil {
		return nil, ErrUnknownCurve
	}
	md := sha512.Sum512(message)
	d := hashToExponent(passphrase, cp)
	sigInt := ecdsaSign(md[:], d, cp)

	out := make([]byte, cp.sigLenBin)
	sb := sigInt.Bytes()
	if len(sb) > cp.sigLenBin {
		// Mathematically unreachable: sig_int < n*n - 1, which by
		// construction of sig_len_bin fits in sig_len_bin bytes.
		return nil, ErrInvalidSignature
	}
	copy(out[cp.sigLenBin-len(sb):], sb)
	return out, nil
}

// Sign produces a deterministic ECDSA signature in compact (base-90) form.
//
// "Deterministic" means the same (message, passphrase, curve) triple ALWAYS
// produces the same signature bytes — see §3.5.
func Sign(message, passphrase []byte, curve Curve) (string, error) {
	bin, err := SignBinary(message, passphrase, curve)
	if err != nil {
		return "", err
	}
	cp := lookupCurve(curve)
	return encodeCompact(bin, cp.sigLenCompact)
}

// Verify returns nil if the compact-form signature is valid for the message
// under the given public key, ErrSignatureMismatch otherwise.
func Verify(message []byte, signature, pubkey string, curve Curve) error {
	cp := lookupCurve(curve)
	if cp == nil {
		return ErrUnknownCurve
	}
	sigBin, err := decodeCompact(signature, cp.sigLenBin)
	if err != nil {
		return ErrInvalidSignature
	}
	return VerifyBinary(message, sigBin, pubkey, curve)
}

// VerifyBinary is the binary-signature counterpart to Verify.
func VerifyBinary(message, signature []byte, pubkey string, curve Curve) error {
	cp := lookupCurve(curve)
	if cp == nil {
		return ErrUnknownCurve
	}
	if len(signature) != cp.sigLenBin {
		return ErrInvalidSignature
	}

	pkBin, err := decodeCompact(pubkey, cp.pkLenBin)
	if err != nil {
		return ErrInvalidPubkey
	}
	q, err := decompress(pkBin, cp)
	if err != nil {
		return ErrInvalidPubkey
	}

	md := sha512.Sum512(message)
	if !ecdsaVerify(md[:], new(big.Int).SetBytes(signature), q, cp) {
		return ErrSignatureMismatch
	}
	return nil
}

// ecdsaSign returns the SECCURE sig_int = s*n + r for message digest md and
// private scalar d. md must be exactly 64 bytes (a SHA-512 digest), matching
// the C reference's `gcry_mpi_scan(&e, GCRYMPI_FMT_USG, msg, 64, NULL)`.
func ecdsaSign(md []byte, d *big.Int, cp *curveParams) *big.Int {
	cprng := newEcdsaCPRNG(md, d, cp)

	// e := md (as big-endian unsigned int) mod n
	e := new(big.Int).SetBytes(md)
	e.Mod(e, cp.n)

	var r, s *big.Int
	for {
		// Inner loop: pull k from the CPRNG until r != 0.
		for {
			k := cprngExponent(cprng, cp)
			p1 := scalarBaseMult(k, cp)
			if p1.isInfinity() {
				continue
			}
			r = new(big.Int).Mod(p1.x, cp.n)
			if r.Sign() == 0 {
				continue
			}

			// s = (d*r + e) / k mod n
			s = new(big.Int).Mul(d, r)
			s.Add(s, e)
			s.Mod(s, cp.n)
			kInv := new(big.Int).ModInverse(k, cp.n)
			s.Mul(s, kInv)
			s.Mod(s, cp.n)
			break
		}
		if s.Sign() != 0 {
			break
		}
		// s == 0 is rejected; loop and pull a new k. In practice this
		// never happens — the probability is on the order of 1/n.
	}

	// sig_int = s * n + r
	sig := new(big.Int).Mul(s, cp.n)
	sig.Add(sig, r)
	return sig
}

// ecdsaVerify implements the standard ECDSA verification equation against
// the SECCURE-packed sig_int = s*n + r. q is the signer's public point.
func ecdsaVerify(md []byte, sigInt *big.Int, q *point, cp *curveParams) bool {
	if sigInt.Sign() < 0 {
		return false
	}
	s, r := new(big.Int).QuoRem(sigInt, cp.n, new(big.Int))

	// 0 < s < n and 0 < r < n.
	one := big.NewInt(1)
	if s.Cmp(one) < 0 || s.Cmp(cp.n) >= 0 || r.Cmp(one) < 0 || r.Cmp(cp.n) >= 0 {
		return false
	}

	// e = md mod n
	e := new(big.Int).SetBytes(md)
	e.Mod(e, cp.n)

	// w = s^-1 mod n
	w := new(big.Int).ModInverse(s, cp.n)
	if w == nil {
		return false
	}

	// u1 = e*w mod n,  u2 = r*w mod n
	u1 := new(big.Int).Mul(e, w)
	u1.Mod(u1, cp.n)
	u2 := new(big.Int).Mul(r, w)
	u2.Mod(u2, cp.n)

	x1 := scalarBaseMult(u1, cp)
	x2 := q.scalarMult(u2, cp)
	sum := x1.add(x2, cp)
	if sum.isInfinity() {
		return false
	}

	v := new(big.Int).Mod(sum.x, cp.n)
	return v.Cmp(r) == 0
}

// newEcdsaCPRNG initialises the per-signature deterministic-k stream.
// Mirrors reference/c/protocol.c::ecdsa_cprng_init.
func newEcdsaCPRNG(md []byte, d *big.Int, cp *curveParams) *ctrprng.Reader {
	// hmk = d as big-endian, padded to orderLenBin bytes.
	hmk := make([]byte, cp.orderLenBin)
	db := d.Bytes()
	copy(hmk[cp.orderLenBin-len(db):], db)

	mac := hmac.New(sha256.New, hmk)
	mac.Write(md)
	var seed [32]byte
	copy(seed[:], mac.Sum(nil))

	return ctrprng.New(seed)
}

// cprngExponent pulls one orderLenBin-byte block from the CPRNG and reduces
// it the same way hashToExponent does ((a mod (n-1)) + 1 ∈ [1, n-1]).
func cprngExponent(r *ctrprng.Reader, cp *curveParams) *big.Int {
	buf := make([]byte, cp.orderLenBin)
	if _, err := io.ReadFull(r, buf); err != nil {
		panic("seccure: ctrprng Read failed unexpectedly: " + err.Error())
	}
	a := new(big.Int).SetBytes(buf)
	nMinus1 := new(big.Int).Sub(cp.n, big.NewInt(1))
	a.Mod(a, nMinus1)
	a.Add(a, big.NewInt(1))
	return a
}
