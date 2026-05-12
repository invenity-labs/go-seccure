// SPDX-License-Identifier: LGPL-3.0-or-later

package seccure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"math/big"
)

// ECIES — see §3.6.
//
// CORRECTION TO THE BRIEF. The brief said the KDF is "SHA-512(z_x_bytes)"
// where z_x is the x-coordinate of the shared point Z. The actual KDF (per
// reference/py/__init__.py::AffinePoint._ECIES_KDF and the C reference) is:
//
//   key := SHA-512( Z.x_bytes || R.x_bytes || R.y_bytes )
//
// where each coordinate is serialised as exactly elem_len_bin bytes
// big-endian, and R is the ephemeral pubkey (NOT compressed for the KDF —
// both x and y of R go in, as full coordinates). The 64-byte key splits as:
//
//   K_ENC = key[0:32]   // AES-256-CTR key
//   K_MAC = key[32:64]  // HMAC-SHA-256 key
//
// Wire format:
//
//   [ R compressed in pk_len_bin bytes ]
//   [ AES-256-CTR ciphertext, same length as plaintext ]
//   [ HMAC-SHA-256(K_MAC, ciphertext) truncated to maclen bytes ]
//
// AES-256-CTR uses an all-zero 16-byte counter starting at 0, big-endian
// increment. HMAC is computed over the CIPHERTEXT (not the plaintext) and
// then truncated to maclen bytes.
//
// The CLI's default maclen is unresolved upstream (see §3.6 and §11): the
// manpage says 80 bits (10 bytes), the C source says DEFAULT_MAC_LEN = 32.
// The LIBRARY API never picks a default; the CLI binaries must select one.

// Encrypt produces SECCURE-compatible ECIES ciphertext.
//
// maclen is the HMAC truncation length in bytes (0..32). py-seccure's library
// uses 10 (80 bits) by default; the CLI argument is in bits, not bytes.
//
// This function is intentionally randomised (the ephemeral ECDH scalar comes
// from crypto/rand). Cross-implementation parity is by round-trip — encrypt
// here, decrypt with py-seccure (or vice versa).
func Encrypt(plaintext []byte, pubkey string, curve Curve, maclen int) ([]byte, error) {
	if maclen < 0 || maclen > sha256.Size {
		return nil, ErrInvalidMACLen
	}
	cp := lookupCurve(curve)
	if cp == nil {
		return nil, ErrUnknownCurve
	}

	pkBin, err := decodeCompact(pubkey, cp.pkLenBin)
	if err != nil {
		return nil, ErrInvalidPubkey
	}
	p, err := decompress(pkBin, cp)
	if err != nil {
		return nil, ErrInvalidPubkey
	}

	// Generate an ephemeral scalar k in [1, n-1) such that both R = k*G
	// and Z = k*P are non-infinity. The loop is borrowed straight from
	// py-seccure (line 538-547).
	var rPoint, zPoint *point
	var k *big.Int
	for {
		k, err = randomScalar(cp)
		if err != nil {
			return nil, err
		}
		rPoint = scalarBaseMult(k, cp)
		if rPoint.isInfinity() {
			continue
		}
		// SECCURE multiplies by the cofactor here; all 15 supported
		// curves have cofactor 1, so k * h = k, but mirror the upstream
		// for clarity.
		kh := new(big.Int).Mul(k, big.NewInt(int64(cp.h)))
		zPoint = p.scalarMult(kh, cp)
		if !zPoint.isInfinity() {
			break
		}
	}

	key := eciesKDF(zPoint, rPoint, cp)
	encKey, macKey := key[:32], key[32:64]

	rBin, err := compress(rPoint, cp)
	if err != nil {
		return nil, err
	}

	ct := make([]byte, len(plaintext))
	if err := aesCTRXOR(encKey, plaintext, ct); err != nil {
		return nil, err
	}

	mac := hmac.New(sha256.New, macKey)
	mac.Write(ct)
	tag := mac.Sum(nil)[:maclen]

	out := make([]byte, 0, len(rBin)+len(ct)+len(tag))
	out = append(out, rBin...)
	out = append(out, ct...)
	out = append(out, tag...)
	return out, nil
}

// Decrypt reverses Encrypt. Returns ErrHMACMismatch on tag failure or
// ErrInvalidCiphertext if the message is too short to contain the required
// header + tag.
func Decrypt(ciphertext, passphrase []byte, curve Curve, maclen int) ([]byte, error) {
	if maclen < 0 || maclen > sha256.Size {
		return nil, ErrInvalidMACLen
	}
	cp := lookupCurve(curve)
	if cp == nil {
		return nil, ErrUnknownCurve
	}

	if len(ciphertext) < cp.pkLenBin+maclen {
		return nil, ErrInvalidCiphertext
	}
	rBin := ciphertext[:cp.pkLenBin]
	ct := ciphertext[cp.pkLenBin : len(ciphertext)-maclen]
	tag := ciphertext[len(ciphertext)-maclen:]

	rPoint, err := decompress(rBin, cp)
	if err != nil {
		return nil, ErrInvalidCiphertext
	}

	d := hashToExponent(passphrase, cp)
	// cofactor = 1 on every supported curve; mirror py-seccure (line 553).
	d = new(big.Int).Mul(d, big.NewInt(int64(cp.h)))
	zPoint := rPoint.scalarMult(d, cp)
	if zPoint.isInfinity() {
		return nil, ErrInvalidCiphertext
	}

	key := eciesKDF(zPoint, rPoint, cp)
	encKey, macKey := key[:32], key[32:64]

	mac := hmac.New(sha256.New, macKey)
	mac.Write(ct)
	want := mac.Sum(nil)[:maclen]
	if !hmac.Equal(want, tag) {
		return nil, ErrHMACMismatch
	}

	pt := make([]byte, len(ct))
	if err := aesCTRXOR(encKey, ct, pt); err != nil {
		return nil, err
	}
	return pt, nil
}

// eciesKDF computes the 64-byte SECCURE ECIES key material for shared point Z
// and ephemeral pubkey R. See the package-level comment above for the rule.
func eciesKDF(z, r *point, cp *curveParams) []byte {
	h := sha512.New()
	h.Write(serializeElem(z.x, cp))
	h.Write(serializeElem(r.x, cp))
	h.Write(serializeElem(r.y, cp))
	return h.Sum(nil)
}

// serializeElem returns x as a big-endian unsigned integer in exactly
// cp.elemLenBin bytes (left-padded with zeros).
func serializeElem(x *big.Int, cp *curveParams) []byte {
	buf := x.Bytes()
	if len(buf) > cp.elemLenBin {
		// Unreachable for any x < cp.p, since elem_len_bin = byteLen(p).
		buf = buf[len(buf)-cp.elemLenBin:]
	}
	out := make([]byte, cp.elemLenBin)
	copy(out[cp.elemLenBin-len(buf):], buf)
	return out
}

// aesCTRXOR encrypts/decrypts src into dst with AES-256-CTR using the given
// 32-byte key and an all-zero 16-byte IV (counter starts at 0, big-endian
// increment). Matches reference/c/protocol.c and py-seccure exactly.
func aesCTRXOR(key, src, dst []byte) error {
	if len(key) != 32 {
		return ErrInvalidPubkey
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	// SECCURE's ECIES uses an all-zero AES-CTR IV starting at 0 (matches
	// reference/c/protocol.c and py-seccure). IV reuse is bounded by the
	// ephemeral DH key R being fresh per encryption, so K_ENC differs per
	// message and the IV-reuse concern that motivates G407 doesn't apply.
	var iv [aes.BlockSize]byte
	cipher.NewCTR(block, iv[:]).XORKeyStream(dst, src) // #nosec G407 -- per-message K_ENC; zero IV is the SECCURE ECIES spec
	return nil
}

// randomScalar pulls a fresh scalar in [1, n-1) using crypto/rand.
// Mirrors py-seccure's Crypto.Random.random.randrange(0, n-1) + the +1 done
// implicitly by the outer loop guard.
func randomScalar(cp *curveParams) (*big.Int, error) {
	nMinus1 := new(big.Int).Sub(cp.n, big.NewInt(1))
	k, err := rand.Int(rand.Reader, nMinus1)
	if err != nil {
		return nil, err
	}
	// rand.Int returns a value in [0, nMinus1). Shift to [1, n-1].
	k.Add(k, big.NewInt(1))
	return k, nil
}
