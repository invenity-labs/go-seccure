// SPDX-License-Identifier: LGPL-3.0-or-later

package seccure

import (
	"crypto/sha512"
	"math/big"
)

// Diffie-Hellman — see §3.7.
//
// CORRECTION TO THE BRIEF. The brief said the established and verification
// keys are derived as SHA-512(z_x_bytes)[ranges]. The actual upstream rule
// (per reference/c/protocol.c::DH_KDF, lines 306-314) hashes BOTH
// coordinates of the shared point:
//
//   keybuf := SHA-512( Z.x_bytes || Z.y_bytes )            // 64 bytes
//   K_ESTABLISHED  := keybuf[0  : dh_len_bin]               // base-90 encoded
//   K_VERIFICATION := keybuf[32 : 32 + dh_len_bin]          // base-90 encoded
//
// where Z = priv * peer_pubkey and each coordinate is serialised big-endian
// in exactly elem_len_bin bytes. Both halves of keybuf are independently
// base-90 encoded to dh_len_compact characters.
//
// dh_len_bin = min((bitLen(n)//2 + 7)//8, 32), per the curve table in §5.
//
// Wire surface: two compact-string pubkeys (one per party) are exchanged on
// the network; each side runs DHEstablish locally.

// DHToken generates a fresh ephemeral DH token (the compact pubkey to send to
// the peer) and the private scalar (kept locally).
//
// The private scalar is returned as a big-endian byte string of exactly
// curve.orderLenBin bytes, so it can be persisted/transported as-is and fed
// back into DHEstablish.
func DHToken(curve Curve) (token string, priv []byte, err error) {
	cp := lookupCurve(curve)
	if cp == nil {
		return "", nil, ErrUnknownCurve
	}

	k, err := randomScalar(cp)
	if err != nil {
		return "", nil, err
	}
	p := scalarBaseMult(k, cp)
	if p.isInfinity() {
		// k ∈ [1, n-1] and gcd(k, n) = 1 (n prime); unreachable for any
		// supported curve.
		return "", nil, ErrInvalidPubkey
	}

	bin, err := compress(p, cp)
	if err != nil {
		return "", nil, err
	}
	token, err = encodeCompact(bin, cp.pkLenCompact)
	if err != nil {
		return "", nil, err
	}

	// Pack the scalar as orderLenBin big-endian bytes (matches how the C
	// reference and py-seccure persist private material).
	priv = make([]byte, cp.orderLenBin)
	kb := k.Bytes()
	copy(priv[cp.orderLenBin-len(kb):], kb)
	return token, priv, nil
}

// DHEstablish completes a DH exchange given the peer's token and the local
// private scalar. Returns the established (shared-secret) key and a separate
// verification key, both as compact strings.
//
// Returns ErrInvalidPubkey if the peer's token decodes to an invalid point
// (wrong length, off-curve, etc.) — corresponds to
// reference/c/ecc.c::full_key_validation. Since every SECCURE curve has
// cofactor 1, the additional order check is a no-op and the embedded-key
// check (length / on-curve / non-infinity) is sufficient.
func DHEstablish(peerToken string, priv []byte, curve Curve) (established, verification string, err error) {
	cp := lookupCurve(curve)
	if cp == nil {
		return "", "", ErrUnknownCurve
	}

	peerBin, err := decodeCompact(peerToken, cp.pkLenBin)
	if err != nil {
		return "", "", ErrInvalidPubkey
	}
	peer, err := decompress(peerBin, cp)
	if err != nil {
		return "", "", ErrInvalidPubkey
	}

	k := new(big.Int).SetBytes(priv)
	z := peer.scalarMult(k, cp)
	if z.isInfinity() {
		return "", "", ErrInvalidPubkey
	}

	// keybuf = SHA-512(Z.x || Z.y), each coord elemLenBin bytes big-endian.
	h := sha512.New()
	h.Write(serializeElem(z.x, cp))
	h.Write(serializeElem(z.y, cp))
	keybuf := h.Sum(nil)

	estBytes := keybuf[0:cp.dhLenBin]
	verBytes := keybuf[32 : 32+cp.dhLenBin]

	established, err = encodeCompact(estBytes, cp.dhLenCompact)
	if err != nil {
		return "", "", err
	}
	verification, err = encodeCompact(verBytes, cp.dhLenCompact)
	if err != nil {
		return "", "", err
	}
	return established, verification, nil
}
