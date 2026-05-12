// SPDX-License-Identifier: LGPL-3.0-or-later

package seccure

import "math/big"

// Point compression — see §3.3.
//
// CORRECTION TO THE BRIEF'S §3.3. The brief described compression as "x
// written big-endian as elem_len_bin bytes, with parity-of-y OR'd into the
// top bit of byte 0". That's a useful mental model for curves where
// bitLen(p) is a multiple of 8 (most of them), but the universal rule —
// matching reference/py/__init__.py:518-523 and reference/c/serialize.c —
// is:
//
//   encoded := x       if y is even
//              x + m   if y is odd          (m = field prime)
//
// then written big-endian in EXACTLY pk_len_bin bytes (left-padded with
// zeros if necessary). Because x < m and pk_len_bin = byteLen(2m - 1), the
// value (x + m) always fits in pk_len_bin bytes.
//
// Decompression reverses this:
//
//   1. Read the value v big-endian from pk_len_bin bytes.
//   2. If v >= m: yflag = true, x = v - m. Else: yflag = false, x = v.
//   3. Compute h = x^3 + a*x + b mod m.
//   4. y = modSqrt(h, m). If y is nil, reject (point not on curve).
//   5. If bit 0 of y matches yflag, keep y; else use (m - y).
//
// This is exactly what py-seccure does, so cross-implementation parity is
// inherited as long as the two share the same big-endian byte handling.

// compress serializes p into exactly cp.pkLenBin bytes per the rule above.
// Returns ErrInvalidPubkey if p is the point at infinity (SECCURE has no
// canonical wire form for it; py-seccure's serializer raises in the same
// situation by way of asserting x > 0).
func compress(p *point, cp *curveParams) ([]byte, error) {
	if p.isInfinity() {
		return nil, ErrInvalidPubkey
	}

	v := new(big.Int).Set(p.x)
	if p.y.Bit(0) == 1 {
		v.Add(v, cp.p)
	}

	buf := v.Bytes()
	if len(buf) > cp.pkLenBin {
		// Should never happen for a valid point on cp; v < 2m and
		// pkLenBin = byteLen(2m - 1).
		return nil, ErrInvalidPubkey
	}

	out := make([]byte, cp.pkLenBin)
	copy(out[cp.pkLenBin-len(buf):], buf)
	return out, nil
}

// decompress is the inverse of compress. Returns ErrInvalidPubkey if the
// input length is wrong, the recovered x falls outside [1, m], or no
// square root exists (i.e. the point is not on the curve).
//
// Mirrors py-seccure's Curve.point_from_string + _point_decompress
// (reference/py/__init__.py:835-856).
func decompress(buf []byte, cp *curveParams) (*point, error) {
	if len(buf) != cp.pkLenBin {
		return nil, ErrInvalidPubkey
	}

	v := new(big.Int).SetBytes(buf)
	yflag := v.Cmp(cp.p) >= 0
	if yflag {
		v.Sub(v, cp.p)
	}

	// py-seccure asserts 0 < x <= m; treat the boundary cases as invalid.
	if v.Sign() <= 0 || v.Cmp(cp.p) > 0 {
		return nil, ErrInvalidPubkey
	}

	// h = x^3 + a*x + b mod m
	h := new(big.Int).Mul(v, v)
	h.Add(h, cp.a)
	h.Mul(h, v)
	h.Add(h, cp.b)
	h.Mod(h, cp.p)

	y := modSqrt(h, cp.p)
	if y == nil {
		return nil, ErrInvalidPubkey
	}

	wantBit := uint(0)
	if yflag {
		wantBit = 1
	}
	if y.Bit(0) != wantBit {
		y = new(big.Int).Sub(cp.p, y)
	}

	return &point{x: v, y: y}, nil
}
