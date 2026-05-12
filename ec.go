// SPDX-License-Identifier: LGPL-3.0-or-later

package seccure

import "math/big"

// Affine elliptic-curve point arithmetic over math/big.
//
// We intentionally do NOT use crypto/elliptic. The reasons:
//
//   - SECCURE supports curves crypto/elliptic does not (the small SECP curves
//     112/128/160, and all seven Brainpool curves).
//   - SECCURE's point compression (sign-bit-via-(x+m)-or-x, see compress.go)
//     is not the SEC1 0x02/0x03 scheme that crypto/elliptic emits.
//
// We DO NOT attempt constant-time arithmetic; SECCURE's threat model
// explicitly does not include timing-side-channel resistance, and we match
// it. §1 calls this out as a non-goal.
//
// The algorithms here mirror py-seccure's affine AffinePoint implementation
// (reference/py/__init__.py:416-501) so that any divergence in test vectors
// can be diff-bisected against a known-good reference. We use the simpler
// affine formulas (one modular inverse per add) rather than Jacobian
// coordinates; performance is good enough for the target use case
// (passphrase-derived keys, not bulk signing).

// point is an affine elliptic-curve point. nil is the point at infinity.
// A non-infinity point ALWAYS has non-nil x and y.
type point struct {
	x, y *big.Int
}

// isInfinity reports whether p is the point at infinity (nil pointer).
func (p *point) isInfinity() bool {
	return p == nil
}

// equal reports whether p and q are the same point (including both infinity).
func (p *point) equal(q *point) bool {
	if p.isInfinity() || q.isInfinity() {
		return p.isInfinity() && q.isInfinity()
	}
	return p.x.Cmp(q.x) == 0 && p.y.Cmp(q.y) == 0
}

// negate returns -p (the additive inverse): (x, -y mod p) for non-infinity,
// infinity otherwise.
func (p *point) negate(cp *curveParams) *point {
	if p.isInfinity() {
		return nil
	}
	negY := new(big.Int).Neg(p.y)
	negY.Mod(negY, cp.p)
	return &point{x: new(big.Int).Set(p.x), y: negY}
}

// onCurve reports whether p satisfies the curve equation y^2 = x^3 + a*x + b
// (mod p). The point at infinity is considered on the curve.
func (p *point) onCurve(cp *curveParams) bool {
	if p.isInfinity() {
		return true
	}
	if p.x.Sign() < 0 || p.x.Cmp(cp.p) >= 0 ||
		p.y.Sign() < 0 || p.y.Cmp(cp.p) >= 0 {
		return false
	}
	lhs := new(big.Int).Mul(p.y, p.y)
	lhs.Mod(lhs, cp.p)

	rhs := new(big.Int).Mul(p.x, p.x)
	rhs.Add(rhs, cp.a)
	rhs.Mul(rhs, p.x)
	rhs.Add(rhs, cp.b)
	rhs.Mod(rhs, cp.p)

	return lhs.Cmp(rhs) == 0
}

// add returns p + q on the curve defined by cp.
//
// Handles every degenerate case:
//   - either operand at infinity: returns the other operand.
//   - p == q: delegates to double.
//   - p == -q (same x, opposite y): returns infinity.
func (p *point) add(q *point, cp *curveParams) *point {
	if p.isInfinity() {
		return q.clone()
	}
	if q.isInfinity() {
		return p.clone()
	}
	if p.x.Cmp(q.x) == 0 {
		if p.y.Cmp(q.y) == 0 {
			return p.double(cp)
		}
		// p == -q (since y_p + y_q ≡ 0 (mod p) is the only other
		// possibility on a Weierstrass curve), so the sum is infinity.
		return nil
	}

	m := cp.p

	// λ = (q.y - p.y) / (q.x - p.x) mod m
	num := new(big.Int).Sub(q.y, p.y)
	den := new(big.Int).Sub(q.x, p.x)
	den.ModInverse(den, m)
	lambda := new(big.Int).Mul(num, den)
	lambda.Mod(lambda, m)

	// rx = λ^2 - p.x - q.x mod m
	rx := new(big.Int).Mul(lambda, lambda)
	rx.Sub(rx, p.x)
	rx.Sub(rx, q.x)
	rx.Mod(rx, m)

	// ry = λ * (p.x - rx) - p.y mod m
	ry := new(big.Int).Sub(p.x, rx)
	ry.Mul(ry, lambda)
	ry.Sub(ry, p.y)
	ry.Mod(ry, m)

	return &point{x: rx, y: ry}
}

// double returns 2*p on the curve defined by cp. Returns infinity if p.y == 0
// (the only point of order 2 on a Weierstrass curve).
func (p *point) double(cp *curveParams) *point {
	if p.isInfinity() {
		return nil
	}
	if p.y.Sign() == 0 {
		return nil
	}

	m := cp.p

	// λ = (3 * p.x^2 + a) / (2 * p.y) mod m
	num := new(big.Int).Mul(p.x, p.x)
	num.Mul(num, big.NewInt(3))
	num.Add(num, cp.a)

	den := new(big.Int).Lsh(p.y, 1) // 2*p.y
	den.ModInverse(den, m)

	lambda := new(big.Int).Mul(num, den)
	lambda.Mod(lambda, m)

	// rx = λ^2 - 2*p.x mod m
	rx := new(big.Int).Mul(lambda, lambda)
	rx.Sub(rx, p.x)
	rx.Sub(rx, p.x)
	rx.Mod(rx, m)

	// ry = λ * (p.x - rx) - p.y mod m
	ry := new(big.Int).Sub(p.x, rx)
	ry.Mul(ry, lambda)
	ry.Sub(ry, p.y)
	ry.Mod(ry, m)

	return &point{x: rx, y: ry}
}

// clone returns a deep copy of p. Used inside add() / scalarMult() so the
// caller's input is never mutated by an intermediate operation.
func (p *point) clone() *point {
	if p.isInfinity() {
		return nil
	}
	return &point{
		x: new(big.Int).Set(p.x),
		y: new(big.Int).Set(p.y),
	}
}

// scalarMult returns k*p using left-to-right double-and-add.
//
// §8 day 2 suggests a Montgomery ladder for constant-ish
// time. We use plain double-and-add here for parity with py-seccure
// (reference/py/__init__.py:463-473) and because constant-time is an
// explicit non-goal (§1). Swapping in a Montgomery ladder later is a local
// rewrite that does not affect output vectors.
//
// Negative k is reduced mod n (the curve order) before scalar multiplication;
// k == 0 returns infinity.
func (p *point) scalarMult(k *big.Int, cp *curveParams) *point {
	if p.isInfinity() {
		return nil
	}
	// Reduce k into [0, n). math/big.Mod returns a non-negative result.
	kr := new(big.Int).Mod(k, cp.n)
	if kr.Sign() == 0 {
		return nil
	}

	var r *point // accumulator, infinity to start
	for i := kr.BitLen() - 1; i >= 0; i-- {
		r = r.double(cp)
		if kr.Bit(i) == 1 {
			r = r.add(p, cp)
		}
	}
	return r
}

// scalarBaseMult returns k*G where G is cp's base point.
func scalarBaseMult(k *big.Int, cp *curveParams) *point {
	g := &point{x: cp.gx, y: cp.gy}
	return g.scalarMult(k, cp)
}

// modSqrt returns one modular square root of a mod p, or nil if no square
// root exists (i.e. a is not a quadratic residue mod p).
//
// Uses the p ≡ 3 mod 4 fast path (Tonelli's formula) when applicable; that
// covers every supported curve except secp224r1 (whose p is 2^224 - 2^96 + 1,
// which is 1 mod 4). For secp224r1 falls back to Tonelli-Shanks.
//
// On success, the returned root r satisfies r^2 ≡ a (mod p) and 0 ≤ r < p.
// The "other" root is p - r.
func modSqrt(a, p *big.Int) *big.Int {
	if a.Sign() == 0 {
		return new(big.Int)
	}

	// Fast path: p ≡ 3 (mod 4).  Then r = a^((p+1)/4) mod p is a square root
	// if one exists; we verify and return.
	four := big.NewInt(4)
	pmod := new(big.Int).Mod(p, four)
	if pmod.Cmp(big.NewInt(3)) == 0 {
		exp := new(big.Int).Add(p, big.NewInt(1))
		exp.Rsh(exp, 2)
		r := new(big.Int).Exp(a, exp, p)
		check := new(big.Int).Mul(r, r)
		check.Mod(check, p)
		if check.Cmp(new(big.Int).Mod(a, p)) != 0 {
			return nil
		}
		return r
	}

	return tonelliShanks(a, p)
}

// tonelliShanks finds a modular square root of a modulo an odd prime p.
// Returns nil if a is not a quadratic residue mod p. Implementation follows
// the textbook algorithm.
func tonelliShanks(a, p *big.Int) *big.Int {
	// Quick QR check via Euler's criterion: a^((p-1)/2) must be 1 mod p.
	pm1 := new(big.Int).Sub(p, big.NewInt(1))
	halfPm1 := new(big.Int).Rsh(pm1, 1)
	euler := new(big.Int).Exp(a, halfPm1, p)
	if euler.Cmp(big.NewInt(1)) != 0 {
		return nil
	}

	// Find Q, S such that p - 1 = Q * 2^S, Q odd.
	q := new(big.Int).Set(pm1)
	s := 0
	for q.Bit(0) == 0 {
		q.Rsh(q, 1)
		s++
	}

	// Find a non-residue z (smallest integer ≥ 2 with z^((p-1)/2) ≡ -1).
	z := big.NewInt(2)
	for {
		test := new(big.Int).Exp(z, halfPm1, p)
		if test.Cmp(pm1) == 0 { // -1 mod p
			break
		}
		z.Add(z, big.NewInt(1))
	}

	m := s
	c := new(big.Int).Exp(z, q, p)
	qPlus1Half := new(big.Int).Add(q, big.NewInt(1))
	qPlus1Half.Rsh(qPlus1Half, 1)
	r := new(big.Int).Exp(a, qPlus1Half, p)
	t := new(big.Int).Exp(a, q, p)

	for {
		if t.Cmp(big.NewInt(1)) == 0 {
			return r
		}
		// Find least i, 0 < i < m, such that t^(2^i) ≡ 1 mod p.
		i := 0
		temp := new(big.Int).Set(t)
		for temp.Cmp(big.NewInt(1)) != 0 {
			temp.Mul(temp, temp).Mod(temp, p)
			i++
			if i >= m {
				// Should never happen for a real QR.
				return nil
			}
		}

		// b = c^(2^(m-i-1)) mod p
		b := new(big.Int).Set(c)
		for j := 0; j < m-i-1; j++ {
			b.Mul(b, b).Mod(b, p)
		}
		m = i
		c = new(big.Int).Mul(b, b)
		c.Mod(c, p)
		r.Mul(r, b).Mod(r, p)
		t.Mul(t, c).Mod(t, p)
	}
}
