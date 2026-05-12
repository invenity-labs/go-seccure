// SPDX-License-Identifier: LGPL-3.0-or-later

package seccure

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"
)

// TestOrderTimesGeneratorIsInfinity is the strongest portable correctness
// check for the EC arithmetic: for every supported curve, n * G must equal
// the point at infinity. If add/double/scalarMult or any curve constant is
// wrong, this almost certainly catches it.
//
// This is the §8-day-2 gate for the 11 curves that crypto/elliptic does NOT
// support (p112, p128, p160, all Brainpool); for the 4 it does support we
// also cross-check against ScalarBaseMult below.
func TestOrderTimesGeneratorIsInfinity(t *testing.T) {
	for _, cp := range curves {
		if cp == nil {
			continue
		}
		t.Run(cp.name, func(t *testing.T) {
			result := scalarBaseMult(cp.n, cp)
			if !result.isInfinity() {
				t.Errorf("n*G should be infinity for %s, got (%x, %x)",
					cp.name, result.x, result.y)
			}
		})
	}
}

// TestScalarMultMatchesRepeatedAdd checks that scalarMult agrees with naive
// repeated addition for small scalars. Catches off-by-one and bit-order bugs
// in the double-and-add loop.
func TestScalarMultMatchesRepeatedAdd(t *testing.T) {
	cp := lookupCurve(CurveP256)
	g := &point{x: cp.gx, y: cp.gy}

	var acc *point
	for k := 1; k <= 16; k++ {
		acc = acc.add(g, cp)
		got := g.scalarMult(big.NewInt(int64(k)), cp)
		if !acc.equal(got) {
			t.Errorf("k=%d: scalarMult and repeated-add disagree:\n  acc = (%x, %x)\n  got = (%x, %x)",
				k, acc.x, acc.y, got.x, got.y)
		}
	}
}

// TestDoubleEqualsAddSelf checks the basic invariant 2P = P + P.
func TestDoubleEqualsAddSelf(t *testing.T) {
	for _, cp := range curves {
		if cp == nil {
			continue
		}
		t.Run(cp.name, func(t *testing.T) {
			g := &point{x: cp.gx, y: cp.gy}
			fromDouble := g.double(cp)
			fromAdd := g.add(g, cp)
			if !fromDouble.equal(fromAdd) {
				t.Errorf("2G != G+G for %s", cp.name)
			}
		})
	}
}

// TestNegate checks that P + (-P) = O and that (n-1)G == -G.
func TestNegate(t *testing.T) {
	for _, cp := range curves {
		if cp == nil {
			continue
		}
		t.Run(cp.name, func(t *testing.T) {
			g := &point{x: cp.gx, y: cp.gy}
			negG := g.negate(cp)
			sum := g.add(negG, cp)
			if !sum.isInfinity() {
				t.Errorf("G + (-G) != infinity for %s", cp.name)
			}

			// (n - 1) * G should equal -G.
			nMinus1 := new(big.Int).Sub(cp.n, big.NewInt(1))
			result := scalarBaseMult(nMinus1, cp)
			if !result.equal(negG) {
				t.Errorf("(n-1)*G != -G for %s", cp.name)
			}
		})
	}
}

// TestAddCommutativity: P + Q = Q + P.
func TestAddCommutativity(t *testing.T) {
	cp := lookupCurve(CurveP256)
	g := &point{x: cp.gx, y: cp.gy}
	p2 := g.double(cp)
	p3 := g.add(p2, cp)

	a := g.add(p3, cp)
	b := p3.add(g, cp)
	if !a.equal(b) {
		t.Fatal("addition is not commutative")
	}
}

// TestAddAssociativity: (P + Q) + R = P + (Q + R).
func TestAddAssociativity(t *testing.T) {
	cp := lookupCurve(CurveP256)
	g := &point{x: cp.gx, y: cp.gy}
	p2 := g.double(cp)
	p3 := g.add(p2, cp)

	left := g.add(p2, cp).add(p3, cp)
	right := g.add(p2.add(p3, cp), cp)
	if !left.equal(right) {
		t.Fatal("addition is not associative")
	}
}

// TestPointsAlwaysOnCurve checks that every result of add/double/scalarMult
// lands back on the curve.
func TestPointsAlwaysOnCurve(t *testing.T) {
	for _, cp := range curves {
		if cp == nil {
			continue
		}
		t.Run(cp.name, func(t *testing.T) {
			g := &point{x: cp.gx, y: cp.gy}
			if !g.onCurve(cp) {
				t.Fatalf("generator not on curve %s (should be caught by TestCurveGeneratorOnCurve too)", cp.name)
			}
			for k := 2; k <= 32; k++ {
				p := scalarBaseMult(big.NewInt(int64(k)), cp)
				if !p.onCurve(cp) {
					t.Errorf("%s: %d*G is not on curve", cp.name, k)
					return
				}
			}
		})
	}
}

// TestScalarBaseMultMatchesStdlib cross-checks our scalarBaseMult against
// crypto/elliptic's ScalarBaseMult for the four curves where stdlib has them.
// This is the §8-day-2 gate's "test against known-good Go ECC library".
func TestScalarBaseMultMatchesStdlib(t *testing.T) {
	cases := []struct {
		seccureID Curve
		stdlib    elliptic.Curve
	}{
		{CurveP224, elliptic.P224()},
		{CurveP256, elliptic.P256()},
		{CurveP384, elliptic.P384()},
		{CurveP521, elliptic.P521()},
	}

	for _, tc := range cases {
		cp := lookupCurve(tc.seccureID)
		t.Run(cp.name, func(t *testing.T) {
			// Run a handful of random scalars per curve.
			for trial := 0; trial < 20; trial++ {
				// We deliberately use the deprecated low-level API
				// (priv.D, ScalarBaseMult) to cross-check raw EC math
				// against a reference. The recommended crypto/ecdh
				// API doesn't expose ScalarBaseMult; using it here
				// would defeat the test's purpose.
				priv, err := ecdsa.GenerateKey(tc.stdlib, rand.Reader)
				if err != nil {
					t.Fatalf("GenerateKey: %v", err)
				}
				//lint:ignore SA1019 low-level EC math cross-check requires the deprecated API
				k := new(big.Int).SetBytes(priv.D.Bytes())
				//lint:ignore SA1019 same as priv.D — deprecated API used intentionally for math cross-check
				wantX, wantY := tc.stdlib.ScalarBaseMult(k.Bytes())

				got := scalarBaseMult(k, cp)
				if got.isInfinity() {
					t.Errorf("trial %d: scalarBaseMult returned infinity", trial)
					continue
				}
				if got.x.Cmp(wantX) != 0 || got.y.Cmp(wantY) != 0 {
					t.Errorf("trial %d on %s: mismatch\n  got  = (%x, %x)\n  want = (%x, %x)",
						trial, cp.name, got.x, got.y, wantX, wantY)
				}
			}
		})
	}
}

// TestModSqrtRoundTrip: for every curve's prime p, take 100 random non-zero a,
// compute r = a^2 mod p, then assert modSqrt(r, p)^2 == r mod p. Verifies
// both the p≡3 mod 4 fast path and the Tonelli-Shanks fallback (p224).
func TestModSqrtRoundTrip(t *testing.T) {
	for _, cp := range curves {
		if cp == nil {
			continue
		}
		t.Run(cp.name, func(t *testing.T) {
			for trial := 0; trial < 100; trial++ {
				a, err := rand.Int(rand.Reader, cp.p)
				if err != nil {
					t.Fatalf("rand.Int: %v", err)
				}
				if a.Sign() == 0 {
					a = big.NewInt(1)
				}
				square := new(big.Int).Mul(a, a)
				square.Mod(square, cp.p)

				r := modSqrt(square, cp.p)
				if r == nil {
					t.Errorf("modSqrt returned nil on a known QR (a=%x)", a)
					continue
				}

				rsq := new(big.Int).Mul(r, r)
				rsq.Mod(rsq, cp.p)
				if rsq.Cmp(square) != 0 {
					t.Errorf("modSqrt round-trip failed: r=%x, a^2=%x, r^2=%x", r, square, rsq)
				}
			}
		})
	}
}

// TestModSqrtRejectsNonResidue checks that modSqrt returns nil for values
// that aren't quadratic residues mod p.
func TestModSqrtRejectsNonResidue(t *testing.T) {
	// p = 7. QRs mod 7 are {0, 1, 2, 4}. Non-residues: {3, 5, 6}.
	p := big.NewInt(7)
	for _, nr := range []int64{3, 5, 6} {
		if r := modSqrt(big.NewInt(nr), p); r != nil {
			t.Errorf("modSqrt(%d, 7) should be nil, got %s", nr, r)
		}
	}
	for _, qr := range []int64{0, 1, 2, 4} {
		r := modSqrt(big.NewInt(qr), p)
		if r == nil {
			t.Errorf("modSqrt(%d, 7) should not be nil", qr)
			continue
		}
		rsq := new(big.Int).Mul(r, r)
		rsq.Mod(rsq, p)
		if rsq.Int64() != qr {
			t.Errorf("modSqrt(%d, 7) = %s, but %s^2 mod 7 = %s", qr, r, r, rsq)
		}
	}
}
