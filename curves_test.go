// SPDX-License-Identifier: LGPL-3.0-or-later

package seccure

import (
	"math/big"
	"testing"
)

// TestCurveLengthTable is the §5 gate. Every curve's derived length fields
// must match the table below. Values are produced by py-seccure's
// Curve.__init__ for the SECP/NIST 8 and verified against reference/c/curves.c
// for the same set; the Brainpool 7 are produced solely by py-seccure
// (reference/py/__init__.py, since seccure-c's curves.c only ships 8 rows).
//
// NOTE: the earlier draft of §5 had at least one sig_len_bin
// error (it claimed 42 for p160; the correct value is 41 = byteLen(n^2 - 1)
// where n < 2^160.5 so n^2 < 2^321). The values below are the COMPUTED
// authoritative ones.
func TestCurveLengthTable(t *testing.T) {
	want := []struct {
		id                                                                  Curve
		name                                                                string
		pkLenBin, pkLenCompact, sigLenBin, sigLenCompact                    int
		dhLenBin, dhLenCompact, elemLenBin, orderLenBin                     int
	}{
		// Values come from py-seccure's get_serialized_number_len applied to
		// each curve's authoritative (p, n) constants. The brief's earlier
		// §5 table had scattered errors (wrong base, several wrong
		// per-curve byte counts); these are the correct values.
		//
		// id          name              pkB pkC sigB sigC dhB dhC elem ord
		{CurveP112, "secp112r1", 15, 18, 28, 35, 7, 9, 14, 14},
		{CurveP128, "secp128r1", 17, 20, 32, 40, 8, 10, 16, 16},
		{CurveP160, "secp160r1", 21, 25, 41, 50, 10, 13, 20, 21},
		{CurveP192, "secp192r1", 25, 30, 48, 60, 12, 15, 24, 24},
		{CurveP224, "secp224r1", 29, 35, 56, 70, 14, 18, 28, 28},
		{CurveP256, "secp256r1", 33, 40, 64, 79, 16, 20, 32, 32},
		{CurveP384, "secp384r1", 49, 60, 96, 119, 24, 30, 48, 48},
		{CurveP521, "secp521r1", 66, 81, 131, 161, 32, 40, 66, 66},
		{CurveBP160, "brainpoolp160r1", 21, 25, 40, 50, 10, 13, 20, 20},
		{CurveBP192, "brainpoolp192r1", 25, 30, 48, 60, 12, 15, 24, 24},
		{CurveBP224, "brainpoolp224r1", 29, 35, 56, 69, 14, 18, 28, 28},
		{CurveBP256, "brainpoolp256r1", 33, 40, 64, 79, 16, 20, 32, 32},
		{CurveBP320, "brainpoolp320r1", 41, 50, 80, 99, 20, 25, 40, 40},
		{CurveBP384, "brainpoolp384r1", 49, 60, 96, 119, 24, 30, 48, 48},
		{CurveBP512, "brainpoolp512r1", 65, 79, 128, 158, 32, 40, 64, 64},
	}

	for _, w := range want {
		t.Run(w.name, func(t *testing.T) {
			cp := lookupCurve(w.id)
			if cp == nil {
				t.Fatalf("curve %s not registered", w.name)
			}
			if cp.name != w.name {
				t.Errorf("name: got %q, want %q", cp.name, w.name)
			}

			check := func(field string, got, expected int) {
				if got != expected {
					t.Errorf("%s: got %d, want %d", field, got, expected)
				}
			}
			check("pkLenBin", cp.pkLenBin, w.pkLenBin)
			check("pkLenCompact", cp.pkLenCompact, w.pkLenCompact)
			check("sigLenBin", cp.sigLenBin, w.sigLenBin)
			check("sigLenCompact", cp.sigLenCompact, w.sigLenCompact)
			check("dhLenBin", cp.dhLenBin, w.dhLenBin)
			check("dhLenCompact", cp.dhLenCompact, w.dhLenCompact)
			check("elemLenBin", cp.elemLenBin, w.elemLenBin)
			check("orderLenBin", cp.orderLenBin, w.orderLenBin)
		})
	}
}

// TestCurveGeneratorOnCurve asserts that every curve's generator (Gx, Gy)
// satisfies y^2 ≡ x^3 + a*x + b (mod p). This catches transcription errors in
// the hex constants without needing scalar multiplication to be implemented.
func TestCurveGeneratorOnCurve(t *testing.T) {
	for _, cp := range curves {
		if cp == nil {
			continue
		}
		t.Run(cp.name, func(t *testing.T) {
			lhs := new(big.Int).Mul(cp.gy, cp.gy)
			lhs.Mod(lhs, cp.p)

			rhs := new(big.Int).Mul(cp.gx, cp.gx)
			rhs.Mul(rhs, cp.gx) // x^3
			ax := new(big.Int).Mul(cp.a, cp.gx)
			rhs.Add(rhs, ax)
			rhs.Add(rhs, cp.b)
			rhs.Mod(rhs, cp.p)

			if lhs.Cmp(rhs) != 0 {
				t.Errorf("generator point not on curve %s:\n  y^2     mod p = %x\n  x^3+ax+b mod p = %x",
					cp.name, lhs, rhs)
			}
		})
	}
}

func TestCurveByName(t *testing.T) {
	cases := []struct {
		input string
		want  Curve
	}{
		{"secp160r1", CurveP160},
		{"p160", CurveP160},
		{"nistp192", CurveP192},
		{"p192", CurveP192},
		{"brainpoolp256r1", CurveBP256},
		{"bp256", CurveBP256},
		{"secp521r1", CurveP521},
	}
	for _, c := range cases {
		got, err := CurveByName(c.input)
		if err != nil {
			t.Errorf("CurveByName(%q): unexpected error %v", c.input, err)
			continue
		}
		if got != c.want {
			t.Errorf("CurveByName(%q): got %d, want %d", c.input, got, c.want)
		}
	}
}

func TestCurveByCompactPubkeyLen(t *testing.T) {
	// Unique lengths resolve to a single curve.
	cases := []struct {
		length int
		want   Curve
	}{
		{18, CurveP112},  // unique
		{20, CurveP128},  // unique
		{50, CurveBP320}, // unique
		{79, CurveBP512}, // unique
		{81, CurveP521},  // unique
	}
	for _, c := range cases {
		got, err := CurveByCompactPubkeyLen(c.length)
		if err != nil {
			t.Errorf("CurveByCompactPubkeyLen(%d): unexpected error %v", c.length, err)
			continue
		}
		if got != c.want {
			t.Errorf("CurveByCompactPubkeyLen(%d): got %d, want %d", c.length, got, c.want)
		}
	}

	// Lengths shared by multiple curves must return ErrAmbiguousCurve.
	// Collisions: 25 (p160/bp160), 30 (p192/bp192), 35 (p224/bp224),
	// 40 (p256/bp256), 60 (p384/bp384).
	ambiguous := []int{25, 30, 35, 40, 60}
	for _, n := range ambiguous {
		if _, err := CurveByCompactPubkeyLen(n); err != ErrAmbiguousCurve {
			t.Errorf("CurveByCompactPubkeyLen(%d): want ErrAmbiguousCurve, got %v", n, err)
		}
	}

	// Unknown length.
	if _, err := CurveByCompactPubkeyLen(999); err != ErrUnknownCurve {
		t.Errorf("CurveByCompactPubkeyLen(999): want ErrUnknownCurve, got %v", err)
	}
}
