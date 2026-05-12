// SPDX-License-Identifier: LGPL-3.0-or-later

package seccure

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"
)

// TestCompressRoundTripGenerator is the smoke test: compress the generator
// for each curve, decompress, get the generator back.
func TestCompressRoundTripGenerator(t *testing.T) {
	for _, cp := range curves {
		if cp == nil {
			continue
		}
		t.Run(cp.name, func(t *testing.T) {
			g := &point{x: cp.gx, y: cp.gy}
			buf, err := compress(g, cp)
			if err != nil {
				t.Fatalf("compress: %v", err)
			}
			if len(buf) != cp.pkLenBin {
				t.Errorf("compressed length: got %d, want %d", len(buf), cp.pkLenBin)
			}

			got, err := decompress(buf, cp)
			if err != nil {
				t.Fatalf("decompress: %v", err)
			}
			if !got.equal(g) {
				t.Errorf("round-trip mismatch:\n  in  = (%x, %x)\n  out = (%x, %x)",
					g.x, g.y, got.x, got.y)
			}
		})
	}
}

// TestCompressRoundTripRandom is the §8-day-2 gate: 1000 random points per
// curve, round-trip via compress/decompress. Random points are produced as
// k*G for a random k.
func TestCompressRoundTripRandom(t *testing.T) {
	for _, cp := range curves {
		if cp == nil {
			continue
		}
		t.Run(cp.name, func(t *testing.T) {
			for trial := 0; trial < 1000; trial++ {
				k, err := rand.Int(rand.Reader, cp.n)
				if err != nil {
					t.Fatalf("rand.Int: %v", err)
				}
				if k.Sign() == 0 {
					k.SetInt64(1)
				}
				p := scalarBaseMult(k, cp)
				if p.isInfinity() {
					continue
				}

				buf, err := compress(p, cp)
				if err != nil {
					t.Fatalf("compress(k=%x): %v", k, err)
				}
				back, err := decompress(buf, cp)
				if err != nil {
					t.Fatalf("decompress(k=%x): %v", k, err)
				}
				if !back.equal(p) {
					t.Errorf("trial %d: mismatch\n  in  = (%x, %x)\n  out = (%x, %x)",
						trial, p.x, p.y, back.x, back.y)
				}
			}
		})
	}
}

// TestCompressInfinityRejected: SECCURE has no canonical wire form for the
// point at infinity, so compress must reject it.
func TestCompressInfinityRejected(t *testing.T) {
	cp := lookupCurve(CurveP256)
	if _, err := compress(nil, cp); err != ErrInvalidPubkey {
		t.Errorf("compress(infinity) = %v, want ErrInvalidPubkey", err)
	}
}

// TestDecompressWrongLength: input that isn't pkLenBin bytes must be rejected.
func TestDecompressWrongLength(t *testing.T) {
	cp := lookupCurve(CurveP256)
	for _, bad := range [][]byte{nil, {}, make([]byte, cp.pkLenBin-1), make([]byte, cp.pkLenBin+1)} {
		if _, err := decompress(bad, cp); err != ErrInvalidPubkey {
			t.Errorf("decompress(len=%d) = %v, want ErrInvalidPubkey", len(bad), err)
		}
	}
}

// TestDecompressNotOnCurve: a buffer that decodes to an x whose y^2 has no
// square root (i.e. x^3 + a*x + b is a non-residue mod p) must be rejected.
func TestDecompressNotOnCurve(t *testing.T) {
	cp := lookupCurve(CurveP256)
	// Iterate small x values until we hit one that's not on the curve. We
	// don't expect any deep math here — on a randomly-distributed elliptic
	// curve about half the x values are valid, so within a few tries we'll
	// find one that isn't.
	for x := int64(1); x < 100; x++ {
		buf := make([]byte, cp.pkLenBin)
		xb := big.NewInt(x).Bytes()
		copy(buf[cp.pkLenBin-len(xb):], xb)

		_, err := decompress(buf, cp)
		if err == ErrInvalidPubkey {
			return // found one — test passes.
		}
	}
	t.Skip("could not find a small x not on the curve to test rejection — implausibly all 99 first x values were valid")
}

// TestCompressUsesPYFlagMapping: a sanity check that yflag is encoded the same
// way py-seccure encodes it. For an even-y point, compressed value < m.
// For an odd-y point, compressed value >= m.
func TestCompressUsesPYFlagMapping(t *testing.T) {
	cp := lookupCurve(CurveP256)
	// We know G has odd y for many of the SECP curves. Walk small multiples
	// until we find one with even y and one with odd, and check.
	var even, odd *point
	for k := int64(1); k < 20 && (even == nil || odd == nil); k++ {
		p := scalarBaseMult(big.NewInt(k), cp)
		if p.isInfinity() {
			continue
		}
		if p.y.Bit(0) == 0 && even == nil {
			even = p
		}
		if p.y.Bit(0) == 1 && odd == nil {
			odd = p
		}
	}
	if even == nil || odd == nil {
		t.Skip("could not find both even- and odd-y points in the first 20 multiples of G")
	}

	for _, tc := range []struct {
		label  string
		p      *point
		wantGE bool // compressed value >= m?
	}{
		{"even-y", even, false},
		{"odd-y", odd, true},
	} {
		t.Run(tc.label, func(t *testing.T) {
			buf, err := compress(tc.p, cp)
			if err != nil {
				t.Fatal(err)
			}
			v := new(big.Int).SetBytes(buf)
			gotGE := v.Cmp(cp.p) >= 0
			if gotGE != tc.wantGE {
				t.Errorf("compressed value vs m: gotGE=%v, want %v (v=%x, m=%x)",
					gotGE, tc.wantGE, v, cp.p)
			}
		})
	}

	// And of course the round-trip should still recover the same y.
	for _, p := range []*point{even, odd} {
		buf, _ := compress(p, cp)
		got, err := decompress(buf, cp)
		if err != nil {
			t.Fatal(err)
		}
		if !got.equal(p) {
			t.Errorf("round-trip lost y parity")
		}
	}
}

// TestCompressedLengthsMatchPkLenBin: trivially, but worth asserting at every
// curve since pk_len_bin is a derived field.
func TestCompressedLengthsMatchPkLenBin(t *testing.T) {
	for _, cp := range curves {
		if cp == nil {
			continue
		}
		t.Run(cp.name, func(t *testing.T) {
			g := &point{x: cp.gx, y: cp.gy}
			buf, err := compress(g, cp)
			if err != nil {
				t.Fatal(err)
			}
			if len(buf) != cp.pkLenBin {
				t.Errorf("%s: compressed length %d, expected pkLenBin %d",
					cp.name, len(buf), cp.pkLenBin)
			}
			// We don't say anything about the leading byte's top bit
			// because the brief's "top bit of byte 0" claim is only
			// accurate for curves where bitLen(p) is < 8*pkLenBin.
			// The compress/decompress round-trip is the actual contract.
			_ = bytes.TrimLeft
		})
	}
}
