// SPDX-License-Identifier: LGPL-3.0-or-later

package seccure

import (
	"crypto/sha512"
	"math/big"
	"testing"
)

// TestDHSymmetry: the two parties of a DH exchange must derive the same
// established and verification keys regardless of which party is "first".
// Run on every curve so any curve-specific length-handling bug surfaces.
//
// This is the §8-day-5 DH gate; py-seccure doesn't expose a public DH API,
// so internal symmetry + the formula-direct check below stand in for the
// "match py-seccure" target.
func TestDHSymmetry(t *testing.T) {
	for _, cp := range curves {
		if cp == nil {
			continue
		}
		t.Run(cp.name, func(t *testing.T) {
			tokenA, privA, err := DHToken(cp.id)
			if err != nil {
				t.Fatalf("DHToken (A): %v", err)
			}
			tokenB, privB, err := DHToken(cp.id)
			if err != nil {
				t.Fatalf("DHToken (B): %v", err)
			}

			estA, verA, err := DHEstablish(tokenB, privA, cp.id)
			if err != nil {
				t.Fatalf("DHEstablish (A): %v", err)
			}
			estB, verB, err := DHEstablish(tokenA, privB, cp.id)
			if err != nil {
				t.Fatalf("DHEstablish (B): %v", err)
			}

			if estA != estB {
				t.Errorf("established key mismatch:\n  A = %q\n  B = %q", estA, estB)
			}
			if verA != verB {
				t.Errorf("verification key mismatch:\n  A = %q\n  B = %q", verA, verB)
			}
			if len(estA) != cp.dhLenCompact {
				t.Errorf("established key length: got %d, want dhLenCompact=%d", len(estA), cp.dhLenCompact)
			}
			if len(verA) != cp.dhLenCompact {
				t.Errorf("verification key length: got %d, want dhLenCompact=%d", len(verA), cp.dhLenCompact)
			}
			if estA == verA {
				t.Error("established and verification keys are identical — should be slices of different SHA-512 halves")
			}
		})
	}
}

// TestDHKeysMatchFormula: reproduce the SECCURE KDF from scratch
// (SHA-512(Z.x || Z.y) sliced into the two halves) and confirm DHEstablish
// agrees byte-for-byte. This is the "match py-seccure" stand-in: py-seccure
// has no public DH wrapper, but its primitives (point arithmetic, SHA-512,
// base-90 encoding) are already proven byte-equal in earlier tests, so
// reproducing the rule directly proves DHEstablish wires those primitives
// together exactly the way the C reference does.
func TestDHKeysMatchFormula(t *testing.T) {
	for _, cp := range curves {
		if cp == nil {
			continue
		}
		t.Run(cp.name, func(t *testing.T) {
			tokenA, privA, err := DHToken(cp.id)
			if err != nil {
				t.Fatal(err)
			}
			tokenB, privB, err := DHToken(cp.id)
			if err != nil {
				t.Fatal(err)
			}

			estA, verA, err := DHEstablish(tokenB, privA, cp.id)
			if err != nil {
				t.Fatal(err)
			}

			// Reproduce the KDF from scratch on side B (treat tokenA as
			// the "peer").
			peerBin, _ := decodeCompact(tokenA, cp.pkLenBin)
			peer, _ := decompress(peerBin, cp)
			kB := new(big.Int).SetBytes(privB)
			z := peer.scalarMult(kB, cp)

			h := sha512.New()
			h.Write(serializeElem(z.x, cp))
			h.Write(serializeElem(z.y, cp))
			keybuf := h.Sum(nil)

			wantEst, _ := encodeCompact(keybuf[0:cp.dhLenBin], cp.dhLenCompact)
			wantVer, _ := encodeCompact(keybuf[32:32+cp.dhLenBin], cp.dhLenCompact)

			if estA != wantEst {
				t.Errorf("established mismatch vs formula:\n  got  = %q\n  want = %q", estA, wantEst)
			}
			if verA != wantVer {
				t.Errorf("verification mismatch vs formula:\n  got  = %q\n  want = %q", verA, wantVer)
			}
		})
	}
}

// TestDHRejectsInvalidPeerToken: malformed peer tokens must surface as
// ErrInvalidPubkey (the same error decompress raises). Catches accidentally
// permissive validation.
func TestDHRejectsInvalidPeerToken(t *testing.T) {
	curve := CurveP256
	_, priv, err := DHToken(curve)
	if err != nil {
		t.Fatal(err)
	}

	for _, bad := range []string{
		"",                                // empty
		"too short",                       // wrong length (chars also out of alphabet)
		"=\"=\"=\"=\"=\"=\"=\"=\"=\"=\"=\"=\"=\"=\"=\"=\"=\"=\"=\"=\"", // contains '"', not in alphabet
	} {
		if _, _, err := DHEstablish(bad, priv, curve); err != ErrInvalidPubkey {
			t.Errorf("DHEstablish(%q): want ErrInvalidPubkey, got %v", bad, err)
		}
	}
}
