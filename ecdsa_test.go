// SPDX-License-Identifier: LGPL-3.0-or-later

package seccure

import (
	"encoding/hex"
	"testing"
)

// TestCanarySignatures asserts that every signature in testdata/vectors.json
// matches the bytes Go produces. Signatures are deterministic (§3.5), so
// byte-equality is the right gate — the same (curve, passphrase, message)
// triple must yield the same compact string as py-seccure on every input.
//
// This is the §8-day-4 ECDSA gate.
func TestCanarySignatures(t *testing.T) {
	v := loadVectors(t)
	if len(v.Signatures) == 0 {
		t.Fatal("vectors.json has no signature entries")
	}

	for _, entry := range v.Signatures {
		t.Run(entry.Curve+"/"+entry.PassphraseHex[:min(16, len(entry.PassphraseHex))]+"/"+entry.MessageHex[:min(8, len(entry.MessageHex))], func(t *testing.T) {
			passphrase, err := hex.DecodeString(entry.PassphraseHex)
			if err != nil {
				t.Fatalf("bad passphrase_hex %q: %v", entry.PassphraseHex, err)
			}
			message, err := hex.DecodeString(entry.MessageHex)
			if err != nil {
				t.Fatalf("bad message_hex %q: %v", entry.MessageHex, err)
			}
			curve, err := CurveByName(entry.Curve)
			if err != nil {
				t.Fatalf("CurveByName(%q): %v", entry.Curve, err)
			}

			got, err := Sign(message, passphrase, curve)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if got != entry.Signature {
				t.Fatalf("signature mismatch on %s\n  got  = %q\n  want = %q",
					entry.Curve, got, entry.Signature)
			}
		})
	}
}

// TestSignVerifyRoundTrip: every signature this library produces must verify
// under the same pubkey. Catches accidental sign/verify disagreement that the
// cross-impl canary above won't catch (e.g. if both directions were wrong in
// the same way).
func TestSignVerifyRoundTrip(t *testing.T) {
	cases := []struct {
		message    []byte
		passphrase []byte
	}{
		{[]byte(""), []byte("Test1234")},
		{[]byte("hello"), []byte("Test1234")},
		{[]byte("the quick brown fox"), []byte("my private key")},
		{make([]byte, 1024), []byte("a")}, // 1KB of zeros
	}

	for _, cp := range curves {
		if cp == nil {
			continue
		}
		curve := cp.id
		t.Run(cp.name, func(t *testing.T) {
			for _, c := range cases {
				sig, err := Sign(c.message, c.passphrase, curve)
				if err != nil {
					t.Fatalf("Sign: %v", err)
				}
				pub, err := PassphraseToPubkey(c.passphrase, curve)
				if err != nil {
					t.Fatalf("PassphraseToPubkey: %v", err)
				}
				if err := Verify(c.message, sig, pub, curve); err != nil {
					t.Errorf("Verify(curve=%s, pw=%q, msg=%q): %v",
						cp.name, c.passphrase, c.message, err)
				}
			}
		})
	}
}

// TestVerifyDetectsTamper: tampered messages, signatures, or pubkeys must be
// rejected.
func TestVerifyDetectsTamper(t *testing.T) {
	curve := CurveP256
	pw := []byte("Test1234")
	msg := []byte("hello world")
	pub, _ := PassphraseToPubkey(pw, curve)
	sig, _ := Sign(msg, pw, curve)

	// Sanity: real sig verifies.
	if err := Verify(msg, sig, pub, curve); err != nil {
		t.Fatalf("baseline Verify failed: %v", err)
	}

	t.Run("wrong message", func(t *testing.T) {
		if err := Verify([]byte("HELLO WORLD"), sig, pub, curve); err == nil {
			t.Error("expected Verify to reject tampered message")
		}
	})

	t.Run("flip one signature char", func(t *testing.T) {
		bad := []byte(sig)
		// Pick a char in the middle and bump it to the next valid alphabet entry.
		idx := len(bad) / 2
		orig := bad[idx]
		for d := 1; d < 90; d++ {
			cand := compactDigits[(int(rCompactDigits[orig])+d)%90]
			if cand != orig {
				bad[idx] = cand
				break
			}
		}
		if err := Verify(msg, string(bad), pub, curve); err == nil {
			t.Error("expected Verify to reject tampered signature")
		}
	})

	t.Run("wrong pubkey", func(t *testing.T) {
		otherPub, _ := PassphraseToPubkey([]byte("not the same"), curve)
		if err := Verify(msg, sig, otherPub, curve); err == nil {
			t.Error("expected Verify to reject signature under wrong pubkey")
		}
	})
}

// TestSignDeterministic: signing the same (msg, pw, curve) twice must produce
// the exact same signature. This is the property that makes the canary
// cross-impl test possible.
func TestSignDeterministic(t *testing.T) {
	for _, cp := range curves {
		if cp == nil {
			continue
		}
		t.Run(cp.name, func(t *testing.T) {
			sig1, err := Sign([]byte("hello"), []byte("Test1234"), cp.id)
			if err != nil {
				t.Fatal(err)
			}
			sig2, err := Sign([]byte("hello"), []byte("Test1234"), cp.id)
			if err != nil {
				t.Fatal(err)
			}
			if sig1 != sig2 {
				t.Errorf("Sign produced different outputs for same input on %s", cp.name)
			}
		})
	}
}
