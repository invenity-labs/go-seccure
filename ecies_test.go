// SPDX-License-Identifier: LGPL-3.0-or-later

package seccure

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestECIESRoundTrip: encrypt with Go, decrypt with Go. Catches in-house
// disagreement between Encrypt and Decrypt that an external parity check
// wouldn't notice.
func TestECIESRoundTrip(t *testing.T) {
	plaintexts := [][]byte{
		[]byte(""),
		[]byte("a"),
		[]byte("the quick brown fox jumps over the lazy dog"),
		bytes.Repeat([]byte{0}, 256),
		bytes.Repeat([]byte{0xff}, 1024),
	}

	for _, cp := range curves {
		if cp == nil {
			continue
		}
		curve := cp.id
		pub, err := PassphraseToPubkey([]byte("Test1234"), curve)
		if err != nil {
			t.Fatalf("PassphraseToPubkey on %s: %v", cp.name, err)
		}

		t.Run(cp.name, func(t *testing.T) {
			for maclen := range []int{10, 16, 32} {
				maclen := maclen // (range is producing the index; use it.)
				ml := []int{10, 16, 32}[maclen]
				for _, pt := range plaintexts {
					ct, err := Encrypt(pt, pub, curve, ml)
					if err != nil {
						t.Fatalf("Encrypt(maclen=%d, plen=%d): %v", ml, len(pt), err)
					}
					if len(ct) != cp.pkLenBin+len(pt)+ml {
						t.Errorf("ciphertext length: got %d, want %d (pkLenBin=%d + plen=%d + maclen=%d)",
							len(ct), cp.pkLenBin+len(pt)+ml, cp.pkLenBin, len(pt), ml)
					}
					back, err := Decrypt(ct, []byte("Test1234"), curve, ml)
					if err != nil {
						t.Fatalf("Decrypt(maclen=%d, plen=%d): %v", ml, len(pt), err)
					}
					if !bytes.Equal(back, pt) {
						t.Errorf("plaintext mismatch (maclen=%d, plen=%d):\n  got  = %x\n  want = %x",
							ml, len(pt), back, pt)
					}
				}
			}
		})
	}
}

// TestECIESDecryptDetectsTamper: tampered ciphertext or HMAC tag must fail.
func TestECIESDecryptDetectsTamper(t *testing.T) {
	curve := CurveP256
	pw := []byte("Test1234")
	pub, _ := PassphraseToPubkey(pw, curve)
	plain := []byte("secret payload")
	maclen := 10

	ct, err := Encrypt(plain, pub, curve, maclen)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Baseline: untampered round-trips.
	if _, err := Decrypt(ct, pw, curve, maclen); err != nil {
		t.Fatalf("baseline Decrypt failed: %v", err)
	}

	t.Run("flip a ciphertext byte", func(t *testing.T) {
		// Flip a byte inside the AES-CTR ciphertext region (between the
		// R-pubkey header and the HMAC tag) — that change MUST surface
		// as an HMAC mismatch, not as a malformed-R decode error.
		cp := lookupCurve(curve)
		bad := bytes.Clone(ct)
		ctIdx := cp.pkLenBin + len(plain)/2
		bad[ctIdx] ^= 0x01
		if _, err := Decrypt(bad, pw, curve, maclen); err != ErrHMACMismatch {
			t.Errorf("expected ErrHMACMismatch, got %v", err)
		}
	})
	t.Run("flip a tag byte", func(t *testing.T) {
		bad := bytes.Clone(ct)
		bad[len(bad)-1] ^= 0x01
		if _, err := Decrypt(bad, pw, curve, maclen); err != ErrHMACMismatch {
			t.Errorf("expected ErrHMACMismatch, got %v", err)
		}
	})
	t.Run("wrong passphrase", func(t *testing.T) {
		if _, err := Decrypt(ct, []byte("wrong"), curve, maclen); err == nil {
			t.Error("expected wrong-passphrase decryption to fail")
		}
	})
	t.Run("too-short ciphertext", func(t *testing.T) {
		if _, err := Decrypt(ct[:5], pw, curve, maclen); err != ErrInvalidCiphertext {
			t.Errorf("expected ErrInvalidCiphertext, got %v", err)
		}
	})
}

// TestECIESCrossImpl_GoEncryptsPyDecrypts: encrypt with Go, hand the
// ciphertext to py-seccure, assert it recovers the plaintext. This is the
// §8-day-4 ECIES gate "round-trip with py-seccure".
//
// Skipped if the .venv (created on Day 2 by the agent) doesn't exist.
func TestECIESCrossImpl_GoEncryptsPyDecrypts(t *testing.T) {
	pyBin := pythonBin(t)

	curve := CurveP256
	pw := []byte("Test1234")
	pub, err := PassphraseToPubkey(pw, curve)
	if err != nil {
		t.Fatalf("PassphraseToPubkey: %v", err)
	}
	plain := []byte("hello from go-seccure, decrypted by py-seccure")
	maclen := 10

	ct, err := Encrypt(plain, pub, curve, maclen)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Stage the ciphertext into a temp file so py-seccure can read it via
	// argv (avoiding the need to set up a process-level stdin pipe).
	tmpDir := t.TempDir()
	ctPath := filepath.Join(tmpDir, "ct.bin")
	if err := os.WriteFile(ctPath, ct, 0o600); err != nil {
		t.Fatalf("write ciphertext: %v", err)
	}

	script := `
import sys, seccure
ct = open(sys.argv[1], "rb").read()
pt = seccure.decrypt(ct, sys.argv[2].encode(), mac_bytes=int(sys.argv[3]), curve=sys.argv[4])
sys.stdout.buffer.write(pt)
`
	cmd := exec.Command(pyBin, "-c", script, ctPath, string(pw),
		"10", "secp256r1/nistp256")
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("py-seccure decrypt failed: %v\nstderr: %s", err, ee.Stderr)
		}
		t.Fatalf("py-seccure decrypt failed: %v", err)
	}
	if !bytes.Equal(out, plain) {
		t.Errorf("py-seccure decrypted plaintext mismatch:\n  got  = %q\n  want = %q", out, plain)
	}
}

// TestECIESCrossImpl_PyEncryptsGoDecrypts: encrypt with py-seccure, decrypt
// with Go. The reverse direction.
func TestECIESCrossImpl_PyEncryptsGoDecrypts(t *testing.T) {
	pyBin := pythonBin(t)

	pw := []byte("Test1234")
	plain := []byte("hello from py-seccure, decrypted by go-seccure")
	maclen := 10

	for _, tc := range []struct {
		curve   Curve
		pyCurve string
	}{
		{CurveP160, "secp160r1"},
		{CurveP256, "secp256r1/nistp256"},
		{CurveP521, "secp521r1/nistp521"},
		{CurveBP256, "brainpoolp256r1"},
		{CurveBP512, "brainpoolp512r1"},
	} {
		t.Run(tc.pyCurve, func(t *testing.T) {
			pub, err := PassphraseToPubkey(pw, tc.curve)
			if err != nil {
				t.Fatal(err)
			}
			script := `
import sys, seccure
ct = seccure.encrypt(sys.argv[1].encode(), sys.argv[2], mac_bytes=int(sys.argv[3]), curve=sys.argv[4])
sys.stdout.buffer.write(ct)
`
			cmd := exec.Command(pyBin, "-c", script, string(plain), pub,
				"10", tc.pyCurve)
			ct, err := cmd.Output()
			if err != nil {
				if ee, ok := err.(*exec.ExitError); ok {
					t.Fatalf("py-seccure encrypt failed: %v\nstderr: %s", err, ee.Stderr)
				}
				t.Fatalf("py-seccure encrypt failed: %v", err)
			}

			back, err := Decrypt(ct, pw, tc.curve, maclen)
			if err != nil {
				t.Fatalf("Go Decrypt: %v", err)
			}
			if !bytes.Equal(back, plain) {
				t.Errorf("plaintext mismatch:\n  got  = %q\n  want = %q", back, plain)
			}
		})
	}
}

// pythonBin returns the path to the project-local Python interpreter that has
// py-seccure installed (created on Day 2 by the agent). Tests skip when it's
// not present so the suite still runs in environments without the venv.
func pythonBin(t *testing.T) string {
	t.Helper()
	p := filepath.Join(".venv", "bin", "python")
	if _, err := os.Stat(p); err != nil {
		t.Skipf(".venv/bin/python not found (%v); skipping cross-impl test. "+
			"Run `python -m venv .venv && .venv/bin/pip install seccure` to enable.", err)
	}
	return p
}
