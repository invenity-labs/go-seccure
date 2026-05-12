// SPDX-License-Identifier: LGPL-3.0-or-later

package seccure

import (
	"bytes"
	"testing"
)

// Fuzz targets — Go 1.18+ built-in fuzzing. Run with e.g.:
//
//   go test -run '^$' -fuzz=FuzzDecodeCompactNeverPanics -fuzztime=30s ./...
//
// The aim is to catch panics / out-of-bounds / unbounded allocations on
// malformed input, not to find cryptographic weaknesses. Each fuzz target's
// invariant is documented in its top comment.

// FuzzDecodeCompactNeverPanics: decodeCompact must never panic on any string
// input. Either it returns a valid byte slice of the requested length, or it
// returns an error.
func FuzzDecodeCompactNeverPanics(f *testing.F) {
	f.Add("!", 1)
	f.Add("~~~~~", 5)
	f.Add("", 0)
	f.Add("hello world", 32)

	f.Fuzz(func(t *testing.T, s string, outLen int) {
		if outLen < 0 || outLen > 4096 {
			t.Skip()
		}
		out, err := decodeCompact(s, outLen)
		if err == nil && len(out) != outLen {
			t.Errorf("decodeCompact returned err=nil but len=%d, want %d", len(out), outLen)
		}
	})
}

// FuzzEncodeDecodeCompactRoundTrip: for any (src, outLen) where the value fits,
// decodeCompact(encodeCompact(src, outLen), len(src)) must recover src exactly.
func FuzzEncodeDecodeCompactRoundTrip(f *testing.F) {
	f.Add([]byte{0x00}, 1)
	f.Add([]byte{0xff}, 2)
	f.Add([]byte("hello"), 10)

	f.Fuzz(func(t *testing.T, src []byte, outLen int) {
		if outLen < 0 || outLen > 4096 || len(src) > 4096 {
			t.Skip()
		}
		encoded, err := encodeCompact(src, outLen)
		if err != nil {
			t.Skip() // value too large for outLen — expected error path
		}
		if len(encoded) != outLen {
			t.Errorf("encoded length: got %d, want %d", len(encoded), outLen)
		}
		decoded, err := decodeCompact(encoded, len(src))
		if err != nil {
			t.Fatalf("decodeCompact rejected our own encoded output: %v", err)
		}
		if !bytes.Equal(decoded, src) {
			t.Errorf("round-trip mismatch:\n  in  = %x\n  out = %x", src, decoded)
		}
	})
}

// FuzzPassphraseToPubkeyNeverPanics: PassphraseToPubkey must produce a valid
// compact-form public key (or a sentinel error) for any passphrase bytes on
// any registered curve. No panics, no OOM, no infinite loops.
func FuzzPassphraseToPubkeyNeverPanics(f *testing.F) {
	f.Add([]byte(""), 0)
	f.Add([]byte("Test1234"), 2)
	f.Add(bytes.Repeat([]byte{0xff}, 1000), 7)

	f.Fuzz(func(t *testing.T, passphrase []byte, curveIdx int) {
		if curveIdx < 0 || curveIdx >= len(curves) || curves[curveIdx] == nil {
			t.Skip()
		}
		if len(passphrase) > 65536 {
			t.Skip() // arbitrary cap — passphrases this big are nonsense
		}
		curve := Curve(curveIdx)
		pub, err := PassphraseToPubkey(passphrase, curve)
		if err != nil {
			return
		}
		lens, _ := CurveByteLengths(curve)
		if len(pub) != lens.PubkeyCompact {
			t.Errorf("pubkey length for curve %d: got %d, want %d", curveIdx, len(pub), lens.PubkeyCompact)
		}
	})
}

// FuzzDecryptNeverPanics: feed Decrypt arbitrary ciphertext bytes. It must
// never panic — only error.
func FuzzDecryptNeverPanics(f *testing.F) {
	// Seed with a real ciphertext so the fuzzer has something to mutate.
	pw := []byte("Test1234")
	pub, _ := PassphraseToPubkey(pw, CurveP256)
	ct, _ := Encrypt([]byte("hello"), pub, CurveP256, 10)
	f.Add(ct, 5)              // p256 enum idx is 5
	f.Add([]byte("garbage"), 5)
	f.Add([]byte{}, 5)

	f.Fuzz(func(t *testing.T, ciphertext []byte, curveIdx int) {
		if curveIdx < 0 || curveIdx >= len(curves) || curves[curveIdx] == nil {
			t.Skip()
		}
		if len(ciphertext) > 65536 {
			t.Skip()
		}
		// Decryption must never panic on any input.
		_, _ = Decrypt(ciphertext, pw, Curve(curveIdx), 10)
	})
}

// FuzzVerifyBinaryNeverPanics: arbitrary signature bytes + arbitrary message +
// any pubkey must never panic Verify.
func FuzzVerifyBinaryNeverPanics(f *testing.F) {
	pw := []byte("Test1234")
	pub, _ := PassphraseToPubkey(pw, CurveP256)
	sig, _ := SignBinary([]byte("hello"), pw, CurveP256)
	f.Add([]byte("hello"), sig, pub, 5)
	f.Add([]byte(""), []byte{}, pub, 5)
	f.Add([]byte("any message"), []byte("not a sig"), "not a pubkey", 5)

	f.Fuzz(func(t *testing.T, message, signature []byte, pubkey string, curveIdx int) {
		if curveIdx < 0 || curveIdx >= len(curves) || curves[curveIdx] == nil {
			t.Skip()
		}
		if len(message) > 65536 || len(signature) > 4096 || len(pubkey) > 4096 {
			t.Skip()
		}
		_ = VerifyBinary(message, signature, pubkey, Curve(curveIdx))
	})
}

// FuzzCurveByNameNeverPanics: any string fed to CurveByName must return
// either a valid Curve or an error. No panics.
func FuzzCurveByNameNeverPanics(f *testing.F) {
	f.Add("p160")
	f.Add("secp256r1")
	f.Add("totally bogus")
	f.Add("")

	f.Fuzz(func(t *testing.T, name string) {
		if len(name) > 1024 {
			t.Skip()
		}
		_, _ = CurveByName(name)
	})
}
