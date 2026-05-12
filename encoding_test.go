// SPDX-License-Identifier: LGPL-3.0-or-later

package seccure

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"strings"
	"testing"
)

func TestCompactAlphabet(t *testing.T) {
	// The alphabet is 90 chars: every byte in 0x21..0x7E except '"', '\'',
	// '\\', and '`'. Matches reference/c/serialize.c and reference/py/__init__.py.
	if len(compactDigits) != 90 {
		t.Fatalf("alphabet size: got %d, want 90", len(compactDigits))
	}
	excluded := map[byte]bool{'"': true, '\'': true, '\\': true, '`': true}
	for c := byte(0x21); c <= 0x7E; c++ {
		want := !excluded[c]
		got := rCompactDigits[c] >= 0
		if got != want {
			t.Errorf("char %#x (%q): expected in-alphabet=%v, got %v", c, c, want, got)
		}
	}
}

func TestCompactKnownVectors(t *testing.T) {
	// digit 0 → '!', digit 1 → '#' (NOT '"'), digit 89 → '~'.
	cases := []struct {
		name    string
		value   *big.Int
		outLen  int
		encoded string
	}{
		{"zero in 1 char", big.NewInt(0), 1, "!"},
		{"zero in 5 chars (left-padded)", big.NewInt(0), 5, "!!!!!"},
		{"digit one == '#'", big.NewInt(1), 1, "#"},
		{"digit 89 == '~'", big.NewInt(89), 1, "~"},
		{"90 = ['#' '!']", big.NewInt(90), 2, "#!"},
		{"90*90 in 3 chars", big.NewInt(90 * 90), 3, "#!!"},
		{"89*90 + 89 = '~~'", big.NewInt(89*90 + 89), 2, "~~"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := tc.value.Bytes()
			got, err := encodeCompact(src, tc.outLen)
			if err != nil {
				t.Fatalf("encodeCompact: %v", err)
			}
			if got != tc.encoded {
				t.Fatalf("encode: got %q, want %q", got, tc.encoded)
			}

			roundTrip, err := decodeCompact(tc.encoded, len(src))
			if err != nil {
				t.Fatalf("decodeCompact: %v", err)
			}
			roundTripVal := new(big.Int).SetBytes(roundTrip)
			if roundTripVal.Cmp(tc.value) != 0 {
				t.Fatalf("decode round-trip: got %s, want %s", roundTripVal, tc.value)
			}
		})
	}
}

func TestCompactRoundTripRandom(t *testing.T) {
	// The codec's contract is: encode/decode are inverse on integer values
	// in [0, 90^compactLen). For each per-curve compact length used by §5,
	// round-trip 1000 random integers in that range.
	compactLens := []int{
		18, 20, 25, 30, 35, 40, 49, 50, 59, 60, 69, 78, 79, 81,
		98, 117, 156, 161,
		9, 10, 13, 15, // dh_len_compact values
	}

	for _, compactLen := range compactLens {
		// Maximum value representable in compactLen base-90 digits.
		maxVal := new(big.Int).Exp(bigBase90, big.NewInt(int64(compactLen)), nil)
		binLen := (maxVal.BitLen() + 7) / 8

		for trial := 0; trial < 1000; trial++ {
			v, err := rand.Int(rand.Reader, maxVal)
			if err != nil {
				t.Fatalf("rand.Int: %v", err)
			}

			vb := v.Bytes()
			src := make([]byte, binLen)
			copy(src[binLen-len(vb):], vb)

			s, err := encodeCompact(src, compactLen)
			if err != nil {
				t.Fatalf("encode(binLen=%d compactLen=%d val=%s): %v", binLen, compactLen, v, err)
			}
			if len(s) != compactLen {
				t.Fatalf("encoded length: got %d, want %d", len(s), compactLen)
			}
			for i := 0; i < len(s); i++ {
				if rCompactDigits[s[i]] < 0 {
					t.Fatalf("encoded char out of alphabet at %d: %#x", i, s[i])
				}
			}

			back, err := decodeCompact(s, binLen)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !bytes.Equal(back, src) {
				t.Fatalf("round-trip mismatch (binLen=%d compactLen=%d):\nsrc=%x\ngot=%x", binLen, compactLen, src, back)
			}
		}
	}
}

func TestCompactLeftPadsWithBang(t *testing.T) {
	// Encoding digit 1 into a long output must left-pad with '!' (digit 0).
	got, err := encodeCompact([]byte{0x01}, 8)
	if err != nil {
		t.Fatal(err)
	}
	if got != strings.Repeat("!", 7)+"#" {
		t.Fatalf("expected 7 '!' padding plus '#', got %q", got)
	}
}

func TestCompactRejectsOutOfAlphabet(t *testing.T) {
	cases := []string{
		" ",     // space (0x20) — one below the alphabet
		"\x7f",  // DEL — one above
		"\"foo", // double quote — excluded from alphabet
		"'bar",  // single quote — excluded
		"a\\b",  // backslash — excluded
		"a`b",   // backtick — excluded
		"hello world",
	}
	for _, s := range cases {
		if _, err := decodeCompact(s, 32); err == nil {
			t.Errorf("decodeCompact(%q) should have rejected out-of-alphabet char", s)
		}
	}
}

func TestCompactRejectsValueOverflowOnEncode(t *testing.T) {
	// 90^2 = 8100 needs 3 base-90 digits, so asking for 2 must fail.
	src := big.NewInt(90 * 90).Bytes()
	if _, err := encodeCompact(src, 2); err == nil {
		t.Fatal("expected overflow error, got nil")
	}
}

func TestCompactRejectsValueOverflowOnDecode(t *testing.T) {
	// "~~" = 89*90 + 89 = 8099, which exceeds one byte (255), so outLen=1 must fail.
	if _, err := decodeCompact("~~", 1); err == nil {
		t.Fatal("expected overflow error, got nil")
	}
}
