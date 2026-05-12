// SPDX-License-Identifier: LGPL-3.0-or-later

package seccure

import (
	"fmt"
	"math/big"
)

// SECCURE compact codec — see §3.2.
//
// CORRECTION FROM AN EARLIER DRAFT OF THE BRIEF: the alphabet is base-90,
// NOT base-94. SECCURE picks every printable ASCII character in 0x21..0x7E
// EXCEPT 0x22 '"', 0x27 '\'', 0x5c '\\', and 0x60 '`'. That leaves 90 digits.
// The chars are NOT contiguous, so the digit ↔ byte mapping requires a
// lookup table on both sides; "c - 0x21" is wrong.
//
// Source of truth: reference/c/serialize.c (compact_digits[]) and
// reference/py/__init__.py (COMPACT_DIGITS) — both lists match byte-for-byte.
//
// Encoding: interpret the input as a big-endian unsigned integer, repeatedly
// take mod 90 (least-significant digit first), reverse, then left-pad with
// the digit-0 character ('!') to the fixed per-curve length.
//
// Decoding is the inverse. Both directions reject any input byte outside the
// 90-character alphabet and require the fixed output length to fit.

const base90Alphabet = 90

// compactDigits is the SECCURE base-90 alphabet, digit index → ASCII byte.
// Verbatim from reference/c/serialize.c:47-53 and
// reference/py/__init__.py:50-51.
var compactDigits = [base90Alphabet]byte{
	'!', '#', '$', '%', '&', '(', ')', '*', '+', ',',
	'-', '.', '/', '0', '1', '2', '3', '4', '5', '6',
	'7', '8', '9', ':', ';', '<', '=', '>', '?', '@',
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
	'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
	'U', 'V', 'W', 'X', 'Y', 'Z', '[', ']', '^', '_',
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
	'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
	'u', 'v', 'w', 'x', 'y', 'z', '{', '|', '}', '~',
}

// rCompactDigits is the reverse alphabet: ASCII byte → digit value, or -1 if
// the byte is not in the alphabet. Initialised in init().
var rCompactDigits [256]int8

var bigBase90 = big.NewInt(int64(base90Alphabet))

func init() {
	for i := range rCompactDigits {
		rCompactDigits[i] = -1
	}
	for i, c := range compactDigits {
		// i ∈ [0, 89] — fits in int8 (range [-128, 127]).
		rCompactDigits[c] = int8(i) // #nosec G115 -- bounded by len(compactDigits)=90
	}
}

// encodeCompact encodes src to a compact (base-90) string of exactly outLen
// characters, left-padded with '!' (digit zero) as needed. Returns an error
// if the numerical value of src does not fit in outLen base-90 digits.
func encodeCompact(src []byte, outLen int) (string, error) {
	if outLen < 0 {
		return "", fmt.Errorf("seccure: encodeCompact: negative outLen %d", outLen)
	}

	n := new(big.Int).SetBytes(src) // big-endian, unsigned
	out := make([]byte, outLen)
	mod := new(big.Int)

	for i := outLen - 1; i >= 0; i-- {
		n.DivMod(n, bigBase90, mod)
		out[i] = compactDigits[mod.Int64()]
	}

	if n.Sign() != 0 {
		return "", fmt.Errorf("seccure: encodeCompact: value does not fit in %d base-90 digits", outLen)
	}
	return string(out), nil
}

// decodeCompact decodes a compact (base-90) string back into a binary blob of
// exactly outLen bytes, left-padded with zero bytes as needed. Returns an
// error if s contains any character outside the 90-digit alphabet or if the
// decoded integer does not fit in outLen bytes.
func decodeCompact(s string, outLen int) ([]byte, error) {
	if outLen < 0 {
		return nil, fmt.Errorf("seccure: decodeCompact: negative outLen %d", outLen)
	}

	n := new(big.Int)
	for i := 0; i < len(s); i++ {
		d := rCompactDigits[s[i]]
		if d < 0 {
			return nil, fmt.Errorf("seccure: decodeCompact: character %#x at index %d is outside the compact alphabet", s[i], i)
		}
		n.Mul(n, bigBase90)
		n.Add(n, big.NewInt(int64(d)))
	}

	buf := n.Bytes()
	if len(buf) > outLen {
		return nil, fmt.Errorf("seccure: decodeCompact: decoded value needs %d bytes, more than the %d requested", len(buf), outLen)
	}

	out := make([]byte, outLen)
	copy(out[outLen-len(buf):], buf) // left-pad with zero bytes
	return out, nil
}
