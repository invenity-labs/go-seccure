// SPDX-License-Identifier: LGPL-3.0-or-later

package ctrprng

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestKeystreamMatchesPySeccureFixture asserts that our keystream byte-for-byte
// equals the one PyCryptodome produces (which py-seccure uses, which matches
// the C reference's libgcrypt). The fixture below was generated with:
//
//   .venv/bin/python -c "
//   from Crypto.Cipher import AES
//   from Crypto.Util.Counter import Counter
//   key = bytes.fromhex('00' * 32)
//   ctr = Counter.new(128, initial_value=0)
//   c = AES.new(key, AES.MODE_CTR, counter=ctr)
//   print(c.encrypt(b'\\0' * 64).hex())
//   "
//
// — and likewise for a non-zero key. If this test ever fails, every other
// SECCURE primitive that derives from a CPRNG (passphrase scalar, ECDSA k)
// will also be wrong, so this is the canary for the entire upstream
// compatibility chain.
func TestKeystreamMatchesPySeccureFixture(t *testing.T) {
	cases := []struct {
		name   string
		keyHex string
		want48 string // first 48 keystream bytes (3 blocks), hex
	}{
		{
			name:   "all-zero key",
			keyHex: "0000000000000000000000000000000000000000000000000000000000000000",
			want48: "dc95c078a2408989ad48a21492842087" +
				"530f8afbc74536b9a963b4f1c4cb738b" +
				"cea7403d4d606b6e074ec5d3baf39d18",
		},
		{
			name:   "0x01..0x20 key",
			keyHex: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
			want48: "a73c5576667b7b43a23a9fd930b5465d" +
				"1f681792a7c4073b9ae1f7a3c6773983" +
				"c679db19bd5515e51f2ae40c7730aafa",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			keyBytes, _ := hex.DecodeString(tc.keyHex)
			var key [32]byte
			copy(key[:], keyBytes)

			r := New(key)
			buf := make([]byte, 48) // 3 full blocks
			n, err := r.Read(buf)
			if err != nil {
				t.Fatalf("Read: %v", err)
			}
			if n != len(buf) {
				t.Fatalf("Read: n=%d, want %d", n, len(buf))
			}

			want, _ := hex.DecodeString(tc.want48)
			if !bytes.Equal(buf, want) {
				t.Fatalf("keystream mismatch:\n  got  = %x\n  want = %x", buf, want)
			}
		})
	}
}

// TestReadAcrossBlockBoundaries: reading 1 byte at a time across multiple
// block boundaries must produce the same keystream as a single bulk read.
// Catches counter-increment / state bugs.
func TestReadAcrossBlockBoundaries(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}

	bulk := make([]byte, 100)
	rb := New(key)
	if _, err := rb.Read(bulk); err != nil {
		t.Fatalf("bulk Read: %v", err)
	}

	piecewise := make([]byte, 100)
	rp := New(key)
	for i := 0; i < len(piecewise); i++ {
		one := make([]byte, 1)
		if _, err := rp.Read(one); err != nil {
			t.Fatalf("piecewise Read at %d: %v", i, err)
		}
		piecewise[i] = one[0]
	}

	if !bytes.Equal(bulk, piecewise) {
		t.Fatalf("piecewise vs bulk mismatch:\n  bulk = %x\n  piecewise = %x", bulk, piecewise)
	}
}

// TestEmptyRead: reading 0 bytes is a no-op that returns (0, nil).
func TestEmptyRead(t *testing.T) {
	var key [32]byte
	r := New(key)
	n, err := r.Read(nil)
	if err != nil {
		t.Errorf("Read(nil): err=%v", err)
	}
	if n != 0 {
		t.Errorf("Read(nil): n=%d, want 0", n)
	}
}
