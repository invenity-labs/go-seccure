// SPDX-License-Identifier: LGPL-3.0-or-later

// Package ctrprng implements the AES-256-CTR-as-CPRNG construction used by
// SECCURE for both passphrase → scalar derivation (kdf.go) and deterministic
// ECDSA k derivation (ecdsa.go).
//
// The construction is plain AES-256 in CTR mode used as a keystream
// generator:
//
//   - key:     32 bytes (typically the output of SHA-256(seed)).
//   - counter: 16 bytes, all zero, starting at 0, big-endian increment.
//   - keystream block N is AES_K(counter = N).
//
// Callers read exactly the number of bytes they need; the keystream is the
// concatenation of consecutive 16-byte AES blocks.
//
// Both upstreams use this exact construction:
//
//   - reference/c/aes256ctr.c: gcry_cipher_setctr(ch, NULL, 0) then
//     aes256cprng_fillbuf does memset(buf, 0) + aes256ctr_enc (XORs the
//     keystream onto zero bytes — i.e. returns the raw keystream).
//   - reference/py/__init__.py:858-864: PyCryptodome's
//     Counter.new(128, initial_value=0) → AES.MODE_CTR → encrypt(b'\0' * n).
//
// Go's cipher.NewCTR uses the same big-endian counter semantics, so we can
// implement this with stdlib alone.
package ctrprng

import (
	"crypto/aes"
	"crypto/cipher"
)

// Reader is a deterministic AES-256-CTR keystream generator. It satisfies
// io.Reader so callers can use io.ReadFull or any other stdlib API that
// consumes an io.Reader.
//
// A Reader is not safe for concurrent use.
type Reader struct {
	stream cipher.Stream
}

// New constructs a Reader keyed with the given 32-byte key and an all-zero
// 16-byte counter starting at 0.
//
// AES-256 with a 32-byte key never fails at construction in Go's standard
// library (the only ways aes.NewCipher returns an error are wrong key length
// or AES not being available). The signature returns no error to keep call
// sites tidy; on the impossible failure path it panics.
func New(key [32]byte) *Reader {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		// Unreachable: key is exactly 32 bytes and AES-256 is always
		// available in Go's stdlib.
		panic("ctrprng: aes.NewCipher with 32-byte key failed: " + err.Error())
	}
	// SECCURE's CPRNG construction REQUIRES an all-zero counter starting
	// at 0 (matches reference/c/aes256ctr.c and py-seccure's
	// Counter.new(128, initial_value=0)). The "hardcoded IV" is the spec,
	// not a bug — the security of the CPRNG comes from the per-instance
	// key (SHA-256(passphrase) or HMAC-SHA-256(d, msg_hash)), never from
	// IV variation.
	var iv [aes.BlockSize]byte
	return &Reader{
		stream: cipher.NewCTR(block, iv[:]), // #nosec G407 -- zero IV is the SECCURE CPRNG spec; uniqueness comes from the per-instance key
	}
}

// Read fills p with keystream bytes. Always returns (len(p), nil); the
// keystream is unbounded and never errors.
func (r *Reader) Read(p []byte) (int, error) {
	// XORKeyStream(dst, src) XORs the keystream onto src into dst. To get
	// the raw keystream we encrypt all-zero plaintext. The C reference
	// does the same trick (memset(buf, 0) + aes256ctr_enc).
	for i := range p {
		p[i] = 0
	}
	r.stream.XORKeyStream(p, p)
	return len(p), nil
}
