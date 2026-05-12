// SPDX-License-Identifier: LGPL-3.0-or-later

package seccure

import (
	"crypto/sha256"
	"io"
	"math/big"

	"github.com/invenity-labs/go-seccure/internal/ctrprng"
)

// Passphrase-to-scalar derivation — see §3.1.
//
// The single most common porting bug, and the cause of every prior failed
// attempt, is to skip the AES-256-CTR-as-CPRNG step and use SHA-256(passphrase)
// directly. The actual flow, mirroring py-seccure's Curve.hash_to_exponent
// (reference/py/__init__.py:858-868):
//
//   1. h := SHA-256(passphrase)                          (32 bytes)
//   2. Seed an AES-256-CTR stream with key = h, all-zero counter, increment 0;
//      pull exactly cp.orderLenBin bytes of keystream.
//   3. a := big-endian unsigned int of those bytes.
//   4. d := (a mod (n - 1)) + 1                          // d in [1, n-1]
//
// The "mod (n - 1) + 1" step matters: reducing mod n directly is a different
// (and silently wrong) function.

// hashToExponent derives the private scalar from a passphrase per the recipe
// above. The output satisfies 1 <= d <= n-1 by construction.
func hashToExponent(passphrase []byte, cp *curveParams) *big.Int {
	h := sha256.Sum256(passphrase)

	buf := make([]byte, cp.orderLenBin)
	if _, err := io.ReadFull(ctrprng.New(h), buf); err != nil {
		// ctrprng.Reader.Read never returns an error.
		panic("seccure: ctrprng Read failed unexpectedly: " + err.Error())
	}

	a := new(big.Int).SetBytes(buf)
	nMinus1 := new(big.Int).Sub(cp.n, big.NewInt(1))
	a.Mod(a, nMinus1)
	a.Add(a, big.NewInt(1))
	return a
}
