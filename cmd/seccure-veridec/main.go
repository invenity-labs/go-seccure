// SPDX-License-Identifier: LGPL-3.0-or-later

// Command seccure-veridec decrypts the stdin payload with the recipient's
// passphrase, splits off the trailing ECDSA signature, and verifies it
// against the sender's pubkey. The decrypted message goes to stdout on
// success. Exits non-zero on HMAC mismatch or signature mismatch.
//
// Usage:
//   seccure-veridec [-c CURVE] [-m MACLEN_BITS] [-p PASSPHRASE] SENDER_PUBKEY
package main

import (
	"errors"
	"flag"
	"os"

	"github.com/invenity-labs/go-seccure"
	"github.com/invenity-labs/go-seccure/internal/cli"
)

func main() {
	fs := flag.NewFlagSet("seccure-veridec", flag.ExitOnError)
	curveName := cli.CurveFlag(fs)
	macBits := cli.MacLenFlag(fs)
	passFlag := cli.PassphraseFlag(fs)
	if err := fs.Parse(os.Args[1:]); err != nil {
		cli.Die("flag parse: %v", err)
	}
	if fs.NArg() < 1 {
		cli.Die("usage: seccure-veridec [-c CURVE] [-m MACLEN_BITS] [-p PASSPHRASE] SENDER_PUBKEY")
	}
	senderPub := fs.Arg(0)

	curve, err := cli.ResolveCurve(*curveName)
	if err != nil {
		cli.Die("curve %q: %v", *curveName, err)
	}
	maclen, err := cli.MacLenBytes(*macBits)
	if err != nil {
		cli.Die("%v", err)
	}
	passphrase, err := cli.ReadPassphrase(*passFlag, false)
	if err != nil {
		cli.Die("%v", err)
	}

	ciphertext, err := cli.ReadAll()
	if err != nil {
		cli.Die("read stdin: %v", err)
	}

	plaintext, err := seccure.Decrypt(ciphertext, passphrase, curve, maclen)
	if err != nil {
		if errors.Is(err, seccure.ErrHMACMismatch) {
			cli.Die("decrypt: HMAC verification failed")
		}
		cli.Die("decrypt: %v", err)
	}

	// The signcrypt'd payload is (message || sig_bin); peel sig_len_bin
	// bytes off the tail.
	lens, err := seccure.CurveByteLengths(curve)
	if err != nil {
		cli.Die("curve lengths: %v", err)
	}
	sigLen := lens.SignatureBin
	if len(plaintext) < sigLen {
		cli.Die("payload too short for signature (got %d bytes, need at least %d)", len(plaintext), sigLen)
	}
	message := plaintext[:len(plaintext)-sigLen]
	sig := plaintext[len(plaintext)-sigLen:]

	if err := seccure.VerifyBinary(message, sig, senderPub, curve); err != nil {
		if errors.Is(err, seccure.ErrSignatureMismatch) {
			cli.Die("verify: signature does not match")
		}
		cli.Die("verify: %v", err)
	}
	if _, err := os.Stdout.Write(message); err != nil {
		cli.Die("write stdout: %v", err)
	}
}
