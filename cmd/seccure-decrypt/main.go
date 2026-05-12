// SPDX-License-Identifier: LGPL-3.0-or-later

// Command seccure-decrypt decrypts stdin to stdout using a passphrase.
//
// Usage:
//   seccure-decrypt [-c CURVE] [-m MACLEN_BITS] [-p PASSPHRASE]
//
// Exits non-zero with no stdout output on HMAC mismatch.
package main

import (
	"errors"
	"flag"
	"os"

	"github.com/invenity-labs/go-seccure"
	"github.com/invenity-labs/go-seccure/internal/cli"
)

func main() {
	fs := flag.NewFlagSet("seccure-decrypt", flag.ExitOnError)
	curveName := cli.CurveFlag(fs)
	macBits := cli.MacLenFlag(fs)
	passFlag := cli.PassphraseFlag(fs)
	if err := fs.Parse(os.Args[1:]); err != nil {
		cli.Die("flag parse: %v", err)
	}

	curve, err := cli.ResolveCurve(*curveName)
	if err != nil {
		cli.Die("curve %q: %v", *curveName, err)
	}
	maclen, err := cli.MacLenBytes(*macBits)
	if err != nil {
		cli.Die("%v", err)
	}
	// We DO consume stdin for the ciphertext, so the passphrase cannot
	// also come from stdin — disallow that fallback.
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
	if _, err := os.Stdout.Write(plaintext); err != nil {
		cli.Die("write stdout: %v", err)
	}
}
