// SPDX-License-Identifier: LGPL-3.0-or-later

// Command seccure-encrypt encrypts stdin to stdout under a recipient pubkey.
//
// Usage:
//   seccure-encrypt [-c CURVE] [-m MACLEN_BITS] PUBKEY
package main

import (
	"flag"
	"os"

	"github.com/invenity-labs/go-seccure"
	"github.com/invenity-labs/go-seccure/internal/cli"
)

func main() {
	fs := flag.NewFlagSet("seccure-encrypt", flag.ExitOnError)
	curveName := cli.CurveFlag(fs)
	macBits := cli.MacLenFlag(fs)
	if err := fs.Parse(os.Args[1:]); err != nil {
		cli.Die("flag parse: %v", err)
	}
	if fs.NArg() < 1 {
		cli.Die("usage: seccure-encrypt [-c CURVE] [-m MACLEN_BITS] PUBKEY")
	}
	pub := fs.Arg(0)

	curve, err := cli.ResolveCurve(*curveName)
	if err != nil {
		cli.Die("curve %q: %v", *curveName, err)
	}
	maclen, err := cli.MacLenBytes(*macBits)
	if err != nil {
		cli.Die("%v", err)
	}

	plaintext, err := cli.ReadAll()
	if err != nil {
		cli.Die("read stdin: %v", err)
	}
	ciphertext, err := seccure.Encrypt(plaintext, pub, curve, maclen)
	if err != nil {
		cli.Die("encrypt: %v", err)
	}
	if _, err := os.Stdout.Write(ciphertext); err != nil {
		cli.Die("write stdout: %v", err)
	}
}
