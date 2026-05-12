// SPDX-License-Identifier: LGPL-3.0-or-later

// Command seccure-verify verifies a signature for a message read from stdin.
//
// Usage:
//   seccure-verify [-c CURVE] PUBKEY SIGNATURE
//
// Exits 0 on success, non-zero on signature mismatch or any other failure.
package main

import (
	"errors"
	"flag"
	"os"

	"github.com/invenity-labs/go-seccure"
	"github.com/invenity-labs/go-seccure/internal/cli"
)

func main() {
	fs := flag.NewFlagSet("seccure-verify", flag.ExitOnError)
	curveName := cli.CurveFlag(fs)
	if err := fs.Parse(os.Args[1:]); err != nil {
		cli.Die("flag parse: %v", err)
	}
	if fs.NArg() < 2 {
		cli.Die("usage: seccure-verify [-c CURVE] PUBKEY SIGNATURE")
	}
	pub, sig := fs.Arg(0), fs.Arg(1)

	curve, err := cli.ResolveCurve(*curveName)
	if err != nil {
		cli.Die("curve %q: %v", *curveName, err)
	}

	message, err := cli.ReadAll()
	if err != nil {
		cli.Die("read stdin: %v", err)
	}
	if err := seccure.Verify(message, sig, pub, curve); err != nil {
		if errors.Is(err, seccure.ErrSignatureMismatch) {
			cli.Die("verify: signature does not match")
		}
		cli.Die("verify: %v", err)
	}
	// Match the C tool's silent-success behaviour: no stdout on success.
}
