// SPDX-License-Identifier: LGPL-3.0-or-later

// Command seccure-key derives the compact public key for a passphrase.
//
// Usage:
//   seccure-key [-c CURVE] [-p PASSPHRASE]
//
// Reads the passphrase from the -p flag, the PASSPHRASE env var, or the
// first line of stdin (in that order of precedence). Prints the compact
// public key to stdout followed by a newline.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/invenity-labs/go-seccure"
	"github.com/invenity-labs/go-seccure/internal/cli"
)

func main() {
	fs := flag.NewFlagSet("seccure-key", flag.ExitOnError)
	curveName := cli.CurveFlag(fs)
	passFlag := cli.PassphraseFlag(fs)
	if err := fs.Parse(os.Args[1:]); err != nil {
		cli.Die("flag parse: %v", err)
	}

	curve, err := cli.ResolveCurve(*curveName)
	if err != nil {
		cli.Die("curve %q: %v", *curveName, err)
	}
	passphrase, err := cli.ReadPassphrase(*passFlag, true)
	if err != nil {
		cli.Die("%v", err)
	}

	pub, err := seccure.PassphraseToPubkey(passphrase, curve)
	if err != nil {
		cli.Die("derive pubkey: %v", err)
	}
	fmt.Println(pub)
}
