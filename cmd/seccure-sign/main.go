// SPDX-License-Identifier: LGPL-3.0-or-later

// Command seccure-sign reads a message from stdin and prints a compact
// signature to stdout (terminated by a newline).
//
// Usage:
//   seccure-sign [-c CURVE] [-p PASSPHRASE]
//
// Differences from the C tool: we put the signature on STDOUT (not stderr,
// as the C tool does). Stderr-as-signature-channel was a way for the C tool
// to pipe a message through itself and capture the signature on the side; our
// CLI uses Unix piping conventions where the primary artefact goes on stdout.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/invenity-labs/go-seccure"
	"github.com/invenity-labs/go-seccure/internal/cli"
)

func main() {
	fs := flag.NewFlagSet("seccure-sign", flag.ExitOnError)
	curveName := cli.CurveFlag(fs)
	passFlag := cli.PassphraseFlag(fs)
	if err := fs.Parse(os.Args[1:]); err != nil {
		cli.Die("flag parse: %v", err)
	}

	curve, err := cli.ResolveCurve(*curveName)
	if err != nil {
		cli.Die("curve %q: %v", *curveName, err)
	}
	passphrase, err := cli.ReadPassphrase(*passFlag, false)
	if err != nil {
		cli.Die("%v", err)
	}

	message, err := cli.ReadAll()
	if err != nil {
		cli.Die("read stdin: %v", err)
	}
	sig, err := seccure.Sign(message, passphrase, curve)
	if err != nil {
		cli.Die("sign: %v", err)
	}
	fmt.Println(sig)
}
