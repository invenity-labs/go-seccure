// SPDX-License-Identifier: LGPL-3.0-or-later

// Command seccure-signcrypt signs the stdin payload, then encrypts the
// (message || signature) blob for the recipient pubkey. Output goes to
// stdout as one binary stream.
//
// Usage:
//   seccure-signcrypt [-c CURVE] [-m MACLEN_BITS] [-p PASSPHRASE] PUBKEY
//
// The companion command is seccure-veridec: decrypt with the recipient's
// passphrase, then verify against the sender's pubkey.
package main

import (
	"flag"
	"os"

	"github.com/invenity-labs/go-seccure"
	"github.com/invenity-labs/go-seccure/internal/cli"
)

func main() {
	fs := flag.NewFlagSet("seccure-signcrypt", flag.ExitOnError)
	curveName := cli.CurveFlag(fs)
	macBits := cli.MacLenFlag(fs)
	passFlag := cli.PassphraseFlag(fs)
	if err := fs.Parse(os.Args[1:]); err != nil {
		cli.Die("flag parse: %v", err)
	}
	if fs.NArg() < 1 {
		cli.Die("usage: seccure-signcrypt [-c CURVE] [-m MACLEN_BITS] [-p PASSPHRASE] PUBKEY")
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
	passphrase, err := cli.ReadPassphrase(*passFlag, false)
	if err != nil {
		cli.Die("%v", err)
	}

	message, err := cli.ReadAll()
	if err != nil {
		cli.Die("read stdin: %v", err)
	}

	sigBin, err := seccure.SignBinary(message, passphrase, curve)
	if err != nil {
		cli.Die("sign: %v", err)
	}

	// Append the binary signature to the message and encrypt the whole
	// blob. The recipient knows sig_len_bin (from -c CURVE) so they can
	// peel it back off after decrypt.
	payload := append(message, sigBin...)
	ct, err := seccure.Encrypt(payload, pub, curve, maclen)
	if err != nil {
		cli.Die("encrypt: %v", err)
	}
	if _, err := os.Stdout.Write(ct); err != nil {
		cli.Die("write stdout: %v", err)
	}
}
