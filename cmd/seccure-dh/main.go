// SPDX-License-Identifier: LGPL-3.0-or-later

// Command seccure-dh runs one side of an ephemeral Diffie-Hellman exchange.
//
// Usage:
//   seccure-dh [-c CURVE]
//
// Prints:
//
//   Local token: <local-compact-pubkey>
//
// then reads the peer's token from stdin (one line) and prints:
//
//   Established key:  <compact>
//   Verification key: <compact>
//
// The private scalar lives only in memory; there is no persistence option.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/invenity-labs/go-seccure"
	"github.com/invenity-labs/go-seccure/internal/cli"
)

func main() {
	fs := flag.NewFlagSet("seccure-dh", flag.ExitOnError)
	curveName := cli.CurveFlag(fs)
	if err := fs.Parse(os.Args[1:]); err != nil {
		cli.Die("flag parse: %v", err)
	}

	curve, err := cli.ResolveCurve(*curveName)
	if err != nil {
		cli.Die("curve %q: %v", *curveName, err)
	}

	token, priv, err := seccure.DHToken(curve)
	if err != nil {
		cli.Die("DH token: %v", err)
	}
	fmt.Fprintln(os.Stderr, "Local token (give this to your peer):")
	fmt.Println(token)

	fmt.Fprintln(os.Stderr, "Enter peer's token:")
	peer, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		cli.Die("read peer token: %v", err)
	}
	peer = strings.TrimRight(peer, "\r\n")

	established, verification, err := seccure.DHEstablish(peer, priv, curve)
	if err != nil {
		cli.Die("DH establish: %v", err)
	}
	fmt.Println("Established key: ", established)
	fmt.Println("Verification key:", verification)
}
