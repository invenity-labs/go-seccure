// SPDX-License-Identifier: LGPL-3.0-or-later

// Package cli is the shared plumbing for the eight cmd/seccure-* binaries.
// It is intentionally tiny — the heavy lifting lives in the seccure package.
//
// Design note on passphrase reading: the C reference uses libgcrypt's
// terminal-echo suppression. Doing that in Go without a third-party dep
// (golang.org/x/term) is awkward, so we accept the passphrase from three
// places, in this priority order: a -p flag (insecure but useful in tests),
// the PASSPHRASE env var, or the first line of stdin if the binary expects
// no other stdin input. This is functional for non-interactive pipelines
// (where passphrases come from a vault or secret manager rather than human
// input) while still allowing manual invocation.
package cli

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/invenity-labs/go-seccure"
)

// CurveFlag parses a -c flag into a seccure.Curve. Default is p160 to match
// the seccure.1 manpage (the C source has DEFAULT_CURVE="p521" in
// seccure.c, which disagrees with the manpage; we side with the manpage,
// which is also what the most-deployed builds of the C tool produce).
func CurveFlag(fs *flag.FlagSet) *string {
	return fs.String("c", "p160", "curve name (e.g. p160, p256, secp384r1, bp512)")
}

// ResolveCurve resolves a curve-name flag value to a seccure.Curve.
func ResolveCurve(name string) (seccure.Curve, error) {
	return seccure.CurveByName(strings.TrimSpace(name))
}

// MacLenFlag parses -m as a MAC length in BITS (matches the C tool's surface).
// Default 80 bits = 10 bytes, per the seccure.1 manpage.
func MacLenFlag(fs *flag.FlagSet) *int {
	return fs.Int("m", 80, "MAC length in bits (multiple of 8, 0..256)")
}

// MacLenBytes converts the bits-flag value into a byte count, validating.
func MacLenBytes(bits int) (int, error) {
	if bits < 0 || bits > 256 || bits%8 != 0 {
		return 0, fmt.Errorf("invalid mac length %d bits (must be a multiple of 8 in [0, 256])", bits)
	}
	return bits / 8, nil
}

// PassphraseFlag adds a -p flag for the passphrase. Empty string means
// "read from PASSPHRASE env var, then fall back to first stdin line."
func PassphraseFlag(fs *flag.FlagSet) *string {
	return fs.String("p", "", "passphrase (or set PASSPHRASE env var; or piped on stdin if no other stdin is consumed)")
}

// ReadPassphrase resolves the passphrase to use. flagValue is the -p flag's
// value; readFromStdin = true if the binary doesn't consume stdin for its
// payload (e.g. seccure-key reads only a passphrase).
func ReadPassphrase(flagValue string, readFromStdin bool) ([]byte, error) {
	if flagValue != "" {
		return []byte(flagValue), nil
	}
	if env := os.Getenv("PASSPHRASE"); env != "" {
		return []byte(env), nil
	}
	if readFromStdin {
		// Read the first line of stdin (without trailing CR/LF).
		r := bufio.NewReader(os.Stdin)
		line, err := r.ReadBytes('\n')
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("read passphrase from stdin: %w", err)
		}
		line = []byte(strings.TrimRight(string(line), "\r\n"))
		return line, nil
	}
	return nil, fmt.Errorf("no passphrase: set -p, PASSPHRASE env var")
}

// ReadAll slurps all of stdin into a byte slice. Used by binaries that take
// the payload (plaintext, ciphertext, message) on stdin.
func ReadAll() ([]byte, error) {
	return io.ReadAll(os.Stdin)
}

// Die prints to stderr and exits non-zero. Use for fatal errors so callers
// don't need to repeat the pattern.
func Die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format, args...)
	if !strings.HasSuffix(format, "\n") {
		fmt.Fprintln(os.Stderr)
	}
	os.Exit(1)
}

