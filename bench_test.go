// SPDX-License-Identifier: LGPL-3.0-or-later

package seccure

import (
	"bytes"
	"testing"
)

// Benchmarks comparable with bench/bench_py.py — same curves, same
// operations, same input shapes. The Python script runs an equivalent loop
// in py-seccure and prints results in the same CSV-ish format. The
// bench/compare.sh wrapper merges both outputs into a side-by-side table.
//
// Run from the repo root:
//
//   go test -bench . -benchmem -run '^$' -benchtime=2s ./...
//   ./bench/compare.sh
//
// Curves chosen as a representative spread: p160 (small / fastest), p256
// (industry standard / most common in practice), p521 (largest / slowest).

var benchCurves = []struct {
	name string
	id   Curve
}{
	{"p160", CurveP160},
	{"p256", CurveP256},
	{"p521", CurveP521},
}

var benchPassphrase = []byte("benchmark passphrase that's reasonably long")
var benchMessage = bytes.Repeat([]byte("payload-"), 32) // 256 bytes

func BenchmarkPassphraseToPubkey(b *testing.B) {
	for _, c := range benchCurves {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := PassphraseToPubkey(benchPassphrase, c.id); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkSign(b *testing.B) {
	for _, c := range benchCurves {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := Sign(benchMessage, benchPassphrase, c.id); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkVerify(b *testing.B) {
	for _, c := range benchCurves {
		pub, err := PassphraseToPubkey(benchPassphrase, c.id)
		if err != nil {
			b.Fatal(err)
		}
		sig, err := Sign(benchMessage, benchPassphrase, c.id)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if err := Verify(benchMessage, sig, pub, c.id); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkEncrypt(b *testing.B) {
	for _, c := range benchCurves {
		pub, err := PassphraseToPubkey(benchPassphrase, c.id)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := Encrypt(benchMessage, pub, c.id, 10); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkDecrypt(b *testing.B) {
	for _, c := range benchCurves {
		pub, err := PassphraseToPubkey(benchPassphrase, c.id)
		if err != nil {
			b.Fatal(err)
		}
		ct, err := Encrypt(benchMessage, pub, c.id, 10)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := Decrypt(ct, benchPassphrase, c.id, 10); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
