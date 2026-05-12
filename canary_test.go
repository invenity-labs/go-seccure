// SPDX-License-Identifier: LGPL-3.0-or-later

package seccure

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// vectorsFile is the canonical JSON test-vector file generated from py-seccure
// by scripts/gen_vectors.py. Its schema is:
//
//   {
//     "pubkeys":    [{"curve":"...", "passphrase_hex":"...", "pubkey":"..."}, ...],
//     "signatures": [{"curve":"...", "passphrase_hex":"...", "message_hex":"...",
//                     "signature":"..."}, ...]
//   }
type vectorsFile struct {
	Pubkeys []struct {
		Curve         string `json:"curve"`
		PassphraseHex string `json:"passphrase_hex"`
		Pubkey        string `json:"pubkey"`
	} `json:"pubkeys"`
	Signatures []struct {
		Curve         string `json:"curve"`
		PassphraseHex string `json:"passphrase_hex"`
		MessageHex    string `json:"message_hex"`
		Signature     string `json:"signature"`
	} `json:"signatures"`
}

func loadVectors(t *testing.T) *vectorsFile {
	t.Helper()
	data, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatalf("read testdata/vectors.json: %v\n\nRegenerate with:\n  ./.venv/bin/python scripts/gen_vectors.py > testdata/vectors.json", err)
	}
	var v vectorsFile
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("parse testdata/vectors.json: %v", err)
	}
	return &v
}

// TestCanaryPassphraseToPubkey is THE canary test from §4.
// Every prior porting attempt failed somewhere in this chain:
//
//   passphrase → SHA-256 → AES-256-CTR → mod (n-1) + 1 → d*G → compress → base-90
//
// Going through every (curve, passphrase) entry in testdata/vectors.json
// and asserting byte-equality with py-seccure rules out drift in any of those
// stages. If this passes for all 15 curves on all 12 passphrases (~180
// entries), the foundation is sound and the rest of the wire format
// (signatures, ECIES, DH) should follow.
func TestCanaryPassphraseToPubkey(t *testing.T) {
	v := loadVectors(t)
	if len(v.Pubkeys) == 0 {
		t.Fatal("vectors.json has no pubkey entries")
	}

	for _, entry := range v.Pubkeys {
		entry := entry
		// Subtest name is curve + a short passphrase tag so failures point
		// to the exact row.
		t.Run(entry.Curve+"/"+entry.PassphraseHex, func(t *testing.T) {
			passphrase, err := hex.DecodeString(entry.PassphraseHex)
			if err != nil {
				t.Fatalf("bad passphrase_hex %q: %v", entry.PassphraseHex, err)
			}

			curve, err := CurveByName(entry.Curve)
			if err != nil {
				t.Fatalf("CurveByName(%q): %v", entry.Curve, err)
			}

			got, err := PassphraseToPubkey(passphrase, curve)
			if err != nil {
				t.Fatalf("PassphraseToPubkey: %v", err)
			}
			if got != entry.Pubkey {
				t.Fatalf("mismatch on curve=%s pw_hex=%s\n  got  = %q\n  want = %q",
					entry.Curve, entry.PassphraseHex, got, entry.Pubkey)
			}
		})
	}
}

// TestCanaryDocumentedVectors covers the three specific vectors mentioned
// inline as canary vectors (§1 ("acceptance criteria") and §4. They are also
// covered by TestCanaryPassphraseToPubkey via vectors.json, but pinning them
// here makes the relationship between the brief's claims and the live test
// suite unambiguous.
func TestCanaryDocumentedVectors(t *testing.T) {
	cases := []struct {
		passphrase string
		curve      Curve
		want       string
	}{
		{"my private key", CurveP160, "8W;>i^H0qi|J&$coR5MFpR*Vn"},
		{"test", CurveP160, "*jMVCU^[QC&q*v_8C1ZAFBAgD"},
		{"seccure is secure", CurveP160, "2@DupCaCKykHBe-QHpAP%d%B["},
	}
	for _, tc := range cases {
		got, err := PassphraseToPubkey([]byte(tc.passphrase), tc.curve)
		if err != nil {
			t.Errorf("PassphraseToPubkey(%q): %v", tc.passphrase, err)
			continue
		}
		if got != tc.want {
			t.Errorf("PassphraseToPubkey(%q):\n  got  = %q\n  want = %q",
				tc.passphrase, got, tc.want)
		}
	}
}
