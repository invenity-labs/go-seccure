// SPDX-License-Identifier: LGPL-3.0-or-later

package seccure

import (
	"fmt"
	"math/big"
	"strings"
)

// curveParams holds the on-the-wire properties of one SECCURE-supported curve.
//
// The (a, b, p, gx, gy, n, h) primitives come from authoritative sources:
//
//   - SECP/NIST p112-p521 from reference/c/curves.c (B. Poettering),
//     which in turn cites SEC 2 v1.0.
//   - Brainpool p160-p512 from reference/py/__init__.py (Bas Westerbaan),
//     which in turn cites RFC 5639.
//
// The length fields are derived per §5 (formulas mirror
// curves.c::load_curve and py-seccure::Curve.__init__).
type curveParams struct {
	id   Curve
	name string   // canonical name, e.g. "secp160r1"
	alias []string // additional CLI-accepted aliases, e.g. {"p160"}

	// Curve equation y^2 = x^3 + a*x + b over GF(p), with base point G of
	// order n and cofactor h.
	p, a, b, gx, gy, n *big.Int
	h                  int

	// Wire byte/char lengths. Derived in newCurveParams, NOT stored as
	// constants — see §5.
	elemLenBin    int
	orderLenBin   int
	pkLenBin      int
	pkLenCompact  int
	sigLenBin     int
	sigLenCompact int
	dhLenBin      int
	dhLenCompact  int
}

// curveSeed is the raw hex-string form of one curve's parameters as they
// appear in py-seccure's RAW_CURVES table (which matches seccure-c's curves.c
// for the SECP/NIST 8 verbatim).
type curveSeed struct {
	id          Curve
	names       string // "secp192r1/nistp192" — slash-separated aliases as in upstream
	a, b, m     string
	gx, gy      string
	order       string
	cofactor    int
	pkLenCompactExpected int // for cross-checking against upstream's stored value
}

// rawCurves is the canonical list of all 15 SECCURE 0.5 curves. The hex
// strings are copied verbatim from reference/py/__init__.py (which agrees with
// reference/c/curves.c for the first 8). Do not edit by hand without
// re-deriving the length self-test (curves_test.go).
var rawCurves = []curveSeed{
	{
		id:    CurveP112,
		names: "secp112r1",
		a:     "db7c2abf62e35e668076bead2088",
		b:     "659ef8ba043916eede8911702b22",
		m:     "db7c2abf62e35e668076bead208b",
		gx:    "09487239995a5ee76b55f9c2f098",
		gy:    "a89ce5af8724c0a23e0e0ff77500",
		order: "db7c2abf62e35e7628dfac6561c5",
		cofactor:             1,
		pkLenCompactExpected: 18,
	},
	{
		id:    CurveP128,
		names: "secp128r1",
		a:     "fffffffdfffffffffffffffffffffffc",
		b:     "e87579c11079f43dd824993c2cee5ed3",
		m:     "fffffffdffffffffffffffffffffffff",
		gx:    "161ff7528b899b2d0c28607ca52c5b86",
		gy:    "cf5ac8395bafeb13c02da292dded7a83",
		order: "fffffffe0000000075a30d1b9038a115",
		cofactor:             1,
		pkLenCompactExpected: 20,
	},
	{
		id:    CurveP160,
		names: "secp160r1",
		a:     "ffffffffffffffffffffffffffffffff7ffffffc",
		b:     "1c97befc54bd7a8b65acf89f81d4d4adc565fa45",
		m:     "ffffffffffffffffffffffffffffffff7fffffff",
		gx:    "4a96b5688ef573284664698968c38bb913cbfc82",
		gy:    "23a628553168947d59dcc912042351377ac5fb32",
		order: "0100000000000000000001f4c8f927aed3ca752257",
		cofactor:             1,
		pkLenCompactExpected: 25,
	},
	{
		id:    CurveP192,
		names: "secp192r1/nistp192",
		a:     "fffffffffffffffffffffffffffffffefffffffffffffffc",
		b:     "64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1",
		m:     "fffffffffffffffffffffffffffffffeffffffffffffffff",
		gx:    "188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012",
		gy:    "07192b95ffc8da78631011ed6b24cdd573f977a11e794811",
		order: "ffffffffffffffffffffffff99def836146bc9b1b4d22831",
		cofactor:             1,
		pkLenCompactExpected: 30,
	},
	{
		id:    CurveP224,
		names: "secp224r1/nistp224",
		a:     "fffffffffffffffffffffffffffffffefffffffffffffffffffffffe",
		b:     "b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4",
		m:     "ffffffffffffffffffffffffffffffff000000000000000000000001",
		gx:    "b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21",
		gy:    "bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34",
		order: "ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d",
		cofactor:             1,
		pkLenCompactExpected: 35,
	},
	{
		id:    CurveP256,
		names: "secp256r1/nistp256",
		a:     "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
		b:     "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
		m:     "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
		gx:    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
		gy:    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
		order: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
		cofactor:             1,
		pkLenCompactExpected: 40,
	},
	{
		id:    CurveP384,
		names: "secp384r1/nistp384",
		a:     "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc",
		b:     "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
		m:     "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
		gx:    "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
		gy:    "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
		order: "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
		cofactor:             1,
		pkLenCompactExpected: 60,
	},
	{
		id:    CurveP521,
		names: "secp521r1/nistp521",
		a:     "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc",
		b:     "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
		m:     "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		gx:    "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
		gy:    "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650",
		order: "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
		cofactor:             1,
		pkLenCompactExpected: 81,
	},
	{
		id:    CurveBP160,
		names: "brainpoolp160r1",
		a:     "340e7be2a280eb74e2be61bada745d97e8f7c300",
		b:     "1e589a8595423412134faa2dbdec95c8d8675e58",
		m:     "e95e4a5f737059dc60dfc7ad95b3d8139515620f",
		gx:    "bed5af16ea3f6a4f62938c4631eb5af7bdbcdbc3",
		gy:    "1667cb477a1a8ec338f94741669c976316da6321",
		order: "e95e4a5f737059dc60df5991d45029409e60fc09",
		cofactor:             1,
		pkLenCompactExpected: 25,
	},
	{
		id:    CurveBP192,
		names: "brainpoolp192r1",
		a:     "6a91174076b1e0e19c39c031fe8685c1cae040e5c69a28ef",
		b:     "469a28ef7c28cca3dc721d044f4496bcca7ef4146fbf25c9",
		m:     "c302f41d932a36cda7a3463093d18db78fce476de1a86297",
		gx:    "c0a0647eaab6a48753b033c56cb0f0900a2f5c4853375fd6",
		gy:    "14b690866abd5bb88b5f4828c1490002e6773fa2fa299b8f",
		order: "c302f41d932a36cda7a3462f9e9e916b5be8f1029ac4acc1",
		cofactor:             1,
		pkLenCompactExpected: 30,
	},
	{
		id:    CurveBP224,
		names: "brainpoolp224r1",
		a:     "68a5e62ca9ce6c1c299803a6c1530b514e182ad8b0042a59cad29f43",
		b:     "2580f63ccfe44138870713b1a92369e33e2135d266dbb372386c400b",
		m:     "d7c134aa264366862a18302575d1d787b09f075797da89f57ec8c0ff",
		gx:    "0d9029ad2c7e5cf4340823b2a87dc68c9e4ce3174c1e6efdee12c07d",
		gy:    "58aa56f772c0726f24c6b89e4ecdac24354b9e99caa3f6d3761402cd",
		order: "d7c134aa264366862a18302575d0fb98d116bc4b6ddebca3a5a7939f",
		cofactor:             1,
		pkLenCompactExpected: 35,
	},
	{
		id:    CurveBP256,
		names: "brainpoolp256r1",
		a:     "7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9",
		b:     "26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6",
		m:     "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377",
		gx:    "8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262",
		gy:    "547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997",
		order: "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7",
		cofactor:             1,
		pkLenCompactExpected: 40,
	},
	{
		id:    CurveBP320,
		names: "brainpoolp320r1",
		a:     "3ee30b568fbab0f883ccebd46d3f3bb8a2a73513f5eb79da66190eb085ffa9f492f375a97d860eb4",
		b:     "520883949dfdbc42d3ad198640688a6fe13f41349554b49acc31dccd884539816f5eb4ac8fb1f1a6",
		m:     "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27",
		gx:    "43bd7e9afb53d8b85289bcc48ee5bfe6f20137d10a087eb6e7871e2a10a599c710af8d0d39e20611",
		gy:    "14fdd05545ec1cc8ab4093247f77275e0743ffed117182eaa9c77877aaac6ac7d35245d1692e8ee1",
		order: "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311",
		cofactor:             1,
		pkLenCompactExpected: 50,
	},
	{
		id:    CurveBP384,
		names: "brainpoolp384r1",
		a:     "7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826",
		b:     "04a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c11",
		m:     "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53",
		gx:    "1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e",
		gy:    "8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315",
		order: "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565",
		cofactor:             1,
		pkLenCompactExpected: 60,
	},
	{
		id:    CurveBP512,
		names: "brainpoolp512r1",
		a:     "7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca",
		b:     "3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723",
		m:     "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3",
		gx:    "81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822",
		gy:    "7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892",
		order: "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069",
		cofactor:             1,
		pkLenCompactExpected: 79,
	},
}

// curves is the in-memory curve registry, indexed by Curve enum value.
// Populated by init() from rawCurves.
var curves [CurveBP512 + 1]*curveParams

// byNameTable maps every recognised name (canonical + aliases + short forms)
// to a Curve enum value. Populated by init().
var byNameTable map[string]Curve

func init() {
	byNameTable = make(map[string]Curve)
	for _, seed := range rawCurves {
		cp := mustBuildCurve(seed)
		curves[cp.id] = cp

		for _, name := range cp.alias {
			byNameTable[name] = cp.id
		}
		byNameTable[cp.name] = cp.id
	}
}

// mustBuildCurve realises one curveSeed into a curveParams, computing all
// derived length fields. Panics on any inconsistency — these are static data,
// so panicking at init() is the right failure mode.
func mustBuildCurve(s curveSeed) *curveParams {
	names := strings.Split(s.names, "/")
	canonical := names[0]
	aliases := append([]string{}, names[1:]...)

	// Short alias: "secp160r1" → "p160", "brainpoolp160r1" → "bp160".
	if rest, ok := strings.CutPrefix(canonical, "secp"); ok {
		aliases = append(aliases, "p"+strings.TrimSuffix(rest, "r1"))
	} else if rest, ok := strings.CutPrefix(canonical, "brainpoolp"); ok {
		aliases = append(aliases, "bp"+strings.TrimSuffix(rest, "r1"))
	}

	cp := &curveParams{
		id:    s.id,
		name:  canonical,
		alias: aliases,
		p:     mustHex(s.m),
		a:     mustHex(s.a),
		b:     mustHex(s.b),
		gx:    mustHex(s.gx),
		gy:    mustHex(s.gy),
		n:     mustHex(s.order),
		h:     s.cofactor,
	}

	cp.elemLenBin = byteLen(cp.p)
	cp.orderLenBin = byteLen(cp.n)

	// pk_len_{bin,compact} = serialization length of (2*p - 1).
	twoP := new(big.Int).Lsh(cp.p, 1)
	twoP.Sub(twoP, big.NewInt(1))
	cp.pkLenBin = byteLen(twoP)
	cp.pkLenCompact = base90Len(twoP)

	// sig_len_{bin,compact} = serialization length of (n*n - 1).
	nSq := new(big.Int).Mul(cp.n, cp.n)
	nSq.Sub(nSq, big.NewInt(1))
	cp.sigLenBin = byteLen(nSq)
	cp.sigLenCompact = base90Len(nSq)

	// dh_len_bin = min((bitLen(n) // 2 + 7) // 8, 32);
	// dh_len_compact = base90Len(2^dh_len_bin - 1).
	dhBin := (cp.n.BitLen()/2 + 7) / 8
	if dhBin > 32 {
		dhBin = 32
	}
	cp.dhLenBin = dhBin
	// dhBin is capped at 32 above, so 8*dhBin ≤ 256 — safe to widen.
	dhMax := new(big.Int).Lsh(big.NewInt(1), uint(8*dhBin)) // #nosec G115 -- dhBin in [0,32]
	dhMax.Sub(dhMax, big.NewInt(1))
	cp.dhLenCompact = base90Len(dhMax)

	if cp.pkLenCompact != s.pkLenCompactExpected {
		panic(fmt.Sprintf("seccure: curve %s: pk_len_compact mismatch — computed %d, upstream %d",
			canonical, cp.pkLenCompact, s.pkLenCompactExpected))
	}

	return cp
}

// mustHex parses a hex string into a big.Int or panics. Used only at init().
func mustHex(s string) *big.Int {
	x, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("seccure: invalid hex constant: " + s)
	}
	return x
}

// byteLen returns ceil(bitLen(x) / 8).
func byteLen(x *big.Int) int {
	return (x.BitLen() + 7) / 8
}

// base90Len returns the number of base-90 digits needed to represent x.
// Mirrors py-seccure's get_serialized_number_len for SER_COMPACT.
func base90Len(x *big.Int) int {
	if x.Sign() == 0 {
		return 0
	}
	tmp := new(big.Int).Set(x)
	count := 0
	for tmp.Sign() != 0 {
		tmp.Quo(tmp, bigBase90)
		count++
	}
	return count
}

// lookupCurve returns the parameters for c. Returns nil for an out-of-range Curve.
func lookupCurve(c Curve) *curveParams {
	if int(c) < 0 || int(c) >= len(curves) {
		return nil
	}
	return curves[c]
}
