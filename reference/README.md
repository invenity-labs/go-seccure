# reference/

Vendored copies of the upstream sources we are cloning, kept locally for
offline diffing.

```
reference/
├── c/    # SECCURE C reference (B. Poettering, v0.4 / v0.5)
└── py/   # py-seccure (Bas Westerbaan et al.)
```

## Why these are in-tree

The Go implementation cites the upstream sources at several points where the
byte-format spec or constant-time semantics matter (the passphrase-scalar
derivation, the deterministic ECDSA `k` derivation, the ECIES KDF, the DH
KDF). Having both trees in the same checkout makes diff-bisection a `grep`
away.

## License

The C reference is **GPL-2.0-or-later**; py-seccure is **LGPL-3.0-or-later**.
go-seccure itself is LGPL-3.0; the vendored copies retain their upstream
licenses unchanged. Keep these copies **only when attribution is clean**:

1. Each file must retain its original copyright and license headers.
2. The `NOTICE` in the repo root credits both upstreams.
3. We make no claim to upstream copyright.

If a file does not satisfy (1), do not commit it — pull it manually for
local diffing only.

## Populating

```sh
# C reference
git clone https://github.com/asciimoo/seccure.git /tmp/seccure-c
cp /tmp/seccure-c/{serialize,protocol,ecc,curves,aes256ctr}.c reference/c/

# Python reference
git clone https://github.com/bwesterb/py-seccure.git /tmp/py-seccure
cp /tmp/py-seccure/src/*.py reference/py/
```

Both repos are LGPL-3.0; verify headers before staging.
