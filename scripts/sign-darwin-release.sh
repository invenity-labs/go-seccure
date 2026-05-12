#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-or-later
#
# Sign + notarize the macOS binaries for an already-published GitHub Release.
#
# Why this exists: CI cross-compiles for linux / darwin / windows but the
# darwin archives are unsigned (we don't pay for macOS-on-GitHub minutes).
# This script downloads the darwin archives from a release, signs each
# binary with our Developer ID Application certificate, ships them to
# Apple's notary service, waits for approval, then re-uploads the signed
# archives — overwriting the unsigned originals.
#
# Notarization is a per-binary attestation from Apple. Once approved, the
# signed binaries pass Gatekeeper checks without requiring users to run
# `xattr -dr com.apple.quarantine`. CLI binaries can't be stapled (only
# .pkg/.dmg/.app/.xip can), so Gatekeeper does an online lookup against
# Apple's notary service the first time each binary runs.
#
# Usage:
#     scripts/sign-darwin-release.sh v0.2.0
#
# Requirements:
#   - Apple Developer ID Application certificate in the macOS Keychain
#   - App-specific password (from appleid.apple.com)
#   - `gh`, `codesign`, `xcrun notarytool`, `syft`, `jq`
#   - .env in the repo root with the four APPLE_* variables (see .env.example)

set -euo pipefail

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
  echo "usage: $0 v<MAJOR>.<MINOR>.<PATCH>" >&2
  echo "  e.g. $0 v0.2.0" >&2
  exit 2
fi
if [[ "$VERSION" != v* ]]; then
  echo "error: version must start with 'v' (got: $VERSION)" >&2
  exit 2
fi
VERSION_NOV="${VERSION#v}"
REPO="invenity-labs/go-seccure"

# --- Load .env -------------------------------------------------------------
if [[ -f .env ]]; then
  set -a
  # shellcheck source=/dev/null
  source .env
  set +a
fi

: "${APPLE_DEV_ID:?missing — put e.g. 'Developer ID Application: Your Name (TEAMID)' in .env}"
: "${APPLE_ID:?missing — Apple ID email used for the developer account}"
: "${APPLE_APP_PASSWORD:?missing — app-specific password from appleid.apple.com}"
: "${APPLE_TEAM_ID:?missing — Apple Team ID (10 chars, from developer.apple.com}"

# --- Sanity checks ---------------------------------------------------------
need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "error: required tool not on PATH: $1" >&2
    exit 1
  }
}
need gh
need codesign
need syft
need jq
xcrun --find notarytool >/dev/null || {
  echo "error: xcrun notarytool not available (install Xcode command line tools)" >&2
  exit 1
}

# Confirm the cert exists in Keychain before doing any network work.
if ! security find-identity -v -p codesigning | grep -q "$APPLE_DEV_ID"; then
  echo "error: signing identity not found in Keychain: $APPLE_DEV_ID" >&2
  echo "available identities:" >&2
  security find-identity -v -p codesigning >&2
  exit 1
fi

# --- Workspace -------------------------------------------------------------
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
echo "=> work dir: $WORK"

mkdir -p "$WORK/in" "$WORK/out" "$WORK/notary"

# --- Download all release artifacts ---------------------------------------
# We need everything (not just darwin) so we can regenerate a consistent
# checksums.txt at the end.
echo "=> downloading release artifacts for $VERSION"
gh release download "$VERSION" --repo "$REPO" --dir "$WORK/in"

# --- Sign each darwin binary ----------------------------------------------
for arch in amd64 arm64; do
  archive="go-seccure_${VERSION_NOV}_darwin_${arch}.tar.gz"
  if [[ ! -f "$WORK/in/$archive" ]]; then
    echo "error: $archive not in release $VERSION — was the cross-compile matrix changed?" >&2
    exit 1
  fi

  echo "=> signing darwin_$arch binaries"
  ext="$WORK/work/$arch"
  mkdir -p "$ext"
  tar xzf "$WORK/in/$archive" -C "$ext"

  for bin in "$ext"/seccure-*; do
    [[ -f "$bin" ]] || continue
    name="$(basename "$bin")"
    codesign \
      --sign "$APPLE_DEV_ID" \
      --options runtime \
      --timestamp \
      --force \
      --identifier "com.invenity-labs.go-seccure.${name}" \
      "$bin"
    codesign --verify --verbose=1 "$bin" 2>&1 | grep -q "satisfies its Designated Requirement" || {
      echo "error: codesign verify failed on $bin" >&2
      exit 1
    }
  done

  # Re-archive into the original tar.gz layout.
  rm "$WORK/in/$archive"
  ( cd "$ext" && tar czf "$WORK/out/$archive" . )
done

# --- Notarize -------------------------------------------------------------
# notarytool needs a .zip / .dmg / .pkg — give it a .zip per arch.
echo "=> submitting to Apple's notary service (this can take a few minutes)"
for arch in amd64 arm64; do
  zip="$WORK/notary/darwin_${arch}.zip"
  ( cd "$WORK/work/$arch" && ditto -c -k --sequesterRsrc --keepParent . "$zip" )

  echo "   submitting darwin_$arch …"
  xcrun notarytool submit "$zip" \
    --apple-id "$APPLE_ID" \
    --password "$APPLE_APP_PASSWORD" \
    --team-id "$APPLE_TEAM_ID" \
    --wait
done

# --- Regenerate the checksums + darwin SBOMs ------------------------------
# Signed darwin archives have new SHA256s, so checksums.txt and the two
# darwin SBOMs (which embed the archive checksum) need refreshing.
echo "=> regenerating checksums.txt"
final="$WORK/final"
mkdir -p "$final"
# Copy linux/windows artifacts unchanged + signed darwin artifacts in.
cp "$WORK/in/"*.{tar.gz,zip} "$final/" 2>/dev/null || true
cp "$WORK/out/"*.tar.gz "$final/"     # overwrite unsigned darwin
# Drop the old checksums file we downloaded; we'll regenerate.
rm -f "$final/checksums.txt"
# Drop the old darwin SBOMs (they reference the old archive SHA).
rm -f "$final/go-seccure_${VERSION_NOV}_darwin_amd64.tar.gz.sbom.json"
rm -f "$final/go-seccure_${VERSION_NOV}_darwin_arm64.tar.gz.sbom.json"

( cd "$final" && shasum -a 256 -- * | sort -k2 > checksums.txt )

echo "=> regenerating darwin SBOMs"
for arch in amd64 arm64; do
  archive="$final/go-seccure_${VERSION_NOV}_darwin_${arch}.tar.gz"
  syft "$archive" --output "spdx-json=${archive}.sbom.json"
done

# --- Upload ---------------------------------------------------------------
echo "=> uploading signed darwin archives, refreshed checksums.txt + SBOMs"
gh release upload "$VERSION" --repo "$REPO" --clobber \
  "$final/go-seccure_${VERSION_NOV}_darwin_amd64.tar.gz" \
  "$final/go-seccure_${VERSION_NOV}_darwin_arm64.tar.gz" \
  "$final/go-seccure_${VERSION_NOV}_darwin_amd64.tar.gz.sbom.json" \
  "$final/go-seccure_${VERSION_NOV}_darwin_arm64.tar.gz.sbom.json" \
  "$final/checksums.txt"

# --- Verify each re-uploaded asset is reachable on the public CDN ---------
# `gh release upload --clobber` does delete-then-upload, and GitHub
# occasionally leaves the new asset stuck in a 404-on-public-URL state
# even though the API reports state="uploaded" and `gh release download`
# works. Catch that here so a broken release doesn't surface as a failed
# `brew install` later. If we hit a 404, delete + re-upload the asset
# fresh (without --clobber) which forces a new ID and bypasses the
# corrupt entry.
echo "=> verifying re-uploaded assets are publicly reachable"
for asset in \
    "go-seccure_${VERSION_NOV}_darwin_amd64.tar.gz" \
    "go-seccure_${VERSION_NOV}_darwin_arm64.tar.gz" \
    "go-seccure_${VERSION_NOV}_darwin_amd64.tar.gz.sbom.json" \
    "go-seccure_${VERSION_NOV}_darwin_arm64.tar.gz.sbom.json" \
    "checksums.txt"; do
  url="https://github.com/invenity-labs/go-seccure/releases/download/${VERSION}/${asset}"
  code=$(curl -sIL -o /dev/null -w '%{http_code}' "$url")
  if [[ "$code" == "200" ]]; then
    echo "   ✓ $asset ($code)"
    continue
  fi
  echo "   ✗ $asset returned $code; recovering via delete + fresh upload"
  gh release delete-asset "$VERSION" "$asset" --repo "$REPO" --yes
  gh release upload "$VERSION" --repo "$REPO" "$final/$asset"
  code=$(curl -sIL -o /dev/null -w '%{http_code}' "$url")
  [[ "$code" == "200" ]] || { echo "   still broken after recovery: $code"; exit 1; }
  echo "   ✓ $asset recovered ($code)"
done

# --- Patch the Homebrew formula -------------------------------------------
# The brew formula goreleaser pushed during the CI release references the
# UNSIGNED archive SHA-256s. Now that we've re-uploaded the signed darwin
# archives (different SHA-256), those entries are stale and `brew install`
# will fail with a checksum mismatch. Clone the tap, rewrite the darwin
# sha256 lines, commit + push.
echo "=> patching invenity-labs/homebrew-tap formula with new darwin sha256s"

amd64_sha=$(shasum -a 256 "$final/go-seccure_${VERSION_NOV}_darwin_amd64.tar.gz" | awk '{print $1}')
arm64_sha=$(shasum -a 256 "$final/go-seccure_${VERSION_NOV}_darwin_arm64.tar.gz" | awk '{print $1}')

tap="$WORK/tap"
git clone --depth 1 https://github.com/invenity-labs/homebrew-tap.git "$tap"
formula="$tap/go-seccure.rb"
[[ -f "$formula" ]] || { echo "error: $formula not found in homebrew-tap" >&2; exit 1; }

# Rewrite both darwin sha256 entries. The formula's structure is stable
# enough that a per-arch awk pass is reliable; if goreleaser changes the
# template significantly, this break will be loud.
awk -v amd64="$amd64_sha" -v arm64="$arm64_sha" '
  /url ".*darwin_amd64\.tar\.gz"/ { print; in_amd64=1; in_arm64=0; next }
  /url ".*darwin_arm64\.tar\.gz"/ { print; in_arm64=1; in_amd64=0; next }
  in_amd64 && /sha256 "/ { sub(/sha256 "[^"]*"/, "sha256 \"" amd64 "\""); in_amd64=0; print; next }
  in_arm64 && /sha256 "/ { sub(/sha256 "[^"]*"/, "sha256 \"" arm64 "\""); in_arm64=0; print; next }
  { print }
' "$formula" > "$formula.new"
mv "$formula.new" "$formula"

# Sanity-check the new SHAs landed in the formula.
grep -q "$amd64_sha" "$formula" || { echo "error: amd64 sha not patched"; exit 1; }
grep -q "$arm64_sha" "$formula" || { echo "error: arm64 sha not patched"; exit 1; }

( cd "$tap"
  git -c user.email='bot@invenity-labs.invalid' -c user.name='goreleaser-bot' \
    commit -am "go-seccure $VERSION: update darwin SHA-256 after signing"
  git push origin main
)

echo
echo "✓ done. $VERSION darwin binaries are signed + notarized + uploaded,"
echo "  and the Homebrew formula now references the signed archive SHA-256s."
echo "  Apple Gatekeeper will accept these on first run (online notary check)."
