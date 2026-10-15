#!/usr/bin/env bash
#
# Publish a signed cortex-agent release to this repository.
#
#   scripts/publish.sh <release-dir>
#
# <release-dir> holds manifest.json, manifest.json.minisig (made with the
# offline release key) and every artifact the manifest names. Nothing is
# uploaded unless the signature verifies against the key pinned in install.sh
# and every artifact matches its signed size and SHA-256. Requires gh, jq and
# openssl, and a gh login with write access to this repository.
#
# The release is created as tag v<version>, marked latest, and install.sh's
# rollback floor (MIN_VERSION) is raised to <version> in a follow-up commit.
set -euo pipefail

REPO="${CORTEX_RELEASES_REPO:-codesidian/cortex-releases}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIR="${1:?usage: scripts/publish.sh <release-dir>}"

die(){ printf '[x] %s\n' "$1" >&2; exit 1; }
for t in gh jq openssl; do command -v "$t" >/dev/null || die "$t is required"; done

# Reuse the installer's verifier and pinned keys so publish and install can
# never disagree about what counts as signed.
eval "$(sed -n '/^RELEASE_PUBKEYS=/p; /^minisign_verify(){/,/^}/p' "$ROOT/install.sh")"

M="$DIR/manifest.json"; S="$DIR/manifest.json.minisig"
[ -f "$M" ] && [ -f "$S" ] || die "missing manifest.json or manifest.json.minisig in $DIR"
minisign_verify "$M" "$S" || die "manifest signature does not verify against the pinned release key"

VERSION="$(jq -er .version "$M")"
FILES=("$M" "$S")
while IFS=$'\t' read -r file size sha; do
  case "$file" in */*|*..*|"") die "unsafe artifact name: $file" ;; esac
  f="$DIR/$file"
  [ -f "$f" ] || die "missing artifact $file"
  [ "$(wc -c < "$f" | tr -d ' ')" = "$size" ] || die "size mismatch for $file"
  [ "$(openssl dgst -sha256 -r "$f" | cut -d' ' -f1)" = "$sha" ] || die "sha256 mismatch for $file"
  FILES+=("$f")
done < <(jq -r '.targets[] | [.file, (.size|tostring), .sha256] | @tsv' "$M")

gh release view "v$VERSION" --repo "$REPO" >/dev/null 2>&1 && die "release v$VERSION already exists"
gh release create "v$VERSION" "${FILES[@]}" --repo "$REPO" --latest \
  --title "cortex-agent $VERSION" \
  --notes "Signed with the cortex-agent release key (see minisign.pub). Verify before running."
echo "[+] published v$VERSION"

# Raise the installer's rollback floor to this release.
sed -i.bak -E "s/^MIN_VERSION=\"[^\"]*\"/MIN_VERSION=\"$VERSION\"/" "$ROOT/install.sh" && rm -f "$ROOT/install.sh.bak"
git -C "$ROOT" add install.sh
git -C "$ROOT" commit -m "install.sh: raise rollback floor to $VERSION"
git -C "$ROOT" push
echo "[+] install.sh floor raised to $VERSION"
