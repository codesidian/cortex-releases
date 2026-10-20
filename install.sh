#!/usr/bin/env bash
#
# Codesidian cortex-agent installer (Linux).
#
#   curl -fsSL -o install.sh https://raw.githubusercontent.com/codesidian/cortex-releases/main/install.sh
#   less install.sh
#   sudo bash install.sh --code <ENROLLMENT_CODE> --fingerprint <USER_KEY_FINGERPRINT>
#
# Downloads the signed cortex-agent release for this machine, verifies its
# integrity against the signed release manifest, installs it onto PATH, then
# enrolls it (which also installs + starts the system service).
#
# SECURITY
# - The release manifest is signed with an offline Ed25519 (minisign) key. Its
#   public half is pinned in this script (RELEASE_PUBKEYS) and the signature is
#   checked here with openssl BEFORE anything downloaded is executed, so a
#   tampered manifest or binary on the release host is refused. The binary is
#   then bound to the verified manifest by SHA-256.
# - This only helps if this script itself comes from somewhere the release host
#   can't modify; read it before piping it to a root shell.
# - The --fingerprint is the CR-1 trust anchor for your USER key. This script
#   only passes it through to `enroll`; it never fetches it from the server.
#   Verify it matches the fingerprint shown in your dashboard.
set -euo pipefail

BASE="${CORTEX_RELEASES_BASE:-https://github.com/codesidian/cortex-releases/releases}"

# Rollback floor: refuse any signed release older than this, so an old (validly
# signed but vulnerable) manifest can't be served in place of the latest.
# Raised (with install.ps1's $MinVersion) by .github/workflows/floor.yml when a
# release is published.
MIN_VERSION="0.1.8"
INSTALL_DIR="${CORTEX_INSTALL_DIR:-/usr/local/bin}"
BIN_NAME="cortex-agent"

# Trusted release signing keys (minisign public key lines). Must match
# $ReleasePubkeys in install.ps1 and
# RELEASE_PUBKEY_CURRENT / RELEASE_PUBKEY_NEXT in cortex-agent/src/release_trust.rs.
RELEASE_PUBKEYS="RWTMOMNGPMMYeyHWCdx4DV3efXIN/mUZ/4HpLKOV2bT5A7/L8uE3KBlr RWT/8/5g10ZGuhRajdSupsEOmAJLihVNgACDUEOkFw6YP95QuLRcsyJ2"

CODE=""; FINGERPRINT=""; API_URL=""; DEV=""

info(){ printf '\033[0;36m[*]\033[0m %s\n' "$1"; }
ok(){   printf '\033[0;32m[+]\033[0m %s\n' "$1"; }
warn(){ printf '\033[0;33m[!]\033[0m %s\n' "$1" >&2; }
die(){  printf '\033[0;31m[x]\033[0m %s\n' "$1" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --code)         CODE="${2:-}"; shift 2 ;;
    --fingerprint)  FINGERPRINT="${2:-}"; shift 2 ;;
    --api-url)      API_URL="${2:-}"; shift 2 ;;
    --dev)          DEV="--dev"; shift ;;
    --base)         BASE="${2:-}"; shift 2 ;;
    -h|--help)
      echo "Usage: sudo bash install.sh --code <CODE> --fingerprint <FP> [--api-url URL] [--dev]"
      exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -n "$CODE" ]        || die "missing --code (get it from the dashboard 'Add Agent' dialog)"
[ -n "$FINGERPRINT" ] || die "missing --fingerprint (shown next to the code in the dashboard)"

have(){ command -v "$1" >/dev/null 2>&1; }
have curl || die "curl is required"
have openssl || die "openssl is required to verify the release signature"

# sha256 helper (coreutils sha256sum, or BSD/macOS shasum).
sha256(){
  if have sha256sum; then sha256sum "$1" | awk '{print $1}';
  elif have shasum;   then shasum -a 256 "$1" | awk '{print $1}';
  else die "need sha256sum or shasum"; fi
}

# Verify a minisign signature ($2) over a file ($1) against RELEASE_PUBKEYS
# using only openssl: Ed25519 over BLAKE2b-512(file) for prehashed ("ED")
# signatures or over the file for legacy ("Ed") ones, plus the global signature
# over signature || trusted comment. Returns non-zero unless a pinned key verifies.
minisign_verify(){
  local file="$1" sigfile="$2" d alg keyid tc pk
  d="$(mktemp -d)"
  sed -n 2p "$sigfile" | base64 -d > "$d/sigblob" 2>/dev/null || { rm -rf "$d"; return 1; }
  sed -n 4p "$sigfile" | base64 -d > "$d/gsig" 2>/dev/null || { rm -rf "$d"; return 1; }
  tc="$(sed -n 3p "$sigfile")"
  case "$tc" in "trusted comment: "*) tc="${tc#trusted comment: }" ;; *) rm -rf "$d"; return 1 ;; esac
  [ "$(wc -c < "$d/sigblob")" -eq 74 ] && [ "$(wc -c < "$d/gsig")" -eq 64 ] || { rm -rf "$d"; return 1; }
  alg="$(head -c 2 "$d/sigblob")"
  keyid="$(head -c 10 "$d/sigblob" | tail -c 8 | od -An -tx1 | tr -d ' \n')"
  tail -c 64 "$d/sigblob" > "$d/sig"
  case "$alg" in
    ED) openssl dgst -blake2b512 -binary "$file" > "$d/msg" ;;
    Ed) cp "$file" "$d/msg" ;;
    *) rm -rf "$d"; return 1 ;;
  esac
  { cat "$d/sig"; printf '%s' "$tc"; } > "$d/gmsg"
  for pk in $RELEASE_PUBKEYS; do
    printf '%s' "$pk" | base64 -d > "$d/pk" 2>/dev/null || continue
    [ "$(wc -c < "$d/pk")" -eq 42 ] && [ "$(head -c 2 "$d/pk")" = "Ed" ] || continue
    [ "$(head -c 10 "$d/pk" | tail -c 8 | od -An -tx1 | tr -d ' \n')" = "$keyid" ] || continue
    { printf '\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00'; tail -c 32 "$d/pk"; } > "$d/pub.der"
    openssl pkey -pubin -inform DER -in "$d/pub.der" -out "$d/pub.pem" 2>/dev/null || continue
    if openssl pkeyutl -verify -pubin -inkey "$d/pub.pem" -rawin -in "$d/msg" -sigfile "$d/sig" >/dev/null 2>&1 &&
       openssl pkeyutl -verify -pubin -inkey "$d/pub.pem" -rawin -in "$d/gmsg" -sigfile "$d/gsig" >/dev/null 2>&1; then
      rm -rf "$d"; return 0
    fi
  done
  rm -rf "$d"; return 1
}

# --- target detection --------------------------------------------------------
OS="$(uname -s)"; ARCH="$(uname -m)"
case "$OS" in
  Linux) ;;
  Darwin) die "macOS is not yet supported (Linux + Windows only at present)" ;;
  *) die "unsupported OS: $OS" ;;
esac
case "$ARCH" in
  x86_64|amd64)   TARGET="x86_64-unknown-linux-gnu" ;;
  aarch64|arm64)  TARGET="aarch64-unknown-linux-gnu" ;;
  *) die "unsupported architecture: $ARCH" ;;
esac
info "Target: $TARGET"

if [ "$(id -u)" != "0" ]; then
  warn "not running as root; install to $INSTALL_DIR and the service step need root."
  warn "re-run with sudo:  sudo bash install.sh --code ... --fingerprint ..."
fi

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# --- fetch + verify manifest -------------------------------------------------
info "Fetching release manifest ..."
curl -fsSL "$BASE/latest/download/manifest.json"         -o "$TMP/manifest.json"         || die "cannot fetch manifest"
curl -fsSL "$BASE/latest/download/manifest.json.minisig" -o "$TMP/manifest.json.minisig" || die "cannot fetch manifest signature"
minisign_verify "$TMP/manifest.json" "$TMP/manifest.json.minisig" \
  || die "release manifest signature does not match the pinned release key; refusing to install"
ok "Release manifest signature verified (pinned key)"

# Pull this target's filename + expected hash out of the verified manifest
# without jq (often not installed). Flatten it to one line first: it is
# pretty-printed, so a target's "file" and "sha256" sit on their own lines. A
# target object is flat, so it ends at the first "}".
FLAT="$(tr -d '\n\r' < "$TMP/manifest.json")"
field(){ printf '%s' "$1" | sed -nE "s/.*\"$2\"[[:space:]]*:[[:space:]]*\"([^\"]*)\".*/\1/p"; }
first_field(){ printf '%s' "$1" | grep -oE "\"$2\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" | head -1 | sed -E 's/.*"([^"]*)"$/\1/'; }
TOBJ="$(printf '%s' "$FLAT" | grep -oE "\"$TARGET\"[[:space:]]*:[[:space:]]*\{[^}]*\}" | head -1 || true)"
[ -n "$TOBJ" ] || die "no release artifact for $TARGET in manifest (not built yet?)"
FILE="$(field "$TOBJ" file)"
WANT_SHA="$(field "$TOBJ" sha256)"
VERSION="$(first_field "$FLAT" version || true)"
EXPIRES="$(first_field "$FLAT" expires || true)"
printf '%s' "$VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$' || die "bad version in manifest: $VERSION"
printf '%s' "$WANT_SHA" | grep -qE '^[0-9a-f]{64}$' || die "bad sha256 in manifest for $TARGET"
printf '%s' "$FILE" | grep -qE '^[A-Za-z0-9._-]+$' || die "unsafe artifact name in manifest: $FILE"
case "$FILE" in *..*) die "unsafe artifact name in manifest: $FILE" ;; esac
if [ -n "$EXPIRES" ]; then
  EXP_S="$(date -u -d "$EXPIRES" +%s 2>/dev/null)" || die "bad manifest expires: $EXPIRES"
  [ "$(date -u +%s)" -le "$EXP_S" ] || die "release manifest expired at $EXPIRES; refusing (possible stale mirror)"
fi
[ "$(printf '%s\n%s\n' "$MIN_VERSION" "$VERSION" | sort -V | head -1)" = "$MIN_VERSION" ] \
  || die "release $VERSION is older than this installer's floor $MIN_VERSION; refusing (possible rollback)"
info "Latest version: ${VERSION:-?} ($FILE)"

# --- download binary + integrity check ---------------------------------------
info "Downloading $FILE ..."
curl -fsSL "$BASE/download/v$VERSION/$FILE" -o "$TMP/$BIN_NAME" || die "download failed"
GOT_SHA="$(sha256 "$TMP/$BIN_NAME")"
[ "$GOT_SHA" = "$WANT_SHA" ] || die "SHA-256 mismatch (expected $WANT_SHA, got $GOT_SHA) — refusing to install"
ok "SHA-256 verified against signed manifest"
chmod +x "$TMP/$BIN_NAME"

# --- install -----------------------------------------------------------------
info "Installing to $INSTALL_DIR/$BIN_NAME ..."
install -d "$INSTALL_DIR"
install -m 0755 "$TMP/$BIN_NAME" "$INSTALL_DIR/$BIN_NAME" \
  || die "install failed (need root for $INSTALL_DIR?)"
ok "installed cortex-agent ${VERSION:-} to $INSTALL_DIR"

case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) warn "$INSTALL_DIR is not on PATH; add it or invoke $INSTALL_DIR/$BIN_NAME directly." ;;
esac

# --- enroll (installs + starts the service) ----------------------------------
info "Enrolling agent ..."
ENROLL_ARGS=(enroll --code "$CODE" --fingerprint "$FINGERPRINT")
[ -n "$API_URL" ] && ENROLL_ARGS+=(--api-url "$API_URL")
[ -n "$DEV" ] && ENROLL_ARGS=("$DEV" "${ENROLL_ARGS[@]}")
"$INSTALL_DIR/$BIN_NAME" "${ENROLL_ARGS[@]}"

ok "Done. The cortex-agent is installed, enrolled, and running as a service."
