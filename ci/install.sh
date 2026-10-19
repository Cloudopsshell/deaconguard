#!/bin/sh
# Installs the deaconguard command for a CI job, without root: it downloads a
# release's archive, verifies checksums.txt's signature with cosign (keyless,
# signed by the release workflow) and the archive against it, and puts the
# deaconguard binary in a folder. Nothing else is installed or changed.
#
#   sh install.sh [VERSION] [FOLDER]
#
# VERSION is a release such as 1.4.0, or latest (the default); FOLDER is
# where the binary goes ($HOME/.local/bin by default). Linux on amd64 or
# arm64. The GitHub Action and the GitLab template run it.
set -eu

REPOSITORY="https://github.com/Cloudopsshell/deaconguard"
SIGNER="$REPOSITORY/.github/workflows/release.yml"
SIGNER_ISSUER="https://token.actions.githubusercontent.com"

# cosign, downloaded to a temporary folder for the check. The same version
# and checksums as packaging/install.sh; CI checks they match.
COSIGN_VERSION="3.1.3"
COSIGN_SHA256_AMD64="4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71"
COSIGN_SHA256_ARM64="c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a"

fail() {
	printf 'deaconguard install: %s\n' "$*" >&2
	exit 1
}

version="${1:-latest}"
folder="${2:-$HOME/.local/bin}"
version="${version#v}"

[ "$(uname -s)" = "Linux" ] || fail "this installs the Linux command; on macOS, download a darwin archive from $REPOSITORY/releases"
case "$(uname -m)" in
x86_64 | amd64) arch=amd64 expected_cosign="$COSIGN_SHA256_AMD64" ;;
aarch64 | arm64) arch=arm64 expected_cosign="$COSIGN_SHA256_ARM64" ;;
*) fail "unsupported architecture $(uname -m); DeaconGuard runs on amd64 and arm64" ;;
esac
command -v curl >/dev/null 2>&1 || fail "curl is needed"
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is needed"

if [ "$version" = "latest" ]; then
	latest="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "$REPOSITORY/releases/latest")" ||
		fail "could not reach GitHub to find the latest release"
	version="${latest##*/tag/v}"
fi
case "$version" in
*[!0-9A-Za-z.-]* | "") fail "invalid version: $version" ;;
esac

work="$(mktemp -d "${TMPDIR:-/tmp}/deaconguard-ci.XXXXXX")"
trap 'rm -rf "$work"' EXIT

archive="deaconguard_${version}_linux_${arch}.tar.gz"
base="$REPOSITORY/releases/download/v$version"
for file in checksums.txt checksums.txt.sigstore.json "$archive"; do
	curl -fsSL --proto '=https' --tlsv1.2 -o "$work/$file" "$base/$file" || fail "could not download $base/$file"
done
curl -fsSL --proto '=https' --tlsv1.2 -o "$work/cosign" "https://github.com/sigstore/cosign/releases/download/v$COSIGN_VERSION/cosign-linux-$arch" ||
	fail "could not download cosign $COSIGN_VERSION"
[ "$(sha256sum "$work/cosign" | cut -d' ' -f1)" = "$expected_cosign" ] || fail "the cosign download does NOT match its pinned checksum"
chmod 0755 "$work/cosign"

"$work/cosign" verify-blob "$work/checksums.txt" --bundle "$work/checksums.txt.sigstore.json" \
	--certificate-identity "$SIGNER@refs/tags/v$version" \
	--certificate-oidc-issuer "$SIGNER_ISSUER" >"$work/cosign.log" 2>&1 ||
	{ cat "$work/cosign.log" >&2; fail "the signature of checksums.txt for v$version is NOT valid; nothing was installed"; }

expected="$(awk -v name="$archive" '$2 == name || $2 == "*" name { print $1 }' "$work/checksums.txt")"
[ -n "$expected" ] || fail "checksums.txt for v$version does not list $archive"
[ "$(sha256sum "$work/$archive" | cut -d' ' -f1)" = "$expected" ] || fail "$archive does NOT match the release's checksums.txt; nothing was installed"

tar -xzf "$work/$archive" -C "$work" deaconguard
mkdir -p "$folder"
install -m 0755 "$work/deaconguard" "$folder/deaconguard" 2>/dev/null || { cp "$work/deaconguard" "$folder/deaconguard" && chmod 0755 "$folder/deaconguard"; }
printf 'Installed %s (signature and checksum verified) to %s\n' "$("$folder/deaconguard" version | head -n 1)" "$folder"
