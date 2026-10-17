#!/bin/sh
# set-version.sh writes a release's version into the deploy files that pin it:
# the Compose file, the Kustomize manifests and the Helm chart. The release tag
# is the one source of the version; these files are stamped from it.
#
#   sh scripts/set-version.sh 1.2.3          update the files
#   sh scripts/set-version.sh --check 1.2.3  fail if any file names another version
#
# Run it from the repository root, in the changelog pull request before tagging
# (see RELEASING.md). The release workflow runs --check against the tag.

set -eu

usage() {
	echo "usage: sh scripts/set-version.sh [--check] X.Y.Z" >&2
	exit 2
}

check=false
if [ "${1-}" = "--check" ]; then
	check=true
	shift
fi
[ $# -eq 1 ] || usage
version=$1
case $version in
"" | *[!0-9.]* | .* | *. | *..*) usage ;;
esac
[ "$(printf '%s' "$version" | tr -cd . | wc -c | tr -d ' ')" -eq 2 ] || usage

semver='[0-9]+\.[0-9]+\.[0-9]+'
image='ghcr\.io/cloudopsshell/deaconguard'

# stamp FILE prints FILE with every pinned version replaced by $version.
stamp() {
	sed -E \
		-e "s#(${image}:)${semver}#\\1${version}#g" \
		-e "s#^([[:space:]]*newTag: )${semver}\$#\\1${version}#" \
		-e "s#(\\?ref=v)${semver}#\\1${version}#g" \
		-e "s#^(version: )${semver}\$#\\1${version}#" \
		-e "s#^(appVersion: \")${semver}(\")\$#\\1${version}\\2#" \
		"$1"
}

files="deploy/compose/compose.yaml
deploy/kustomize/server/kustomization.yaml
deploy/kustomize/server/statefulset.yaml
deploy/kustomize/agent/kustomization.yaml
deploy/kustomize/agent/daemonset.yaml
deploy/helm/deaconguard/Chart.yaml"

status=0
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
for file in $files; do
	[ -f "$file" ] || {
		echo "set-version.sh: $file is missing; run from the repository root" >&2
		exit 1
	}
	stamp "$file" >"$tmp"
	if cmp -s "$file" "$tmp"; then
		continue
	fi
	if $check; then
		echo "::error file=$file::$file pins another version than $version; run: sh scripts/set-version.sh $version"
		status=1
	else
		cat "$tmp" >"$file"
		echo "Updated $file"
	fi
done

if $check && [ $status -eq 0 ]; then
	echo "All deploy files pin $version."
fi
exit $status
