#!/bin/sh
# prepare-release.sh does a release's paperwork in one step:
#
#   sh scripts/prepare-release.sh 1.2.0
#
# - moves the entries under ## [Unreleased] in CHANGELOG.md into a new
#   ## [1.2.0] - YYYY-MM-DD section, and updates the comparison links;
# - runs scripts/set-version.sh 1.2.0 for the deploy files.
#
# Run it from the repository root on a branch, then open the release pull
# request. See RELEASING.md for the rest: merge, tag an rc, test, tag the release.

set -eu

[ $# -eq 1 ] || {
	echo "usage: sh scripts/prepare-release.sh X.Y.Z" >&2
	exit 2
}
version=$1
case $version in
"" | *[!0-9.]* | .* | *. | *..*)
	echo "prepare-release.sh: $version is not a version such as 1.2.0" >&2
	exit 2
	;;
esac

changelog=CHANGELOG.md
repo_url=https://github.com/Cloudopsshell/deaconguard

if grep -q "^## \[$version\]" "$changelog"; then
	echo "prepare-release.sh: $changelog already has a section for $version" >&2
	exit 1
fi

# The previous release is the one the [Unreleased] link compares from.
previous=$(sed -n 's#^\[Unreleased\]: .*/compare/v\(.*\)\.\.\.HEAD$#\1#p' "$changelog")
[ -n "$previous" ] || {
	echo "prepare-release.sh: no [Unreleased] comparison link at the end of $changelog" >&2
	exit 1
}

# There must be something to release: a non-blank line between ## [Unreleased]
# and the next section.
entries=$(awk '/^## \[Unreleased\]/ { inside = 1; next } /^## \[/ { inside = 0 } inside && NF { n++ } END { print n + 0 }' "$changelog")
[ "$entries" -gt 0 ] || {
	echo "prepare-release.sh: ## [Unreleased] in $changelog is empty; add the changes first" >&2
	exit 1
}

date=$(date -u +%Y-%m-%d)
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
awk -v version="$version" -v date="$date" -v previous="$previous" -v url="$repo_url" '
	/^## \[Unreleased\]$/ { print; print ""; print "## [" version "] - " date; next }
	/^\[Unreleased\]: / {
		print "[Unreleased]: " url "/compare/v" version "...HEAD"
		print "[" version "]: " url "/compare/v" previous "...v" version
		next
	}
	{ print }
' "$changelog" >"$tmp"
cat "$tmp" >"$changelog"
echo "Moved the Unreleased entries into $version in $changelog (compared with $previous)."

sh scripts/set-version.sh "$version"

echo
echo "Next: commit, push, and open the release pull request for $version."
