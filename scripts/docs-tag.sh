#!/bin/sh
# Publishes documentation changes without an app release.
#
# docs.deaconguard.io takes docs/ from the latest release tag, so the docs
# describe what people can install. A docs tag, docs-vX.Y.Z.N, lets docs-only
# changes merged after release X.Y.Z reach the site without a new app version:
# the site builds docs/ from the newest docs tag of the latest release.
#
#   sh scripts/docs-tag.sh          check main and tag it docs-vX.Y.Z.N (not pushed)
#   sh scripts/docs-tag.sh --push   the same, and push the tag
#   sh scripts/docs-tag.sh --check docs-vX.Y.Z.N
#                                   check an existing docs tag (the Docs tag workflow)
#
# A docs tag is refused unless everything changed since vX.Y.Z is
# documentation: docs/, the Markdown files at the top, and scripts/check-docs.mjs.
# Code changes need an app release instead (RELEASING.md).
set -eu

allowed='^(docs/|[^/]+\.md$|scripts/check-docs\.mjs$|scripts/docs-tag\.sh$|\.github/workflows/docs-tag\.yml$)'

check() { # release tag, commit
	changed=$(git diff --name-only "$1" "$2")
	if [ -z "$changed" ]; then
		echo "nothing changed since $1" >&2
		return 1
	fi
	other=$(printf '%s\n' "$changed" | grep -Ev "$allowed" || true)
	if [ -n "$other" ]; then
		echo "not only documentation changed since $1; release the app instead:" >&2
		printf '  %s\n' $other >&2
		return 1
	fi
	node scripts/check-docs.mjs
}

if [ "${1:-}" = --check ]; then
	tag=${2:?usage: docs-tag.sh --check docs-vX.Y.Z.N}
	release=$(printf '%s' "$tag" | sed -n 's/^docs-\(v[0-9]*\.[0-9]*\.[0-9]*\)\.[0-9]*$/\1/p')
	[ -n "$release" ] || { echo "$tag is not docs-vX.Y.Z.N" >&2; exit 1; }
	latest=$(git tag -l 'v[0-9]*' | grep -v -- - | sort -V | tail -1)
	[ "$release" = "$latest" ] || { echo "$tag is for $release, but the latest release is $latest" >&2; exit 1; }
	git merge-base --is-ancestor "$release" "$tag" || { echo "$tag doesn't follow $release" >&2; exit 1; }
	check "$release" "$tag"
	echo "$tag: documentation only since $release"
	exit 0
fi

git fetch --quiet --tags origin
commit=$(git rev-parse origin/main)
release=$(git tag -l 'v[0-9]*' | grep -v -- - | sort -V | tail -1)
check "$release" "$commit"
last=$(git tag -l "docs-$release.*" | sed "s/^docs-$release\.//" | sort -n | tail -1)
tag="docs-$release.$(( ${last:-0} + 1 ))"
git tag -a "$tag" -m "DeaconGuard documentation for $release, revision ${tag##*.}" "$commit"
echo "Tagged $tag on $commit (main): documentation only since $release."
if [ "${1:-}" = --push ]; then
	git push --quiet origin "$tag"
	echo "Pushed $tag. The website's next build publishes it; run its Build workflow to publish now."
else
	echo "Push it with: git push origin $tag"
fi
