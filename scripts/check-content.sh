#!/bin/sh
# check-content.sh fails when tracked files contain content DeaconGuard must
# not ship: material from the CIS Benchmarks, whose licence forbids using it
# in a product, or third-party licence headers that aren't ours. See
# CONTRIBUTING.md, "Third-party content".
#
# Run it from the repository root: sh scripts/check-content.sh

set -eu

status=0

# fail_on PATTERN WHY: report tracked files matching an extended regular
# expression, case-insensitively. This script and CONTRIBUTING.md name the
# patterns, so they are skipped.
fail_on() {
	matches="$(git grep -n -I -i -E "$1" -- . ':!scripts/check-content.sh' ':!CONTRIBUTING.md' || true)"
	if [ -n "$matches" ]; then
		printf '::error::%s\n%s\n\n' "$2" "$matches"
		status=1
	fi
}

fail_on 'CIS (Benchmark|Controls|Critical Security Controls)|cisecurity\.org|Center for Internet Security' \
	"CIS Benchmark material is licensed for internal use only. Write controls in our own words from public-domain sources (DISA STIG, NIST), and don't name CIS."
fail_on 'Copyright \(c\) [0-9]{4} (Center|International Organization for Standardization|PCI Security Standards Council)|© *(ISO|PCI SSC|CIS)' \
	"A copyright notice of a standards body: quote requirement numbers and short titles in our own words, never the standard's text."
fail_on 'GNU (Affero )?General Public License|SPDX-License-Identifier: *(A?GPL|LGPL|SSPL|BUSL)' \
	"Code under a copyleft or source-available licence can't be copied into an MIT project."

if [ "$status" -eq 0 ]; then
	echo "No restricted third-party content found."
fi
exit "$status"
