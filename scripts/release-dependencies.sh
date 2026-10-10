#!/bin/sh
# Prints the "Dependencies" section of a release's notes, in Markdown: what the
# release was built with, read from go.mod, web/package-lock.json and the Go
# toolchain, and what packaging/install.sh installs on each machine. It fails
# when a package named here is missing from install.sh, so the table cannot
# drift from the script. Run from the repository root, after Go and Node.js are
# set up.
set -eu

script=packaging/install.sh

# module prints a Go module's version from go.mod.
module() { awk -v name="$1" '$1 == name { print $2; exit }' go.mod; }

# web prints the version npm installed for a web UI package.
web() {
	node -e 'const lock = require("./web/package-lock.json"); console.log(lock.packages["node_modules/" + process.argv[1]].version)' "$1"
}

# Every word of install.sh's package lists, without /usr/bin/ for file paths.
listed="$(sed -n 's/^[[:space:]]*packages="\(.*\)"$/\1/p' "$script" | tr ' ' '\n' | sed 's#^/usr/bin/##')"

# installed fails unless install.sh installs package.
installed() {
	printf '%s\n' "$listed" | grep -qx "$1" ||
		{ echo "release-dependencies.sh: $script does not install $1; update this table" >&2; exit 1; }
}

for package in procps iproute2 findutils clamav clamav-freshclam procps-ng iproute needs-restarting clamscan freshclam; do
	installed "$package"
done
cosign="$(sed -n 's/^COSIGN_VERSION="\(.*\)"$/\1/p' "$script")"
[ -n "$cosign" ] || { echo "release-dependencies.sh: COSIGN_VERSION not found in $script" >&2; exit 1; }

cat <<EOF

## Dependencies

DeaconGuard is one statically linked binary: it needs no libraries on the machine. The release was built with:

| Component | Version |
| --- | --- |
| Go | $(go env GOVERSION | sed 's/^go//') |
| SQLite driver (\`modernc.org/sqlite\`) | $(module modernc.org/sqlite) |
| \`golang.org/x/net\` | $(module golang.org/x/net) |
| \`golang.org/x/term\` | $(module golang.org/x/term) |
| React (web UI) | $(web react) |
| React Router (web UI) | $(web react-router) |
| TanStack Query (web UI) | $(web @tanstack/react-query) |

The install script (\`curl -fsSL https://get.deaconguard.io | sudo sh -\`) installs these on every server and agent, from the distribution's own signed repositories at the version the distribution currently ships:

| For | Debian, Ubuntu | RHEL 8/9, Amazon Linux 2023 |
| --- | --- | --- |
| Malware check (\`ps\`, \`find\`) | \`procps\`, \`findutils\` | \`procps-ng\`, \`findutils\` |
| Security configuration check (\`ss\`) | \`iproute2\` | \`iproute\` |
| Pending-reboot check | (not needed) | \`needs-restarting\` (\`dnf-utils\` / \`yum-utils\`) |
| Antivirus check | \`clamav\`, \`clamav-freshclam\` (signature updates switched on) | \`clamav\`, \`clamav-freshclam\` / \`clamav-update\`; on RHEL from EPEL, which the script enables |
| Release signature check | cosign $cosign, downloaded from Sigstore's GitHub release and checked against a pinned checksum | the same |

Every dependency of the binary and the web UI, with versions and licenses, is listed in the SBOM files attached to this release (SPDX JSON).
EOF
