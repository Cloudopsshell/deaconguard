#!/bin/sh
# DeaconGuard installer: https://github.com/Cloudopsshell/deaconguard
#
#   curl -fsSL https://github.com/Cloudopsshell/deaconguard/releases/latest/download/install.sh | sudo sh -s -- --server
#   curl -fsSL https://github.com/Cloudopsshell/deaconguard/releases/latest/download/install.sh | sudo sh -s -- --agent
#
# Downloads this machine's .deb or .rpm package from a GitHub release over
# HTTPS, checks its checksum against the release's checksums.txt, installs the
# package, and runs `deaconguard setup server` or `deaconguard setup agent`.
# When cosign is installed, it also verifies that checksums.txt was signed by
# this repository's release workflow. Run it again to upgrade. Nothing is
# installed when a check fails.
#
# Everything is inside main, which runs on the last line, so a download cut
# short runs nothing.

set -eu

REPOSITORY="https://github.com/Cloudopsshell/deaconguard"

# The release workflow that signs checksums.txt, for cosign verify-blob.
SIGNER="$REPOSITORY/.github/workflows/release.yml"
SIGNER_ISSUER="https://token.actions.githubusercontent.com"

usage() {
	cat <<'EOF'
Usage: install.sh --server | --agent [--version VERSION] [SETUP OPTIONS]

  --server            install and start the DeaconGuard server
  --agent             install, enroll, and start the agent; asks for the token
  --version VERSION   install this release, such as 0.2.0; default: the latest

Setup options are passed to `deaconguard setup server` or `deaconguard setup agent`:
  server: --listen ADDRESS:PORT  --tls-cert FILE --tls-key FILE
          --admin-user NAME  --admin-password-file FILE
  agent:  --token-file FILE  --force

Run it as root, for example:
  curl -fsSL https://github.com/Cloudopsshell/deaconguard/releases/latest/download/install.sh | sudo sh -s -- --agent
EOF
}

ok() { printf '  \342\234\223 %s\n' "$*"; }
fail() {
	printf '\ndeaconguard install: %s\n' "$*" >&2
	exit 1
}

# quote prints its argument as a single-quoted shell word, for eval.
quote() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }

main() {
	mode=""
	version=""
	setup_options=""
	while [ $# -gt 0 ]; do
		case "$1" in
		--server | --agent)
			[ -z "$mode" ] || fail "choose either --server or --agent"
			mode="${1#--}"
			;;
		--version)
			[ $# -ge 2 ] || fail "--version needs a version, such as 0.2.0"
			version="${2#v}"
			shift
			;;
		--version=*)
			version="${1#--version=}"
			version="${version#v}"
			;;
		-h | --help)
			usage
			exit 0
			;;
		deaconguard1.*)
			fail "do not pass the token on the command line, where other users and the shell history can see it; enter it when asked, or use --token-file FILE"
			;;
		*)
			setup_options="$setup_options $(quote "$1")"
			;;
		esac
		shift
	done
	if [ -z "$mode" ]; then
		usage >&2
		fail "choose --server or --agent"
	fi

	printf 'DeaconGuard installer\n'
	[ "$(uname -s)" = "Linux" ] || fail "the installer supports Linux; on other systems, download a release archive from $REPOSITORY/releases"
	if [ "$(id -u)" -ne 0 ]; then
		fail "run the installer as root: curl -fsSL $REPOSITORY/releases/latest/download/install.sh | sudo sh -s -- --$mode"
	fi
	[ -d /run/systemd/system ] || fail "DeaconGuard's services need systemd, which is not running on this machine"
	for tool in curl sha256sum; do
		command -v "$tool" >/dev/null 2>&1 || fail "$tool is required; install it with your package manager and run the installer again"
	done

	case "$(uname -m)" in
	x86_64 | amd64) arch="amd64" ;;
	aarch64 | arm64) arch="arm64" ;;
	*) fail "unsupported processor $(uname -m); DeaconGuard supports amd64 and arm64" ;;
	esac

	[ -r /etc/os-release ] || fail "cannot identify this Linux distribution: /etc/os-release is missing"
	# shellcheck disable=SC1091
	os_name="$(. /etc/os-release && printf '%s' "${PRETTY_NAME:-$ID}")"
	# shellcheck disable=SC1091
	os_family="$(. /etc/os-release && printf '%s %s' "${ID:-}" "${ID_LIKE:-}")"
	case " $os_family " in
	*" debian "* | *" ubuntu "*)
		format="deb"
		command -v apt-get >/dev/null 2>&1 || fail "apt-get is missing on $os_name"
		;;
	*" rhel "* | *" fedora "* | *" centos "* | *" amzn "*)
		format="rpm"
		if command -v dnf >/dev/null 2>&1; then
			rpm_installer="dnf"
		elif command -v yum >/dev/null 2>&1; then
			rpm_installer="yum"
		else
			fail "dnf or yum is required on $os_name"
		fi
		;;
	*)
		fail "$os_name is not supported. DeaconGuard supports Ubuntu, Debian, RHEL, and Amazon Linux 2023"
		;;
	esac
	if [ "$mode" = "agent" ]; then
		# The server runs on any of these families, but an agent can only scan
		# the distributions DeaconGuard has advisories for.
		# shellcheck disable=SC1091
		os_id="$(. /etc/os-release && printf '%s %s' "${ID:-}" "${VERSION_ID:-}")"
		case "$os_id" in
		"ubuntu "* | "debian "* | "rhel "* | "amzn 2023"*) ;;
		*) fail "DeaconGuard cannot scan $os_name. Agents support Ubuntu LTS, Debian 12 and 13, RHEL 8 and 9, and Amazon Linux 2023" ;;
		esac
	fi
	ok "$os_name, $arch"

	if [ -z "$version" ]; then
		latest="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "$REPOSITORY/releases/latest")" ||
			fail "could not reach GitHub to find the latest release"
		version="${latest##*/tag/v}"
	fi
	case "$version" in
	"" | *[!0-9A-Za-z.-]* | */*) fail "could not determine the release to install; pass --version, such as --version 0.2.0" ;;
	esac
	ok "Release v$version"

	work="$(mktemp -d /tmp/deaconguard-install.XXXXXX)"
	trap 'rm -rf "$work"' EXIT
	trap 'exit 130' INT TERM
	# apt reads local packages as its own unprivileged user.
	chmod 0755 "$work"

	package="deaconguard_${version}_linux_${arch}.${format}"
	base="$REPOSITORY/releases/download/v$version"
	for file in checksums.txt checksums.txt.sigstore.json "$package"; do
		curl -fsSL --proto '=https' --tlsv1.2 -o "$work/$file" "$base/$file" ||
			fail "could not download $base/$file"
	done
	chmod 0644 "$work/$package"
	ok "Downloaded $package"

	if command -v cosign >/dev/null 2>&1; then
		cosign verify-blob "$work/checksums.txt" --bundle "$work/checksums.txt.sigstore.json" \
			--certificate-identity "$SIGNER@refs/tags/v$version" \
			--certificate-oidc-issuer "$SIGNER_ISSUER" >"$work/cosign.log" 2>&1 ||
			{ cat "$work/cosign.log" >&2; fail "the signature of checksums.txt for v$version is NOT valid. Nothing was installed. Report this: $REPOSITORY/security"; }
		ok "Signature valid (signed by the release workflow for v$version)"
	fi

	expected="$(awk -v name="$package" '$2 == name || $2 == "*" name { print $1 }' "$work/checksums.txt")"
	actual="$(sha256sum "$work/$package" | cut -d' ' -f1)"
	[ -n "$expected" ] || fail "checksums.txt for v$version does not list $package"
	[ "$expected" = "$actual" ] || fail "the checksum of $package does NOT match the release's checksums.txt. Nothing was installed"
	ok "Checksum valid"
	command -v cosign >/dev/null 2>&1 ||
		printf '    (Install cosign to also verify the release signature: https://docs.sigstore.dev)\n'

	if [ "$format" = "deb" ]; then
		DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$work/$package" >"$work/install.log" 2>&1 ||
			{ cat "$work/install.log" >&2; fail "apt-get could not install $package"; }
	else
		"$rpm_installer" install -y -q "$work/$package" >"$work/install.log" 2>&1 ||
			{ cat "$work/install.log" >&2; fail "$rpm_installer could not install $package"; }
	fi
	ok "Installed $(/usr/bin/deaconguard version | cut -d' ' -f1-2)"
	/usr/bin/deaconguard help 2>/dev/null | grep -q "deaconguard setup $mode" ||
		fail "DeaconGuard v$version predates this installer; install 0.2.0 or later, or follow the manual steps in the README"
	printf '\n'

	# Prompts read from the terminal, not from this script on standard input.
	eval "set -- $setup_options"
	/usr/bin/deaconguard setup "$mode" "$@" </dev/null
}

main "$@"
