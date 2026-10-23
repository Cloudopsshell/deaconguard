#!/bin/sh
# DeaconGuard installer: https://deaconguard.io
# Documentation: https://docs.deaconguard.io/installation/install-script
#
# get.deaconguard.io serves this file from the main branch as soon as it is
# merged, and it installs the latest release: keep it working with that
# release's packages.
#
# It installs a system package and service, so it runs as root:
#
# Server:
#   curl -fsSL https://get.deaconguard.io | sudo sh -
# Agent, with the enrollment token from the server's Agents page (-E passes the
# token to sudo without putting it on a command line other users can see):
#   curl -fsSL https://get.deaconguard.io | DEACONGUARD_TOKEN=deaconguard1.... sudo -E sh -
#
# On a Mac it installs the agent only, as the launchd daemon
# io.deaconguard.agent, from the release's macOS archive.
#
# Without a token it sets up a server, or upgrades the agent on a machine that
# is already enrolled. Started without root, it stops before doing anything
# and shows the command to use; it never asks for a password itself.
#
# It installs what DeaconGuard's checks use, from the distribution's own
# repositories: procps, iproute2, findutils, needs-restarting (RHEL family and
# Fedora) and ClamAV with its signature updater (on RHEL and its rebuilds, from
# EPEL, which it enables).
# It installs YARA-X (yr), for the advanced antivirus scan, and cosign, to
# verify releases, each pinned to a version and checksum.
# Then it downloads this machine's .deb or .rpm package from a GitHub release,
# verifies that checksums.txt was signed by this repository's release workflow
# and that the package matches it, installs the package, and runs
# `deaconguard setup server` or `deaconguard setup agent`. Run it again to
# upgrade. DeaconGuard is not installed when a check fails.
#
# Everything is inside main, which runs on the last line, so a download cut
# short runs nothing.

set -eu

REPOSITORY="https://github.com/Cloudopsshell/deaconguard"

# The release workflow that signs checksums.txt, for cosign verify-blob.
SIGNER="$REPOSITORY/.github/workflows/release.yml"
SIGNER_ISSUER="https://token.actions.githubusercontent.com"

# cosign, installed to /usr/local/bin when missing. The checksums are from the
# release's cosign_checksums.txt; update all three together.
COSIGN_VERSION="3.1.3"
COSIGN_SHA256_AMD64="4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71"
COSIGN_SHA256_ARM64="c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a"
COSIGN_SHA256_DARWIN_AMD64="2347488e5d5b25336644024dfeca5601b190e91197a71a917bda44744aff106c"
COSIGN_SHA256_DARWIN_ARM64="5cf948c2f4dfe59687bdd0b8523709067383e03982cc543475c8a7dc70e92a76"

# YARA-X, the engine of the advanced antivirus scan, installed to
# /usr/local/bin. Its releases publish no checksums, so these are of the
# reviewed downloads; update all three together.
YARA_X_VERSION="1.21.0"
YARA_X_SHA256_AMD64="01585181e8979e36ac10ab123fcf8921cf8ba879bf942916413e091e18d64852"
YARA_X_SHA256_ARM64="8d56947d82c7959a65fd4a7327d339d326649f6208c01c9f7fe7fd249e61c66a"

usage() {
	cat <<'EOF'
Usage: install.sh [--server | --agent] [--version VERSION] [SETUP OPTIONS]

  (no option)         a server, or an agent when DEACONGUARD_TOKEN is set or
                      this machine is already an enrolled agent
  --server            install and start the DeaconGuard server, and an agent
                      that scans this machine as root (--no-agent to skip it)
  --agent             install, enroll, and start the agent; asks for the token
                      unless DEACONGUARD_TOKEN is set
  --version VERSION   install this release, such as 1.0.0; default: the latest

Environment: DEACONGUARD_TOKEN (the agent's enrollment token) and
DEACONGUARD_VERSION (same as --version).

Setup options are passed to `deaconguard setup server` or `deaconguard setup agent`:
  server: --listen ADDRESS:PORT  --agent-listen ADDRESS:PORT|off (default 0.0.0.0:8444)  --tls-cert FILE --tls-key FILE
          --admin-user NAME  --admin-password-file FILE
          --no-agent (do not scan this machine as root)  --with-agent
  agent:  --token-file FILE  --force

Run it as root, for example with sudo:
  Server:  curl -fsSL https://get.deaconguard.io | sudo sh -
  Agent:   curl -fsSL https://get.deaconguard.io | DEACONGUARD_TOKEN=<token> sudo -E sh -
EOF
}

ok() { printf '  \342\234\223 %s\n' "$*"; }
fail() {
	printf '\ndeaconguard install: %s\n' "$*" >&2
	exit 1
}

# install_dependencies installs, from the distribution's signed repositories,
# the tools DeaconGuard's checks run, and ClamAV with its signature updater.
# Packages that are already installed are left as they are.
install_dependencies() {
	if [ "$format" = "deb" ]; then
		packages="procps iproute2 findutils clamav clamav-freshclam"
		# DeaconGuard runs clamscan and needs no ClamAV daemon, so tell the
		# updater not to notify one; otherwise it logs an error after each update.
		printf 'clamav-freshclam clamav-freshclam/NotifyClamd boolean false\n' | debconf-set-selections 2>/dev/null || true
		# shellcheck disable=SC2086 # the package list splits into words on purpose
		{
			apt-get update -q &&
				DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends $packages
		} >"$work/dependencies.log" 2>&1 ||
			{ cat "$work/dependencies.log" >&2; fail "apt-get could not install the dependencies ($packages)"; }
	elif [ "$rpm_installer" = "zypper" ]; then
		# SUSE has ClamAV in its own repositories, and marks a pending reboot
		# itself, so needs no needs-restarting.
		packages="procps iproute2 findutils tar gzip clamav"
		# shellcheck disable=SC2086 # the package list splits into words on purpose
		zypper --non-interactive --quiet install --no-recommends $packages >"$work/dependencies.log" 2>&1 ||
			{ cat "$work/dependencies.log" >&2; fail "zypper could not install the dependencies ($packages)"; }
	else
		# ClamAV is in EPEL on RHEL and its rebuilds; Amazon Linux and Fedora have
		# it. Decide by ID: rebuilds list "fedora" in ID_LIKE too.
		# shellcheck disable=SC1091
		os_id="$(. /etc/os-release && printf '%s' "$ID")"
		# shellcheck disable=SC1091
		os_major="$(. /etc/os-release && printf '%s' "${VERSION_ID%%.*}")"
		case "$os_id" in
		amzn | fedora) ;;
		*)
			if ! rpm -q epel-release oracle-epel-release-el"$os_major" 2>/dev/null | grep -qv 'not installed'; then
				# Rocky and AlmaLinux carry epel-release, Oracle Linux its own
				# oracle-epel-release; plain RHEL installs it from the Fedora
				# project, signed with the EPEL key.
				epel="epel-release"
				case "$os_id" in
				rhel) epel="https://dl.fedoraproject.org/pub/epel/epel-release-latest-$os_major.noarch.rpm" ;;
				ol) epel="oracle-epel-release-el$os_major" ;;
				esac
				"$rpm_installer" install -y -q "$epel" >"$work/epel.log" 2>&1 ||
					{ cat "$work/epel.log" >&2; fail "could not enable EPEL, which provides ClamAV on $os_name"; }
				ok "Enabled EPEL (it provides ClamAV on $os_name)"
			fi
			;;
		esac
		# File paths, because package names differ between releases.
		packages="procps-ng iproute findutils tar gzip /usr/bin/needs-restarting /usr/bin/clamscan /usr/bin/freshclam"
		# shellcheck disable=SC2086 # the package list splits into words on purpose
		"$rpm_installer" install -y -q $packages >"$work/dependencies.log" 2>&1 ||
			{ cat "$work/dependencies.log" >&2; fail "$rpm_installer could not install the dependencies ($packages)"; }
	fi
	ok "Dependencies installed: procps, iproute2, findutils, ClamAV$([ "$format" = "rpm" ] && [ "$rpm_installer" != "zypper" ] && printf ', needs-restarting')"
}

# start_signature_updates switches on ClamAV's signature updater, which the
# packages install but leave off. It downloads the signatures in the
# background, then checks for new ones several times a day.
start_signature_updates() {
	# SUSE runs freshclam from a timer instead of a service.
	unit="clamav-freshclam.service"
	[ "${rpm_installer:-}" = "zypper" ] && unit="freshclam.timer"
	if systemctl enable --now "$unit" >"$work/freshclam.log" 2>&1; then
		ok "ClamAV signature updates on (${unit%.*}; the first download runs in the background)"
	else
		printf '  ! ClamAV signature updates could not be switched on; see: systemctl status %s\n' "$unit"
	fi
}

# install_cosign installs cosign to /usr/local/bin unless it is already on the
# PATH, checking the download against the pinned checksum.
install_cosign() {
	if command -v cosign >/dev/null 2>&1; then
		ok "cosign $(cosign version 2>/dev/null | awk '/GitVersion/{print $2}') found"
		return
	fi
	case "$system-$arch" in
	linux-amd64) expected_cosign="$COSIGN_SHA256_AMD64" ;;
	linux-arm64) expected_cosign="$COSIGN_SHA256_ARM64" ;;
	darwin-amd64) expected_cosign="$COSIGN_SHA256_DARWIN_AMD64" ;;
	darwin-arm64) expected_cosign="$COSIGN_SHA256_DARWIN_ARM64" ;;
	esac
	url="https://github.com/sigstore/cosign/releases/download/v$COSIGN_VERSION/cosign-$system-$arch"
	curl -fsSL --proto '=https' --tlsv1.2 -o "$work/cosign" "$url" || fail "could not download cosign from $url"
	[ "$(sha256 "$work/cosign")" = "$expected_cosign" ] ||
		fail "the cosign download does NOT match its pinned checksum. Nothing was installed"
	install -m 0755 "$work/cosign" /usr/local/bin/cosign
	ok "Installed cosign $COSIGN_VERSION to /usr/local/bin (verifies release signatures)"
}

# install_yara_x installs YARA-X's yr to /usr/local/bin, checking the download
# against the pinned checksum. It replaces an older yr there, and leaves alone
# one installed elsewhere, such as by a package.
install_yara_x() {
	found="$(command -v yr 2>/dev/null || true)"
	if [ -n "$found" ] && [ "$found" != /usr/local/bin/yr ]; then
		ok "YARA-X $(yr --version 2>/dev/null | awk '{print $NF}') found at $found"
		return
	fi
	if [ "$(/usr/local/bin/yr --version 2>/dev/null | awk '{print $NF}')" = "$YARA_X_VERSION" ]; then
		ok "YARA-X $YARA_X_VERSION found"
		return
	fi
	case "$arch" in
	amd64) expected_yara_x="$YARA_X_SHA256_AMD64" target="x86_64-unknown-linux-gnu" ;;
	arm64) expected_yara_x="$YARA_X_SHA256_ARM64" target="aarch64-unknown-linux-gnu" ;;
	esac
	url="https://github.com/VirusTotal/yara-x/releases/download/v$YARA_X_VERSION/yara-x-v$YARA_X_VERSION-$target.tar.gz"
	curl -fsSL --proto '=https' --tlsv1.2 -o "$work/yara-x.tar.gz" "$url" || fail "could not download YARA-X from $url"
	[ "$(sha256sum "$work/yara-x.tar.gz" | cut -d' ' -f1)" = "$expected_yara_x" ] ||
		fail "the YARA-X download does NOT match its pinned checksum. Nothing was installed"
	mkdir "$work/yara-x"
	tar -xzf "$work/yara-x.tar.gz" -C "$work/yara-x" yr || fail "could not unpack YARA-X"
	install -m 0755 "$work/yara-x/yr" /usr/local/bin/yr
	ok "Installed YARA-X $YARA_X_VERSION to /usr/local/bin (the advanced antivirus scan)"
}

# sha256 prints a file's SHA-256: sha256sum on Linux, shasum on a Mac.
sha256() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | cut -d' ' -f1
	else
		shasum -a 256 "$1" | cut -d' ' -f1
	fi
}

# find_version sets version to the latest release, unless one was given.
find_version() {
	if [ -z "$version" ]; then
		latest="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "$REPOSITORY/releases/latest")" ||
			fail "could not reach GitHub to find the latest release"
		version="${latest##*/tag/v}"
	fi
	case "$version" in
	"" | *[!0-9A-Za-z.-]* | */*) fail "could not determine the release to install; pass --version, such as --version 1.0.0" ;;
	esac
	ok "Release v$version"
}

# download_verified downloads checksums.txt, its signature and the file
# named, checks the signature with cosign and the file against checksums.txt.
download_verified() {
	base="$REPOSITORY/releases/download/v$version"
	for file in checksums.txt checksums.txt.sigstore.json "$1"; do
		curl -fsSL --proto '=https' --tlsv1.2 -o "$work/$file" "$base/$file" ||
			fail "could not download $base/$file"
	done
	chmod 0644 "$work/$1"
	ok "Downloaded $1"

	cosign verify-blob "$work/checksums.txt" --bundle "$work/checksums.txt.sigstore.json" \
		--certificate-identity "$SIGNER@refs/tags/v$version" \
		--certificate-oidc-issuer "$SIGNER_ISSUER" >"$work/cosign.log" 2>&1 ||
		{ cat "$work/cosign.log" >&2; fail "the signature of checksums.txt for v$version is NOT valid. DeaconGuard was not installed. Report this: $REPOSITORY/security"; }
	ok "Signature valid (signed by the release workflow for v$version)"

	expected="$(awk -v name="$1" '$2 == name || $2 == "*" name { print $1 }' "$work/checksums.txt")"
	[ -n "$expected" ] || fail "checksums.txt for v$version does not list $1"
	[ "$expected" = "$(sha256 "$work/$1")" ] || fail "the checksum of $1 does NOT match the release's checksums.txt. DeaconGuard was not installed"
	ok "Checksum valid"
}

# shellcheck disable=SC2120 # "$@" is the setup options, set inside.
# install_mac installs the agent on a Mac: the binary from the release's
# macOS archive to /usr/local/bin, then `deaconguard setup agent`, which
# enrolls the Mac and starts the launchd daemon. ClamAV and YARA-X aren't
# installed: those scans are for Linux.
install_mac() {
	[ "$mode" != "server" ] || fail "on a Mac, the installer sets up the agent only. Run the server on Linux, in Docker or in Kubernetes, or run deaconguard serve from the macOS archive: $REPOSITORY/releases"
	if [ -z "$token" ] && [ "$mode" != "agent" ] && [ ! -f /etc/deaconguard/agent.json ]; then
		fail "this Mac isn't enrolled yet: pass the enrollment token from the server's Agents page, or --agent to paste it when asked:
  curl -fsSL https://get.deaconguard.io | DEACONGUARD_TOKEN=<your token> sudo -E sh -"
	fi
	mode="agent"
	for tool in curl shasum tar; do
		command -v "$tool" >/dev/null 2>&1 || fail "$tool is required"
	done
	ok "macOS $(sw_vers -productVersion), $arch"
	ok "Mode: agent"
	find_version

	work="$(mktemp -d /tmp/deaconguard-install.XXXXXX)"
	trap 'rm -rf "$work"' EXIT
	trap 'exit 130' INT TERM
	install_cosign
	archive="deaconguard_${version}_darwin_${arch}.tar.gz"
	download_verified "$archive"
	tar -xzf "$work/$archive" -C "$work" deaconguard || fail "could not unpack $archive"
	mkdir -p /usr/local/bin
	install -m 0755 -o root -g wheel "$work/deaconguard" /usr/local/bin/deaconguard
	ok "Installed $(/usr/local/bin/deaconguard version | cut -d' ' -f1-2) to /usr/local/bin"
	/usr/local/bin/deaconguard help 2>/dev/null | grep -q "deaconguard setup agent" ||
		fail "DeaconGuard v$version predates the macOS agent; install 1.8.0 or later"
	printf '\n'
	if [ -n "$token" ]; then
		(umask 077 && printf '%s\n' "$token" >"$work/token")
		setup_options="$setup_options --token-file $(quote "$work/token")"
	fi
	eval "set -- $setup_options"
	/usr/local/bin/deaconguard setup agent "$@" </dev/null
}

# quote prints its argument as a single-quoted shell word, for eval.
quote() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }

main() {
	mode=""
	version="${DEACONGUARD_VERSION:-}"
	version="${version#v}"
	token="${DEACONGUARD_TOKEN:-}"
	# The token goes to setup in a private file, not through the environment.
	unset DEACONGUARD_TOKEN
	setup_options=""
	while [ $# -gt 0 ]; do
		case "$1" in
		--server | --agent)
			[ -z "$mode" ] || fail "choose either --server or --agent"
			mode="${1#--}"
			;;
		--version)
			[ $# -ge 2 ] || fail "--version needs a version, such as 1.0.0"
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
			fail "pass the token as DEACONGUARD_TOKEN=... before sh, not as an argument, which every user on this machine can see"
			;;
		*)
			setup_options="$setup_options $(quote "$1")"
			;;
		esac
		shift
	done
	printf 'DeaconGuard installer\n'
	case "$(uname -s)" in
	Linux) system="linux" ;;
	Darwin) system="darwin" ;;
	*) fail "the installer supports Linux and macOS; on other systems, download a release archive from $REPOSITORY/releases" ;;
	esac

	# Installing a package and a service needs root. Say so plainly instead of
	# asking for a password part-way through.
	if [ "$(id -u)" -ne 0 ]; then
		if [ -n "$token" ] || [ "$mode" = "agent" ] || [ "$system" = "darwin" ]; then
			example="curl -fsSL https://get.deaconguard.io | DEACONGUARD_TOKEN=<your token> sudo -E sh -"
		else
			example="curl -fsSL https://get.deaconguard.io | sudo sh -"
		fi
		printf '\nThe installer needs root: it installs a system package and a service.\nRun it again with sudo (or as root, without sudo):\n\n  %s\n\nNothing was installed.\n' "$example" >&2
		exit 1
	fi

	case "$(uname -m)" in
	x86_64 | amd64) arch="amd64" ;;
	aarch64 | arm64) arch="arm64" ;;
	*) fail "unsupported processor $(uname -m); DeaconGuard supports amd64 and arm64" ;;
	esac
	if [ "$system" = "darwin" ]; then
		install_mac
		return
	fi

	if [ -n "$token" ]; then
		[ "$mode" != "server" ] || fail "DEACONGUARD_TOKEN enrolls an agent; leave it out to install a server"
		mode="agent"
	elif [ -z "$mode" ]; then
		mode="server"
		# Upgrading an agent must not turn it into a server. A server's own
		# machine has an agent too, and its server data says it is a server.
		if [ -f /etc/deaconguard/agent.json ] && [ ! -f /var/lib/deaconguard/deaconguard.db ]; then
			mode="agent"
		fi
	fi

	[ -d /run/systemd/system ] || fail "DeaconGuard's services need systemd, which is not running on this machine"
	for tool in curl sha256sum; do
		command -v "$tool" >/dev/null 2>&1 || fail "$tool is required; install it with your package manager and run the installer again"
	done

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
	*" suse "*)
		format="rpm"
		rpm_installer="zypper"
		command -v zypper >/dev/null 2>&1 || fail "zypper is missing on $os_name"
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
		fail "$os_name is not supported. DeaconGuard supports Ubuntu, Debian, RHEL, Rocky Linux, AlmaLinux, Oracle Linux, Fedora, openSUSE Leap, SUSE Linux Enterprise, and Amazon Linux 2023"
		;;
	esac
	if [ "$mode" = "agent" ]; then
		# The server runs on any of these families, but an agent can only scan
		# the distributions DeaconGuard has advisories for.
		# shellcheck disable=SC1091
		os_id="$(. /etc/os-release && printf '%s %s' "${ID:-}" "${VERSION_ID:-}")"
		case "$os_id" in
		"ubuntu "* | "debian "* | "rhel "* | "amzn 2023"*) ;;
		"rocky "[89]* | "rocky 10"* | "almalinux "[89]* | "almalinux 10"* | "ol "[89]* | "ol 10"*) ;;
		"fedora "[4-9][0-9]* | "opensuse-leap 15.6" | "opensuse-leap 16."* | "sles 15."[6-9] | "sles 16"* | "sled 15."[6-9] | "sled 16"*) ;;
		*) fail "DeaconGuard cannot scan $os_name. Agents support Ubuntu LTS, Debian 12 and 13, RHEL 8 and 9, Rocky Linux, AlmaLinux and Oracle Linux 8 to 10, Fedora 40 and later, openSUSE Leap 15.6 and 16, SUSE Linux Enterprise 15 SP6 and later, and Amazon Linux 2023" ;;
		esac
	fi
	ok "$os_name, $arch"
	if [ "$mode" = "agent" ]; then
		ok "Mode: agent"
	else
		ok "Mode: server"
	fi

	find_version

	work="$(mktemp -d /tmp/deaconguard-install.XXXXXX)"
	trap 'rm -rf "$work"' EXIT
	trap 'exit 130' INT TERM
	# apt reads local packages as its own unprivileged user.
	chmod 0755 "$work"

	install_dependencies
	install_yara_x
	install_cosign

	package="deaconguard_${version}_linux_${arch}.${format}"
	download_verified "$package"

	if [ "$format" = "deb" ]; then
		DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$work/$package" >"$work/install.log" 2>&1 ||
			{ cat "$work/install.log" >&2; fail "apt-get could not install $package"; }
	elif [ "$rpm_installer" = "zypper" ]; then
		# The package is unsigned: cosign verified the checksums it matches.
		zypper --non-interactive --quiet install --allow-unsigned-rpm "$work/$package" >"$work/install.log" 2>&1 ||
			{ cat "$work/install.log" >&2; fail "zypper could not install $package"; }
	else
		"$rpm_installer" install -y -q "$work/$package" >"$work/install.log" 2>&1 ||
			{ cat "$work/install.log" >&2; fail "$rpm_installer could not install $package"; }
	fi
	ok "Installed $(/usr/bin/deaconguard version | cut -d' ' -f1-2)"
	start_signature_updates
	/usr/bin/deaconguard help 2>/dev/null | grep -q "deaconguard setup $mode" ||
		fail "DeaconGuard v$version predates this installer; install 0.2.0 or later, or follow the manual steps in the README"
	printf '\n'

	if [ -n "$token" ]; then
		(umask 077 && printf '%s\n' "$token" >"$work/token")
		setup_options="$setup_options --token-file $(quote "$work/token")"
	fi
	# Prompts read from the terminal, not from this script on standard input.
	eval "set -- $setup_options"
	/usr/bin/deaconguard setup "$mode" "$@" </dev/null
}

main "$@"
