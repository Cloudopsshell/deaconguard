---
title: Manual install
description: Install the DeaconGuard package or binary yourself.
---

Each release on the [Releases page](https://github.com/Cloudopsshell/deaconguard/releases) has `.deb` and `.rpm` packages, Linux and macOS archives, `install.sh`, `checksums.txt` and its [Sigstore signature](../security/verify-a-release.md). Downloads need no GitHub account. The `.deb` and `.rpm` packages depend on `ca-certificates` (and the `.rpm` recommends `ca-certificates-mozilla` for SUSE), so the server can verify the advisory feeds' HTTPS certificates even on a minimal system; with an archive, install your distribution's CA bundle yourself.

The commands below install the latest release: `get.deaconguard.io/stable.txt` holds its version, currently `@RELEASE@`. To install another release, set `VERSION` yourself, for example `VERSION=@RELEASE@`. After installing a package, run `sudo deaconguard setup server` or `sudo deaconguard setup agent`. To check a download before installing it, see [Verify the download](#verify-the-download).

## Debian and Ubuntu

```bash
VERSION=$(curl -fsSL https://get.deaconguard.io/stable.txt)
ARCH=$(dpkg --print-architecture)
cd /tmp
curl -fsSLO "https://github.com/Cloudopsshell/deaconguard/releases/download/v${VERSION}/deaconguard_${VERSION}_linux_${ARCH}.deb"
sudo apt install "./deaconguard_${VERSION}_linux_${ARCH}.deb"
deaconguard version
```

## RHEL, Rocky Linux, AlmaLinux, Oracle Linux, Fedora and Amazon Linux

```bash
VERSION=$(curl -fsSL https://get.deaconguard.io/stable.txt)
ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
cd /tmp
curl -fsSLO "https://github.com/Cloudopsshell/deaconguard/releases/download/v${VERSION}/deaconguard_${VERSION}_linux_${ARCH}.rpm"
sudo dnf install "./deaconguard_${VERSION}_linux_${ARCH}.rpm"
deaconguard version
```

## openSUSE and SUSE Linux Enterprise

Download the `.rpm` as above, then install it with zypper. The package itself isn't signed, so [verify the download](#verify-the-download) first; the checksum vouches for it.

```bash
sudo zypper install --allow-unsigned-rpm "./deaconguard_${VERSION}_linux_${ARCH}.rpm"
```

## Other Linux systems and macOS

The archive contains only the binary; there are no services. Use [local mode](../usage/local-mode.md), or run the server in the foreground.

```bash
VERSION=$(curl -fsSL https://get.deaconguard.io/stable.txt)
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
cd /tmp
curl -fsSLO "https://github.com/Cloudopsshell/deaconguard/releases/download/v${VERSION}/deaconguard_${VERSION}_${OS}_${ARCH}.tar.gz"
tar -xzf "deaconguard_${VERSION}_${OS}_${ARCH}.tar.gz" deaconguard
sudo install -m 0755 deaconguard /usr/local/bin/deaconguard
deaconguard version
```

## Verify the download

Optional, and recommended. The [install script](./install-script.md) always does this for you. Before installing a file you downloaded yourself, in the same directory and shell:

```bash
curl -fsSLO "https://github.com/Cloudopsshell/deaconguard/releases/download/v${VERSION}/checksums.txt"
sha256sum --check --ignore-missing checksums.txt   # macOS: shasum -a 256 --check --ignore-missing checksums.txt
```

`OK` means the file matches the release's checksum list. To also check that the list itself came from DeaconGuard's release workflow, verify its Sigstore signature: see [Verify a release](../security/verify-a-release.md).

macOS builds are not yet signed by Apple. If macOS blocks the first run, allow it with `xattr -d com.apple.quarantine /usr/local/bin/deaconguard`.

## From source

Requires Go 1.26 or later and, for the web UI, Node.js 24 with npm.

```bash
git clone https://github.com/Cloudopsshell/deaconguard.git && cd deaconguard
make build
./deaconguard version
```
