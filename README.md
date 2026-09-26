# OpsArmor

OpsArmor is an agentless Linux package vulnerability scanner written in Go. Its local CLI connects only to hosts you register, collects a small read-only inventory over SSH without `sudo`, and evaluates it against the distribution's own security data. The matching and scan orchestration are OpsArmor code; no third-party scanner is installed or run.

## Requirements

- Go 1.26 or later to build from source.
- SSH access to the registered host and network access to the relevant official advisory feed.
- A remote account able to read `/etc/os-release`, the DPKG inventory or RPM inventory, and run `uname` plus the fixed inventory commands. No root privileges are required.

Build and run:

```sh
go build -o opsarmor ./cmd/opsarmor
./opsarmor host add ubuntu.example.com --username ubuntu --key-path ~/.ssh/id_ed25519
./opsarmor host list
./opsarmor scan HOST_ID
./opsarmor report REPORT_ID --json
./opsarmor host remove HOST_ID
```

For development, run `go test ./...` and `go vet ./...`.

## Linux packages and containers

Tagged releases build portable Linux archives plus `.deb` and RPM packages for `amd64` and `arm64`. Install the downloaded Debian package with `sudo apt install ./opsarmor_VERSION_linux_ARCH.deb` (or `sudo dpkg -i ...`), or the RPM with `sudo dnf install ./opsarmor_VERSION_linux_ARCH.rpm`. The standalone archive contains the `opsarmor` executable and this README.

The release workflow also publishes `ghcr.io/cloudopsshell/opsarmor:vVERSION` and `:latest` for `linux/amd64` and `linux/arm64`. After the first publish, set the GHCR package visibility to public if you intend anonymous downloads. For local testing, run `make docker-build`. A container can keep profiles, reports, feed cache, and host-key pins in a persistent volume while mounting SSH files read-only:

```sh
docker volume create opsarmor-data
docker run --rm -it \
	-v opsarmor-data:/data \
	-v "$HOME/.ssh:/ssh-keys:ro" \
	-v "$HOME/.ssh:/home/nonroot/.ssh:ro" \
	-e OPSARMOR_HOME=/data \
	ghcr.io/cloudopsshell/opsarmor:v0.1.0 \
	host add ubuntu.example.com --username ubuntu --key-path /ssh-keys/id_ed25519
```

Use the returned host ID with `scan` in another `docker run` using the same volume and mounts.

The Helm chart is an opt-in CronJob runner, not a dashboard service. It creates one scheduled scan per configured host. Supply host profiles, a pre-created Secret containing the private key files, and independently verified host keys; private keys are not stored in Helm values or ConfigMaps. See [the chart README](charts/opsarmor/README.md) and [example values](charts/opsarmor/values.example.yaml). Install locally with `helm upgrade --install opsarmor ./charts/opsarmor -n opsarmor --create-namespace -f my-values.yaml`.

To publish all release artifacts, push a version tag after the changes are in Git:

```sh
git tag v0.1.0
git push origin v0.1.0
```

GitHub Actions runs tests and vet, creates release binaries/packages and checksums, publishes the multi-architecture container, and attaches the versioned Helm chart to the GitHub Release. Local packaging checks are available via `make release-snapshot`, `make docker-build`, and `make helm-lint`.

On a first interactive scan, OpsArmor displays the SSH host-key fingerprint and requires typing `trust` before saving it. Compare the fingerprint with AWS or another trusted source first: this is trust-on-first-use and the fetched fingerprint is not independently authenticated. Subsequent key changes are rejected. Encrypted private keys prompt once per scan; passphrases are held only in memory. Non-interactive use should load credentials into `ssh-agent`. Only register systems you own or are authorized to scan.

Profiles, trusted host keys, reports, and cached advisory feeds use `~/.local/share/opsarmor/` with owner-only file permissions. Set `OPSARMOR_HOME` to use a different directory. Profiles and report JSON are compatible with the previous CLI format.

## Verified advisory coverage

- Ubuntu 18.04, 20.04, 22.04, 24.04, and 26.04 LTS: Canonical CVE OVAL package and running-kernel checks. Unsupported OVAL checks are listed, not treated as clean.
- Debian 12 (Bookworm) and 13 (Trixie): Debian Security Tracker package-source statuses and fixed versions.
- Amazon Linux 2023: ALAS RSS/bulletins and replacement RPM versions. Repository snapshots are immutable; AWS notes that bulletin pages and repository metadata can be temporarily inconsistent.
- Red Hat Enterprise Linux 8 and 9: Red Hat's official OVAL feeds. Unsupported OVAL checks are listed.

CentOS Stream 9/10 is recognized but deliberately rejected: the official repositories checked here publish no `updateinfo` metadata, and RHEL OVAL is not assumed to be compatible. RHEL 10 is not enabled because no official RHEL 10 feed was present in the verified Red Hat feed index. Amazon Linux 2, other RPM distributions, and end-of-life releases are not supported.

Reports cover the installed DPKG/RPM packages and the running kernel where the platform's feed supports it. They do not cover applications outside the system package manager, containers, services, open ports, cloud configuration, or hardening settings, and are not a claim that a machine is secure. Missing, invalid, stale-without-cache, or unsupported advisory data must not be interpreted as zero vulnerabilities.

OpsArmor is available under the MIT license. Advisory data remains the property and responsibility of its publishing distribution.
