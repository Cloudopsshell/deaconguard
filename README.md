# OpsArmor

OpsArmor is an agentless Linux security scanner written in Go. It connects only to hosts you register, runs fixed read-only commands over SSH, and by default evaluates the installed packages against the distribution's own security data without `sudo`. Optional checks add system file integrity, malware and compromise indicators, security configuration, and ClamAV antivirus. The matching, checks, and scan orchestration are OpsArmor code; OpsArmor never installs software on a host, and the only third-party engine it runs is a ClamAV that is already installed there, when you choose the antivirus check.

## Requirements

- Go 1.26 or later to build from source.
- SSH access to the registered host and network access to the relevant official advisory feed.
- A remote account able to read `/etc/os-release`, the DPKG inventory or RPM inventory, and run `uname` plus the fixed inventory commands. No root privileges are required; the optional checks see more when sudo is allowed for the host.

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

## Checks

Each scan runs the checks you choose, in the web UI's scan dialog or with `opsarmor scan HOST_ID --checks packages,integrity,malware,config,antivirus`. Package vulnerabilities is the default.

| Check | What it does | Commands |
|---|---|---|
| Package vulnerabilities | Compares installed packages and the running kernel with official advisories (see below). | `/etc/os-release`, the DPKG status file or `rpm -qa`, `uname -r` |
| System file integrity | Verifies packaged files against the package manager's checksums. Changed binaries and libraries, a classic rootkit sign, are reported; edited configuration files are counted but not reported. | `dpkg --verify` or `rpm -Va` |
| Malware & compromise indicators | Looks for crypto-miner processes, programs running from `/tmp`, `/dev/shm`, memory, or deleted files, programs disguised as kernel threads, `/etc/ld.so.preload`, hidden executables in temporary directories, and download-and-execute or reverse-shell patterns in cron and systemd. This is not a complete antivirus scan. | `/proc`, `ps`, `find` on temporary directories, cron and systemd files |
| Security configuration | Reports SSH root or password login, empty passwords, X11 forwarding, risky services such as Redis, databases, Telnet, or the Docker API listening on all interfaces, pending reboots, disabled automatic updates, and, with sudo, a missing host firewall. | sshd configuration, `ss`/`netstat`, reboot and update settings, firewall rules |
| Antivirus (ClamAV) | Runs the host's own `clamscan` at low priority on temporary, home, and application directories and reports detections and signatures older than 7 days. Skipped when ClamAV is not installed. ClamAV uses about 1 GB of memory while it runs. | `clamscan` |

Every command is a fixed string in OpsArmor's source; nothing from the user or the host is inserted into it.

By default checks run as the SSH user, which cannot see other users' processes, protected files, or firewall rules; results then say they have partial coverage. Allow sudo for a host (`--allow-sudo` when adding it, `opsarmor host sudo HOST_ID on`, or the switch on the host page) to run the same read-only commands through `sudo`. If sudo needs a password, the UI or terminal asks for it once per scan and keeps it in memory only; declining continues the scan without sudo. A skipped or failed check is never shown as clean.

## Web UI

`opsarmor serve` starts a local dashboard at http://127.0.0.1:7480 (change the port with `--listen 127.0.0.1:PORT`). It shows every registered host, a severity overview, full scan reports with search and filters, scan history, and which hosts are affected by each CVE. Hosts can be added, removed, and scanned from the browser; the CLI and the UI share the same data.

The server only listens on a loopback address and rejects requests addressed to other host names or sent from other websites. While a scan runs, a host's page shows a live console with each step, every fixed command OpsArmor runs on the host (marked when it goes through sudo), how long each took, and findings as each check completes; it never shows command output or credentials. The console opens when a scan starts from that page and shrinks to a status pill that stays while the scan is running. A finished scan's pill disappears when you leave or reload the page. Each scan's activity log is saved with its results, so **View logs** in the scan history replays it later. The log is served at `/api/scans/SCAN_ID/events?after=SEQ`.

When a scan needs something from you, it pauses and the browser asks: to approve a new host's SSH key fingerprint (compare it with a trusted source first), for the passphrase of an encrypted key that `ssh-agent` does not already hold, or for the SSH password when the server rejects the keys and accepts passwords. Answers go to that one scan, are kept in memory only until the connection is made, and are never saved or logged. A wrong passphrase or password can be retried up to three times; closing the dialog cancels the scan, and an unanswered question stops the scan after 10 minutes. The CLI asks the same questions in the terminal.

`make build` builds the React UI (Node.js 24 and npm required) and embeds it in the binary. A plain `go build` still works without Node.js; the binary then explains that the UI was not built. To work on the UI with hot reload, run `./opsarmor serve` and, in a second terminal, `make ui-dev`, then open http://localhost:5173. The UI source is in [web/](web/) and uses React, TypeScript, Vite, Tailwind CSS, TanStack Query, and React Router.

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

On a first interactive scan, OpsArmor displays the SSH host-key fingerprint and requires typing `trust` before saving it. Compare the fingerprint with AWS or another trusted source first: this is trust-on-first-use and the fetched fingerprint is not independently authenticated. Subsequent key changes are rejected. Encrypted private keys prompt once per scan, and hosts that accept passwords prompt for one when key authentication fails; both are held only in memory. Non-interactive use should load credentials into `ssh-agent`. Only register systems you own or are authorized to scan.

Host profiles and scan history are stored in a SQLite database, `opsarmor.db`, in `~/.local/share/opsarmor/`, next to the trusted host keys and cached advisory feeds, all with owner-only file permissions. Set `OPSARMOR_HOME` to use a different directory. On first use, `hosts.json` and `reports/*.json` from earlier releases are imported once and left in place; report JSON printed by `opsarmor report --json` keeps the previous format.

## Verified advisory coverage

- Ubuntu 18.04, 20.04, 22.04, 24.04, and 26.04 LTS: Canonical CVE OVAL package and running-kernel checks. Unsupported OVAL checks are listed, not treated as clean.
- Debian 12 (Bookworm) and 13 (Trixie): Debian Security Tracker package-source statuses and fixed versions.
- Amazon Linux 2023: ALAS RSS/bulletins and replacement RPM versions. Repository snapshots are immutable; AWS notes that bulletin pages and repository metadata can be temporarily inconsistent.
- Red Hat Enterprise Linux 8 and 9: Red Hat's official OVAL feeds. Unsupported OVAL checks are listed.

CentOS Stream 9/10 is recognized but deliberately rejected: the official repositories checked here publish no `updateinfo` metadata, and RHEL OVAL is not assumed to be compatible. RHEL 10 is not enabled because no official RHEL 10 feed was present in the verified Red Hat feed index. Amazon Linux 2, other RPM distributions, and end-of-life releases are not supported.

Package reports cover the installed DPKG/RPM packages and the running kernel where the platform's feed supports it; they do not cover applications outside the system package manager or containers. The optional checks look for common signs of tampering and misconfiguration, not every possible compromise. No report is a claim that a machine is secure. Missing, invalid, stale-without-cache, or unsupported advisory data must not be interpreted as zero vulnerabilities.

OpsArmor is available under the MIT license. Advisory data remains the property and responsibility of its publishing distribution.
