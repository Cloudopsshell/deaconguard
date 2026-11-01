---
title: Checks
description: What each DeaconGuard check looks at, and the commands it runs.
---

Each scan runs the checks you choose, in the dashboard's scan dialog or with:

```bash
deaconguard scan HOST_ID --checks packages,libraries,containers,integrity,malware,config,changes,hardening,antivirus
```

**Package vulnerabilities** is the default. A [server audit](./usage/audits.md) runs every check at once and grades the result. The antivirus scan is **Basic** (ClamAV) unless you choose **Advanced** in the scan dialog, or add `yara` to `--checks`, which runs YARA rules as well.

| Check | ID | What it does | Reads or runs |
| --- | --- | --- | --- |
| Package vulnerabilities | `packages` | Compares installed packages and the running kernel with the distribution's official advisories (see [Supported distributions](./supported-distributions.md)), and marks each vulnerability [known or likely to be exploited](./usage/vulnerabilities.md) from CISA KEV and EPSS. | `/etc/os-release`, the DPKG status file or `rpm -qa`, `uname -r` |
| Application libraries | `libraries` | Finds the libraries applications use (npm, Python, Go, Ruby, Rust and PHP) from their lock files and installed packages, and the Go version and modules of compiled Go programs (1.8.0 and later), and checks them against [OSV](https://osv.dev) on the server. See [Application libraries and SBOM](./usage/libraries-and-sbom.md). Needs agent 1.1.0 or later. | `find` for package-manager files on `/`, `/home`, `/opt`, `/srv`, `/usr/local`, `/var/www` and `/root` (not `/usr/lib` or `/usr/share`), and `head -c` to read each, at most 4 MB. The agent reads Go programs' build information itself, as files, outside the distribution's folders; it never runs them |
| Running containers | `containers` | Lists the machine's containers (Docker, Podman, containerd or CRI-O), running and stopped, with their state, image, user and ports, and checks each running one's OS packages and libraries, as for the machine itself. Nothing in a container is run, and links in a container are never followed. See [Running containers](./usage/containers.md). Needs agent 1.2.0 or later, as root. | `docker`/`podman`/`crictl` `ps` and `inspect`; then each container's files read through `/proc/PID/root` by the agent itself |
| System file integrity | `integrity` | Verifies packaged files against the package manager's checksums. Changed binaries and libraries, a classic rootkit sign, are reported; edited configuration files are counted but not reported. | `dpkg --verify` or `rpm -Va` |
| Malware & compromise indicators | `malware` | Looks for crypto-miner processes; programs running from `/tmp`, `/dev/shm`, memory or deleted files; programs disguised as kernel threads; `/etc/ld.so.preload`; hidden executables in temporary directories, the running containers' included; and download-and-execute or reverse-shell patterns in cron and systemd. Processes in containers are named after their container (1.19.0 and later). This is not a full antivirus scan. | `/proc`, `ps`, `find` on temporary directories, cron and systemd files |
| Security configuration | `config` | Reports SSH root or password login, empty passwords, X11 forwarding; risky services such as Redis, databases, Telnet or the Docker API listening on all interfaces; pending reboots; disabled automatic updates; and, with sudo, a missing host firewall. | sshd configuration, `ss`/`netstat`, reboot and update settings, firewall rules |
| Host changes | `changes` | Records the ports open to the network, login accounts, administrators, enabled services and, with root, sudoers rules, SSH keys (as fingerprints) and scheduled jobs, and reports what changed since the previous scan that ran it: a new port open to the network, a second root account, a new SSH key for root. The first scan is the baseline. See [Host changes](./usage/host-changes.md). Needs agent 1.22.0 or later. | `/etc/passwd`, `getent group`, `ss`/`netstat`, `systemctl list-unit-files`; with root, the sudoers files, each account's `authorized_keys`, which the agent turns into fingerprints, and the crontabs |
| Hardening audit | `hardening` | Checks the 72 controls of the [DeaconGuard Linux baseline](./usage/audits.md#the-deaconguard-linux-baseline): accounts and passwords, SSH, network and kernel settings, services and the firewall, logging and auditing, file permissions, updates, time and AppArmor or SELinux. Each control passes, fails, doesn't apply, or couldn't be checked, with the evidence. Also records the machine's inventory. Needs agent 0.12.0 or later. | `/etc/passwd`, `/etc/login.defs`, PAM and pwquality settings, `sysctl`, `/proc/mounts`, `stat` of key files, `systemctl`, `timedatectl`, the package list, sshd settings (`sshd -T` with root); with root also `/etc/shadow` (account names and whether a password is set only), firewall rules, `find` for world-writable, unowned and setuid files, and `auditctl -l` |
| Antivirus scan, Basic | `antivirus` | Runs the host's own `clamscan` at low priority on temporary, home and application directories, and on [what running containers wrote](./usage/containers.md#malware-in-containers) (1.19.0 and later), and reports detections and signatures older than 7 days. The install script installs ClamAV and keeps its signatures current. Skipped when ClamAV isn't installed (for example after a manual install), or when the host has less than about 1.5 GB of free memory and swap, since ClamAV loads its whole signature database into memory. | `clamscan` |
| Antivirus scan, Advanced | `yara` | Everything Basic does, plus [YARA-X](https://virustotal.github.io/yara-x/) with the [YARA Forge](https://github.com/YARAHQ/yara-forge) **core** rules on the same directories and containers, for webshells, crypto miners, backdoors and attacker tools that signature scanners often miss. See [the advanced antivirus scan](#the-advanced-antivirus-scan). Needs agent 0.5.0 or later. | `yr scan` |

Every command is a **fixed string** in DeaconGuard's source; nothing from the user or the host is inserted into it, and every command only reads. Folders found on the host, such as a container's writable layer, reach the antivirus scans on standard input, never in the command. The files a scan writes are the antivirus scans' private, temporary lists of folders and the advanced scan's copy of the YARA rules, compiled once, all deleted when it finishes.

## The advanced antivirus scan

ClamAV matches known malware by signature. The advanced scan adds YARA rules, which describe how kinds of malicious files look, so they also catch new variants: PHP and JSP webshells, crypto miners, backdoors, and the tools attackers bring with them.

- **Rules:** the YARA Forge **core** package, about 5,000 public rules from many authors, tested weekly and chosen for few false positives. The server downloads the latest package from GitHub and refreshes it every 12 hours; if GitHub can't be reached it keeps using the last one and the report says how old it is. Agents get the rules from the server with each scan, so they don't need to reach GitHub.
- **Engine:** YARA-X (`yr`), which the [install script](./installation/install-script.md) installs on every server and agent. It runs at the lowest CPU and disk priority, skips files over 50 MB, and gives up on a file after 30 seconds. From 1.19.0 the rules are compiled once per scan and every folder is scanned with the compiled rules: about a fifth of the time and a third of the memory per folder (about 0.2 seconds and 65 MB) of compiling them for each.
- **Findings:** each match names the rule, its author and reference, with a severity from the rule's own score: 90 or more is critical, 75 high, 60 medium, anything lower low. A match is a strong lead, not proof: look at the file before acting, and isolate the machine if it's malicious.
- **Never falsely clean:** if the rules can't be loaded or `yr` isn't installed, the scan is reported as skipped, with the reason.
- **Agents older than 0.5.0** can't run it; the server refuses the scan and says to upgrade the agent. Their Basic scans work as before.

## What clears each vulnerability

Every package finding says what clears it, on every supported distribution, so a machine that is fully up to date doesn't look alarming:

| Fix | Meaning | What to do |
| --- | --- | --- |
| **Update available** | The distribution published a fixed package. | `sudo apt update && sudo apt upgrade`, `sudo dnf upgrade`, or `sudo zypper patch` on SUSE. On Amazon Linux 2023, `sudo dnf upgrade --releasever=latest`: each machine stays on the release it was installed from until you move it on. |
| **Restart needed** | The running kernel is vulnerable, and a fixed kernel is already installed. | `sudo reboot` |
| **Old kernel** | An older kernel that is installed but not running, kept as a fallback. | `sudo apt autoremove --purge`, `sudo dnf remove --oldinstallonly`, or `sudo zypper purge-kernels` |
| **Ubuntu Pro** | Ubuntu publishes the fix only in Ubuntu Pro (ESM), free for up to 5 machines for personal use. | `sudo pro attach` |
| **No fix yet** | The distribution knows about it but hasn't published a fix. | Nothing yet: it clears once a fix ships and you update. |

The dashboard leads with **To fix now**, the findings an update or a restart fixes, and lists the rest by what clears them. They are still counted, never shown as clean. Each host's page has a **What to do** card with the packages in each group and the command for that machine.

**Severity is the distribution's own rating:** Ubuntu's priority, Debian's urgency, and the advisory severity of Red Hat, the rebuilds, Oracle, Fedora, SUSE and Amazon. They account for how the package is built and used on that distribution, so a CVE with a high generic (CVSS) score can be rated low. For Ubuntu, the CVSS rating is shown beside the severity when they differ.

The RPM distributions' feeds list only issues that have a fix, so findings there are never "No fix yet". Every scan also says whether the release still gets security fixes; see [Release lifecycle](./supported-distributions.md#release-lifecycle).

## Running checks with sudo

Agents run as root and see everything. In [local mode](./usage/local-mode.md) and on the server's own host, checks run as the user running DeaconGuard. That user can't see other users' processes, protected files or firewall rules, so those results say they have **partial coverage**.

Allow sudo to run the same read-only commands through `sudo`:

- `--allow-sudo` when adding the machine or scanning it once;
- `deaconguard host sudo HOST_ID on`;
- or the switch on the host's page.

If sudo needs a password, the dashboard or terminal asks for it once per scan and keeps it in memory only. Declining continues the scan without sudo.

## Results you can trust

- A skipped, partial or failed check is **never shown as clean**.
- Advisory rules DeaconGuard can't evaluate are listed as "not evaluated", not counted as passed.
- Missing, invalid or stale advisory data is never reported as zero vulnerabilities.
