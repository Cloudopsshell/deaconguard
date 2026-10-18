---
title: Install script
description: Install a DeaconGuard server or agent with one command.
---

The install script is the recommended way to install and upgrade DeaconGuard.

:::info Runs as root
The installer adds a system package and a service, so run it with `sudo` as shown, or as root without `sudo`. It never asks for a password itself: started without root, it stops before doing anything and shows the command to use.
:::

## Server

```bash
curl -fsSL https://get.deaconguard.io | sudo sh -
```

## Agent

Run the command from the dashboard's **Enroll a machine** dialog. It carries the machine's enrollment token:

```bash
curl -fsSL https://get.deaconguard.io | DEACONGUARD_TOKEN=deaconguard1.… sudo -E sh -
```

`sudo -E` hands the token to the installer through the environment, so it never appears on a command line other users of the machine can see. If your sudo rules don't allow `-E`, open a root shell with `sudo -i` and run the command without `sudo -E`.

## What the script does

1. Detects the distribution and the processor (amd64 or arm64).
2. **Installs what DeaconGuard's checks use**, on servers and agents alike, from the distribution's own signed repositories. Packages that are already installed are left as they are:

   | For | Debian, Ubuntu | RHEL, Rocky, AlmaLinux, Oracle Linux, Fedora, Amazon Linux 2023 | openSUSE Leap, SUSE Linux Enterprise |
   | --- | --- | --- | --- |
   | Malware check (`ps`, `find`) | `procps`, `findutils` | `procps-ng`, `findutils` | `procps`, `findutils` |
   | Security configuration check (`ss`) | `iproute2` | `iproute` | `iproute2` |
   | Pending-reboot check | (not needed) | `needs-restarting` | (not needed) |
   | Antivirus scan, Basic | `clamav`, `clamav-freshclam` | `clamav` and its updater; on RHEL and its rebuilds from **EPEL**, which the script enables (`oracle-epel-release` on Oracle Linux) | `clamav` |

   It switches on ClamAV's signature updates (`clamav-freshclam`, or `freshclam.timer` on SUSE): about 110 MB of signatures download in the background after the install, then stay current.
3. **Installs [YARA-X](https://virustotal.github.io/yara-x/)** (`yr`, for the [advanced antivirus scan](../checks.md#the-advanced-antivirus-scan)) and **[cosign](https://docs.sigstore.dev)** (to verify releases) to `/usr/local/bin`: each a pinned version, checked against a pinned checksum. A `yr` installed elsewhere, such as by a package, and an existing cosign are left as they are.
4. Downloads the matching `.deb` or `.rpm` package and the release's `checksums.txt` from GitHub over HTTPS.
5. Verifies with cosign that `checksums.txt` was [signed by DeaconGuard's release workflow](../security/verify-a-release.md), then checks the package against it. **DeaconGuard is not installed when a check fails.**
6. Installs the package, then runs `deaconguard setup server` or `deaconguard setup agent`. A server also gets an agent on the same machine, so the server's own machine is scanned as root (`--no-agent` skips it); see [Architecture](../architecture.md#who-runs-as-what).

Each release's notes on GitHub list the exact versions it was built with, and its SBOM lists every dependency.

`get.deaconguard.io` serves `install.sh` from the [deaconguard repository](https://github.com/Cloudopsshell/deaconguard/blob/main/packaging/install.sh)'s `main` branch, and the script installs the latest release unless you choose a version.

### Server or agent?

| You run | The script sets up |
| --- | --- |
| `… \| sudo sh -` on a new machine | a **server**, with an agent that scans this machine |
| `… \| DEACONGUARD_TOKEN=… sudo -E sh -` | an **agent**, enrolled with that token |
| `… \| sudo sh -` on a machine that is already an enrolled agent | an **upgrade of the agent** (it never turns an agent into a server) |
| `… \| sudo sh -` on a server | an **upgrade of the server and its agent** |
| `… \| sudo sh -s -- --server` or `--agent` | the mode you name |

### Root and sudo

Installing a package and a service needs root. Use the commands as shown, with `sudo`, or run them as root without `sudo`. As a user without root, the script stops before downloading anything and prints the right command; it never calls `sudo` or asks for a password itself.

## Options

Options go after `sh -s --`:

```bash
curl -fsSL https://get.deaconguard.io | sudo sh -s -- --listen 0.0.0.0:9443
```

| Option or variable | Effect |
| --- | --- |
| `DEACONGUARD_TOKEN=…` | Enroll an agent with this token. |
| `DEACONGUARD_VERSION=@RELEASE@` (with `sudo -E`) or `--version @RELEASE@` | Install that release instead of the latest. |
| `--server`, `--agent` | Choose the mode explicitly. |
| Server: `--listen`, `--agent-listen`, `--tls-cert`/`--tls-key`, `--admin-user`/`--admin-password-file` | See [Server](../usage/server.md#setup-options). |
| Agent: `--token-file FILE`, `--force` | See [Agents](../usage/agents.md#automation). |

## Read the script first

To read the script before running it:

```bash
curl -fsSLO https://github.com/Cloudopsshell/deaconguard/releases/latest/download/install.sh
less install.sh
sudo sh install.sh
```

## Without the script

To install the package yourself, see [Manual install](./manual-install.md).
