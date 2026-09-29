# Security policy

## Supported versions

Security fixes are released for the latest minor version of OpsArmor. Upgrade to the newest release on the [Releases page](https://github.com/Cloudopsshell/OpsArmor/releases) before reporting, and check `opsarmor version`.

| Version | Supported |
| --- | --- |
| 0.1.x (latest patch) | Yes |
| Older | No |

## Reporting a vulnerability

Please report security problems privately, not in a public issue:

1. Go to the repository's **Security** tab and choose **Report a vulnerability**. This opens a private advisory that only the maintainers can see.
2. If that option is unavailable, email **opensource@cloudopsshell.com** with "OpsArmor security" in the subject.

Include the OpsArmor version, how to reproduce the problem, and what an attacker could achieve. You should receive an acknowledgement within a few working days. We will agree a disclosure date with you, publish a fixed release, and credit you in the advisory unless you prefer otherwise.

## Scope

In scope: OpsArmor itself, including the SSH client and host-key handling, the commands it runs on scanned hosts, the local web server and its API, credential prompts, the stored data directory, and the release artifacts.

Out of scope: vulnerabilities that OpsArmor reports on your hosts (those belong to the affected software), and problems in the distributions' advisory data (report those to the distribution).

## How OpsArmor limits risk

- Commands run on scanned hosts are fixed strings in the source; nothing from the user or the host is inserted into them, and they only read.
- SSH host keys are pinned on first use and changes are refused.
- Passphrases and passwords are held in memory for one scan and never written to disk or logs.
- The web UI listens only on a loopback address and rejects requests from other sites and host names.
