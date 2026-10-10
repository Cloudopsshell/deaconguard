# Security policy

## Supported versions

Security fixes are released for the **latest minor version** of DeaconGuard, as a new patch release (for example 0.4.0 → 0.4.1). Older minor versions don't get fixes: upgrade to the newest release on the [Releases page](https://github.com/Cloudopsshell/deaconguard/releases) before reporting, and check `deaconguard version`.

## Reporting a vulnerability

Please report security problems privately, not in a public issue:

1. Go to the repository's **Security** tab and choose **Report a vulnerability**. This opens a private advisory that only the maintainers can see.
2. If that option is unavailable, email **opensource@cloudopsshell.com** with "DeaconGuard security" in the subject.

Include the DeaconGuard version, how to reproduce the problem, and what an attacker could achieve. You should receive an acknowledgement within a few working days. We will agree a disclosure date with you, publish a fixed release, and credit you in the advisory unless you prefer otherwise.

## Scope

In scope: DeaconGuard itself, including the commands it runs on scanned machines, its use of sudo, the server, its API and dashboard, the agent and its enrollment, the local web UI, the sudo password prompt, the stored data directory, the install script, the download and delivery of the YARA rules, and the release files.

Out of scope: vulnerabilities that DeaconGuard reports on your hosts (those belong to the affected software), and problems in the distributions' advisory data (report those to the distribution). False positives and missed detections of a ClamAV signature or YARA rule belong to its authors: YARA findings name the rule and its author.

## How DeaconGuard limits risk

- Commands run on the scanned machine are fixed strings in the source; nothing from the user or the machine is inserted into them, and they only read.
- Sudo is used only when allowed for the host; a sudo password is held in memory for one scan and never written to disk or logs.
- The local web UI listens only on a loopback address and rejects requests from other sites and host names. The server's dashboard is HTTPS-only with sign-in, rate-limited sign-ins and enrollments, and an audit log.
- Agents open no ports. They connect out to the server and accept only its pinned certificate key, or a certificate their system's authorities trust for the server's name.
- The server evaluates agents' packages itself, so a modified agent cannot supply its own vulnerability verdicts.
- Releases are signed keyless with Sigstore by the release workflow; the install script checks package checksums, and the signature when cosign is installed.
