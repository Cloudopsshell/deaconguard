---
title: CLI reference
description: Every deaconguard command.
---

Run `deaconguard help` for this list on your machine, and `deaconguard version` for the installed version.

## Scanning

| Command | Does |
| --- | --- |
| `deaconguard host add [--allow-sudo]` | Register this machine (Linux). |
| `deaconguard host list` | List hosts. |
| `deaconguard host sudo HOST_ID on\|off` | Allow or stop the deeper checks using sudo. |
| `deaconguard host remove HOST_ID` | Remove a host; for an agent host, also revoke its agent. |
| `deaconguard scan HOST_ID [--checks LIST] [--json]` | Scan a host. `LIST` is a comma-separated choice of `packages,libraries,integrity,malware,config,hardening,antivirus,yara`. |
| `deaconguard scan --local [--allow-sudo] [--checks LIST] [--json]` | Scan this machine without registering it. |
| `deaconguard report REPORT_ID [--json]` | Show a saved report. |
| `deaconguard sbom SCAN_ID [--format cyclonedx\|spdx]` | Print a scan's [software bill of materials](../usage/libraries-and-sbom.md#download-an-sbom), CycloneDX by default. |
| `deaconguard audit HOST_ID [--advanced] [--json]` | Run a [server audit](../usage/audits.md): every check and the hardening baseline, graded A to F, with the failed controls and how to fix them. `--advanced` adds the YARA antivirus scan. For an agent host, the server must be running; run it as the `deaconguard` user. |
| `deaconguard audit --local [--allow-sudo] [--advanced] [--json]` | Audit this machine without a server. |

## Setup

Run as root after installing the package; the install script runs these for you.

| Command | Does |
| --- | --- |
| `deaconguard setup server [--listen ADDRESS:PORT] [--agent-listen ADDRESS:PORT\|off] [--tls-cert FILE --tls-key FILE] [--admin-user NAME] [--admin-password-file FILE]` | Create the first account, an admin, and start the server service. |
| `deaconguard setup agent [--token-file FILE] [--force]` | Enroll (asks for the token unless given) and start the agent service. |

## Server and dashboard

| Command | Does |
| --- | --- |
| `deaconguard serve` | Local dashboard at `http://127.0.0.1:7480`, no sign-in. |
| `deaconguard serve --listen 0.0.0.0:8443 [--agent-listen 0.0.0.0:8444] [--tls-cert FILE --tls-key FILE] [--trusted-proxy CIDR]...` | Server: HTTPS dashboard with sign-in; agents can enroll. `--agent-listen` gives agents a port that serves only the agent API. `--trusted-proxy`, once per proxy address or network, takes each client's address from `X-Forwarded-For` when a request comes through those proxies. |
| `deaconguard user add USERNAME [--role admin\|operator\|viewer] [--password-stdin]` | Create an account; an admin unless `--role` says otherwise. |
| `deaconguard user passwd USERNAME [--password-stdin]` | Change an account's password and sign it out. |
| `deaconguard user role USERNAME admin\|operator\|viewer` | Change an account's [role](../usage/accounts.md#roles) and sign it out. The last admin keeps its role. |
| `deaconguard user mfa-reset USERNAME` | Turn off an account's two-step sign-in and sign it out, for a lost phone when no other admin can reset it. |
| `deaconguard user list` | List accounts, with roles, two-step sign-in status and recovery codes left. |
| `deaconguard user remove USERNAME` | Remove an account and sign it out. |
| `deaconguard token create --server-url https://HOST:8443` | Create a one-time enrollment token, valid for 24 hours, and print the install command. |
| `deaconguard token create --server-url URL --reusable [--days N] [--name NAME] [--quiet]` | Create a [reusable token](../usage/agents.md#reusable-tokens) for any number of machines, for N days (1 to 365, 30 by default). `--quiet` prints only the token. |

On a server installed as a service, run `user` and `token` commands as the service user: `sudo -u deaconguard deaconguard …`. In a container, run them in it: `docker compose exec server deaconguard …`, or `kubectl -n deaconguard exec deaconguard-0 -- deaconguard …`.

## Agent

| Command | Does |
| --- | --- |
| `deaconguard agent enroll TOKEN [--force]` | Enroll with the server that made the token. |
| `deaconguard agent run` | Wait for scans; this is what the `deaconguard-agent` service runs. With a token in its [environment](./environment.md#containers), it enrolls first when needed. |
| `deaconguard agent status` | Show where this machine is enrolled. |
