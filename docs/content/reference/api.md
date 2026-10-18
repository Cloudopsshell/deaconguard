---
title: API
description: Use DeaconGuard's JSON API from scripts and other tools with an API token.
---

Everything the dashboard does goes through a JSON API under `/api/` on the server. Scripts, CI pipelines and other tools use it with an **API token**.

## API tokens

Create one under **My account → API tokens**:

- **Name**: what uses it, such as `CI pipeline`, so you know what stops working if you revoke it.
- **Role**: Viewer, Operator or Admin, up to your own. Viewer reads everything; Operator also starts scans and audits and changes tags; Admin also manages machines and settings. See [Roles](../usage/accounts.md#roles).
- **Lasts**: 30, 90, 180 or 365 days, or until revoked.

The token, starting `dgt_`, is shown once; only a hash of it is stored. Keep it in a secret store, such as your CI system's secrets.

A token acts as its account:

- It never has more than the account's role: if an admin demotes the account, its tokens are demoted too. A disabled account's tokens stop working.
- It can't manage accounts, API tokens or sign-in (`/api/account…`, `/api/users…`, `/api/tokens…`, `/api/settings/security`), so a leaked token can't make itself a lasting way in.
- Its actions are in the **Audit log** as `NAME (API token TOKEN)`.

**My account** shows each token's role, when it expires, and when and from which address it was last used. **Revoke** stops it at once. Admins see every account's tokens on the **Accounts** page and can revoke any of them. Revoked and expired tokens are listed for 30 days.

## Making requests

Send the token in the `Authorization` header. Requests that change something send JSON:

```bash
export DEACONGUARD=https://deaconguard.example.com:8443
export DEACONGUARD_TOKEN=dgt_…

curl -H "Authorization: Bearer $DEACONGUARD_TOKEN" "$DEACONGUARD/api/vulnerabilities"

curl -H "Authorization: Bearer $DEACONGUARD_TOKEN" -H "Content-Type: application/json" \
  -d '{"checks": ["packages"]}' "$DEACONGUARD/api/hosts/HOST_ID/scans"
```

With the server's self-signed certificate, give `curl` the certificate with `--cacert`, or use your own trusted certificate; don't turn verification off.

Errors come back as `{"error": "…"}` with the HTTP status: 401 for a token that is wrong, revoked or expired, 403 for one whose role isn't enough, 429 after too many wrong tokens from one address (wait 15 minutes).

## Useful endpoints

| Method and path | Role | Does |
| --- | --- | --- |
| `GET /api/summary` | Viewer | The dashboard's numbers: hosts, what to fix, known exploited, overdue |
| `GET /api/hosts` | Viewer | Every host with its latest results and tags |
| `GET /api/hosts/{id}` | Viewer | One host, with its scan history |
| `POST /api/hosts/{id}/scans` | Operator | Start a scan: `{"checks": ["packages", "integrity", "malware", "config", "hardening", "antivirus"]}` |
| `POST /api/hosts/{id}/audits` | Operator | Start a [server audit](../usage/audits.md): `{}` |
| `GET /api/scans/{id}` | Viewer | A scan's status and full results; poll until `scan.status` is `succeeded` or `failed` |
| `GET /api/scans/{id}/sbom?format=cyclonedx` | Viewer | The scan's [software bill of materials](../usage/libraries-and-sbom.md#download-an-sbom), as CycloneDX 1.6 (`cyclonedx`, the default) or SPDX 2.3 (`spdx`) JSON; 404 for scans from before 1.1.0 |
| `GET /api/vulnerabilities` | Viewer | Every CVE on every host, most urgent first, with KEV, EPSS, CVSS and fix deadlines |
| `GET /api/vulnerabilities/{cve}` | Viewer | The hosts and packages one CVE affects |
| `GET /api/audits` | Viewer | Audits, with their grades |
| `PUT /api/hosts/{id}/tags` | Operator | Set a host's tags: `{"tags": ["prod", "web"]}` |
| `GET /api/trends?days=90&tag=prod` | Viewer | Open vulnerabilities per day |
| `POST /api/reports` | Operator | Create a [report](../usage/reports.md) of a scan or audit |
| `GET /api/reports/{id}/download?format=pdf` | Viewer | Download a report as `pdf`, `html`, `xlsx`, `csv` or `json` |

For example, fail a pipeline when a host has a known exploited vulnerability with a fix:

```bash
count=$(curl -fsS -H "Authorization: Bearer $DEACONGUARD_TOKEN" "$DEACONGUARD/api/summary" | jq '.exploit.known_fixable')
[ "$count" -eq 0 ] || { echo "$count known exploited vulnerabilities have a fix waiting"; exit 1; }
```
