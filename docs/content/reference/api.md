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
| `GET /api/hosts` | Viewer | Every host with its latest results and tags. An agent older than the server has `agent.upgrade`: `to` (the server's version), `checks` it can't run yet, `live` when it can't run live detection yet, and `command`, the install-script command that upgrades it (1.23.0 and later). Agent hosts and clusters have `live`, their live detection, as `GET /api/hosts/{id}/live` gives it (1.27.0 and later) |
| `GET /api/hosts/{id}` | Viewer | One host, with its scan history. A host whose token was revoked with its machines has `disconnected` (`at`, `by`, `reason`); a node of a cluster has `cluster_id` (1.21.0 and later) |
| `GET /api/hosts/{id}/cluster` | Viewer | A Kubernetes cluster's [page](../usage/kubernetes.md#the-clusters-page): its nodes, namespaces, workloads, pods and containers, with the problems in each (1.21.0 and later) |
| `GET /api/hosts/{id}/live` | Viewer | The host's [live detection](../usage/live-detection.md): `status` (`state`: `active`, `stopped`, `off`, `unsupported`, `agent_too_old`, `waiting` or `starting`; `reason`, `since`, `updated_at`, `kernel`, `events_last_hour`, `lost`, `suppressed`, `cpu_percent`, `memory_bytes`, `enabled`, and `alerts_24h` by severity) and its newest 200 `alerts`. A cluster's status counts its nodes' (`nodes`, `nodes_active`) (1.27.0 and later) |
| `PUT /api/hosts/{id}/live` | Admin | Turn live detection on or off for a host: `{"enabled": false}` |
| `POST /api/hosts/{id}/live/test` | Operator | Ask the host's agent for a test alert, which arrives within about 20 seconds; refused unless detection is active there |
| `PATCH /api/hosts/{id}` | Operator | Change a host's settings: `{"name": "payments-api-prod"}` for its [display name](../usage/agents.md#names) (`""` shows its hostname again), `{"auto_scan_containers": true}` for an agent's [automatic container scans](../usage/containers.md#scan-new-containers-automatically), or `{"allow_sudo": true}` for this machine. Hosts have `address` (what they are called), `hostname` and `name` |
| `POST /api/hosts/{id}/scans` | Operator | Start a scan: `{"checks": ["packages", "libraries", "containers", "integrity", "malware", "config", "changes", "paths", "hardening", "antivirus", "yara"]}`, or `["kubernetes"]` for a cluster; see [Checks](../checks.md) for each ID |
| `GET /api/diagnostics/cpu?seconds=30` | Admin | A CPU profile of the server over the next 5 to 60 seconds (30 by default), as a `.pprof` file for `go tool pprof` |
| `POST /api/hosts/{id}/audits` | Operator | Start a [server audit](../usage/audits.md): `{}` |
| `GET /api/scans/{id}` | Viewer | A scan's status and full results; poll until `scan.status` is `succeeded` or `failed` |
| `GET /api/scans/{id}/sbom?format=cyclonedx` | Viewer | The scan's [software bill of materials](../usage/libraries-and-sbom.md#download-an-sbom), as CycloneDX 1.6 (`cyclonedx`, the default) or SPDX 2.3 (`spdx`) JSON; 404 for scans from before 1.1.0 |
| `GET /api/vulnerabilities` | Viewer | Every CVE on every host, most urgent first, with KEV, EPSS, CVSS and fix deadlines |
| `GET /api/vulnerabilities/{cve}` | Viewer | The hosts and packages one CVE affects |
| `GET /api/images` | Viewer | The [registry images](../usage/images.md) DeaconGuard checks, each with its latest scan |
| `POST /api/images` | Operator | Add an image and start its first scan: `{"reference": "ghcr.io/acme/shop:4.2", "platform": "linux/amd64", "watch": true}`; watching is on unless `watch` is `false` |
| `POST /api/images/{id}/scans` | Operator | Scan an image again, for example from CI after a push; 409 while a scan of it is queued or running |
| `PATCH /api/images/{id}` | Operator | Watch an image for new builds, or stop: `{"watch": false}` |
| `GET /api/images/{id}` | Viewer | One image with its last 20 scans, without their results |
| `GET /api/image-scans/{id}` | Viewer | One image scan with its full result; poll until `status` is `succeeded` or `failed` |
| `POST /api/registry-logins` | Admin | Save a registry login: `{"registry": "ghcr.io", "username": "robot", "secret": "…"}`, or for Amazon ECR `"kind": "ecr"` with an access key ID as `username`; the secret is never returned |
| `POST /api/registry-logins/{id}/check` | Admin | Log in to the registry with a saved login: `status` is `ok`, `failed` (with `message`) or `unchecked` |
| `GET /api/registry-logins/{id}/repositories` | Operator | The repositories the login can see; `listed` is `false` when the registry won't list them |
| `GET /api/registry-logins/{id}/tags?repository=team/app&pattern=&platform=` | Operator | A repository's tags, newest first, each with whether it matches `pattern`, its `digest` and `pushed_at` where the registry gives them (Amazon ECR, Docker Hub, GHCR with a login, Google Artifact Registry, Azure Container Registry, Quay, Harbor and GitLab), and a `note` when the registry's own API failed and the registry API listed them instead. With `platform` (such as `linux/amd64`), the matching tags get `created`, when their image was built, and are ordered by it where there are no push times, as a watch's first check orders them |
| `GET /api/repository-watches` | Viewer | The [watched repositories](../usage/images.md#watch-a-repository) |
| `POST /api/repository-watches` | Operator | Watch a repository: `{"registry": "ghcr.io", "repository": "acme/app", "tag_pattern": "^v\\d+", "platform": "linux/amd64", "keep": 5, "history": 50, "notify_level": "any", "notify_channels": []}`; `notify_level` is `off`, `any`, `low`, `medium`, `high`, `critical` or `exploited`, and empty `notify_channels` means every channel that takes `image_report` |
| `GET /api/repository-watches/{id}` | Viewer | One watched repository with its `builds`: every scan of the images it added, newest first, at most 1,000 |
| `PATCH /api/repository-watches/{id}` | Operator | Change a watch: any of `tag_pattern`, `keep`, `history`, `notify_level` and `notify_channels` |
| `DELETE /api/repository-watches/{id}` | Operator | Stop watching a repository; the images it added stay, no longer watched |
| `POST /api/repository-watches/{id}/check` | Operator | Check a watched repository for new pushes now |
| `GET /api/repository-watches/report-channels` | Operator | The notification channels a watch's reports can go to, by name |
| `GET /api/network-targets` | Viewer | The [network targets](../usage/network.md#in-the-dashboard) the server scans, each with its latest scan |
| `POST /api/network-targets` | Admin | Add a network target and start its first scan: `{"name": "Office", "targets": ["10.0.0.0/24", "shop.example.com"], "ports": "", "tls": true, "web": true, "web_paths": true, "interval_hours": 24}`; `ports` empty means the default ports, `web` checks each [web site](../usage/network.md#web-sites) found and `web_paths` also asks for the paths a site should never publish (both default to `true`, 1.25.0 and later), and `interval_hours` is 0 (only on demand), 1, 6, 12, 24 or 168 |
| `PATCH /api/network-targets/{id}` | Admin | Change a network target: send every field, as when adding it; `web` and `web_paths` keep their values when left out |
| `DELETE /api/network-targets/{id}` | Admin | Remove a network target and its scans |
| `GET /api/network-targets/{id}` | Viewer | One network target with its last 20 scans, without their results |
| `POST /api/network-targets/{id}/scans` | Operator | Scan a network target now; 409 while a scan of it is queued or running |
| `GET /api/network-scans/{id}` | Viewer | One network scan with its full result: hosts, open ports, TLS and findings |
| `GET /api/audits` | Viewer | Audits, with their grades |
| `PUT /api/hosts/{id}/tags` | Operator | Set a host's tags: `{"tags": ["prod", "web"]}` |
| `GET /api/trends?days=90&tag=prod` | Viewer | Open vulnerabilities per day |
| `POST /api/reports` | Operator | Create a [report](../usage/reports.md) of a scan or audit |
| `GET /api/reports/{id}/download?format=pdf` | Viewer | Download a report as `pdf`, `html`, `xlsx`, `csv` or `json` |

## Notifications

Admins set up [notifications](../usage/notifications.md) with these, as the dashboard's **Settings → Notifications** page does:

| Method and path | Role | Does |
| --- | --- | --- |
| `GET /api/notifications` | Admin | The channels, with their secrets left out; the last 100 messages sent and how each went; the dashboard's address; and the events a channel can take |
| `POST /api/notifications/channels` | Admin | Add a channel: `{"name": "Security team", "kind": "slack", "config": {"url": "https://hooks.slack.com/…"}, "events": ["exploited", "critical", "malware", "config"], "tags": [], "digest": "daily", "digest_time": "08:00", "timezone": "UTC"}`. `kind` is `email`, `slack`, `teams`, `webhook`, `syslog`, `splunk`, `jira` or `servicenow`; `config` takes what that kind needs, as on [Channels](../usage/notifications.md#channels); `events` are the ones under [Events](../usage/notifications.md#events), by their webhook names; `digest` is `none`, `daily` or `weekly` (with `digest_days`, 0 for Sunday) |
| `PATCH /api/notifications/channels/{id}` | Admin | Change a channel: send every field, as when adding it, and `"enabled": false` to turn it off; secrets left empty are kept |
| `DELETE /api/notifications/channels/{id}` | Admin | Remove a channel |
| `POST /api/notifications/channels/{id}/test` | Admin | Send a test message now and answer whether it arrived |
| `PUT /api/notifications/settings` | Admin | Set the dashboard's address, for links in messages: `{"dashboard_url": "https://deaconguard.example.com"}` |
| `GET /api/maintenance` | Viewer | The [maintenance windows](../usage/notifications.md#maintenance-windows) |
| `POST /api/maintenance` | Operator | Add one: `{"name": "Patching", "tags": ["prod"], "starts_at": "2026-11-01T22:00:00Z", "ends_at": "2026-11-02T02:00:00Z", "skip_scans": true}`; no `tags` means every host |
| `DELETE /api/maintenance/{id}` | Operator | End or remove a maintenance window |

For example, fail a pipeline when a host has a known exploited vulnerability with a fix:

```bash
count=$(curl -fsS -H "Authorization: Bearer $DEACONGUARD_TOKEN" "$DEACONGUARD/api/summary" | jq '.exploit.known_fixable')
[ "$count" -eq 0 ] || { echo "$count known exploited vulnerabilities have a fix waiting"; exit 1; }
```
