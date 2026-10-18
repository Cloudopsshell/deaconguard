---
title: Notifications
description: Email, Slack, Microsoft Teams and webhook notifications for newly exploited vulnerabilities, malware, failed scans and offline agents, and daily or weekly digests.
---

DeaconGuard tells you when something needs attention, so you don't have to watch the dashboard. Admins set it up under **Settings → Notifications**.

## Channels

A channel is where messages go. Choose its type when you add it:

| Type | Set up |
| --- | --- |
| **Email** | Your mail server's host and port, encryption (**STARTTLS**, usually port 587; **TLS**, usually 465; or **none**, only for a relay on your network), an optional username and password, the From address, and up to 20 recipients. |
| **Slack** | In Slack, create an app with an [incoming webhook](https://api.slack.com/messaging/webhooks) for the channel, and paste its `https://hooks.slack.com/…` address. |
| **Microsoft Teams** | On the Teams channel, open **Workflows** and choose **Post to a channel when a webhook request is received**; paste the address it gives you. Messages arrive as Adaptive Cards. |
| **Webhook** | Any address that accepts a JSON POST: a ticketing system, a SIEM, your own script. HTTPS is best; plain HTTP is allowed for internal tools. |
| **Syslog** | Your SIEM's syslog server, port and protocol: **TCP**, **TLS** (its certificate must be trusted) or **UDP**. Messages are RFC 5424, from facility local0, with the [webhook's JSON](#webhook-format) as the text; over TCP and TLS each is framed with its length. |
| **Splunk** | The HTTP Event Collector's address, such as `https://splunk.example.com:8088/services/collector/event`, its token, and optionally an index. Events have source `deaconguard` and sourcetype `deaconguard:EVENT`, such as `deaconguard:exploited`. |
| **Jira** | Your site, such as `https://acme.atlassian.net`, a project key and an issue type (Task by default). For Jira Cloud, an account's email and an [API token](https://id.atlassian.com/manage-profile/security/api-tokens); for Data Center, leave the email empty and give a personal access token. Each event opens an issue labelled `deaconguard` and `deaconguard-EVENT`. |
| **ServiceNow** | Your instance, such as `https://acme.service-now.com`, an account that can create records, and the table: `incident` by default, or another such as `sn_si_incident`. Each event opens a record with category `security` and urgency and impact from how urgent the event is. |

Each channel then chooses its **events**, and optionally **Only hosts tagged**: [tags](./vulnerabilities.md#host-tags) such as `prod`, so a team hears only about its own hosts.

For Jira and ServiceNow, choose the events that need someone to act, such as known exploited vulnerabilities and malware: each one opens a ticket. **Test** sends a message at once and shows whether it arrived or why it didn't, such as a refused password or an unreachable server. The switch turns a channel off without deleting it.

## Events

| Event | Sent when | Urgency |
| --- | --- | --- |
| Known exploited vulnerabilities | A host has vulnerabilities in CISA's [KEV catalog](./vulnerabilities.md) that its previous scan didn't. | Critical |
| New critical vulnerabilities | A host has new critical vulnerabilities an update fixes. | Warning |
| Malware | A scan finds malware or signs of compromise. | Critical |
| Changed system files | System files differ from what their packages installed. | Critical |
| Failed scans | A scan fails, so the host's results are out of date. | Warning |
| Audits | An [audit](./audits.md) finishes, with its grade and what holds it back. | Warning for D and F |
| Agents offline | An agent stops checking in for 2 minutes. | Warning |
| Digest | Daily, or weekly on chosen days, at a time in a time zone. | |

Only what is new is sent: a vulnerability already reported for a host isn't reported again by its next scan. Malware and changed system files are reported by every scan that finds them.

## The digest

The digest sums up every host, or only the channel's tagged hosts: how many have results, which weren't scanned in the last 7 days or failed their last scan, what to fix now by severity, and how many vulnerabilities are known or likely to be exploited, with the known exploited ones to fix first. By email it attaches every open vulnerability as a CSV file, one row per host and package, with severity, CVSS, EPSS and whether it is known exploited.

## Links

Set **Dashboard address** at the top of the page, such as `https://deaconguard.example.com`, so messages link to the host, scan or audit. It is filled in with the address you are using; save it once. Without it, messages go out without links.

## Maintenance windows

While hosts are patched or restarted, notifications about them would only be noise. A **maintenance window**, added on the **Schedules** page by an operator or admin, covers every host or those with given tags for up to 7 days. Meanwhile notifications about those hosts are held back (the [Logs](./dashboard.md#logs) page lists each one), and their scheduled scans can be skipped. Scans started by hand still run. **End now** ends a window early.

## Delivery

Messages are sent from the server in the background. One that fails is retried after 1, 5 and 30 minutes, then marked failed; the server's [log](./dashboard.md#logs) says so. **Recently sent** lists the last 100 messages and how each went, kept for 30 days. A channel that is turned off or deleted gets nothing more.

The server reaches your mail server and webhook addresses directly; allow them in your firewall. Webhooks don't follow redirects.

## Webhook format

DeaconGuard POSTs `application/json`:

```json
{
  "event": "exploited",
  "level": "critical",
  "title": "web-01: 1 new vulnerability known to be exploited",
  "lines": ["CVE-2024-38475", "In CISA's Known Exploited Vulnerabilities catalog: attackers use them. Fix these first."],
  "link": "https://deaconguard.example.com/scans/…",
  "host": "web-01",
  "host_id": "…",
  "scan_id": "…",
  "data": { "cves": ["CVE-2024-38475"] },
  "at": "2026-10-13T09:16:12Z",
  "source": "deaconguard",
  "version": "@RELEASE@"
}
```

`event` is `exploited`, `critical`, `malware`, `integrity`, `scan_failed`, `audit`, `agent_offline`, `digest` or `test`; `level` is `critical`, `warning` or `info`. Each request carries `X-DeaconGuard-Event` and `X-DeaconGuard-Timestamp` (Unix seconds).

### Checking the signature

Give the webhook a **signing secret**, and each request also carries `X-DeaconGuard-Signature: sha256=` followed by the hex HMAC-SHA256, keyed with the secret, of the timestamp, a dot, and the raw body. Check it, and reject old timestamps, before trusting a request:

```python
import hashlib, hmac, time

def genuine(secret: bytes, headers, body: bytes) -> bool:
    timestamp = headers["X-DeaconGuard-Timestamp"]
    if abs(time.time() - int(timestamp)) > 300:
        return False
    expected = "sha256=" + hmac.new(secret, timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, headers["X-DeaconGuard-Signature"])
```

## Secrets

Mail passwords, webhook addresses (which are secrets themselves for Slack and Teams) and signing secrets are kept in the server's database, readable only by the `deaconguard` user. The dashboard never shows them again: editing a channel keeps them unless you type new ones. Keep [backups](./backup-and-restore.md) as safe as the server. Adding, changing, testing and removing channels are recorded in the audit log.
