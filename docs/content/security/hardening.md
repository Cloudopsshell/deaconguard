---
title: Hardening
description: Recommendations for running DeaconGuard securely.
---

## Network

- Don't expose port **8443** to the internet. Allow it only from the networks your administrators and agents are in, and reach the dashboard over a VPN or another private network; see [Securing the dashboard](./securing-the-dashboard.md).
- Enroll agents with the server's private address.
- Give agents [a port of their own](./securing-the-dashboard.md#give-agents-their-own-port) (`--agent-listen`), so the dashboard's port only has to reach your administrators.
- Agents need no inbound ports. Their only connection is outbound, to the server.

## Certificates

- The self-signed certificate is safe for agents, which [pin its key](../architecture.md#certificate-pinning). For browsers, check the fingerprint once, or use your own certificate with `--tls-cert` and `--tls-key`.
- Back up `/var/lib/deaconguard/tls/`. If the key is lost, agents must be enrolled again.

## Accounts

- Turn on [two-step sign-in](../usage/accounts.md#two-step-sign-in) for your account, then **Require it** for everyone on the **Accounts** page.
- Give everyone their own account, with a long, unique password, and the [least role](../usage/accounts.md#roles) they need: Viewer to see results, Operator to scan, Admin only for those who manage machines and accounts.
- Keep at least two admin accounts, so one can reset the other's access.
- Disable or remove accounts that are no longer needed on the **Accounts** page. This signs them out everywhere.
- Review the **Audit log** for failed sign-ins, unexpected addresses, account changes, tokens or enrollments, and **My account → Sessions** for browsers you don't recognize.
- Protect `deaconguard.db` and its backups: it holds the authenticator keys.

## Enrollment tokens

- Create a token just before you enroll a machine, and revoke tokens you didn't use.
- Treat an unused token like a password: anyone with it can enroll a machine with your server until it expires.

## Audit your servers

- Run a [server audit](../usage/audits.md) on each server, and again after changes. Fix failed controls, or accept their risk with a reason and an expiry date, so exceptions are written down rather than forgotten.
- DeaconGuard's own server is a host too: audit **This server** like any other.

## Reports

- Prefer sending a report's PDF over a share link. When you share a link, give it the shortest life that works, and revoke it once the client has the report.
- Ask clients to check a report's fingerprint on **Verify a report** if it reached them indirectly.

## Keep it current

- Upgrade regularly; security fixes go into the latest minor version. Watch the repository's releases on GitHub to be notified.
- [Verify releases](./verify-a-release.md) you install by hand.
