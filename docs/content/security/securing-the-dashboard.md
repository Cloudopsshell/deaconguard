---
title: Securing the dashboard
description: How to keep the DeaconGuard dashboard away from the internet, and what to turn on when it can't be.
---

The dashboard shows every machine's weaknesses and can start scans on all of them, so it deserves more protection than a password. In order of how much they help:

1. **Don't expose port 8443 to the internet.** Reach the dashboard over a private network. [Give agents a port of their own](#give-agents-their-own-port) so the dashboard's port only needs to reach people.
2. **Turn on two-step sign-in** for every account, and [require it](../usage/accounts.md#require-it-for-everyone).
3. **Keep accounts tidy:** one per person, no shared accounts, the [least role](../usage/accounts.md#roles) each person needs, and remove or disable people who leave.

## Keep it off the internet

Agents and browsers both use port 8443. Agents only need to reach it from your machines' networks, and people only from where they work, so the internet never needs to.

Pick whichever fits what you already use:

| Option | Fits when |
| --- | --- |
| **Firewall or security group** that allows 8443 only from your networks and your office or VPN addresses | Always; do this whatever else you choose. |
| **Your VPN** (WireGuard, OpenVPN, your company VPN) | You already have one. Browse to the server's private address. |
| **Tailscale or another mesh VPN** | You want private access without running VPN servers. Install it on the server and on admins' laptops, then browse to the server's Tailscale address. |
| **SSH tunnel**: `ssh -L 8443:localhost:8443 SERVER`, then open `https://localhost:8443` | Occasional access by people who already have SSH. |
| **AWS Systems Manager port forwarding** | The server runs in AWS and you don't want any inbound ports for people. |
| **An identity-aware proxy** (Cloudflare Access, Google IAP, an OAuth2 proxy) | People must reach it from anywhere; the proxy adds your company sign-in in front of DeaconGuard's. |

On AWS with one port, give the server's security group one rule for port 8443 from your VPC's range (for agents) and one from your VPN or office range (for people), and nothing from `0.0.0.0/0`.

Enroll agents with the server's **private** address, so they never leave your network to reach it.

## Give agents their own port

By default, browsers and agents share port 8443, so a firewall can't tell them apart. With an agent port, agents connect to a port that serves only the agent API: no dashboard, no sign-in page. You can then open the agent port to every machine's network and keep 8443 for people only.

```bash
sudo deaconguard setup server --agent-listen 0.0.0.0:8444
```

Or pass `--agent-listen 0.0.0.0:8444` to the install script. Setup remembers it across upgrades; `--agent-listen off` removes it.

Turning it on adds port 8444; it doesn't close 8443. Nothing breaks: every agent keeps working while it moves.

- **Agents move by themselves.** At its next check-in, an agent on 8443 (version 0.11.0 or later) hears about the agent port, checks that it reaches the same server with the same pinned key, then saves the new address and uses it from then on. If it can't reach the new port, for example because a firewall blocks it, it stays on 8443, says why in its log, and tries again an hour later.
- **Older agents stay on 8443** and keep working. Upgrade them to 0.11.0 and they move too, or enroll them again with a new token.
- **New enrollment tokens** point at the agent port: **Enroll a machine** fills it in.
- **The server's own agent** stays on `127.0.0.1:8443`, which no firewall rule affects.
- Both ports use the same certificate, so agents pin the same key.

The **Agents** page shows the port each agent uses, which ones haven't moved and why, and says when every agent has moved.

Then, and only then, tighten the firewall. On AWS, for example: allow 8444 from your VPC's range, allow 8443 only from your VPN or office range, and nothing from `0.0.0.0/0`. Closing 8443 to your machines before they move would cut off the agents still using it.

## If it must be reachable from the internet

Then the dashboard's own sign-in is all that stands in the way, so:

- [Require two-step sign-in](../usage/accounts.md#require-it-for-everyone) for every account.
- Use your own certificate (`--tls-cert`, `--tls-key`) so people don't get used to clicking through browser warnings.
- Give people the [least role](../usage/accounts.md#roles) they need: most only need **Viewer**.
- Watch the **Audit log** for failed sign-ins and sign-ins from unexpected addresses, and check **My account → Sessions**.

Report share links are the one way in without signing in: each opens a single report, expires within 30 days, can be revoked, and every use is in the audit log. Prefer sending the PDF when you can.

DeaconGuard already limits failed sign-ins and failed two-step codes per address, ends sessions after 12 hours, and refuses a code that was already used.

## Behind a reverse proxy

A reverse proxy or a Kubernetes ingress in front of the dashboard connects to the server itself, so every request seems to come from the proxy's address. Sign-in limits are per address, so one person's failed attempts would lock everyone out, and the audit log would show only the proxy.

Tell the server which proxies to believe, with their addresses or networks:

```bash
deaconguard serve --listen 0.0.0.0:8443 --trusted-proxy 10.42.0.0/16
```

`--trusted-proxy` can be given more than once; `DEACONGUARD_TRUSTED_PROXIES` takes a comma-separated list, and the Helm chart's `server.trustedProxies` a list. For a request from a trusted proxy, the server takes the client's address from `X-Forwarded-For`: the last address in it that isn't a trusted proxy, so a client can't choose its own by sending the header. From anywhere else, it ignores the header.

Make sure the proxy sets `X-Forwarded-For`; most do. Agents connect to the server directly, not through the proxy.

## What DeaconGuard does not do

- **Single sign-on (OIDC, SAML) and passkeys** are not supported yet; they are planned. Until then, an identity-aware proxy can add your company sign-in.
- **Password reset by email** is deliberately missing: another admin, or the command line on the server, resets access. See [When someone loses access](../usage/accounts.md#when-someone-loses-access).

See also [Hardening](./hardening.md).
