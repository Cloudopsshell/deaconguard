---
title: Server
description: Set up and run the DeaconGuard server and its dashboard.
---

The server hosts the dashboard, stores results, evaluates packages against the advisories and hands scans to agents. It runs without root and never scans anything itself; see [Architecture](../architecture.md#the-rule). The [install script](../installation/install-script.md) sets it up for you. After installing the package yourself, run:

```bash
sudo deaconguard setup server
```

Setup creates the first dashboard account, enables and starts the `deaconguard-server` service on port 8443, gives this machine an agent of its own, and prints the dashboard's addresses, the certificate's fingerprint, and what runs on the machine. Running it again keeps the existing accounts and settings.

## The server's own machine

Setup installs and enrolls an agent on the server's machine, over `127.0.0.1`, so it is scanned as root like every other machine while the server itself keeps running without root. It appears on the **Hosts** page as **This server**, and you can schedule and scan it like any other host.

If this machine was added as a host before DeaconGuard 0.9.0, the server scanned it itself, without root, so its results were partial. Running setup again (for example by running the install script to upgrade) moves that host's scans, log entries and schedules to the agent host.

## The certificate

On its first start the server creates a self-signed certificate in `/var/lib/deaconguard/tls/`. Browsers warn about it once; check that the fingerprint matches the one setup printed.

Agents don't depend on that warning: every enrollment token carries the certificate's fingerprint, and agents trust **only** that certificate. See [Architecture](../architecture.md#certificate-pinning).

## Setup options

These options work with `deaconguard setup server`, and the install script passes them on.

| Option | Use |
| --- | --- |
| `--listen ADDRESS:PORT` | Listen elsewhere than `0.0.0.0:8443`. |
| `--agent-listen ADDRESS:PORT` | Give agents a port of their own, such as `0.0.0.0:8444`, that serves only the agent API, so the dashboard's port can be limited to people. Agents from 0.11.0 move to it by themselves; older ones keep using 8443. `off` removes it. See [Give agents their own port](../security/securing-the-dashboard.md#give-agents-their-own-port). |
| `--tls-cert FILE --tls-key FILE` | Use your own certificate. Use absolute paths; the `deaconguard` user must be able to read both files. Agents enrolled earlier keep working when the new certificate is trusted by their system for the server's name; otherwise enroll them again. |
| `--admin-user NAME --admin-password-file FILE` | Create the first account without prompts, for automation. Delete the file afterwards. |
| `--no-agent` | Give this machine no agent. It is then not scanned as root, and later runs remember the choice. |
| `--with-agent` | Add the agent after an earlier `--no-agent`. |

Setup saves these in `/etc/systemd/system/deaconguard-server.service.d/10-setup.conf`, so package upgrades keep them.

## Accounts

Setup creates the first account, an admin. After that, admins create accounts on the dashboard's **Accounts** page, each with a [role](./accounts.md#roles) (Viewer, Operator or Admin) and a temporary password that the person changes at their first sign-in. Everyone manages their own password, two-step sign-in, appearance and sessions on **My account**. See [Accounts and sign-in](./accounts.md).

On the server, as the `deaconguard` user:

```bash
sudo -u deaconguard deaconguard user add alice --role operator
sudo -u deaconguard deaconguard user role alice viewer
sudo -u deaconguard deaconguard user passwd alice
sudo -u deaconguard deaconguard user mfa-reset alice
sudo -u deaconguard deaconguard user list
sudo -u deaconguard deaconguard user remove alice
```

Changing a password or role, resetting two-step sign-in or removing an account signs it out everywhere.

:::warning Don't expose port 8443 to the internet
Reach the dashboard over a VPN or another private network, and turn on two-step sign-in. See [Securing the dashboard](../security/securing-the-dashboard.md).
:::

## Built-in protections

- [Two-step sign-in](./accounts.md#two-step-sign-in) with any authenticator app, which admins can require for every account.
- Failed sign-ins, two-step codes and enrollments are rate-limited per address.
- [Roles](./accounts.md#roles): viewers only see results, operators also scan, admins also manage machines and accounts. The server checks the role on every request.
- Sessions last 12 hours, and each account can see and end its own.
- The **Audit log** page records sign-ins, account changes, tokens, enrollments, scans and removals.
- The **Logs** page shows what the server and each agent did, including why the server last restarted; see [Logs](./dashboard.md#logs).

## Running without systemd

```bash
deaconguard serve --listen 0.0.0.0:8443
```

Any address other than loopback turns on HTTPS and sign-in. Create an account first with `deaconguard user add`. Add `--agent-listen 0.0.0.0:8444` for a port only agents use.
