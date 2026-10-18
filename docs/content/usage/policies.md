---
title: Policies
description: Add your organisation's own controls to every server audit, written in YAML.
---

A **policy** is a set of your own controls, written in YAML, that every [server audit](./audits.md) tests next to the DeaconGuard baseline: a monitoring agent that must run, a port that must stay closed, a stricter password age than the baseline's.

Policies test only the settings the audit already reads. They can't make an agent run a command or read anything else, so adding one is as safe as the audit itself.

## Add a policy

Admins open **Settings → Policies → New policy**. The editor starts with an example to adapt. Saving checks the policy and says what's wrong, if anything, for example `control 2 (ACME-02): severity must be critical, high, medium or low`. A policy can be turned off without deleting it.

Results appear on each audit's page under **Policy: _name_**, and in reports. Policies **don't change the grade**, which stays comparable between servers and organisations. A failed policy control's risk can be [accepted](./audits.md#accepted-risks) like a baseline one.

Policies apply to audits as you look at them: adding, changing or turning one off shows straight away on existing audits, but not in reports already made.

Policies need the settings agents send from DeaconGuard 0.14.0. On audits from older agents, policy controls show as **not checked**.

## Format

```yaml
name: Acme server policy
description: Settings Acme requires on every server, beyond the baseline.
controls:
  - id: ACME-01
    title: Root can't log in over SSH at all
    severity: high            # critical, high, medium or low
    rationale: Admins sign in as themselves and use sudo, so every action is attributed.
    remediation: Set PermitRootLogin no in /etc/ssh/sshd_config.
    check:
      sshd: { setting: PermitRootLogin, is: ["no"] }
```

- `name`: up to 80 characters. `description` is optional.
- `controls`: 1 to 200. Each needs an `id` (a letter, then letters, digits, `-`, `_` or `.`, up to 32; not a baseline ID such as `SSH-01`, and unique), a `title`, a `severity` and one `check`. `rationale` and `remediation` are optional and shown with the control.

## Checks

| Check | Example | Tests |
| --- | --- | --- |
| `sshd` | `{ setting: MaxAuthTries, at_most: 3 }` | An SSH server setting as the server uses it. Not applicable without an SSH server. |
| `sysctl` | `{ setting: net.ipv4.ip_forward, is: ["0"] }` | Any kernel setting. |
| `login_defs` | `{ setting: PASS_MAX_DAYS, at_most: 90 }` | A setting in `/etc/login.defs`. |
| `package` | `{ name: telnet, installed: false }` | Whether a package is installed. |
| `service` | `{ name: auditd, running: true }` | Whether a service, socket or timer is running. |
| `mount` | `{ path: /tmp, options: [nodev, nosuid] }` | That a path is a separate mount with these options. |
| `port` | `{ port: 3306, exposed: false }` | `listening: false`: nothing listens on the port. `exposed: false`: it may listen, but not on every interface. `protocol: tcp` or `udp` narrows it. |
| `file` | `{ path: /etc/shadow, mode_at_most: "0640", owner: root }` | The permissions or owner of one of the files the audit reads: `/etc/passwd`, `/etc/group`, `/etc/shadow`, `/etc/gshadow`, `/etc/ssh/sshd_config`, `/etc/crontab`, the `/etc/cron.*` directories, and the GRUB configuration. |

Settings compare with `is` (a list of accepted values; SSH and login.defs ignore case), or as numbers with `at_most` and `at_least`.
