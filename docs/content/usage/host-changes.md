---
title: Host changes
description: Find out when a machine gets a new port open to the network, a new account or administrator, a sudoers rule, an SSH key, a service or a scheduled job, compared with its previous scan.
---

The **Host changes** check (`changes`) records what an attacker, or a change nobody told you about, adds to a Linux machine, and reports what changed since the machine's previous scan:

- ports open to the network, and ports listening on the machine only;
- login accounts, and their UIDs;
- administrators: the members of the `sudo`, `wheel` and `admin` groups;
- with root: sudoers rules, SSH keys in each account's `authorized_keys`, and scheduled jobs (crontabs, `/etc/cron.d` and the `cron.hourly` to `cron.monthly` folders);
- enabled services, sockets and timers.

It needs the DeaconGuard agent 1.22.0 or later. Agents run as root, so they record everything. `deaconguard scan --local` records the machine, but its one-off scans aren't tied to a host, so it has nothing to compare with: use an agent, which is how the server's own machine is scanned too. Without root, sudoers rules, SSH keys and scheduled jobs aren't read, and the check says it has partial coverage.

## Turn it on

The check is a scan's **Host changes** box, in the scan dialog and in each [schedule](./dashboard.md#schedules). Changes are found between two scans that ran the check, so add it to the host's schedule: run daily, it finds a change within a day.

```bash
deaconguard scan HOST_ID --checks packages,changes
```

**The first scan is the baseline.** It records the machine and reports nothing. Every later scan compares itself with the previous scan that ran the check.

## What is reported

Each change is a finding on the scan's **Host changes** tab, with what to do:

| Change | Severity |
| --- | --- |
| New login account with UID 0, a second root | Critical |
| New port open to the network | High |
| New administrator | High |
| New sudoers rule | High |
| New SSH key for root, or another account with UID 0 | High |
| New SSH key for another account | Medium |
| New login account | Medium |
| New enabled service, socket or timer | Medium |
| New scheduled job | Medium |
| New port listening on the machine only, such as `127.0.0.1` | Low |
| Anything removed | Low |

A scan lists at most 100 changes. Ephemeral UDP ports (32768 and up), which change each time a program starts, aren't recorded.

To be told about changes, tick **Host changes** on a [notification channel](./notifications.md#events). It sends the medium, high and critical changes; removals and ports on the machine only aren't sent.

## What leaves the machine

- **SSH keys** as their fingerprints, the SHA256 ones `ssh-keygen -l` shows, which the agent works out itself: the keys never leave the machine, and `ssh-keygen` needn't be installed.
- **Scheduled jobs and sudoers rules** with anything that looks like a password or token masked, such as `curl -u admin:***`. Each line is compared by a hash of the whole line, so a changed password is still a change, but the password itself isn't sent.
- **Accounts** as their name, UID and shell; nothing from `/etc/shadow`.

## How light it is

The check is two short shell scripts: one reads `/etc/passwd`, the `sudo`, `wheel` and `admin` groups, `ss -tulnp` (or `netstat`) and `systemctl list-unit-files`; the other, with root, reads the sudoers files, each account's `authorized_keys` and the crontabs, at most 500 lines of crontab. Nothing is walked or scanned: on a test machine it took a tenth of a second. The server keeps each scan's record with the scan and compares the two when the scan finishes.
