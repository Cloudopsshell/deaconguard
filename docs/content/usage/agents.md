---
title: Agents
description: Enroll machines, automate enrollment and manage agents.
---

The agent runs on each machine you want to scan. It connects **out** to the server, so the machine needs no open ports and, once installed, no internet access.

## Enroll a machine

1. As an admin, open **Agents → Enroll a machine** in the dashboard, keep **One machine**, check the address agents will use to reach the server (it uses the [agent port](../security/securing-the-dashboard.md#give-agents-their-own-port) if the server has one), and click **Create token**. On the server's command line, `deaconguard token create --server-url https://SERVER:8443` does the same.
2. Run the command the dialog shows on the machine to scan, a Linux machine or a Mac, as a user with sudo rights (as root, leave out `sudo -E`):

   ```bash
   curl -fsSL https://get.deaconguard.io | DEACONGUARD_TOKEN=deaconguard1.… sudo -E sh -
   ```

   The dialog's command pins the same version as the server.
3. The machine appears on the **Agents** and **Hosts** pages. Scan it from the dashboard or with `deaconguard scan HOST_ID` on the server.

## The enrollment token

- A one-time token enrolls **one** machine, within **24 hours**. Unused tokens can be revoked on the **Agents** page. For many machines, use a [reusable token](#reusable-tokens).
- It contains the server's address and its certificate fingerprint, so the agent knows exactly which server to trust.
- `sudo -E` passes the token to the installer through the environment. It never appears in the process list, where other users of the machine could read it.
- The token ends up in the shell history. Once used it is worthless. To keep it out of the history anyway, run `curl -fsSL https://get.deaconguard.io | sudo sh -s -- --agent`, and paste the token when the script asks for it.
- On a machine that already has DeaconGuard installed, `sudo deaconguard setup agent` asks for the token.

## Reusable tokens

A reusable token enrolls **any number of machines** until it expires or you revoke it: every node of a [Kubernetes cluster](../installation/kubernetes.md), including nodes added later, or a fleet built from one image.

1. In **Agents → Enroll a machine**, choose **Many machines**.
2. Give it a name, such as the cluster's, and pick how long it lasts: 7, 30, 90, 180 or 365 days.
3. Click **Create token**. The dialog shows the `kubectl` commands that put it in the agent DaemonSet's secret; the token alone and the install command for a machine are under the dialog's details.

On the server's command line: `deaconguard token create --server-url URL --reusable [--days N] [--name NAME] [--quiet]`, where `--days` is 1 to 365 (30 by default) and `--quiet` prints only the token.

The **Enrollment tokens** list marks reusable tokens, with their name, how many machines each has enrolled, and when it was last used. **Revoke** stops it enrolling more machines; the ones it enrolled stay enrolled. Anyone with the token can enroll a machine with your server until then, so keep it in a secret store, and prefer a short lifetime.

### Agents that enroll themselves

An agent given a token in its environment, as the [DaemonSet](../installation/kubernetes.md) and [Compose](../installation/docker.md) agents are, enrolls by itself:

| Variable | Holds |
| --- | --- |
| `DEACONGUARD_ENROLL_TOKEN_FILE` | The path of a file with the token, such as a mounted secret |
| `DEACONGUARD_ENROLL_TOKEN` | The token itself |

`deaconguard agent run` then enrolls when the agent isn't enrolled yet, when the token is for a server with another certificate (the server was replaced), and when the server no longer knows the agent. So **removing the host of such an agent brings it back** while the token is valid; revoke the token first, or stop the agent.

## Automation

For cloud-init, Ansible or golden images, give the token without a prompt. A [reusable token](#reusable-tokens) lets one script enroll every machine:

```bash
# from the environment (cloud-init and Ansible usually run as root, so no sudo)
curl -fsSL https://get.deaconguard.io | DEACONGUARD_TOKEN="$TOKEN" sh -

# from a file, readable by root only
curl -fsSL https://get.deaconguard.io | sudo sh -s -- --agent --token-file /run/secrets/deaconguard-token
```

`--force` enrolls a machine again even if it is already enrolled.

## Status and logs

```bash
deaconguard agent status              # where it is enrolled
journalctl -u deaconguard-agent       # what it did
```

On a Mac, the agent is the launchd daemon `io.deaconguard.agent`:

```bash
sudo launchctl print system/io.deaconguard.agent | grep state   # whether it runs
tail /var/log/deaconguard-agent.log                              # what it did
```

From 0.6.0, the agent also sends its log to the server: the host's page and the [Logs](./dashboard.md#logs) page show it, including the lines from while the server was unreachable.

The agent checks in with the server every 25 seconds. The dashboard shows an agent as offline when it hasn't checked in for 90 seconds; scans you start for it wait up to an hour for it to reconnect. While it runs a scan, the agent doesn't ask for more work, so the server's log and the **Agents offline** notification wait for it: from 1.18.0, they don't call an agent offline in the middle of a long scan such as an audit.

## Removing an agent

Remove the host in the dashboard. That revokes the agent's credential at once, and the agent service stops (on a Mac, launchd doesn't start it again). The credential is stored on the machine in `/etc/deaconguard/agent.json`, readable by root only.
