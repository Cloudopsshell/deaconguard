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

1. In **Agents → Enroll a machine**, choose **Many machines** for a fleet, or **Kubernetes** for the Helm chart's agents.
2. Give it a name, such as the cluster's, and pick how long it lasts: 7, 30, 90, 180 or 365 days.
3. Click **Create token**. For **Kubernetes**, the dialog fills in the server's address inside the cluster, and shows the `kubectl` command for the secret and the Helm values that give it to every agent of the chart, the node agents and the cluster agent (1.20.2 and later); see [Install in Kubernetes](../installation/kubernetes.md#2-one-token-for-the-agents). For **Many machines**, the token alone and the install command for a machine are under the dialog's details.

In Kubernetes, the chart's agents share one token, so it must be reusable even for a single node with the cluster agent: a one-time token enrolls only the first to start, and the agent that comes second says so in its log.

On the server's command line: `deaconguard token create --server-url URL --reusable [--days N] [--name NAME] [--quiet]`, where `--days` is 1 to 365 (30 by default) and `--quiet` prints only the token.

The **Enrollment tokens** list marks reusable tokens, with their name, how many machines each has enrolled, which hosts those are, and when it was last used. Anyone with the token can enroll a machine with your server until it expires or is revoked, so keep it in a secret store, and prefer a short lifetime.

### Revoking a token

**Revoke** stops a token enrolling more machines. From 1.21.0, its dialog lists the machines it enrolled, with **Also disconnect them** ticked:

- **Disconnected** machines' agents are refused from then on. Each agent logs why, such as `this agent was disconnected on 2026-10-31 19:30 UTC by admin: its enrollment token d4f02283 was revoked`, and a scan it was running fails. Their hosts stay, with their scans, marked **Disconnected** on the **Hosts** and **Agents** pages and on their own page, which say who disconnected them, when and why. Scans of a disconnected host are refused.
- **To reconnect** a disconnected machine, enroll its agent again with a new token. It comes back as the same host, with its history. In Kubernetes, put a new token from **Enroll a machine** > **Kubernetes** in the enrollment secret and delete the agents' pods.
- **Untick it** when a new token replaces the old one: rotating a cluster's token shouldn't take its nodes offline. The machines stay connected, as before 1.21.0.

The server knows which token enrolled a machine for machines enrolled from 1.21.0 on, and for earlier ones where it is certain: the one-time token that names the host, or the only reusable token that could enroll when the machine did. Machines it can't tie to a token stay connected; remove their hosts to disconnect them.

**Remove revoked tokens** at the top of the list removes every revoked token from it. The machines they enrolled stay as they are, and the **Audit log** page keeps each token's creation and revocation. Unrevoked tokens leave the list 30 days after they are created, or after a reusable one expires.

### When a token is refused

From 1.21.0, the server says why it refuses a token, and the agent prints it: the token was **revoked** (and when), it **expired** (and when), it is a **one-time token already used** to enroll another machine, or the server **doesn't know it**, as when it was made by another server. In Kubernetes, the agent adds what to do: for a used one-time token, that the chart's agents share the secret, so its token must be reusable; otherwise, to put a new token in the secret and delete the pod.

### Agents that enroll themselves

An agent given a token in its environment, as the [DaemonSet](../installation/kubernetes.md) and [Compose](../installation/docker.md) agents are, enrolls by itself:

| Variable | Holds |
| --- | --- |
| `DEACONGUARD_ENROLL_TOKEN_FILE` | The path of a file with the token, such as a mounted secret |
| `DEACONGUARD_ENROLL_TOKEN` | The token itself |

`deaconguard agent run` then enrolls when the agent isn't enrolled yet, when the token is for a server with another certificate (the server was replaced), and when the server no longer knows the agent. So **removing the host of such an agent brings it back** while the token is valid; revoke the token first, or stop the agent. A host disconnected when its token was revoked gets its agent back, as the same host, when that agent enrolls with a new token.

## Automation

For cloud-init, Ansible or golden images, give the token without a prompt. A [reusable token](#reusable-tokens) lets one script enroll every machine:

```bash
# from the environment (cloud-init and Ansible usually run as root, so no sudo)
curl -fsSL https://get.deaconguard.io | DEACONGUARD_TOKEN="$TOKEN" sh -

# from a file, readable by root only
curl -fsSL https://get.deaconguard.io | sudo sh -s -- --agent --token-file /run/secrets/deaconguard-token
```

`--force` enrolls a machine again even if it is already enrolled.

## Names

A host is shown by its machine's hostname, which its agent sends every time it checks in, such as `ip-10-92-0-178` on Amazon EC2. To show it by a name of your own instead, such as `payments-api-prod` (from 1.18.0):

- **In the dashboard:** **Rename** next to the host's name on its page, for operators and admins. Leave the name empty to show the hostname again.
- **When enrolling:** set `DEACONGUARD_NAME`, or pass `--name` to `deaconguard setup agent` or `deaconguard agent enroll`:

  ```bash
  curl -fsSL https://get.deaconguard.io | DEACONGUARD_TOKEN=deaconguard1.… DEACONGUARD_NAME=payments-api-prod sudo -E sh -
  ```

- **Through the API:** `PATCH /api/hosts/{id}` with `{"name": "payments-api-prod"}`.

The name is used everywhere the host is named: the Hosts list, its page, scans and their reports, vulnerabilities, the logs and notifications, including the host's earlier scans. Its hostname stays under the name on the Hosts list and the host's page, and searching the logs finds either. If the machine's hostname changes, the host keeps its name. A name has at most 80 characters, on one line; renames are in the audit log.

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

An agent older than the server shows **Upgrade to** the server's version on the **Agents** page, with the command that upgrades it; see [Which agents to upgrade](../installation/upgrade.md#which-agents-to-upgrade).

The agent checks in with the server every 25 seconds. The dashboard shows an agent as offline when it hasn't checked in for 90 seconds; scans you start for it wait up to an hour for it to reconnect. While it runs a scan, the agent doesn't ask for more work, so the server's log and the **Agents offline** notification wait for it: from 1.18.0, they don't call an agent offline in the middle of a long scan such as an audit.

## Removing an agent

Remove the host in the dashboard. That revokes the agent's credential at once, and the agent service stops (on a Mac, launchd doesn't start it again). To cut off every machine a token enrolled but keep their history, [revoke the token and disconnect them](#revoking-a-token) instead. The credential is stored on the machine in `/etc/deaconguard/agent.json`, readable by root only.
