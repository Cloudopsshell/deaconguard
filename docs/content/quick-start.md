---
title: Quick start
description: Install a DeaconGuard server, enroll a first machine and run a scan.
---

This sets up a DeaconGuard server, scans the server's own machine, then enrolls another machine and scans it. You need a Linux machine running a [supported distribution](./supported-distributions.md) with systemd, and root on it: an account that can use `sudo`, or root itself. For step 2, a second machine.

:::info Runs as root
The installer adds a system package and a service, so run it with `sudo` as shown, or as root without `sudo`. It never asks for a password itself: started without root, it stops before doing anything and shows the command to use.
:::


## 1. Install the server

On the machine that will host the dashboard:

```bash
curl -fsSL https://get.deaconguard.io | sudo sh -
```

The script checks and installs the package, then asks you for the first dashboard account. The password needs at least 12 characters. It also gives this machine an agent of its own, so the server's own machine is scanned as root like every other one (see [How it works](./index.md#how-it-works)). When it finishes it prints the dashboard's addresses, the server certificate's fingerprint, and what runs on the machine:

```text
The DeaconGuard server is running. Open the dashboard and sign in:

  https://dg-server:8443
  https://203.0.113.10:8443

Certificate public key (SHA-256): 5Qf7450fYjqub77irpmvRGyNK-HhiYE-GCAEBIYleEs

What runs on this machine:
  deaconguard-server  the dashboard on port 8443 and the agent API on port 8444, as the deaconguard user, without root
  deaconguard-agent   scans this machine as root and reports to this server; listens on nothing
```

Open one of the addresses and sign in. The server uses a self-signed certificate, so your browser warns about it once; check that the fingerprint matches before you continue.

The server's own machine is already on the **Hosts** page, marked **This server**. Click **Scan now** to scan it, or **Run audit** for a full check graded A to F (see [Server audits](./usage/audits.md)).

:::tip Firewall and two-step sign-in
Don't expose ports 8443 and 8444 to the internet: allow 8443, the dashboard, only from your administrators' networks, and 8444, which agents use, only from your machines' networks. After signing in, turn on two-step sign-in under **My account**, and add accounts for your team on **Accounts** with the [role](./usage/accounts.md#roles) each needs. See [Securing the dashboard](./security/securing-the-dashboard.md).
:::

## 2. Enroll another machine

1. In the dashboard, open **Agents** and click **Enroll a machine**.
2. Check the address agents will use to reach the server, then click **Create token**.
3. Copy the command the dialog shows and run it on the machine you want to scan:

   ```bash
   curl -fsSL https://get.deaconguard.io | DEACONGUARD_TOKEN=deaconguard1.… sudo -E sh -
   ```

   `sudo -E` passes the token to the installer without putting it on a command line other users can see. As root, leave out `sudo -E`.

The machine appears on the **Agents** and **Hosts** pages within a few seconds. The token works once and expires after 24 hours. To run DeaconGuard in [Docker](./installation/docker.md) or [Kubernetes](./installation/kubernetes.md) instead, see those pages.

## 3. Scan it

Open the machine on the **Hosts** page and click **Scan now**. Choose the checks you want; **Package vulnerabilities** is the default. The page shows a live console while the scan runs, and the full report when it finishes.

## Next steps

- Enroll more machines the same way; each needs its own token.
- Read about the [checks](./checks.md) and what each one looks at.
- [Back up](./usage/backup-and-restore.md) `/var/lib/deaconguard/` on the server.
