---
title: Docker and Compose
description: Run the DeaconGuard server, and an agent for the Docker host, in containers.
---

DeaconGuard publishes a container image for every release:

```text
ghcr.io/cloudopsshell/deaconguard:@RELEASE@
```

It's the same binary as the packages, for **amd64 and arm64**, on Chainguard's minimal static base image: no shell and no package manager, running as the non-root user `nonroot` (65532). Its entrypoint is `deaconguard`, so the container's command is a DeaconGuard command, such as `serve …` or `agent run`. The image is [signed keyless](../security/verify-a-release.md#the-container-image-and-the-helm-chart) like the release files, and carries its SBOM in the registry. Tags: the version, such as `@RELEASE@`, the minor version, such as `@RELEASE_MINOR@`, and `latest`. Pin the exact version; `https://get.deaconguard.io/stable.txt` holds the latest.

## Docker Compose

[`deploy/compose/compose.yaml`](https://github.com/Cloudopsshell/deaconguard/blob/main/deploy/compose/compose.yaml) runs the server, with its data in a volume:

```bash
mkdir deaconguard && cd deaconguard
VERSION=$(curl -fsSL https://get.deaconguard.io/stable.txt)
curl -fsSLO "https://raw.githubusercontent.com/Cloudopsshell/deaconguard/v${VERSION}/deploy/compose/compose.yaml"
printf '%s' 'a-long-password' > admin-password && chmod 600 admin-password && sudo chown 65532 admin-password
docker compose up -d
docker compose logs server
```

Compose mounts the file as it is, so it must be readable by the image's user, 65532, hence the `chown`. Open `https://THIS-MACHINE:8443` and sign in as `admin` with that password (at least 12 characters). The server creates a self-signed certificate on its first start; the log shows its fingerprint. Then delete `admin-password`: it's only read while there is no account.

What the file sets up:

| | |
| --- | --- |
| Command | `serve --listen 0.0.0.0:8443 --agent-listen 0.0.0.0:8444`: the dashboard on 8443, and a [port for agents](../security/securing-the-dashboard.md#give-agents-their-own-port) on 8444 |
| First account | `DEACONGUARD_ADMIN_USER=admin`, with the password from the `admin-password` [secret](https://docs.docker.com/compose/how-tos/use-secrets/) through `DEACONGUARD_ADMIN_PASSWORD_FILE` |
| Data | the `data` volume, at `/home/nonroot` (`DEACONGUARD_HOME`): the database, the certificate and the feed cache |
| Hardening | read-only root filesystem, no Linux capabilities, `no-new-privileges` |

Keep ports 8443 and 8444 away from the internet: see [Securing the dashboard](../security/securing-the-dashboard.md). `"8443:8443"` and `"8444:8444"` publish them on **every address of the host**, so other machines can reach them; that is how agents on other machines connect to 8444. Docker writes its own firewall rules for published ports, which `ufw` and firewalld don't filter, so limit them with a firewall in front of the host, such as a cloud security group. If no agent outside the host connects, publish the agent port on loopback only: `"127.0.0.1:8444:8444"`.

### Scan the Docker host too

The `agent` service, in the `agent` profile, scans the machine Compose runs on, not its container:

1. On the **Agents** page, choose **Enroll a machine**. As the server address, use `https://127.0.0.1:8444`, and create the token. That works here because the agent runs with `network_mode: host`: its `127.0.0.1` is the Docker host's, where Compose publishes the server's port 8444. For agents on other machines, use the host's address instead, such as `https://10.0.1.5:8444`.
2. Save it next to `compose.yaml`:

   ```bash
   printf '%s' 'deaconguard1.…' > enrollment-token && chmod 600 enrollment-token
   docker compose --profile agent up -d
   ```

3. The machine appears on the **Agents** page under its host name. The agent keeps its identity in the `agent` volume, so it enrolls only once; delete `enrollment-token` afterwards if you like.

The agent reads the host's root filesystem, mounted **read-only** at `/host`, and runs its checks there with the host's own tools: `dpkg` or `rpm`, `sshd -T`, `sysctl`, `ss`, ClamAV. So its results are the same as an agent [installed on the host](./install-script.md), and the host needs those tools installed for the checks that use them. For that, the container:

- runs as root, with the host's process list (`pid: host`) and network (`network_mode: host`);
- has only the capabilities the checks need: `SYS_CHROOT` to run them in the host's root, `DAC_READ_SEARCH` and `DAC_OVERRIDE` to read every file, `NET_ADMIN` and `AUDIT_CONTROL` to list firewall and audit rules, `SYS_PTRACE` to see every process;
- mounts the host's `/tmp` writable at `/host/tmp`, where the [advanced malware scan](../checks.md#the-advanced-antivirus-scan) writes its rules for a moment.

### Use your own certificate

Mount the certificate and key, and pass them to `serve`:

```yaml
services:
  server:
    command: [serve, --listen, "0.0.0.0:8443", --agent-listen, "0.0.0.0:8444",
              --tls-cert, /run/secrets/tls.crt, --tls-key, /run/secrets/tls.key]
    secrets: [admin-password, tls.crt, tls.key]
secrets:
  tls.crt: {file: ./tls.crt}
  tls.key: {file: ./tls.key}
```

The files must be readable by user 65532. Agents enrolled earlier keep working when their system trusts the new certificate for the server's name; otherwise [enroll them again](../usage/agents.md).

### Behind a reverse proxy

Add `--trusted-proxy` with the proxy's address or network to the command, or set `DEACONGUARD_TRUSTED_PROXIES`, so sign-in limits and the audit log see each browser's address instead of the proxy's. See [Behind a reverse proxy](../security/securing-the-dashboard.md#behind-a-reverse-proxy).

## Plain Docker

```bash
docker volume create deaconguard
printf '%s' 'a-long-password' > admin-password && chmod 600 admin-password && sudo chown 65532 admin-password
docker run -d --name deaconguard --restart unless-stopped \
  -p 8443:8443 -p 8444:8444 \
  -v deaconguard:/home/nonroot \
  -v "$PWD/admin-password:/run/secrets/admin-password:ro" \
  -e DEACONGUARD_HOME=/home/nonroot \
  -e DEACONGUARD_ADMIN_USER=admin -e DEACONGUARD_ADMIN_PASSWORD_FILE=/run/secrets/admin-password \
  --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
  ghcr.io/cloudopsshell/deaconguard:@RELEASE@ serve --listen 0.0.0.0:8443 --agent-listen 0.0.0.0:8444
```

The volume must be mounted at `/home/nonroot`: the image's user owns that directory, so a new volume there is writable without root.

## Manage the server

Commands run in the container, as its user, with its data directory:

```bash
docker compose exec server deaconguard user list
docker compose exec server deaconguard user passwd admin
docker compose exec server deaconguard token create --server-url https://HOST:8444 --reusable --days 30
```

Upgrade, back up and remove it as described in [Upgrade](./upgrade.md#docker-compose), [Back up and restore](../usage/backup-and-restore.md#in-a-container) and [Uninstall](./uninstall.md#docker-compose).
