---
title: Backup and restore
description: Back up and restore DeaconGuard's data.
---

All data lives in one directory:

| Installation | Directory |
| --- | --- |
| Server service | `/var/lib/deaconguard/` |
| Local mode | `~/.local/share/deaconguard/` |
| Either, if set | the directory in `DEACONGUARD_HOME` |

It holds:

- `deaconguard.db`: hosts, scan results, audits, reports, activity logs, accounts, tokens, [notification](./notifications.md) channels (with mail passwords and webhook addresses) and the audit log. Passwords are stored as PBKDF2 hashes; recovery codes, tokens and credentials as SHA-256 hashes. Authenticator keys for two-step sign-in are stored as is, because checking a code needs them, so keep backups as safe as the server.
- `tls/`: the server's certificate and key. **Keep them:** agents trust this key.
- `feeds/`: a cache of advisory data, downloaded again if missing.

Files are readable only by their owner.

## Back up

Stop the server, copy the directory, start it again:

```bash
sudo systemctl stop deaconguard-server
sudo cp -a /var/lib/deaconguard /root/deaconguard-backup-$(date +%Y%m%d)
sudo systemctl start deaconguard-server
```

## Restore

Stop the server, put the backup back in place with its ownership, and start it:

```bash
sudo systemctl stop deaconguard-server
sudo rm -rf /var/lib/deaconguard
sudo cp -a /root/deaconguard-backup-YYYYMMDD /var/lib/deaconguard
sudo systemctl start deaconguard-server
```

Agents keep working as long as the restored `tls/` directory holds the same key.

## In a container

The server's data is in `/home/nonroot`, on the `data` volume with [Compose](../installation/docker.md) or the PersistentVolumeClaim `data-deaconguard-0` in [Kubernetes](../installation/kubernetes.md). Back it up with your platform's volume snapshots, or stop the server and copy it:

```bash
docker compose stop server
docker run --rm -v deaconguard_data:/data:ro -v "$PWD:/backup" alpine tar -C /data -czf /backup/deaconguard-$(date +%Y%m%d).tgz .
docker compose start server
```

In Kubernetes, scale the server to zero first (`kubectl -n deaconguard scale statefulset/deaconguard --replicas=0`) and back to one afterwards. Restore by putting the files back on the volume, owned by user 65532.
