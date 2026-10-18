---
title: Local mode
description: Scan a single machine without a server or accounts.
---

Local mode checks the machine DeaconGuard runs on, without a server, agents or accounts.

| | Server | Local mode |
| --- | --- | --- |
| For | one dashboard for many machines | one machine on its own |
| Dashboard | `https://SERVER:8443`, with sign-in | `http://127.0.0.1:7480`, this machine only, no sign-in |
| Scans | every machine with an agent, as root, the server's own included | only this machine |

## Dashboard

```bash
deaconguard host add        # add --allow-sudo to let the deeper checks use sudo
deaconguard serve           # then open http://127.0.0.1:7480
```

The local dashboard listens only on a loopback address and rejects requests addressed to other host names or sent from other websites.

## Terminal

```bash
deaconguard host list
deaconguard scan HOST_ID --checks packages,malware,config
deaconguard report REPORT_ID --json
```

A one-off scan without registering the machine:

```bash
deaconguard scan --local --checks packages,integrity,malware,config --allow-sudo
```
