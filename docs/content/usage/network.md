---
title: TLS and network scans
description: Check TLS certificates and settings, and find open ports and exposed services on networks you own, from the outside, without logging in.
---

Two commands look at machines from the network, as an outsider would: what answers, and how well it protects itself. The server can also run the same scans on a schedule, from the [dashboard](#in-the-dashboard). They need DeaconGuard 1.6.0 or later, and no agent, root or login on the machines.

**Only scan what you own or are allowed to test.** Scanning other people's networks can break the law and their acceptable-use terms, even when nothing is attacked. DeaconGuard only connects and reads what services announce: it never logs in, guesses passwords, sends exploits or floods.

## TLS

`deaconguard tls check` checks TLS services: the certificate, and which protocol versions and cipher suites the server accepts. It only performs TLS handshakes.

```bash
deaconguard tls check shop.example.com mail.example.com:993 10.0.0.12:8443
```

Without a port it checks 443. For a name, the certificate must carry that name. It reports:

- a certificate that has expired, or expires within 14 or 30 days;
- a certificate that isn't trusted (self-signed, or from an authority this machine doesn't trust), or doesn't name the host;
- TLS 1.0 or 1.1 accepted, and TLS 1.3 not offered;
- broken cipher suites accepted (3DES, RC4), and suites without forward secrecy (RSA key exchange);
- a key that is too short (RSA below 2048 bits) or a SHA-1 signature.

```text
shop.example.com:443: TLS 1.3, TLS_AES_128_GCM_SHA256; certificate for shop.example.com, by CN=R11,O=Let's Encrypt,C=US, until 2026-12-28; TLS 1.2, TLS 1.3
Checked TLS on 1 of 1: 0 findings
```

## Network scan

`deaconguard net scan` finds the open TCP ports on the addresses, ranges or names you give, what answers on them, and services that shouldn't be reachable: databases, caches and brokers, the Docker API without TLS, kubelets and etcd, cleartext logins such as Telnet and FTP, and SMB or Remote Desktop.

```bash
deaconguard net scan 10.0.0.0/24
deaconguard net scan 10.0.0.0/24 192.168.1.10 db.internal --tls --fail-on high
```

- **Ports**: about 70 well-known ports by default; `--ports 22,80,443,8000-8100` names others.
- **What answers**: services that greet, such as SSH and FTP, show their greeting; web ports their `Server` header (one `HEAD /` request); and TLS ports are recognised by a handshake. `--tls` also checks each TLS service, as `tls check` does.
- **Limits**: plain TCP connects, at most 64 at a time (`--concurrency`), 2 seconds each (`--timeout`), and at most 4096 addresses per scan (`--max-addresses`); ranges larger than 65536 addresses are refused.

```text
10.0.0.2
   6379/tcp  Redis
10.0.0.4
     80/tcp  HTTP: nginx/1.27.5
10.0.0.5
     22/tcp  SSH: SSH-2.0-OpenSSH_9.6
Scanned 254 addresses: 3 with open ports, 3 open ports: 1 finding (1 high)
  HIGH     10.0.0.2: Redis answers on port 6379 [DG-NET-001]
```

### From the outside

To see what the internet sees, scan your public addresses and names from a machine outside your network, such as a small cloud instance or a CI runner:

```bash
deaconguard net scan shop.example.com 203.0.113.10 --tls --fail-on high --format sarif --output exposure.sarif
```

Anything the scan finds that you didn't mean to publish is open to everyone. `--fail-on`, `--skip`, `--format` and `--output` work as for [pipelines](./ci-cd.md), so the check can run on a schedule in CI and fail when something new appears.

## In the dashboard

The **Network** page keeps network targets the server scans itself, from its own network: each is a list of addresses, ranges and names, the ports to try, and how often to scan (hourly, every 6 or 12 hours, daily, weekly, or only on **Scan now**).

1. An admin clicks **Add target**, and gives it a name and one address, range (at most a /20) or name per line, at most 4096 addresses in all. **Ports** left empty means the default ports. **Check the TLS** of each TLS service found is on unless you clear it.
2. **Add and scan** saves it and starts the first scan. Operators can press **Scan now** at any time.
3. Open the target to see its latest result: the findings, every open port with what answered on it, and the certificate and protocols of each TLS service. **Scan history** keeps the newest 20 scans; click one to see what it found.

Scans run one at a time, 32 connections at a time, and stop after an hour. A scan the server was running when it stopped is marked failed, and the next one runs on schedule. With [notifications](./notifications.md), a scan that finds critical or high findings its previous scan didn't sends **New network findings**, and a scan that fails sends **Failed scans**.

The server scans from where it runs. To see what the internet sees, run `deaconguard net scan` [from outside](#from-the-outside) too.

## Rules

| Rule | Severity | Finding |
| --- | --- | --- |
| `DG-NET-001` | High | A database, cache or message broker answers on the network (MySQL, PostgreSQL, SQL Server, Oracle, Redis, MongoDB, Elasticsearch, Memcached, CouchDB, Cassandra, InfluxDB, Kafka, ZooKeeper, RabbitMQ, MQTT) |
| `DG-NET-002` | Critical | The Docker API answers without TLS (port 2375) |
| `DG-NET-003` | High | A Kubernetes node or etcd port answers (kubelet 10250 and 10255, etcd 2379 and 2380) |
| `DG-NET-004` | High | A cleartext remote-access service answers (Telnet, FTP, rlogin, rsh, rexec, VNC) |
| `DG-NET-005` | Medium | Windows file sharing or Remote Desktop answers (SMB, NetBIOS, RDP) |
| `DG-TLS-001` | Critical | The certificate has expired |
| `DG-TLS-002` | High | The certificate expires within 14 days |
| `DG-TLS-003` | Medium | The certificate expires within 30 days |
| `DG-TLS-004` | Medium | The certificate isn't trusted (self-signed or an unknown authority) |
| `DG-TLS-005` | High | The certificate doesn't name the host |
| `DG-TLS-006` | High | TLS 1.0 or 1.1 is accepted |
| `DG-TLS-007` | Medium | A broken cipher suite is accepted (3DES, RC4) |
| `DG-TLS-008` | Medium | The certificate's key is too short |
| `DG-TLS-009` | Medium | The certificate is signed with SHA-1 |
| `DG-TLS-010` | Low | TLS 1.3 isn't offered |
| `DG-TLS-011` | Low | Cipher suites without forward secrecy are accepted |
