---
title: TLS, network and web checks
description: Check TLS certificates and settings, find open ports and exposed services on networks you own, and check web sites for published files and missing protections, from the outside, without logging in.
---

Three commands look at machines from the network, as an outsider would: what answers, and how well it protects itself. The server can also run the same scans on a schedule, from the [dashboard](#in-the-dashboard). They need DeaconGuard 1.6.0 or later (web checks 1.25.0), and no agent, root or login on the machines.

**Only scan what you own or are allowed to test.** Scanning other people's networks can break the law and their acceptable-use terms, even when nothing is attacked. DeaconGuard only connects and reads what services announce, and asks web sites for a few pages with GET requests: it never logs in, guesses passwords, submits forms, sends exploits or floods.

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

## Web sites

`deaconguard web check` checks web sites as a visitor who isn't logged in sees them (1.25.0 and later):

```bash
deaconguard web check https://shop.example.com http://10.0.0.4:8080
deaconguard net scan 10.0.0.0/24 --tls --web
```

A bare name, such as `shop.example.com`, is checked as `https://`. `net scan --web` checks each web site the scan finds: plain HTTP on the web ports (80, 3000, 5000, 5601, 8000, 8080, 8081, 8086, 8500, 8888, 9000, 9090, 9100 and 15672), and HTTPS on 443, 8443 and 9443.

| It checks | How |
| --- | --- |
| Files and pages that should never be public | Asks for `/.git/HEAD`, `/.env`, `/.svn/entries`, `/server-status`, `/phpinfo.php`, `/info.php`, `/actuator/env` and `/metrics`. One counts only when its content looks like that file, such as a `.git/HEAD` that starts with `ref:`, so a site that answers every address with its home page isn't reported. |
| CORS | Asks for the home page as if from another website. Reported when the site trusts that origin with the visitor's cookies. |
| HTTPS | Plain HTTP that doesn't redirect to HTTPS, when the same host serves HTTPS on port 443; HSTS on HTTPS sites. |
| Cookies | `Secure` on HTTPS sites; `HttpOnly` and `SameSite`. |
| Pages | `Content-Security-Policy`, protection against framing, `X-Content-Type-Options: nosniff`, and directory listing. Only for HTML pages, not APIs. |
| Versions | `Server`, `X-Powered-By` and `X-AspNet-Version` headers that name a version. |

**What it sends:** GET requests only, one at a time, about 15 for each site; `--no-paths` leaves out the paths above, and leaves two (the home page, and the home page as if from another website). Redirects are followed on the same host only, at most 3. At most 64 KB of each answer is read; certificates aren't checked here, as that's what `--tls` and `tls check` do. A network scan checks 4 sites at a time. Requests carry the user agent `DeaconGuard/VERSION (web check; ...)`, so you can find them in your logs; a strict web application firewall may log the paths, or briefly block the address they come from.

It doesn't crawl, log in, submit forms or match server versions to vulnerabilities: a clean result means none of these problems were found, not that the site is secure.

## In the dashboard

The **Network** page keeps network targets the server scans itself, from its own network: each is a list of addresses, ranges and names, the ports to try, and how often to scan (hourly, every 6 or 12 hours, daily, weekly, or only on **Scan now**).

1. An admin clicks **Add target**, and gives it a name and one address, range (at most a /20) or name per line, at most 4096 addresses in all. **Ports** left empty means the default ports. **Check the TLS** of each TLS service found is on unless you clear it, and so is **Check every web site found**, with **Look for files and pages that should never be public** under it ([web sites](#web-sites)). Targets added before 1.25.0 don't check web sites until you edit them and tick it.
2. **Add and scan** saves it and starts the first scan. Operators can press **Scan now** at any time.
3. Open the target to see its latest result: the findings, every open port with what answered on it, the certificate and protocols of each TLS service, and each web site checked. **Scan history** keeps the newest 20 scans; click one to see what it found.

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
| `DG-WEB-001` | Critical | A Git repository is published (`/.git/HEAD`) |
| `DG-WEB-002` | Critical | An environment (`.env`) file is published |
| `DG-WEB-003` | High | A Subversion working copy is published (`/.svn/entries`) |
| `DG-WEB-004` | High | A server status or PHP information page is public |
| `DG-WEB-005` | High | Spring Boot's environment endpoint is public (`/actuator/env`) |
| `DG-WEB-006` | Medium | Prometheus metrics are public (`/metrics`) |
| `DG-WEB-007` | High | CORS lets any website read responses with the visitor's cookies |
| `DG-WEB-008` | Medium | The site answers over plain HTTP without redirecting to HTTPS |
| `DG-WEB-009` | Medium | Directory listing is on |
| `DG-WEB-010` | Medium | Cookies are set without Secure on HTTPS |
| `DG-WEB-011` | Low | Cookies are set without HttpOnly or SameSite |
| `DG-WEB-012` | Medium | HTTPS without HSTS, or with HSTS shorter than 180 days |
| `DG-WEB-013` | Low | Pages have no Content-Security-Policy |
| `DG-WEB-014` | Low | Pages can be framed by other sites |
| `DG-WEB-015` | Low | Pages don't set X-Content-Type-Options: nosniff |
| `DG-WEB-016` | Low | The server names its software version |
