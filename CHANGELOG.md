# Changelog

All notable changes to DeaconGuard are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and DeaconGuard uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Breaking changes
only come in a new major version; they are listed under **Changed** with
upgrade notes.

## [Unreleased]

### Added

- **Passkeys:** on **My account**, add passkeys (WebAuthn) kept on the device, a phone or a password manager, then choose **Sign in with a passkey**: a fingerprint, face or device PIN, with no password or code. A passkey counts as two-step sign-in, by itself or as the second step after the password, and also meets **Require it**. Only the public key is stored; DeaconGuard checks ES256, EdDSA and RS256 signatures itself, needs user verification, and refuses a passkey whose counter goes back. Passkeys need the dashboard on a name with a trusted certificate. Resetting an account's two-step sign-in, on the Accounts page or with `user mfa-reset`, removes its passkeys too. The database moves to schema 25.
- **Single sign-on:** **Settings → Single sign-on** connects an OpenID Connect provider, such as Microsoft Entra ID, Google, Okta, Keycloak, Authentik or Dex, and the sign-in page offers it next to passwords. Accounts are made at the first sign-in, named by the verified email or the username, and linked to the provider's ID for the person; they have no password. Sign-in can be limited to email domains or groups, and admin and operator groups set roles at every sign-in. DeaconGuard uses the code flow with PKCE, state and nonce, and checks ID tokens itself (RS256, RS384, RS512, PS256, ES256, ES384). The database moves to schema 26.

## [1.6.0] - 2026-10-20

### Added

- **TLS checks:** `deaconguard tls check HOST[:PORT]...` checks a TLS service with handshakes only: a certificate expired or expiring within 14 or 30 days, untrusted or for another name, a short key or a SHA-1 signature; TLS 1.0 or 1.1 accepted, TLS 1.3 missing; 3DES or RC4 accepted, and suites without forward secrecy.
- **Network scans:** `deaconguard net scan TARGET...` finds open TCP ports on addresses, ranges and names you own, with each service's greeting, web server header or TLS, and reports exposed databases, caches and brokers, the Docker API without TLS, kubelets and etcd, cleartext logins, and SMB or Remote Desktop. `--tls` checks each TLS service it finds. Plain TCP connects, 64 at a time, at most 4096 addresses per scan. Run from outside your network, it shows what the internet sees.
- **Network in the dashboard:** a new **Network** page keeps network targets (addresses, ranges up to a /20 and names, at most 4096 addresses each) that the server scans itself, hourly to weekly or on **Scan now**, with each target's open ports, services, TLS and findings, and its newest 20 scans. Admins add and change targets; operators scan them. The database moves to schema 24.
- **New network findings** notifications: critical and high findings a network target's previous scan didn't have, as a new event, `exposure`.

### Changed

- SARIF reports of config and cluster scans carry each finding's DISA STIG IDs as a `stig` property too, besides naming them in the message.

## [1.5.0] - 2026-10-19

### Added

- **Kubernetes clusters:** `deaconguard kube scan` checks a running cluster through the Kubernetes API, read-only (list and get, no secrets). It covers workloads and RBAC with the manifest rules; namespaces with pods but no NetworkPolicy or no enforced Pod Security Standard; the Kubernetes version past its end of life or behind its latest patch (from endoflife.date); Kubernetes' own CVEs (from OSV, sending only the version); and, where the API server runs as a pod (kubeadm), its authorization, anonymous access, audit log, encryption of secrets and profiling. `--images` reads each running image from its registry and reports those a newer build fixes. Kubernetes' own objects are left out unless `--include-system`. It logs in with the kubeconfig (certificates, tokens, exec plugins such as EKS, GKE and AKS logins) or, in a pod, its service account. A read-only ClusterRole, without secrets, is in the docs.
- **Clusters in the dashboard:** the Helm chart's cluster agent (`cluster.enabled=true`) checks the cluster it runs in, as one unprivileged pod with that read-only role, and enrolls with a token like a machine's agent. The cluster appears on **Hosts** as a Kubernetes cluster and runs a new check, **Kubernetes**, from **Scan now** or a schedule; the server adds the version's support and CVEs to what the agent read. Machines can't run the Kubernetes check and clusters can't run the others; a schedule runs on each host the checks that apply to it. The database moves to schema 23 (a host's kind).
- **Scan when the cluster changes:** the cluster agent watches workloads, roles, namespaces and network policies through the API, and the server checks the cluster within about a minute of a change a scan would see (not rollouts or restarts), at most once a minute. Turn it on from the cluster's page. A count the server defers is kept by the agent for later, for new containers too.
- **New cluster findings** notifications: critical and high findings a cluster's previous scan didn't have, as a new event, `cluster`.
- **Admission warnings:** `cluster.admission.enabled=true` makes the cluster agent a validating webhook in warn mode: `kubectl apply` shows DeaconGuard's findings for each workload and role, at or above `cluster.admission.severity`, and nothing is blocked (`failurePolicy: Ignore`). The chart makes and keeps its certificate.
- **DISA Kubernetes STIG:** findings of rules that check what a DISA Kubernetes STIG (V2R6) rule checks name it, such as V-242390, in their detail and in JSON and SARIF. Two rules come from the STIG: workloads in the `default` namespace (V-242383) and the Kubernetes dashboard installed (V-242395).

## [1.4.0] - 2026-10-19

### Added

- **Images in pipelines:** `deaconguard image scan` also reads a `docker save` or `podman save` archive (gzip-compressed or not), an OCI image layout (a folder or a tar, with `--platform` for several platforms), or a folder (`dir:`): an unpacked image, a chroot or a project with lock files. Archive layers are checked against their digests; links in a folder are never followed outside it. Prefixes `docker-archive:`, `oci:` and `dir:` say which; without one, DeaconGuard looks.
- **Reports for CI:** `--format sarif` (SARIF 2.1.0 for GitHub code scanning and others, with `security-severity`), `--format junit` (a test case per vulnerability; those at or above `--fail-on` fail), `--format cyclonedx` and `--format spdx` (the image's SBOM), and `--format json`, which now lists every vulnerability with `fixable` and `known_exploited`. `--output FILE` writes the report to a file and keeps the summary in the log.
- **Dockerfiles and Kubernetes manifests:** `deaconguard config scan PATH...` checks Dockerfiles and Containerfiles (running as root, unpinned bases, secrets in ENV and ARG, unchecked downloads, sudo, SSH, world-writable files, no .dockerignore or HEALTHCHECK) and Kubernetes workloads and RBAC (the Pod Security Standards' baseline and restricted rules, NSA/CISA guidance such as read-only root file systems and memory limits, unpinned images, secrets in manifests, cluster-admin bindings, wildcard roles, reading secrets, escalation). Folders are walked; `-` reads `helm template` or `kubectl kustomize` output. Findings have file and line, in table, JSON, SARIF or JUnit, and `--fail-on` exits with status 4. Accept a finding with the `deaconguard.io/ignore` annotation, a `# deaconguard:ignore` comment, or `--skip`. `deaconguard config rules` lists the 31 rules.
- **GitHub Action:** `uses: Cloudopsshell/deaconguard@v1.4.0` checks an image (`scan: image`) or Dockerfiles and manifests (`scan: config`), with `fail-on`, `ignore-unfixed`, `skip`, a report in any format, an optional upload to code scanning, a registry login sent only to its registry, and the advisory data cached between runs. It installs the release it is pinned to, after checking its signature and checksum.
- **GitLab CI template:** `ci/gitlab/deaconguard.gitlab-ci.yml` has `.deaconguard-image` and `.deaconguard-config` jobs to extend: JUnit test reports, SARIF artifacts and the image's CycloneDX SBOM, in `alpine:3.22` without Docker or privileges, logging in to `$CI_REGISTRY` only. The docs have examples for Jenkins, Bitbucket Pipelines and Azure DevOps.
- **`ci/install.sh`:** installs only the `deaconguard` command for a CI job, without root, after checking the release's cosign signature and the archive's checksum.
- **`DEACONGUARD_REGISTRY`:** limits the login in `DEACONGUARD_REGISTRY_USERNAME` and `_PASSWORD` to one registry, so a CI job's login for its own registry never reaches another.
- **`--ignore-unfixed`:** `--fail-on` counts, and reports list, only vulnerabilities an update fixes or that are known to be exploited.

## [1.3.0] - 2026-10-19

### Added

- **Images in registries:** `deaconguard image scan IMAGE` reads an image from its registry (Docker Hub, GHCR, Quay, Harbor, GitLab, Artifact Registry, ACR, ECR or any registry API v2), without pulling it into Docker or running it, and checks its packages and libraries as a running container is checked. Layers are read as they download, checked against their digests, and what was read is cached by digest (at most 2 GB), so shared base layers are read once. `--platform` picks a platform of a multi-platform image, `--fail-on` exits with status 4 at or above a severity, for pipelines, and `--json` prints everything. A login for private images comes from `DEACONGUARD_REGISTRY_USERNAME` and `DEACONGUARD_REGISTRY_PASSWORD`.
- **Images page:** the dashboard checks registry images too. Operators add an image by name and platform and press **Scan now**; the server reads it, one image at a time, and keeps its last 20 scans with their digests and results. Admins save **registry logins** for private registries; the token is stored on the server and never shown again. The API has `/api/images`, `/api/image-scans/{id}` and `/api/registry-logins`. The database moves to schema 22.
- **Watch images for new builds:** a watched image (the default) has its tag checked every 15 minutes with a `HEAD` request, which downloads nothing and doesn't count against Docker Hub's pull limits, and is scanned again when the tag moves to a new build, and once a day for new advisories. New known exploited and critical vulnerabilities in an image, and failed image scans, go to the notification channels subscribed to those events. To scan right after a push, CI calls `POST /api/images/{id}/scans` with an API token.
- **Amazon ECR logins:** save an AWS access key for an ECR registry; DeaconGuard gets ECR's 12-hour registry password from the ECR API when it needs one (Signature Version 4, no AWS SDK). The docs say what to save for Artifact Registry, ACR, GHCR and Docker Hub.

## [1.2.0] - 2026-10-18

### Added

- **Running containers:** a new check, `containers`, finds the containers running on a machine (Docker, Podman, and containerd or CRI-O through `crictl`, such as Kubernetes nodes) and checks each one's OS packages against its distribution's advisories and its libraries against OSV, with its release support. Nothing inside a container is run: the agent reads each container's files itself through `/proc/PID/root` and never follows a symbolic link there, so a container can't make it read a host file. RPM-based images are read from `rpmdb.sqlite` directly; distroless images from `status.d`. Containers with the same contents are checked once. The scan's **Running containers** tab lists every container with its OS, support, vulnerabilities and what to fix in its image. It needs agent 1.2.0 or later, as root; the Kubernetes DaemonSet already qualifies.
- **Scan new containers automatically:** a per-machine setting on an agent's host page (off by default). The agent looks at the running container IDs about once a minute and tells the server when new ones start; the server then queues a Running containers scan, at most one every 10 minutes per machine and never while another of its scans is queued or running. Also `PATCH /api/hosts/{id}` with `auto_scan_containers`.
- **Alpine Linux** 3.18 and later: installed packages (`/lib/apk/db/installed`) are checked against Alpine's security database for the main and community repositories, with Alpine's own version ordering. Alpine lists only vulnerabilities it has fixed, and rates none, so each CVE's severity is its CVSS v3 score from OSV (only CVE IDs are sent), or unknown when none is published. The release lifecycle uses Alpine's published end-of-life dates. The install script still needs systemd, so on Alpine machines run the agent from the release archive or its container image.

## [1.1.0] - 2026-10-18

### Added

- **Application libraries:** a new check, `libraries`, finds the libraries applications use and checks them against [OSV](https://osv.dev). It reads npm (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, global packages), Python (installed packages and virtualenvs, `poetry.lock`, `Pipfile.lock`, pinned `requirements.txt`), Go (`go.mod`), Ruby (`Gemfile.lock`), Rust (`Cargo.lock`) and PHP (`composer.lock`). The distribution's own copies in `/usr/lib` and `/usr/share` are left to the package check. Findings have the OSV and CVE IDs, severity, fixed versions and CISA KEV and EPSS exploit data; one vulnerability listed under several IDs is shown once. Only the server talks to OSV, and it sends only library names and versions. If OSV can't be reached, the check fails rather than looking clean. Choose it in the scan dialog or with `--checks libraries`; it needs agent 1.1.0 or later and isn't part of server audits yet.
- **SBOM:** every scan can be downloaded as a software bill of materials of its OS packages and libraries, in CycloneDX 1.6 or SPDX 2.3 JSON with package URLs: **SBOM** on the scan's page, `deaconguard sbom SCAN_ID [--format cyclonedx|spdx]`, or `GET /api/scans/{id}/sbom`. Scans from before 1.1.0 have none.

### Changed

- **Documentation** now lives in the repository's `docs/` folder and is published to docs.deaconguard.io from each release.
- **Upgrading:** upgrade the server first, then the agents; an agent before 1.1.0 is refused the library check with a message saying to upgrade it. The server needs HTTPS access to `api.osv.dev` for the library check.

## [1.0.2] - 2026-10-18

### Fixed

- **Compose and Kustomize:** the files in `deploy/` now pin the image of their own release. At 1.0.1 they still deployed image 1.0.0 (the same code, so nothing behaved differently). A check in the release workflow now stops a release whose deploy files name another version.

## [1.0.1] - 2026-10-17

### Fixed

- **Packages:** the `.deb` and `.rpm` packages now depend on `ca-certificates`, and the `.rpm` recommends `ca-certificates-mozilla` for SUSE. On a minimal system without a CA bundle, the server couldn't download any advisory feed ("x509: certificate signed by unknown authority"). The install script was not affected.

## [1.0.0] - 2026-10-17

The first stable release, and the first published from this repository. DeaconGuard was developed as versions 0.1.0 to 0.19.0 before this; those releases are not republished here. Notes in the documentation such as "agents before 0.16.0" refer to them.

### Added

- **Server and agents:** one binary. The server runs without root and serves an HTTPS dashboard and API; an agent on each machine, the server's own included, scans as root, connects out to the server, and listens on nothing. Agents enroll with single-use or reusable enrollment tokens and can use a port of their own. `deaconguard serve` also runs a local dashboard for one machine without sign-in.
- **Package vulnerabilities** from each distribution's own security data, with fixed versions and what clears each finding, prioritised by known exploitation (CISA KEV), likely exploitation (EPSS), CVSS and the distribution's severity. Supported: Ubuntu 18.04 to 26.04 LTS, Debian 12 and 13, Red Hat Enterprise Linux 8 and 9, Rocky Linux, AlmaLinux and Oracle Linux 8 to 10, Fedora 40 and later, openSUSE Leap 15.6 and 16.0, SUSE Linux Enterprise 15 SP6 and later and 16, and Amazon Linux 2023. Each scan shows whether the release still gets security fixes.
- **Optional checks:** system file integrity, malware and compromise indicators, security configuration, and an antivirus scan: Basic with ClamAV, or Advanced with ClamAV and the YARA Forge core rules run by YARA-X.
- **Server audits:** a hardening audit against the 72 controls of the DeaconGuard Linux baseline, with a grade, evidence and a fix for each control, accepted risks with a reason and an expiry, a server inventory, compliance views for NIST SP 800-53, PCI DSS 4.0, HIPAA and ISO/IEC 27001, and custom policies in YAML.
- **Reports** in PDF, HTML, CSV, XLSX and JSON, with your company's branding, before-and-after comparisons, expiring share links, and a **Verify a report** page for each report's ID and fingerprint.
- **Dashboard:** hosts, tags, vulnerability trends, scan history, scheduled scans that run as root by default, maintenance windows, fix deadlines, a Logs page, light, dark and system modes, and five colour themes.
- **Accounts:** two-step sign-in with any authenticator app (can be required for everyone), Admin, Operator and Viewer roles, API tokens, and an audit log.
- **Notifications** by email, Slack, Microsoft Teams, webhooks, syslog, Splunk, Jira and ServiceNow, for newly exploited or critical vulnerabilities, malware, changed system files, failed scans, audits, offline agents, and daily or weekly digests.
- **Install and hosting:** an install script for servers and agents that verifies the release signature and installs the tools the checks use; `.deb` and `.rpm` packages and archives for Linux and macOS; a container image, a Helm chart, Docker Compose and Kustomize files; and keyless Sigstore signatures on every release.

### Changed

- **Upgrading from 0.x:** run the install script again, or install the new package, on the server first and then on each agent. The database is upgraded in place and no settings change.
- **Versions:** from 1.0.0, minor releases add features without breaking changes; anything that breaks an upgrade, the CLI, or the API needs a new major version.

### Security

- Updated excelize, the Excel report library, to a commit that fixes 15 advisories in reading workbooks (GHSA-mx22-3794-2vpv and others). DeaconGuard only writes workbooks, so none of them could be reached.

[Unreleased]: https://github.com/Cloudopsshell/deaconguard/compare/v1.6.0...HEAD
[1.6.0]: https://github.com/Cloudopsshell/deaconguard/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/Cloudopsshell/deaconguard/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/Cloudopsshell/deaconguard/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/Cloudopsshell/deaconguard/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/Cloudopsshell/deaconguard/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/Cloudopsshell/deaconguard/compare/v1.0.2...v1.1.0
[1.0.2]: https://github.com/Cloudopsshell/deaconguard/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/Cloudopsshell/deaconguard/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/Cloudopsshell/deaconguard/releases/tag/v1.0.0
