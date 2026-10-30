# Changelog

All notable changes to DeaconGuard are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and DeaconGuard uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Breaking changes
only come in a new major version; they are listed under **Changed** with
upgrade notes.

## [Unreleased]

### Fixed

- The access log leaves out Kubernetes health checks (requests from `kube-probe`), as it does agents' and the dashboard's routine polls, unless they fail. They added about eight lines a minute to `kubectl logs`.

## [1.17.0] - 2026-10-29

### Added

- **Access log:** `deaconguard serve --access-log`, `DEACONGUARD_ACCESS_LOG=1`, or the Helm value `server.accessLog: true` writes a line to standard output for each request, as `ACCESS GET /api/summary 200 38ms user=admin ip=203.0.113.7`: method, path (never the query string), status, duration, account and client address. Agents' job polls and the dashboard's sudo-prompt polls are left out unless they fail.

### Changed

- Each server line on standard output starts with its level (`INFO`, `WARNING`, `ERROR`), and "Press Ctrl+C to stop." is printed only when the server runs in a terminal, not under systemd or in a container.
- **Scans no longer read large advisory feeds again each time.** The server reads Ubuntu's, Debian's, Red Hat's, AlmaLinux's, Oracle Linux's and SUSE's feeds, and Rocky Linux's and Fedora's updateinfo, once per download and keeps them parsed for the scans that follow, of machines and images alike. A second scan of an Ubuntu 24.04 machine or image no longer spends several seconds of CPU (half a minute on a small server, which the High CPU log line from 1.16.0 found) reading Canonical's OVAL: it takes about 70 ms. Parsed feeds take up to about 400 MB, the least recently used going first, and go after 30 minutes without a scan; `DEACONGUARD_FEED_CACHE_MB` or the Helm value `server.feedCacheMB` changes it, and `0` turns it off. The Ubuntu feed is also kept in less memory: repeated values once, and no spare room.

### Fixed

- When an Amazon ECR key may not list repositories, Browse says which permissions to add and shows AWS's own reason, without the misleading advice to check the login.

## [1.16.0] - 2026-10-29

### Added

- **Finding out why the server is busy:** the Logs page and the server's standard output now record requests that take more than 2 seconds, with the CPU the server used meanwhile, and a watchdog that, when the server keeps more than one core busy for 30 seconds, logs which parts of DeaconGuard's code the time went to and which requests were running. Admins can also download a 30-second CPU profile from the Logs page (`GET /api/diagnostics/cpu`).
- The **Vulnerabilities over time** chart shows a day's numbers by severity in a box at the pointer, marks each band, works with touch, and says when nothing changed over the period.

### Fixed

- The dashboard's vulnerability counts read every finding of every scan a host kept, finding its latest scan again for each one; they now find each host's latest scan once. For a host with about 12,000 findings over 10 scans, the dashboard summary's queries take about 40 ms instead of 250 ms, and no longer grow with the scans kept.

## [1.15.0] - 2026-10-29

### Added

- **Push times from more registries:** repository watches and the browse dialog get each tag's push time and digest from Google Artifact Registry and gcr.io (in the registry API's answer), Azure Container Registry (its own API, with the registry login), Quay (its API; private repositories with `$oauthtoken` and an OAuth token), Harbor (its API, with the registry login) and GitLab (its GraphQL API; private projects with a `read_api` token), so the newest tags are the most recently pushed ones. Harbor, a self-hosted Quay and a self-hosted GitLab are recognised by asking the host, once an hour; GitLab only on hosts named for it. Browsing a Harbor login lists its repositories. When a registry's own API fails, the registry API lists the tags as before, and the browse dialog and the server log say why.

## [1.14.0] - 2026-10-29

### Added

- **Docker Hub and GHCR say when each tag was pushed:** a repository watch and the browse dialog list Docker Hub tags through Docker Hub's API (public repositories without a login, their 1,000 most recently pushed tags; private ones, and up to 2,500 tags, with a login), and GHCR tags through GitHub's packages API with a GHCR login, so the newest tags are the most recently pushed ones, as on Amazon ECR, and their digests come with the listing. Browsing a Docker Hub login lists its namespace's repositories, and a GHCR login its user's and organizations' packages, which the registry API refused. When either API fails, the registry API lists the tags as before, and the browse dialog and the server log say why.

## [1.13.0] - 2026-10-29

### Added

- **Repository watches order tags by build time** on registries that don't say when a tag was pushed, such as GHCR, GitLab, Harbor or a self-hosted registry: the first check, and tags that appear at the same check, go by when each image was built (the `created` time in its config), then by version. Tags named by commit, such as `main-3f9c2a1`, now come in build order. The watch dialog's preview orders the matching tags the same way and shows when each was built. Docker Hub, which limits reads, stays in version order.

## [1.12.0] - 2026-10-29

### Added

- **Browse a registry:** **Browse** next to a registry login lists its repositories (through the ECR API for Amazon ECR, the registry API's catalog elsewhere) and a repository's tags, newest first, to scan a tag's image.
- **Watch a repository:** scan each new or re-pushed image in a repository whose tag matches a pattern (a regular expression, previewed against the existing tags), keeping the newest 1 to 20 rescanned daily. Checked every 15 minutes, or at once with **Check now**; on Amazon ECR by push time. ECR keys need `ecr:DescribeRepositories` and `ecr:DescribeImages` for this. The database moves to schema 27.
- **Reports of new pushes:** a new notification event, **Image scan reports**, sent when the scan of a watched repository's new push finishes: counts by severity, known exploited and fixable, what changed since the previous build (new and fixed CVEs), the 5 most urgent vulnerabilities and a link. Each watch chooses which pushes it reports (every one, a minimum severity, known exploited only, or none) and to which channels.
- **A repository's page:** a watched repository's builds, newest first, with what each scan found, and a chart of vulnerabilities by build.
- **History per watch:** a watch keeps the newest 50 images it added (up to 500), with their scans, and removes older ones. Images added by hand are never removed.
- The Images page groups the images a watched repository added under it, has a search box, and shows 50 rows a page. Browsing a registry shows 100 repositories or tags a page, and the filter searches all of them.
- Long error messages on the Images page have **Show all**, so they can be read whole.
- **Check a registry login:** **Check** next to each login on the Images page logs in to the registry the way `docker login` does and says whether it works, why not in plain words (such as an AWS secret access key that doesn't belong to its access key ID), or that the registry doesn't ask for a login. Saving a login checks it too.

### Fixed

- An image's "Can't check for new builds" message stayed for up to 15 minutes after its registry's login was fixed. Saving a login now clears it for that registry's images and checks their tags at once, and a scan that succeeds clears it too.
- Spaces and line breaks pasted around an AWS access key are removed; they made AWS refuse the signature.
- Card headers keep their button beside the title when the description is long.

### Security

- Updated `golang.org/x/net` to 0.62.0 for GO-2026-6860 (quadratic complexity in HTML parsing, reached by the Amazon Linux advisory parser).

### Changed

- The ECR login's hint and the Images docs give the least IAM permissions DeaconGuard needs: `ecr:GetAuthorizationToken`, `ecr:BatchGetImage` and `ecr:GetDownloadUrlForLayer`.

## [1.11.1] - 2026-10-25

### Fixed

- **Exploit data on cloud servers:** when CISA's site refuses the Known Exploited Vulnerabilities download, as it does for some cloud providers' addresses such as Hetzner's (HTTP 403), the server takes the same catalog from CISA's copy on GitHub (`cisagov/kev-data`). Before, findings lost their "known exploited" marks there. Allow `raw.githubusercontent.com` if the server's outbound traffic is limited.

### Changed

- **Documentation:** the Kubernetes page's **With Traefik** section has steps for k3s/RKE2, Traefik's own Helm chart and a load balancer in front; **Agents outside the cluster** compares the agent Service and the agent route, and explains `externalTrafficPolicy` for agents; a **Troubleshooting** section covers the dashboard and agents. The README gives agents' default port as 8444.

## [1.11.0] - 2026-10-25

### Added

- **Helm, with Traefik:** `server.ingress.traefik.enabled` creates the `ServersTransport` and Service annotations Traefik needs to reach the dashboard (without them it answers 404), and `.allowSourceRanges` an IP allow list for it. `server.agentRoute` brings agents outside the cluster in through Traefik on port 443 with TLS passed through, instead of a load balancer on 8444. Both are off by default.
- **Documentation:** a **With Traefik** section on the Kubernetes page, including the `externalTrafficPolicy: Local` setting Traefik needs to see client addresses.

### Changed

- Updated lucide-react (dashboard icons) and the release workflow's cosign installer (3.10.1, cosign 2.6.1).
- The maintainer's GitHub account is now `shellctl` (CLA allowlist and MAINTAINERS.md).

## [1.10.0] - 2026-10-24

### Added

- **Helm:** `server.agentService.externalTrafficPolicy` (`Local` keeps each agent's own address in the server's logs and audit log), `.loadBalancerClass` (which load balancer implementation answers, when a cluster has several) and `.nodePort` (a fixed node port instead of a random one).

### Changed

- **Documentation:** a new **Reaching the agent port** page (Security) covers machines outside the server's network: in the same private network, in another data centre or cloud, or over the internet, what `loadBalancerSourceRanges` does, and `server.agentService` values with the firewall steps for your own data centre (k3s ServiceLB, MetalLB), Hetzner, AWS, Azure, Google Cloud, DigitalOcean, Akamai/Linode and Oracle Cloud.
- **Documentation:** the Kubernetes page shows how to install and upgrade with Flux (`OCIRepository` and `HelmRelease`), Argo CD (an `Application` from the OCI chart) and CI/CD pipelines (`helm upgrade --install -f`), keeping secrets out of Git.
- **Documentation:** the Upgrade page is the same for every release, and a new **Upgrade notes** section has a page per release, from 1.0.0: what's new, what to do before upgrading, and what applies to Kubernetes, the install script and Docker Compose, and known issues. The docs check requires notes for every release of the last ten minor lines.

## [1.9.2] - 2026-10-24

### Fixed

- **Helm upgrades with `--reuse-values`** from an earlier release failed with the 1.9.0 and 1.9.1 charts (`nil pointer evaluating interface {}.enabled` at `server.agentService.enabled`), and from 1.4.0 and earlier at `cluster.enabled`: `--reuse-values` renders the new chart with the old release's values, which lack settings added since. The chart now fills in any missing setting from its own defaults (a value you set is kept), so the documented upgrade works from every release, and CI renders the chart that way against every earlier release.
- **The Upgrade page** now upgrades with `--reset-then-reuse-values`, and upgrades the agent release only if you installed one (`helm list -A` shows them); before, it upgraded `deaconguard-agent` unconditionally, which fails where there is none.

## [1.9.1] - 2026-10-23

### Fixed

- **Docs:** the README showed the architecture diagram from before 1.9.0, with the dashboard and agents both on 8443; it now uses the same diagrams as the docs, with 8443 for people and 8444 for agents. Next to the install command, the README, Quick start and Install script pages say which ports the server listens on, and show `--agent-listen` to change the agent port or turn it off. No change to DeaconGuard itself.

## [1.9.0] - 2026-10-23

### Added

- **Helm: a Service for agents outside the cluster.** `server.agentService.enabled=true` adds `deaconguard-agents`, a `LoadBalancer` with only the agent port, 8444, with its own annotations (such as an internal load balancer) and `loadBalancerSourceRanges`, so machines outside the cluster can enroll while the dashboard's port stays inside.
- **Enroll a machine warns about loopback addresses.** A server address of `127.0.0.1`, `localhost` or `::1` gets a warning that only an agent on the server's own machine can reach it, and `deaconguard token create` says the same. With the Helm chart or Kustomize, a dashboard opened through `kubectl port-forward` suggests the cluster's agent address, `https://deaconguard.deaconguard.svc:8444`, instead of `127.0.0.1`.

### Changed

- **Agents get a port of their own, 8444, with the install script too,** as with the Helm chart, Kustomize and Compose: people use 8443, agents 8444, on every install. A new server listens on both. Upgrading a server set up by the install script adds 8444, unless you chose another agent port, chose `--agent-listen off`, or something else uses 8444; 8443 keeps answering agents, and each agent moves to 8444 by itself once it can reach it. Allow 8444 from your machines' networks. To keep one port: `sudo deaconguard setup server --agent-listen off`, which later upgrades remember.

### Fixed

- **A Kubernetes server without its admin secret waits for it** instead of restarting in a loop: it serves a page, and logs, saying which secret to create, keeps the health checks passing, and creates the first account once the secret is mounted.
- An agent that moved to the agent port goes back to the address it came from (or the same host on 8443) when that port has stopped answering for two minutes, as after `--agent-listen off`, and moves to it again if it returns. Before, it kept trying the closed port.
- A server that couldn't start records why, and the dashboard's notice says so (**The server couldn't start**: the reason) instead of guessing that the machine ran out of memory.

## [1.8.1] - 2026-10-23

### Added

- **End-of-life releases in containers and images:** a container or image on a release that has ended, such as Debian 10 or 11, Alpine before 3.18, CentOS Linux, CentOS Stream 8, Amazon Linux 2, openSUSE Leap before 15.6 or Fedora before 40, gets a high finding, `DG-EOL-001`, with the release, when it ended and what to rebuild on, an **End of life** badge, and a count in the **End-of-life OS** tile. Before, it only said "Packages not checked: unsupported Debian release", and a container with no vulnerable libraries looked as if it had nothing to fix. A machine on such a release still isn't scanned, but the error now says when the release ended and what to upgrade to.

### Changed

- An image scan with `--fail-on high` (or lower) now fails on an image whose release has ended.

### Fixed

- The **Running containers** check is **partial**, not complete, when a container's packages or libraries couldn't be checked, such as when the server can't reach the advisory feeds or OSV. Before, those containers were counted as having 0 vulnerabilities. The summary and each container say what wasn't checked.
- A server test failed in the days around a daylight saving change: it expected a daily schedule's next run exactly 24 hours later in UTC.

## [1.8.0] - 2026-10-22

### Added

- **macOS:** DeaconGuard scans Macs, macOS 10.15 and later. The package check reports whether the Mac's macOS release still gets security updates (from endoflife.date), each newer version of its release (high), and the updates the Mac has already found but not installed (`softwareupdate --list --no-scan`). The audit checks a new **macOS baseline** of 18 controls (`MACOS-01` to `MACOS-18`): FileVault, System Integrity Protection, Gatekeeper, XProtect's age, the firewall and stealth mode, Remote Login, Screen Sharing and File Sharing, the guest account and automatic login, the update settings, waiting updates and network time, reading configuration profiles (MDM) before local settings. The controls map to NIST 800-53, PCI DSS, HIPAA and ISO 27001. A Mac enrolls as a new kind of host, `mac`, which runs only these checks; `deaconguard scan --local` and `audit --local` work on a Mac too.
- **The agent on a Mac:** the install script installs the agent on macOS with the same command as on Linux. It checks the macOS archive's signature with cosign for macOS, installs `deaconguard` to `/usr/local/bin`, and `deaconguard setup agent` starts the launchd daemon `io.deaconguard.agent` as root, logging to `/var/log/deaconguard-agent.log`. A Mac agent whose host is removed stays stopped.
- **Containers in the dashboard:** the **Running containers** tab shows totals (running, stopped, images, vulnerabilities, known exploited, end-of-life releases) and a row per container with its state, start time or exit code, restarts, image and image ID, OS and its support, contents, vulnerabilities by severity, and the user it runs as. Opening a container shows its command, user, privileged or not, network, published ports and times, and **every vulnerability in it as a tree**: OS packages, and each library folder or lock file inside the container, then each package with the version that fixes it, then its vulnerabilities, filtered to those with a fix or known to be exploited, or grouped by severity. Image pages show the same tree. The flat findings list names each finding's container, image and path inside the container.
- **Stopped containers:** agent 1.8.0 lists stopped containers too (`ps -a`), with their exit code; they are marked as not checked, since they have no files to read, and point to scanning their image. It also sends each container's state, times, restart count, user, privileged, network, ports and command, and reads the user its main process runs as. Agents before 1.8.0 still work; their containers show without these details.
- **Go programs:** the library check, the running-container check and image scans read the build information in compiled Go programs (Go 1.18 and later): the Go version, checked against OSV as the module `stdlib`, and every module the program was built with. A program built with an old Go is reported for Go's own vulnerabilities, such as the compromised eMudhra CA keys (GO-2026-6809). Programs are read as files, never run, and image layers are read as they stream, without holding programs in memory. On machines, and in images with a package database, the distribution's folders (`/usr/bin`, `/usr/lib` and the like) are left to the package check.

### Changed

- A container's result keeps **all** its vulnerabilities (`vulnerabilities`, the 1,000 most urgent), not only those with a fix or known to be exploited (`findings`, still at most 300). Library and container findings carry `container`, `image`, `source`, `package`, `version`, `ecosystem`, `fixed`, `fixable`, `exploited` and `paths` in the API.
- A container on a release DeaconGuard doesn't support says **OS packages not checked** instead of "None found".

### Fixed

- The host's **Application libraries** check no longer reads container storage (`/var/lib/docker`, `/var/lib/containerd`, `/var/lib/containers`, `/var/lib/kubelet`, k3s's and RKE2's containerd, Docker's snap, rootless Podman). Image layers there were reported as the machine's own libraries, under paths like `/var/lib/containerd/…/snapshots/9/fs/…`, without the container they belonged to; the Running containers check reports them under each container instead.

### Security

- DeaconGuard needs Go 1.26.10 or later to build, so no build lacks Go's fix for the compromised eMudhra intermediate CA keys (GO-2026-6809, CVE-2026-111943): `crypto/x509` refuses certificate chains through them. Release 1.7.0 was already built with Go 1.26.10; 1.6.0 and earlier were built with Go 1.26.9, so on them a forged certificate could intercept the server's HTTPS to advisory feeds, OSV, registries or an identity provider. Agents' connections to the server pin its key and weren't affected. Upgrade to 1.7.0 or later.
- **Single sign-on with Google:** with **Allowed email domains** set, a Google sign-in must also come from an account that one of those Google Workspace domains manages (the ID token's `hd`), as Google advises. Before, a personal Google account with a verified address at an allowed domain could sign in.

## [1.7.0] - 2026-10-20

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

[Unreleased]: https://github.com/Cloudopsshell/deaconguard/compare/v1.17.0...HEAD
[1.17.0]: https://github.com/Cloudopsshell/deaconguard/compare/v1.16.0...v1.17.0
[1.16.0]: https://github.com/Cloudopsshell/deaconguard/compare/v1.15.0...v1.16.0
[1.15.0]: https://github.com/Cloudopsshell/deaconguard/compare/v1.14.0...v1.15.0
[1.14.0]: https://github.com/Cloudopsshell/deaconguard/compare/v1.13.0...v1.14.0
[1.13.0]: https://github.com/Cloudopsshell/deaconguard/compare/v1.12.0...v1.13.0
[1.12.0]: https://github.com/Cloudopsshell/deaconguard/compare/v1.11.1...v1.12.0
[1.11.1]: https://github.com/Cloudopsshell/deaconguard/compare/v1.11.0...v1.11.1
[1.11.0]: https://github.com/Cloudopsshell/deaconguard/compare/v1.10.0...v1.11.0
[1.10.0]: https://github.com/Cloudopsshell/deaconguard/compare/v1.9.2...v1.10.0
[1.9.2]: https://github.com/Cloudopsshell/deaconguard/compare/v1.9.1...v1.9.2
[1.9.1]: https://github.com/Cloudopsshell/deaconguard/compare/v1.9.0...v1.9.1
[1.9.0]: https://github.com/Cloudopsshell/deaconguard/compare/v1.8.1...v1.9.0
[1.8.1]: https://github.com/Cloudopsshell/deaconguard/compare/v1.8.0...v1.8.1
[1.8.0]: https://github.com/Cloudopsshell/deaconguard/compare/v1.7.0...v1.8.0
[1.7.0]: https://github.com/Cloudopsshell/deaconguard/compare/v1.6.0...v1.7.0
[1.6.0]: https://github.com/Cloudopsshell/deaconguard/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/Cloudopsshell/deaconguard/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/Cloudopsshell/deaconguard/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/Cloudopsshell/deaconguard/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/Cloudopsshell/deaconguard/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/Cloudopsshell/deaconguard/compare/v1.0.2...v1.1.0
[1.0.2]: https://github.com/Cloudopsshell/deaconguard/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/Cloudopsshell/deaconguard/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/Cloudopsshell/deaconguard/releases/tag/v1.0.0
