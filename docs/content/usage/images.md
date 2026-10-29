---
title: Images in registries
description: Check container images in Docker Hub, GHCR, Quay, Harbor and other registries before they run, from the dashboard or the command line, without running them.
---

DeaconGuard checks container images **where they are stored**, before anything runs them: their OS packages against their distribution's advisories, their [application libraries](./libraries-and-sbom.md) against OSV, and their release support, as for [running containers](./containers.md). It needs DeaconGuard 1.3.0 or later.

Check images from the dashboard's **Images** page, where the server keeps each image's results and history, or from the command line, in a pipeline for example:

```bash
deaconguard image scan nginx:1.27
deaconguard image scan ghcr.io/acme/shop:4.2 --platform linux/arm64
```

## In the dashboard

On **Images**, **Add image** takes an image's name, as in `docker pull`, and a platform (`linux/amd64` unless you choose another), and checks it at once. Each image shows its last scan, its vulnerabilities, those known to be exploited and how many a newer image fixes. **Scan now** checks it again; an image's page shows its latest result, every vulnerability as a tree (OS packages and library folders, then packages, then vulnerabilities, filtered to those with a fix or known to be exploited if you like, or grouped by severity, as for a [running container](./containers.md#results)), and its last 20 scans with their digests, so you can see when the tag moved to a new build.

The server reads the image itself, one at a time, so the machine running DeaconGuard needs to reach the registry over HTTPS. A scan interrupted by a server restart is marked failed; scan it again.

Operators add, scan and remove images; viewers see the results. Removing an image deletes its results in DeaconGuard, never anything in the registry.

## Watch for new builds

A **watched** image is checked again without anyone pressing **Scan now**. Watching is on for new images, and **Stop watching** on the image's page turns it off.

- **New builds:** every 15 minutes, the server asks the registry which build the tag points to, with a `HEAD` request for the manifest: nothing is downloaded, and Docker Hub doesn't count it against its pull limits. When the tag has moved to a new build, the image is scanned again.
- **New vulnerabilities:** once a day, the image is scanned again for advisories published since. Unchanged layers come from the cache, so this takes a second or two.

The scan history says what started each scan: a person, `watch: new build pushed`, or `watch: daily rescan`. When the check fails, for example because the registry is rate-limiting or the login stopped working, the image says why, and the server log records it once. The message goes away at the next check that works, when a scan of the image succeeds, or as soon as the registry's login is saved again, which also checks the image's tag at once.

## Browse a registry

**Browse**, next to a saved [registry login](#registries-and-logins), lists the repositories the login can see, and then a repository's tags, newest first. From there, **Scan** adds one tag's image, as **Add image** does, and **Watch repository** watches the whole repository, as below.

- **Amazon ECR** lists every repository, and says when each tag was pushed, through the ECR API: the key's user also needs `ecr:DescribeRepositories` and `ecr:DescribeImages` (see the [policy](#an-iam-policy-for-amazon-ecr)).
- **Docker Hub** lists, through its API, the repositories in the login's own namespace, and any repository's tags, with when each was pushed; public repositories need no login. To browse another namespace, type its name, such as `library/alpine`.
- **GHCR** lists, through GitHub's packages API, the packages of the login's user and of its organizations, and their tags, with when each was pushed. The login's token must be a classic one with `read:packages`; without a login, or with a token GitHub's API refuses, the tags come from the registry API, as below.
- **Other registries** are listed with the registry API's catalog. Some don't list repositories at all: type the repository's name, such as `team/app`, and its tags are listed. The registry API doesn't say when a tag was pushed, so tags are listed by version, newest first: `v1.10.0` before `v1.9.0`. While you set up a watch, the tags its pattern matches are listed by when their image was built instead, as its first check orders them (see **Newest** below).

Browsing is for admins, who hold the logins.

## Watch a repository

A **watched repository** scans each new image pushed to it, without anyone adding it: every 15 minutes, the server lists the repository's tags and scans each new or re-pushed image whose tag matches.

- **Tag pattern:** a regular expression ([RE2](https://github.com/google/re2/wiki/Syntax)) the tags must match; empty matches every tag. For example `^v?\d+\.\d+\.\d+$` for releases (`v1.4.2`), `^main-` for main-branch builds, `^latest$` for one moving tag. The dashboard shows which existing tags match while you type.
- **Rescan the newest:** how many of the newest matching tags stay watched (1 to 20, 5 by default). Their images are rescanned daily for new advisories, and checked for new builds, as watched images are. When a newer tag arrives, the oldest kept one stops being watched; its scans stay.
- **Keep the history of:** how many of the images the watch added are kept, with their scans (from the number rescanned up to 500, 50 by default). When there are more, the oldest are removed. Images you added yourself are never removed, even when a watch matches their tag.
- **Report new pushes:** which new pushes send an [image scan report](#reports-of-new-pushes): every one (the default), only those with a vulnerability of a chosen severity or worse, only those with one known to be exploited, or none. **Send reports to** picks the channels, of those that take image scan reports; none ticked sends to all of them.
- **The first check** scans the newest matching tags at once. After that, a tag that appears, or that is pushed again with a new image, is scanned. **Check now** checks at once.
- **Newest** is by push time on Amazon ECR, Docker Hub (its 1,000 most recently pushed tags, as far as Docker Hub lets an anonymous request page, or 2,500 with a Docker Hub login), and GHCR with a login. Other registries don't say when a tag was pushed, so:
  - the first check orders the matching tags by when their image was built for the watch's platform (the `created` time in the image's config), then by version. Tags named by commit, such as `main-3f9c2a1`, come in build order, not in the order of their names. It reads the build time of the 100 matching tags that are newest by version, 6 at a time;
  - later, a tag that appears counts as the newest, and tags that appear at the same check are ordered by build time;
  - a tag whose image has no build time, as reproducible builds often leave it, keeps its place by version.
- **When Docker Hub's or GitHub's API fails**, for example because it is limiting requests or the token may not read packages, the tags come from the registry API and are ordered as for other registries. The browse dialog says why, and the server log records it once.

### Tag pattern examples

A pattern is a [regular expression](https://github.com/google/re2/wiki/Syntax) tested against each tag. Anchor it: `^` marks the start of the tag and `$` the end, so `^production-` matches `production-12c8a460…` but not `pre-production-12c8a460…`, and without `^` it would match both.

| You want | Pattern | Matches | Doesn't match |
| --- | --- | --- | --- |
| Every tag | *(empty)* | everything | |
| Releases | `^v?\d+\.\d+\.\d+$` | `v1.4.2`, `1.4.2` | `v1.4.2-rc.1`, `latest` |
| Only `production-` builds | `^production-` | `production-12c8a460…-1791137998` | `12c8a460…`, `pre-production-12c8a460…` |
| Exactly `production-<commit>-<time>` | `^production-[0-9a-f]{40}-\d+$` | `production-12c8a460dcba7d3950828e52476fe34a7f5a91a3-1791137998` | `production-test` |
| Production or staging builds | `^(production\|staging)-` | `production-…`, `staging-…` | `dev-…` |
| Main-branch builds | `^main-` | `main-4f2a9c1` | `maintenance-1` |
| One moving tag | `^latest$` | `latest` | `latest-arm64` |
| A commit SHA alone | `^[0-9a-f]{40}$` | `12c8a460dcba7d3950828e52476fe34a7f5a91a3` | `production-12c8a460…` |

RE2 has no look-ahead, so "every tag except `dev-`" can't be written as one pattern: list the prefixes you do want instead, such as `^(production|staging)-`. Upper and lower case differ; `(?i)` at the start ignores case.

**One pattern or several watches?** Several kinds of tags can be watched in two ways:

- **One watch, with `|`**, such as `^(production|staging)-`: one list of the newest matching tags, so **Rescan the newest 5** rescans the 5 newest of both kinds together.
- **Several watches on the same repository**, one per pattern: each keeps its own newest tags, such as the newest 5 `production-` builds and the newest 2 `staging-` builds. Browse the repository again and watch it with another pattern.

A tag matched by two watches is added and scanned once.

On **Images**, the images a watch added are grouped under their repository, one row with its newest image's result; the arrow shows them all. The search box finds any image by name, and the list shows 50 rows a page. Their scans say `watch: repository added` or `watch: new push of TAG`. Changing a watch's pattern, or how many tags it rescans, starts it afresh; changing its history or reports doesn't. Removing a watch keeps the images it added, no longer watched. When a check fails, the watch says why, with the whole message under **Show all**, until a check works or the registry's login is saved again.

### A repository's page

The repository's name opens its page: **Vulnerabilities by build**, a bar per build, oldest on the left, stacked by severity (the newest 50 builds, each with its latest scan), and **Builds**, every scan of its images, newest first, with the tag, digest, counts, those known to be exploited, those an update fixes and why it was scanned. A tag opens its image. **Check now**, edit and remove are there too.

### Reports of new pushes

When the scan of a new push finishes, the watch sends an **image scan report** to the [notification](./notifications.md) channels that take the "Image scan reports" event:

- the counts by severity, those known to be exploited and those an update fixes;
- **what changed:** how many vulnerabilities are new and how many are fixed, compared with the image the watch added before it, or for a tag pushed again, with what the tag held before; the new CVEs are listed;
- the 5 most urgent vulnerabilities, with their packages and fixed versions;
- a link to the repository's page.

In Slack it reads like this:

```text
🚨 New push of registry.example.com/acme/app:v1.12.0: 6 critical, 52 high
• Critical 6 · High 52 · Medium 34 · Low 8 · Unknown 11
• 0 known to be exploited · 111 fixed by an update
• Compared with registry.example.com/acme/app:v1.11.0: 16 new, 13 fixed. New: CVE-2025-11187, CVE-2025-15469, … and 6 more
• Most urgent: CVE-2026-34182 (critical, libcrypto3 3.5.0-r0 → 3.5.7-r0); …
Open in DeaconGuard
```

The first check of a watch, and daily rescans, send no report. Webhooks get the same facts in `data`: `repository`, `tag`, `image`, `digest`, `severity`, `exploited`, `fixable`, `previous`, `new_cves`, `fixed_cves` and `top`.

New known exploited and critical vulnerabilities in an image, and failed scans, are also sent to the channels subscribed to those events, as for hosts.

**Scan on push from CI:** to scan an image the moment a pipeline pushes it, call the API with an operator's [API token](../reference/api.md#api-tokens) after the push:

```bash
curl -fsS -X POST -H "Authorization: Bearer $DEACONGUARD_TOKEN" \
  https://deaconguard.example.com/api/images/IMAGE_ID/scans
```

The image's ID is in its page's address.

## Nothing in the image is run

DeaconGuard reads an image the standard way, through the registry API that `docker pull` uses, as data:

1. It asks the registry for the image's **manifest**, the list of its layers. For an image built for several platforms, it picks one: the machine's own (`linux/amd64` or `linux/arm64`), or the one given with `--platform`.
2. It downloads each **layer**, a compressed archive, and reads it as it arrives. It keeps only the files that say what is installed: `/etc/os-release`, the package database (dpkg, apk, or RPM's `rpmdb.sqlite`) and package-manager files such as lock files. Everything else passes through and is thrown away. Later layers replace and delete files of earlier ones, as when the image runs.
3. Each layer is **checked against its digest**, the SHA-256 the manifest names. A layer that doesn't match is rejected, and the scan fails.

No container is created and nothing in the image is executed. Docker isn't needed.

**Layer cache:** what was read from each layer is kept by its digest in `/var/lib/deaconguard/feeds/layers/` (at most 2 GB, least recently used first). Images that share base layers, such as everything built `FROM debian:12`, read them once; scanning an image again downloads only the manifest.

## Registries and logins

Any registry that implements the standard registry API works: Docker Hub, GitHub's GHCR, Quay, Harbor, GitLab, Google Artifact Registry, Azure Container Registry, Amazon ECR, a self-hosted `registry`. Public images need no login.

For a private image, DeaconGuard needs a login for its registry: a username and a token or password with **pull** access. Prefer a read-only token where the registry offers one.

**In the dashboard**, an admin saves it under **Images**, **Registry logins**: the registry's host (`docker.io`, `ghcr.io`, `registry.example.com:5000`), the username and the token. It is used for every image in that registry. The server stores it in its database and never shows it again; to change it, edit the login and type a new one, or leave it empty to keep the saved one. A saved token is never sent to another registry: changing a login's registry needs the token again. The audit log records who added, changed or deleted each login, without the token.

**Check a login** with **Check** next to it, and saving a login checks it too: DeaconGuard logs in to the registry the way `docker login` does and shows the answer under the login.

- **Works:** the registry accepted the login.
- **Doesn't work:** the registry refused it, with the reason in plain words, such as a wrong password, or for ECR an AWS secret access key that doesn't belong to the access key ID.
- **Couldn't check:** the registry answers without asking for a login, so it can't say whether this one is right. DeaconGuard still uses it for images that need it.

A check proves the login, not access to every repository: a token limited to some repositories still fails for the others when their images are scanned.

What to save for the cloud registries:

| Registry | Host | Login |
| --- | --- | --- |
| Amazon ECR | `123456789012.dkr.ecr.eu-north-1.amazonaws.com` | Choose **An AWS access key**, and give an access key ID and secret access key of an IAM user that may only read: `ecr:GetAuthorizationToken` (on `*`), and `ecr:BatchGetImage` and `ecr:GetDownloadUrlForLayer` on the repositories to scan (see the [policy below](#an-iam-policy-for-amazon-ecr)), or the managed `AmazonEC2ContainerRegistryReadOnly`. ECR's registry passwords last 12 hours, so DeaconGuard keeps the key and gets a new password from the ECR API when it needs one. |
| Google Artifact Registry | `europe-north1-docker.pkg.dev` | Username `_json_key`, and as the password the JSON key of a service account with the **Artifact Registry Reader** role. |
| Azure Container Registry | `myregistry.azurecr.io` | A [repository-scoped token](https://learn.microsoft.com/azure/container-registry/container-registry-repository-scoped-permissions) with `content/read`, or a service principal's application ID and secret with the **AcrPull** role. |
| GitHub (GHCR) | `ghcr.io` | Your GitHub username and a personal access token (classic) with only `read:packages`. GitHub's packages API takes the same token, to list your packages and say when each tag was pushed; it refuses fine-grained tokens. |
| Docker Hub | `docker.io` | Your username and a personal access token with **Read-only** access. A login also raises Docker Hub's pull limits, lists your repositories when browsing, and lets private repositories be watched. |

### An IAM policy for Amazon ECR

To scan, DeaconGuard calls one ECR API, `GetAuthorizationToken`, then reads manifests and layers through the registry, which ECR allows with `ecr:BatchGetImage` and `ecr:GetDownloadUrlForLayer`. To [browse](#browse-a-registry) and [watch repositories](#watch-a-repository), it also lists with `ecr:DescribeRepositories` and `ecr:DescribeImages`; leave those out if you only add images by name. The least an IAM user needs, here for every repository whose name starts with `team-`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": "ecr:GetAuthorizationToken", "Resource": "*" },
    {
      "Effect": "Allow",
      "Action": ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:DescribeImages"],
      "Resource": "arn:aws:ecr:eu-north-1:123456789012:repository/team-*"
    },
    { "Effect": "Allow", "Action": "ecr:DescribeRepositories", "Resource": "arn:aws:ecr:eu-north-1:123456789012:repository/*" }
  ]
}
```

`GetAuthorizationToken` can't be limited to repositories; it only gives a registry password. `DescribeRepositories` on `repository/*` lists every repository's name, without access to its images. Repositories in other regions need their own ARNs, and their own login.

**On the command line**, give it in the environment:

```bash
DEACONGUARD_REGISTRY_USERNAME=robot \
DEACONGUARD_REGISTRY_PASSWORD="$(cat token)" \
deaconguard image scan registry.example.com/team/app:2.1
```

DeaconGuard sends it only to the image's registry, or to the login service that registry names, and asks only to pull.

## The result

```text
Image: nginx:1.27
Digest: sha256:… (linux/amd64)
OS: Debian 12 (bookworm), 149 packages
Release support: Regular support ended 10 June 2026; security fixes need Debian LTS, until 30 June 2028
Libraries: 0
Vulnerabilities: 734 (142 low, 592 unknown); 258 fixed by a newer image, 1 known to be exploited
  LOW  nginx 1.27.5-1~bookworm (Debian 12 (bookworm)): CVE-2023-44487 · Fixed in …: update the image. Known to be exploited (CISA KEV).
```

It lists each vulnerability with a fix or known to be exploited, most urgent first. `--format json` prints it all as JSON.

**In a pipeline:** `--fail-on high` (or `critical`, `medium`, `low`) exits with status **4** when the image has a vulnerability at or above that severity, so a build can stop before the image is pushed or deployed. The same command checks `docker save` archives, OCI layouts and folders, and writes SARIF, JUnit and SBOM reports: see [Images in CI/CD pipelines](./ci-cd.md).

## Limits

- Images with an RPM database in Berkeley DB or ndb format (RHEL 8, SUSE) have only their libraries checked for now.
- Static images with no package database, such as Go binaries on `scratch`, have only their package-manager files checked.
- Layers up to 8 GB; files larger than the [library check](./libraries-and-sbom.md#what-it-looks-at) reads are skipped, and the result says so.
