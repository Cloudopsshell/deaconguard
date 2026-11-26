---
title: Images in CI/CD pipelines
description: Check a container image, an image archive or a project folder in a pipeline, fail the build on what matters, and publish SARIF, JUnit or SBOM reports.
---

`deaconguard image scan` checks an image in a pipeline, before it is pushed or deployed, and [`deaconguard config scan`](./config-checks.md) checks its Dockerfile and Kubernetes manifests. It reads the image as data and never runs it, so it needs no Docker daemon, no root and no DeaconGuard server. It needs DeaconGuard 1.4.0 or later.

## What it can check

| Argument | What it reads |
| --- | --- |
| `nginx:1.27`, `ghcr.io/acme/shop:4.2` | An image in its registry. See [Images in registries](./images.md). |
| `image.tar`, `docker-archive:image.tar` | An archive from `docker save` or `podman save`, compressed with gzip or not. |
| `oci:layout/`, `oci:image.tar` | An OCI image layout, a folder or a tar of one, as `docker buildx build --output type=oci`, `buildah push` or `skopeo copy` write it. `--platform` picks one of several platforms. |
| `dir:path/` | A folder: an image's unpacked files, a chroot, or a project. Its OS packages are checked when it has a package database, and its lock files (`package-lock.json`, `requirements.txt`, `go.mod`, `Cargo.lock` and the others in [Libraries](./libraries-and-sbom.md#what-it-looks-at)) and [compiled Go programs](./libraries-and-sbom.md#go-programs), such as a build's output, against OSV. |

Without a prefix, a path that exists is read as what it holds: an archive with `manifest.json` is a `docker save` archive, one with `index.json` and `oci-layout` an OCI layout, and a plain folder a folder. Anything else is an image name.

Archives and layouts are checked like registry images: layers named by digest must match it. Symbolic links in a folder are never followed outside it.

```bash
docker build -t shop:ci .
docker save shop:ci -o shop.tar
deaconguard image scan shop.tar --fail-on high
```

## Failing the build

`--fail-on critical`, `high`, `medium` or `low` makes the command exit with status **4** when the image has a vulnerability at or above that severity, so the pipeline stops. Vulnerabilities with no published severity don't count. An image on a release that has [ended](../supported-distributions.md#releases-that-have-ended), such as Debian 10, has a high finding for it (`DG-EOL-001`), so `--fail-on high` stops it.

`--ignore-unfixed` counts, and reports, only the vulnerabilities an update fixes or attackers are known to use. A vulnerability with no fix yet can't be fixed by rebuilding, so it doesn't fail the build.

| Exit status | Means |
| --- | --- |
| 0 | Checked; nothing at or above `--fail-on` |
| 4 | Checked; vulnerabilities at or above `--fail-on` |
| 1 | Not checked: the image couldn't be read, or an option is wrong |

## Reports

`--format` chooses what the command writes, and `--output FILE` writes it to a file and keeps the summary in the job's log. `--summary FILE` (1.35.0 and later) also adds a Markdown summary to a file: whether the check passed, the counts by severity and the 20 worst findings with what to do about each. The [GitHub action](#github-actions) puts it on the run's Summary page; elsewhere, give it any file your pipeline shows:

| `--format` | For |
| --- | --- |
| `table` | People: the summary and what to fix (the default) |
| `json` | Scripts: the result and every vulnerability, with `fixable` and `known_exploited` |
| `sarif` | SARIF 2.1.0 for GitHub code scanning, GitLab, Azure DevOps and other code-scanning tools: one result per vulnerability and package, with GitHub's `security-severity` |
| `junit` | JUnit XML for GitLab, Jenkins, Bitbucket and Azure DevOps test reports: a test case per vulnerability; those at or above `--fail-on` fail |
| `cyclonedx`, `spdx` | A software bill of materials of the image's packages and libraries: CycloneDX 1.6 or SPDX 2.3 JSON, as for [hosts](./libraries-and-sbom.md#download-an-sbom) |

```bash
deaconguard image scan shop.tar --ignore-unfixed --fail-on high --format sarif --output deaconguard.sarif
deaconguard image scan shop.tar --format cyclonedx --output shop.cdx.json
```

Progress goes to standard error, so a report on standard output can be piped.

## What leaves the machine

Only what any image check sends: OS package checks use the [advisory data](./vulnerabilities.md) DeaconGuard downloads, and libraries are checked against OSV, which is sent their names and versions. The image itself, and its files, stay where they are. To scan without these downloads on each run, cache `$DEACONGUARD_HOME` (by default `~/.local/share/deaconguard` for a user) between jobs: it holds the advisory data and the [layer cache](./images.md#nothing-in-the-image-is-run).

## GitHub Actions

The DeaconGuard action installs the command (checking the release's signature and checksum), keeps the advisory data in the Actions cache for a day, runs the check, fails the job on what you choose, and shows what it found on the run's **Summary** page. This works in public and private repositories on every GitHub plan:

```yaml
jobs:
  deaconguard:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v7

      - name: Build the image
        run: docker build -t shop:${{ github.sha }} . && docker save shop:${{ github.sha }} -o shop.tar

      - name: Check the image
        uses: Cloudopsshell/deaconguard@v@RELEASE@
        with:
          target: shop.tar
          fail-on: high
          ignore-unfixed: "true"

      - name: Check the Dockerfile and manifests
        if: always()
        uses: Cloudopsshell/deaconguard@v@RELEASE@
        with:
          scan: config
          target: Dockerfile deploy
          fail-on: high
          output: config.sarif

      - name: Keep the reports
        if: always()
        uses: actions/upload-artifact@v7
        with:
          name: deaconguard-reports
          path: "*.sarif"
```

### Where the results show

| Where | What | Needs |
| --- | --- | --- |
| The job's result | Passed, or failed with "DeaconGuard found problems at or above high" | `fail-on` |
| The run's **Summary** page | Whether each check passed, the counts by severity, and the 20 worst findings with what to do about each; the rest are in the report (1.35.0 and later) | Nothing: on by default, on every plan, in private repositories too. `summary: "false"` turns it off |
| The job's log | The same findings as text | Nothing |
| The report file | Every finding, as SARIF, JUnit, JSON or an SBOM; keep it with `actions/upload-artifact` | Nothing |
| The repository's **Security → Code scanning** page | Findings as alerts that GitHub tracks between runs and shows on pull requests | `upload-sarif: "true"`, and see below |

This is the Summary page of a real run, in a private repository, for an image that failed `fail-on: medium`:

<div className="screenshot">
  <img src="/img/screens/ci-image-summary.png" alt="A GitHub run's Summary page: DeaconGuard's image check failed on findings at or above medium. It lists the image's system, release support and digest, the counts by severity (6 medium, 2 low), and a table of findings with what to do about each." />
</div>

And for `scan: config` on a Dockerfile and a Kubernetes manifest, failing `fail-on: high`:

<div className="screenshot">
  <img src="/img/screens/ci-config-summary.png" alt="A GitHub run's Summary page: DeaconGuard's config check of 2 files failed on findings at or above high: a privileged container (critical), a container that may run as root (medium), and five low findings, each with what to change." />
</div>

### Code scanning

`upload-sarif: "true"` also sends the SARIF report to GitHub code scanning. The report goes to your own repository's Security tab and nowhere else. It shows the same findings as the Summary page, as alerts GitHub remembers between runs. GitHub decides who can use it:

| Repository | Code scanning |
| --- | --- |
| Public | Available, free |
| Private or internal | Needs GitHub Code Security (part of what was GitHub Advanced Security), a paid GitHub add-on; see [GitHub's code scanning documentation](https://docs.github.com/en/code-security/code-scanning) for who can buy it |

The job then needs these permissions:

```yaml
    permissions:
      contents: read
      security-events: write   # to upload to code scanning
      actions: read            # in a private repository
```

From 1.35.0 a refused upload is a warning, with why, and doesn't fail the job: whether the job passes depends on what the check found. Before 1.35.0 a refused upload failed the job, even for a clean image; leave `upload-sarif` off there unless the repository has code scanning.

A refused upload in a private repository without Code Security: the image passed, and the Summary page says why nothing was uploaded.

<div className="screenshot">
  <img src="/img/screens/ci-passed-summary.png" alt="A GitHub run's Summary page: DeaconGuard's check of alpine:3.22 passed, with nothing at or above high, and a note that the report was not uploaded to code scanning because the private repository doesn't have GitHub Code Security." />
</div>

| Input | Default | |
| --- | --- | --- |
| `scan` | `image` | `image`, or `config` for Dockerfiles and Kubernetes manifests |
| `target` | | The image or path; for `config`, files and folders separated by spaces |
| `fail-on` | | `critical`, `high`, `medium` or `low` fails the step; empty only reports |
| `ignore-unfixed` | `false` | Images: count and report only what an update fixes |
| `platform` | the runner's | Images: a platform of a multi-platform image |
| `skip` | | Config: rules to leave out |
| `format`, `output` | `sarif`, `deaconguard.sarif` | The report and its file |
| `summary` | `true` | Show what was found on the run's Summary page (1.35.0 and later) |
| `upload-sarif` | `false` | Also upload the SARIF report to [code scanning](#code-scanning): a public repository, or GitHub Code Security on a private one |
| `category` | `deaconguard-image` or `deaconguard-config` | The code scanning category |
| `registry`, `registry-username`, `registry-password` | | A login for a private registry, from secrets; sent to `registry` only |
| `version` | the action's release | A release such as `@RELEASE@`, `latest`, or `installed` for a `deaconguard` already on the PATH |
| `cache` | `true` | Keep the advisory data and layer cache between runs |

The `status` output is `0`, or `4` when there were findings at or above `fail-on`; `summary` is `true` when the Summary page got the findings. Pin the action to a release, as above, or to its commit.

For an image in GHCR, use the job's token:

```yaml
      - uses: Cloudopsshell/deaconguard@v@RELEASE@
        with:
          target: ghcr.io/${{ github.repository }}:${{ github.sha }}
          registry: ghcr.io
          registry-username: ${{ github.actor }}
          registry-password: ${{ secrets.GITHUB_TOKEN }}   # the job needs packages: read
```

## GitLab CI

Include the template from a release, and extend its jobs. They run in `alpine:3.22`, need no Docker or privileges, show findings as test results with JUnit, keep SARIF as an artifact, and give GitLab the image's CycloneDX SBOM:

```yaml
include:
  - remote: https://raw.githubusercontent.com/Cloudopsshell/deaconguard/v@RELEASE@/ci/gitlab/deaconguard.gitlab-ci.yml

deaconguard-image:
  extends: .deaconguard-image
  needs: [build]
  variables:
    DEACONGUARD_VERSION: "@RELEASE@"
    DEACONGUARD_TARGET: $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
    DEACONGUARD_FAIL_ON: high
    DEACONGUARD_ARGS: --ignore-unfixed

deaconguard-config:
  extends: .deaconguard-config
  variables:
    DEACONGUARD_VERSION: "@RELEASE@"
    DEACONGUARD_FAIL_ON: high
```

The image job logs in to `$CI_REGISTRY` with the job's own token, and only there (`DEACONGUARD_REGISTRY`). `DEACONGUARD_TARGET` can also be an archive or OCI layout an earlier job left as an artifact.

## Other CI systems

Everywhere else, install the command with `ci/install.sh` from a release, which checks the release's signature and checksum, needs no root, and installs only the `deaconguard` binary:

```bash
curl -fsSL https://raw.githubusercontent.com/Cloudopsshell/deaconguard/v@RELEASE@/ci/install.sh | sh -s -- @RELEASE@ "$HOME/.local/bin"
```

It needs Linux on amd64 or arm64, `curl` and `sha256sum`.

### Jenkins

This stage follows one that built the image as `shop:${GIT_COMMIT}`, on an agent with Docker:

```groovy
pipeline {
  agent any
  environment { PATH = "${env.HOME}/.local/bin:${env.PATH}" }
  stages {
    stage('DeaconGuard') {
      steps {
        sh 'curl -fsSL https://raw.githubusercontent.com/Cloudopsshell/deaconguard/v@RELEASE@/ci/install.sh | sh -s -- @RELEASE@'
        sh 'docker save shop:${GIT_COMMIT} -o shop.tar'
        // Each check fails the build on its findings, after both have run.
        catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
          sh 'deaconguard image scan shop.tar --ignore-unfixed --fail-on high --format junit --output deaconguard-image.xml'
        }
        catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
          sh 'deaconguard config scan . --fail-on high --format junit --output deaconguard-config.xml'
        }
      }
    }
  }
  post {
    always { junit allowEmptyResults: true, testResults: 'deaconguard-*.xml' }
  }
}
```

`catchError` lets the second check run when the first finds something; with two plain `sh` steps, the first check's findings would stop the build before the second runs. The build's **Tests** page lists every finding as a test, failed when it's at or above `--fail-on`:

<div className="screenshot">
  <img src="/img/screens/jenkins-tests.png" alt="A Jenkins build's Tests page: 25 tests, 14 failed, each failed test a DeaconGuard finding, such as an image running as root from old/Dockerfile and libcrypto3 vulnerabilities in the shop image." />
</div>

With the Warnings Next Generation plugin, `--format sarif --output deaconguard.sarif` and `recordIssues(enabledForFailure: true, tools: [sarif(pattern: 'deaconguard.sarif')])` in `post` show the findings as issues, by severity and from build to build. Without `enabledForFailure: true`, the plugin skips a build that failed, which is just when the findings matter.

<div className="screenshot">
  <img src="/img/screens/jenkins-issues.png" alt="A Jenkins build's SARIF Warnings page: DeaconGuard's findings by severity in a chart, their history across builds, and a table by CVE." />
</div>

### Bitbucket Pipelines

Bitbucket shows JUnit reports it finds under `test-results/`:

```yaml
pipelines:
  default:
    - step:
        name: DeaconGuard
        image: alpine:3.22
        script:
          - apk add --no-cache curl
          - curl -fsSL https://raw.githubusercontent.com/Cloudopsshell/deaconguard/v@RELEASE@/ci/install.sh | sh -s -- @RELEASE@ /usr/local/bin
          - mkdir -p test-results
          - deaconguard config scan . --fail-on high --format junit --output test-results/deaconguard-config.xml
          - deaconguard image scan "$IMAGE" --ignore-unfixed --fail-on high --format junit --output test-results/deaconguard-image.xml
```

For a private image, set `DEACONGUARD_REGISTRY`, `DEACONGUARD_REGISTRY_USERNAME` and `DEACONGUARD_REGISTRY_PASSWORD` as secured repository variables.

### Azure DevOps

```yaml
steps:
  - script: curl -fsSL https://raw.githubusercontent.com/Cloudopsshell/deaconguard/v@RELEASE@/ci/install.sh | sh -s -- @RELEASE@ "$HOME/.local/bin"
    displayName: Install DeaconGuard
  - script: |
      export PATH="$HOME/.local/bin:$PATH"
      deaconguard image scan "$(image)" --ignore-unfixed --fail-on high --format junit --output deaconguard-image.xml
    displayName: Check the image
  - task: PublishTestResults@2
    condition: always()
    inputs:
      testResultsFormat: JUnit
      testResultsFiles: deaconguard-*.xml
```

To see SARIF in Azure DevOps, publish the `--format sarif` report as a build artifact named `CodeAnalysisLogs`, which the SARIF SAST Scans Tab extension shows.
