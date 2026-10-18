---
title: Verify a release
description: Check that a DeaconGuard download is genuine.
---

Every release is signed **keyless with [Sigstore](https://www.sigstore.dev)**, the same way Kubernetes and Flux sign theirs. `checksums.txt.sigstore.json` proves that DeaconGuard's release workflow on GitHub produced `checksums.txt`, and `checksums.txt` lists the SHA-256 of every file in the release. Nobody holds a signing key that could leak.

The [install script](../installation/install-script.md) checks both on every install: it installs [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) if needed, verifies the signature, then the checksum.

## Check it yourself

Download `checksums.txt`, `checksums.txt.sigstore.json` and the files you want from the release, then:

```bash
VERSION=$(curl -fsSL https://get.deaconguard.io/stable.txt)   # or the release you downloaded
cosign verify-blob checksums.txt --bundle checksums.txt.sigstore.json \
  --certificate-identity "https://github.com/Cloudopsshell/deaconguard/.github/workflows/release.yml@refs/tags/v${VERSION}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

sha256sum --check --ignore-missing checksums.txt
```

`Verified OK` from cosign and `OK` for each file mean the files are exactly what the release workflow built for that version.

## The container image and the Helm chart

The [image](../installation/docker.md) and the [chart](../installation/kubernetes.md) are signed by the same workflow, in the registry:

```bash
VERSION=$(curl -fsSL https://get.deaconguard.io/stable.txt)   # or the version you run
cosign verify "ghcr.io/cloudopsshell/deaconguard:${VERSION}" \
  --certificate-identity "https://github.com/Cloudopsshell/deaconguard/.github/workflows/release.yml@refs/tags/v${VERSION}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
cosign verify "ghcr.io/cloudopsshell/charts/deaconguard:${VERSION}" \
  --certificate-identity "https://github.com/Cloudopsshell/deaconguard/.github/workflows/release.yml@refs/tags/v${VERSION}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

A policy controller such as Kyverno or Sigstore's policy-controller can require that signature before a cluster runs the image. The image's SBOM is attached to it in the registry.

## Dependencies and SBOM

Each release's notes on GitHub include a **Dependencies** section: the Go version and main libraries the release was built with, and what the install script installs on each machine. The release also carries `deaconguard_X.Y.Z_sbom.spdx.json`, an SBOM in SPDX format listing every Go module and web UI package with its version and license. `checksums.txt` covers it, so the same signature proves it's genuine.
