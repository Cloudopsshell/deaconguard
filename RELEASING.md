# Releasing DeaconGuard

Releases are built by the [release workflow](.github/workflows/release.yml) when a `v*` tag is pushed. It checks that the tag is a semantic version, runs the tests, and publishes:

- Linux and macOS archives, `.deb` and `.rpm` packages, `install.sh`, and `checksums.txt` on the GitHub release, with the notes from the matching `CHANGELOG.md` section.
- `deaconguard_X.Y.Z_sbom.spdx.json`, the SBOM (Syft), and a "Dependencies" section appended to the notes by `scripts/release-dependencies.sh`. That script fails the release if its table names a package `install.sh` no longer installs.
- The container image and the Helm chart on GHCR. The chart's version comes from the tag; the Compose and Kustomize files in `deploy/` must already pin it (see step 1).
- `checksums.txt.sigstore.json`, a keyless [Sigstore](https://www.sigstore.dev) signature of `checksums.txt`. GitHub vouches that this workflow, for this tag, produced it, so there is no signing key to create or keep.

## Choose the version

Follow [Semantic Versioning](https://semver.org):

- **Patch** (`1.0.0` → `1.0.1`): bug fixes only.
- **Minor** (`1.0.1` → `1.1.0`): new features that keep working with existing installs, scripts and API clients.
- **Major** (`1.x` → `2.0.0`): any breaking change, such as a database change that cannot be downgraded, a removed or changed CLI flag, or a changed API.

## Steps

1. **Prepare the release** on a branch. Changes land under `## [Unreleased]` in `CHANGELOG.md` as they are merged, grouped as Added, Changed, Deprecated, Removed, Fixed, and Security, with any upgrade steps under **Changed**. Then run:

   ```sh
   git switch main && git pull && git switch -c release/X.Y.Z
   sh scripts/prepare-release.sh X.Y.Z
   ```

   It moves the Unreleased entries into `## [X.Y.Z] - YYYY-MM-DD`, updates the comparison links, and runs `scripts/set-version.sh X.Y.Z`, which writes the version into the Compose file, the Kustomize manifests and the Helm chart. Don't edit those versions by hand: CI checks the files agree, and the release workflow stops if they don't match the tag. Commit, push and open the release pull request.
2. **Merge** the branch into `main` through a pull request once the CI checks pass and it is approved.
3. **Tag a release candidate** from `main` to test the pipeline without affecting users:

   ```sh
   git switch main && git pull
   git tag -a vX.Y.Z-rc.1 -m "DeaconGuard X.Y.Z release candidate 1"
   git push origin vX.Y.Z-rc.1
   ```

   The GitHub release is marked as a pre-release. Install it, check `deaconguard version`, and scan a test machine. Then test it **the way the docs tell people to**, starting from the **previous release**, with each command copied from the page as it is written:

   - **Install script:** install the previous release on a test machine, then run the upgrade command from [Upgrade](docs/content/installation/upgrade.md) and [Install script](docs/content/installation/install-script.md), with an agent from another machine enrolled.
   - **Helm:** install the previous release's chart as [Kubernetes](docs/content/installation/kubernetes.md) did, the server and the agent DaemonSet as releases of their own, then run every `helm upgrade` on the Upgrade page, word for word (with the candidate's version). CI's **Helm upgrade** job renders the chart as `--reuse-values` does against every earlier release; this is the real thing.
   - **Compose and Kustomize:** follow their upgrade steps the same way.

   A command that fails as written is a release blocker, even if another way works: fix the chart, the script or the page, and tag the next candidate.
4. **Tag the release** from the same commit once the candidate works:

   ```sh
   git tag -a vX.Y.Z -m "DeaconGuard X.Y.Z"
   git push origin vX.Y.Z
   ```

5. **Check the release** on GitHub: the notes and the assets, including `install.sh` and `checksums.txt.sigstore.json`. The workflow verifies the signature before it finishes.
6. **Check what people read**, once the website has rebuilt for the release (hourly, or run its Build workflow): `get.deaconguard.io/stable.txt`, the pages the release changed on docs.deaconguard.io, the homepage at deaconguard.io if the release changes what it describes (its own PR, in the website repository, merged after the release), and the README on GitHub, diagrams included.

A tag that fails the workflow can be deleted with `git push --delete origin TAG` and `git tag -d TAG` before retrying; delete the draft or failed release on GitHub first. Never reuse a version number that users may already have installed; publish the next patch version instead.

## Test the packaging locally

`make release-snapshot` builds all archives and packages into `dist/` without publishing or signing (requires [GoReleaser](https://goreleaser.com)).

## Updating cosign in the install script

`packaging/install.sh` pins `COSIGN_VERSION` and the SHA-256 of `cosign-linux-amd64` and `cosign-linux-arm64`. To update, take the new values from that cosign release's `cosign_checksums.txt` and change all three together.
