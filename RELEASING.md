# Releasing DeaconGuard

Releases are built by the [release workflow](.github/workflows/release.yml) when a `v*` tag is pushed. It checks that the tag is a semantic version, runs the tests, and publishes:

- Linux and macOS archives, `.deb` and `.rpm` packages, `install.sh`, and `checksums.txt` on the GitHub release, with the notes from the matching `CHANGELOG.md` section.
- `deaconguard_X.Y.Z_sbom.spdx.json`, the SBOM (Syft), and a "Dependencies" section appended to the notes by `scripts/release-dependencies.sh`. That script fails the release if its table names a package `install.sh` no longer installs.
- `checksums.txt.sigstore.json`, a keyless [Sigstore](https://www.sigstore.dev) signature of `checksums.txt`. GitHub vouches that this workflow, for this tag, produced it, so there is no signing key to create or keep.

## Choose the version

Follow [Semantic Versioning](https://semver.org):

- **Patch** (`0.1.0` → `0.1.1`): bug fixes only.
- **Minor** (`0.1.1` → `0.2.0`): new features. Before 1.0.0, also any breaking change, such as a database change that cannot be downgraded or a changed CLI flag.
- **Major** (`1.x` → `2.0.0`): breaking changes after 1.0.0.

## Steps

1. **Update `CHANGELOG.md`** on a branch: move the entries under `[Unreleased]` into a new section `## [X.Y.Z] - YYYY-MM-DD`, grouped as Added, Changed, Deprecated, Removed, Fixed, and Security, and update the comparison links at the bottom. List any upgrade steps under **Changed**.
2. **Merge** the branch into `main` through a pull request once the CI checks pass and it is approved.
3. **Tag a release candidate** from `main` to test the pipeline without affecting users:

   ```sh
   git switch main && git pull
   git tag -a vX.Y.Z-rc.1 -m "DeaconGuard X.Y.Z release candidate 1"
   git push origin vX.Y.Z-rc.1
   ```

   The GitHub release is marked as a pre-release. Install it, check `deaconguard version`, and scan a test machine.
4. **Tag the release** from the same commit once the candidate works:

   ```sh
   git tag -a vX.Y.Z -m "DeaconGuard X.Y.Z"
   git push origin vX.Y.Z
   ```

5. **Check the release** on GitHub: the notes and the assets, including `install.sh` and `checksums.txt.sigstore.json`. The workflow verifies the signature before it finishes.

A tag that fails the workflow can be deleted with `git push --delete origin TAG` and `git tag -d TAG` before retrying; delete the draft or failed release on GitHub first. Never reuse a version number that users may already have installed; publish the next patch version instead.

## Test the packaging locally

`make release-snapshot` builds all archives and packages into `dist/` without publishing or signing (requires [GoReleaser](https://goreleaser.com)).

## Updating cosign in the install script

`packaging/install.sh` pins `COSIGN_VERSION` and the SHA-256 of `cosign-linux-amd64` and `cosign-linux-arm64`. To update, take the new values from that cosign release's `cosign_checksums.txt` and change all three together.
