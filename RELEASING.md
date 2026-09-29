# Releasing OpsArmor

Releases are built by the [release workflow](.github/workflows/release.yml) when a `v*` tag is pushed. It checks that the tag is a semantic version, runs the tests, and publishes:

- Linux and macOS archives, `.deb` and `.rpm` packages, and `checksums.txt` on the GitHub release, with the notes from the matching `CHANGELOG.md` section.

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
   git tag -a vX.Y.Z-rc.1 -m "OpsArmor X.Y.Z release candidate 1"
   git push origin vX.Y.Z-rc.1
   ```

   The GitHub release is marked as a pre-release. Install it, check `opsarmor version`, and scan a test machine.
4. **Tag the release** from the same commit once the candidate works:

   ```sh
   git tag -a vX.Y.Z -m "OpsArmor X.Y.Z"
   git push origin vX.Y.Z
   ```

5. **Check the release** on GitHub: the notes and the assets.

A tag that fails the workflow can be deleted with `git push --delete origin TAG` and `git tag -d TAG` before retrying; delete the draft or failed release on GitHub first. Never reuse a version number that users may already have installed; publish the next patch version instead.

## Test the packaging locally

`make release-snapshot` builds all archives and packages into `dist/` without publishing (requires [GoReleaser](https://goreleaser.com)).
