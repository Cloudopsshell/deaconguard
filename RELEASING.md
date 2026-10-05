# Releasing DeaconGuard

Releases are built by the [release workflow](.github/workflows/release.yml) when a `v*` tag is pushed. It checks that the tag is a semantic version, runs the tests, and publishes:

- Linux and macOS archives, `.deb` and `.rpm` packages, `install.sh`, and `checksums.txt` on the GitHub release, with the notes from the matching `CHANGELOG.md` section.
- `checksums.txt.sig`, signed with the release key, and `checksums.txt.sigstore.json`, a keyless [Sigstore](https://www.sigstore.dev) signature tied to the release workflow.

## The release signing key

`install.sh` refuses any release whose `checksums.txt` is not signed by the key whose public half it carries. The workflow reads the private key from the `RELEASE_SIGNING_KEY` repository secret, and stops before publishing when the secret is missing or does not match the public key in `packaging/install.sh`.

Create the key once, on a trusted machine:

```sh
umask 077
openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out release-signing-key.pem
openssl pkey -in release-signing-key.pem -pubout                 # the public key for packaging/install.sh
gh secret set RELEASE_SIGNING_KEY -R Cloudopsshell/deaconguard < release-signing-key.pem
```

Put the public key in `RELEASE_KEY` in `packaging/install.sh` through a pull request. Keep an offline copy of the private key in a password manager, then delete the file.

Changing the key later breaks the install script of every earlier release, because each one carries the old public key; users then download the newest `install.sh`. Change it only when the key may be compromised, and say so in the release notes.

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

5. **Check the release** on GitHub: the notes and the assets, including `install.sh`, `checksums.txt.sig`, and `checksums.txt.sigstore.json`. The workflow verifies both signatures before it finishes.

A tag that fails the workflow can be deleted with `git push --delete origin TAG` and `git tag -d TAG` before retrying; delete the draft or failed release on GitHub first. Never reuse a version number that users may already have installed; publish the next patch version instead.

## Test the packaging locally

`make release-snapshot` builds all archives and packages into `dist/` without publishing or signing (requires [GoReleaser](https://goreleaser.com)).
