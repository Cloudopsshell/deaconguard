# Contributing to DeaconGuard

Thanks for helping. This guide covers setting up, making a change, and getting it merged.

## Set up

You need Go 1.26 or later and Node.js 24 with npm.

```sh
git clone https://github.com/Cloudopsshell/deaconguard.git && cd deaconguard
make build        # web UI and binary
make test vet     # Go tests and vet
make ui-dev       # web UI with hot reload; run ./deaconguard serve alongside it
```

## Make a change

1. **Open an issue first** for anything larger than a small fix, so the approach can be agreed before you write code.
2. **Work on a branch.** `main` is protected: nobody, maintainers included, can push to it directly. Name the branch after the change, for example `fix/scan-timeout` or `feature/csv-export`.
3. **Keep the change focused** and match the surrounding code's style. Run `gofmt` on Go files.
4. **Add or update tests.** Bug fixes should come with a test that fails without the fix.
5. **Update `CHANGELOG.md`** under `## [Unreleased]` for anything a user would notice, in the Added, Changed, Fixed, or Security group.
6. **Update the README** when behavior, commands, or setup change, and the documentation at [docs.deaconguard.io](https://docs.deaconguard.io) (the `deaconguard-website` repository) in the same release.
7. **`packaging/install.sh` goes live on merge.** `get.deaconguard.io` serves it from `main`, and it installs the *latest release*. A change to it must work with that release's packages; anything that needs a newer binary must check for it first, as the script does for `deaconguard setup`.

## Sign the Contributor License Agreement

Before your first pull request can be merged, you need to sign the [DeaconGuard Contributor License Agreement](CLA.md). You keep the copyright in your work; the agreement grants the project a license to use and distribute your contribution. When you open your first pull request, the CLA Assistant bot comments with a link: sign in with GitHub and accept. This takes a minute, is needed only once, and covers all of your later contributions.

If your employer has rights to code you write, make sure you have their permission before you sign.

## Open a pull request

Push the branch and open a pull request against `main`. Fill in the template: what changed, why, and how you tested it.

A pull request can be merged when:

- the author has signed the **[CLA](CLA.md)**;
- the **CI** checks pass (Go formatting, vet, tests with the race detector, the vulnerability scan, the web UI build, ShellCheck of the install script, and the release configuration check);
- it has an **approving review** from a [maintainer](MAINTAINERS.md), given after the last push;
- every review conversation is resolved.

## Rules for scanner code

DeaconGuard runs on other people's servers, so these rules are not negotiable:

- Commands run on a scanned machine are **fixed, read-only strings** defined in `internal/target` or `internal/checks`, and run through the `target.Target` interface (implemented by `internal/local`). Never insert user input or data from the machine into a command.
- Use sudo only when the host allows it, and never store or log passwords.
- A scan that fails or cannot evaluate something must never be reported as clean.
- Only enable a distribution when its official advisory source and evaluator have been verified.

## Third-party content

DeaconGuard is MIT-licensed, and every release ships its dependencies inside the binary. CI enforces these rules, in the **Go tests** and **Web UI build** jobs:

- **Dependencies** must be MIT, ISC, BSD-2-Clause, BSD-3-Clause or Apache-2.0, for Go modules and the web UI's runtime packages alike. Copyleft (GPL, LGPL, AGPL) and source-available licences (SSPL, BUSL) can't be used. If a dependency needs another licence, read it and ask in the pull request before adding it to the list in `.github/workflows/ci.yml`.
- **No CIS Benchmark material.** Its licence forbids using it in a product. Don't copy, paraphrase line by line, or name CIS Benchmarks or CIS Controls. Base hardening controls on public-domain sources (DISA STIG, NIST SP 800-53, NSA/CISA guides) or permissively licensed ones (ComplianceAsCode, BSD), and write them in our own words.
- **Copyrighted standards** (PCI DSS, ISO/IEC 27001) are referenced by requirement number and a short title in our own words, never their text. A test keeps titles to 10 words.
- **Advisory data and detection rules** (distribution feeds, CISA KEV, EPSS, YARA Forge) are downloaded by the server when it runs. Don't add them to the repository or the binary; test fixtures are small and written for the tests.
- **Images, icons and fonts** are our own or come with a licence that allows redistribution. Don't use distributions' or other companies' logos.

Run the checks locally with `sh scripts/check-content.sh` and `go run github.com/google/go-licenses/v2@v2.0.1 check ./... --allowed_licenses=MIT,ISC,BSD-2-Clause,BSD-3-Clause,Apache-2.0`.

## Security issues

Do not open public issues for vulnerabilities. Follow [SECURITY.md](SECURITY.md) instead.

## Releases

Maintainers publish releases as described in [RELEASING.md](RELEASING.md).
