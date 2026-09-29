# Contributing to OpsArmor

Thanks for helping. This guide covers setting up, making a change, and getting it merged.

## Set up

You need Go 1.26 or later and Node.js 24 with npm.

```sh
git clone https://github.com/Cloudopsshell/OpsArmor.git && cd OpsArmor
make build        # web UI and binary
make test vet     # Go tests and vet
make ui-dev       # web UI with hot reload; run ./opsarmor serve alongside it
```

## Make a change

1. **Open an issue first** for anything larger than a small fix, so the approach can be agreed before you write code.
2. **Work on a branch.** `main` is protected: nobody, maintainers included, can push to it directly. Name the branch after the change, for example `fix/ssh-timeout` or `feature/csv-export`.
3. **Keep the change focused** and match the surrounding code's style. Run `gofmt` on Go files.
4. **Add or update tests.** Bug fixes should come with a test that fails without the fix.
5. **Update `CHANGELOG.md`** under `## [Unreleased]` for anything a user would notice, in the Added, Changed, Fixed, or Security group.
6. **Update the README** when behavior, commands, or setup change.

## Open a pull request

Push the branch and open a pull request against `main`. Fill in the template: what changed, why, and how you tested it.

A pull request can be merged when:

- the **CI** checks pass (Go formatting, vet, tests with the race detector, the vulnerability scan, the web UI build, and the release configuration check);
- it has an **approving review** from a maintainer, given after the last push;
- every review conversation is resolved.

## Rules for scanner code

OpsArmor runs on other people's servers, so these rules are not negotiable:

- Commands run on a scanned host are **fixed, read-only strings** defined in `internal/target` or `internal/checks`, and must behave the same over every transport (`internal/remote` for SSH, `internal/local` for this machine). Never insert user input or data from the host into a command.
- Keep SSH host-key verification strict: never skip or loosen it.
- Never store or log private keys, passphrases, or passwords.
- A scan that fails or cannot evaluate something must never be reported as clean.
- Only enable a distribution when its official advisory source and evaluator have been verified.

## Security issues

Do not open public issues for vulnerabilities. Follow [SECURITY.md](SECURITY.md) instead.

## Releases

Maintainers publish releases as described in [RELEASING.md](RELEASING.md).
