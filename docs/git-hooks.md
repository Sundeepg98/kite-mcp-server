# Git hooks

Opt-in pre-commit hooks that run gofmt + go vet + go build on staged changes.
Fail fast locally rather than in CI.

## Install (one-time, per clone)

```sh
./scripts/install-git-hooks.sh
```

This sets `git config core.hooksPath .githooks` so the versioned hooks are used.

## What the pre-commit hook does

- `gofmt -l` on all staged `.go` files -> fail if any need formatting
- `go vet` on packages containing staged Go files -> fail on issues
- `go build ./...` -> fail if build breaks
- Exit 0 if no `.go` files staged

## Bypass (rare - only for WIP commits)

```sh
git commit --no-verify -m "wip: something"
```

## Uninstall

```sh
git config --unset core.hooksPath
```
