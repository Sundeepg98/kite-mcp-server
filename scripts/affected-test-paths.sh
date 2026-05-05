#!/usr/bin/env bash
# affected-test-paths.sh — print Go test paths affected by current git diff.
#
# Path A item 3 per audit 6ee6520: smart test selection (Go-equivalent of
# nx affected). Avoids re-running `go test ./...` across all 29 workspace
# modules + root when only a single module changed.
#
# Usage:
#   scripts/affected-test-paths.sh                    # vs origin/master
#   scripts/affected-test-paths.sh BASE_REF           # vs custom base
#
# Output (stdout, space-separated):
#   ./mcp/... ./kc/usecases/... ./kc/audit/...        # narrow case
#   ./...                                             # safety-net case
#   (empty)                                           # no Go-relevant change
#
# Stderr is reserved for diagnostics — pipe-safe in CI.
#
# Decision tree:
#   1. If any go.mod / go.sum / go.work / go.work.sum / Dockerfile* / fly.toml
#      changed -> emit "./..." (safety: workspace-wide impact possible).
#   2. Else, for each changed file:
#        a. Map to nearest workspace-member directory containing a go.mod.
#        b. If file is a Go file at root (main.go, fly_toml_test.go) or under
#           app/, cmd/, mcp/ -> include ./<top-dir>/... (root-module path).
#        c. If file is under one of the 29 extracted modules -> include
#           ./<module>/...
#        d. Otherwise (docs/, *.md, scripts/, .github/) -> skip.
#   3. Deduplicate and emit space-separated.
#
# Safety net: callers should also run `go test ./...` periodically (master
# push + weekly cron) to catch cross-module regressions this script cannot
# detect (e.g. an unchanged consumer broken by a changed exported API).

set -euo pipefail

BASE_REF="${1:-origin/master}"

# 1. Collect changed files vs the base ref. `--diff-filter=ACMRT` excludes
# pure deletions (deleted file has nothing to test).
CHANGED_FILES=$(git diff --name-only --diff-filter=ACMRT "${BASE_REF}...HEAD" 2>/dev/null || git diff --name-only --diff-filter=ACMRT HEAD)

if [[ -z "${CHANGED_FILES}" ]]; then
    echo "affected-test-paths: no changed files vs ${BASE_REF}" >&2
    exit 0
fi

# 2. Workspace-wide-impact files trigger full `./...`.
if echo "${CHANGED_FILES}" | grep -qE '^(go\.mod|go\.sum|go\.work|go\.work\.sum|Dockerfile|Dockerfile\.selfhost|fly\.toml)$'; then
    echo "affected-test-paths: workspace-impact file changed -> ./..." >&2
    echo "./..."
    exit 0
fi

# 3. Per-file mapping. Map each changed file to a test path or skip.
declare -A AFFECTED=()

# Workspace member directories (29 extracted modules — kept in sync with
# go.work `use (...)` block. Shell-grep this list against go.work in CI to
# catch drift if a module is added/removed without updating this script).
WORKSPACE_MEMBERS=(
    "app/providers"
    "broker"
    "kc/alerts"
    "kc/aop"
    "kc/audit"
    "kc/billing"
    "kc/cqrs"
    "kc/decorators"
    "kc/domain"
    "kc/eventsourcing"
    "kc/i18n"
    "kc/instruments"
    "kc/isttz"
    "kc/legaldocs"
    "kc/logger"
    "kc/money"
    "kc/papertrading"
    "kc/registry"
    "kc/riskguard"
    "kc/scheduler"
    "kc/telegram"
    "kc/templates"
    "kc/ticker"
    "kc/usecases"
    "kc/users"
    "kc/watchlist"
    "oauth"
    "plugins"
    "testutil"
)

# Root-level Go-test-relevant top-level dirs (subset of root module — the
# root go.mod covers everything not under a workspace member).
ROOT_TOP_DIRS=("app" "cmd" "mcp")

while IFS= read -r f; do
    [[ -z "${f}" ]] && continue

    # Skip Go-irrelevant files (docs, markdown, scripts, GitHub config).
    if [[ "${f}" == docs/* ]] || [[ "${f}" == *.md ]] || [[ "${f}" == scripts/* ]] \
        || [[ "${f}" == .github/* ]] || [[ "${f}" == .research/* ]] \
        || [[ "${f}" == examples/* ]]; then
        continue
    fi

    # Match against workspace members (longest-prefix wins — kc/audit before kc/).
    matched=""
    for m in "${WORKSPACE_MEMBERS[@]}"; do
        if [[ "${f}" == "${m}/"* ]] || [[ "${f}" == "${m}" ]]; then
            matched="${m}"
            break
        fi
    done

    if [[ -n "${matched}" ]]; then
        AFFECTED["./${matched}/..."]=1
        continue
    fi

    # Not in a workspace member — must be in root module. Map to top-level
    # dir for the narrowest scope. Note: `go list ./top/...` respects
    # workspace boundaries, so `./kc/...` does NOT recurse into extracted
    # workspace members (kc/audit, kc/alerts, etc.) — verified empirically
    # via `go list` against go1.25 workspace mode.
    top="${f%%/*}"
    case "${top}" in
        app|cmd|mcp|kc)
            AFFECTED["./${top}/..."]=1
            ;;
        *)
            # Root-level Go file (main.go, fly_toml_test.go, etc.) — these
            # belong to the root package. Run root-only tests.
            if [[ "${f}" == *.go ]]; then
                AFFECTED["."]=1
            fi
            ;;
    esac
done <<< "${CHANGED_FILES}"

# 4. Emit space-separated list. Sorted for determinism.
if [[ ${#AFFECTED[@]} -eq 0 ]]; then
    echo "affected-test-paths: no Go-relevant changes detected" >&2
    exit 0
fi

# Sort keys for deterministic output
for path in $(printf '%s\n' "${!AFFECTED[@]}" | sort); do
    printf '%s ' "${path}"
done
printf '\n'
