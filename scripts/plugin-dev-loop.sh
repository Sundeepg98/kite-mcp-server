#!/usr/bin/env bash
# plugin-dev-loop.sh — file-watch TDD loop for plugin development.
#
# Watches plugin-registry source files and re-runs tests on change.
# Gives the solo developer the "edit plugin, see green/red
# immediately" workflow without adding an in-tree daemon dependency.
#
# Requires one of (auto-detected):
#   - watchexec (preferred, native debouncing)
#   - entr      (minimal, ubiquitous)
#   - fswatch   (fallback)
#
# Usage:
#   ./scripts/plugin-dev-loop.sh           # Watch every plugin registry
#   ./scripts/plugin-dev-loop.sh riskguard # Watch one registry only
#
# Registry list — extend as new plugin extension points are added.
# Each line is: name | watch_dir | test_args (passed to `go test`)
set -euo pipefail

# Trampoline: when the watcher fires, it re-invokes this script
# with __run_tests as the first arg. Handle that FIRST so we don't
# drop into the watcher setup path a second time.
if [[ "${1:-}" == "__run_tests" ]]; then
  shift
  # shellcheck disable=SC2086
  go test -count=1 -timeout 60s ${TEST_TARGETS_JOINED:-./...}
  exit $?
fi

FILTER="${1:-}"

# Registry declarations. Format: name@dir@test-args
REG_SPECS=(
  "mcp@mcp@./mcp/"
  "riskguard@kc/riskguard@./kc/riskguard/"
  "scheduler@kc/scheduler@./kc/scheduler/"
  "telegram@kc/telegram@./kc/telegram/"
  "audit@kc/audit@./kc/audit/"
  "routes@app@./app/"
  "widgets@mcp@./mcp/"
)

# Build watch dirs and the test targets.
WATCH_DIRS=()
TEST_TARGETS=()
for spec in "${REG_SPECS[@]}"; do
  IFS='@' read -r name dir target <<< "$spec"
  if [[ -n "$FILTER" && "$name" != "$FILTER" ]]; then
    continue
  fi
  WATCH_DIRS+=("$dir")
  TEST_TARGETS+=("$target")
done

if [[ ${#WATCH_DIRS[@]} -eq 0 ]]; then
  echo "No registry matched filter: $FILTER"
  echo "Available: $(printf '%s ' "${REG_SPECS[@]%%@*}")"
  exit 1
fi

# Deduplicate (widgets and mcp both want ./mcp/).
TEST_TARGETS=($(printf '%s\n' "${TEST_TARGETS[@]}" | sort -u))

# Export for child shells.
export TEST_TARGETS_JOINED="${TEST_TARGETS[*]}"

run_tests() {
  # shellcheck disable=SC2086
  go test -count=1 -timeout 60s $TEST_TARGETS_JOINED
}

if command -v watchexec >/dev/null 2>&1; then
  echo ">> using watchexec (recommended)"
  WATCH_ARGS=()
  for d in "${WATCH_DIRS[@]}"; do
    WATCH_ARGS+=("--watch" "$d")
  done
  exec watchexec --exts go --restart "${WATCH_ARGS[@]}" -- "$0" __run_tests
elif command -v entr >/dev/null 2>&1; then
  echo ">> using entr"
  find "${WATCH_DIRS[@]}" -type f -name '*.go' | entr -c "$0" __run_tests
elif command -v fswatch >/dev/null 2>&1; then
  echo ">> using fswatch"
  while :; do
    run_tests || true
    fswatch -1 -l 0.5 "${WATCH_DIRS[@]}" >/dev/null
  done
else
  cat <<EOF
No file-watcher detected. Install one of:

  watchexec  (recommended)
    macOS:    brew install watchexec
    Linux:    cargo install watchexec-cli
    Windows:  scoop install watchexec / winget install watchexec-cli

  entr
    macOS:    brew install entr
    Linux:    apt install entr
    Windows:  pacman -S entr (msys2)

  fswatch
    macOS:    brew install fswatch
    Linux:    apt install fswatch

Or run the tests once directly:

  go test -count=1 -timeout 60s $TEST_TARGETS_JOINED
EOF
  exit 1
fi

