#!/usr/bin/env bash
# Path A.4 — kc/i18n extraction dry-run.
# Mirror of path-a-decorators-prep-dryrun.sh.

set -euo pipefail

SCRATCH=/tmp/algo2go-i18n-extract-dryrun
SOURCE=/mnt/d/Sundeep/projects/kite-mcp-server

echo "=== Setup ==="
rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"
cd "$SCRATCH"

echo "=== Phase 1: Fresh clone ==="
git clone -q "$SOURCE" kite-mcp-i18n-extract
cd kite-mcp-i18n-extract
echo "Fresh clone HEAD: $(git rev-parse HEAD)"
echo "Total commits: $(git log --oneline | wc -l)"
echo "kc/i18n-touching commits: $(git log --oneline -- kc/i18n/ | wc -l)"
echo ""

echo "=== Phase 2: filter-repo --subdirectory-filter kc/i18n/ ==="
git filter-repo --subdirectory-filter kc/i18n/ --tag-rename ':i18n-v' --force 2>&1 | tail -10
echo ""

echo "=== Phase 3: Result inspection ==="
echo "Post-extract HEAD: $(git rev-parse HEAD)"
echo "Post-extract commits: $(git log --oneline | wc -l)"
echo ""

echo "=== Phase 4: Top-level structure ==="
ls -la
echo ""

echo "=== Phase 5: Commit timeline ==="
git log --oneline --reverse
echo ""

echo "=== Phase 6: Module skeleton ==="
[ -f go.mod ] && head -3 go.mod
echo ""
echo "Go files:"
find . -maxdepth 2 -name '*.go' -type f | sort
echo ""
echo "locales/ subdir:"
ls -la locales/ 2>/dev/null
