#!/usr/bin/env bash
# Path A — kc/decorators extraction dry-run.
# Mirror of path-b-money-prep-dryrun.sh adapted for kc/decorators.

set -euo pipefail

SCRATCH=/tmp/algo2go-decorators-extract-dryrun
SOURCE=/mnt/d/Sundeep/projects/kite-mcp-server

echo "=== Setup ==="
rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"
cd "$SCRATCH"

echo "=== Phase 1: Fresh clone (local file://) ==="
git clone -q "$SOURCE" kite-mcp-decorators-extract
cd kite-mcp-decorators-extract
echo "Fresh clone HEAD: $(git rev-parse HEAD)"
echo "Total commits: $(git log --oneline | wc -l)"
echo "kc/decorators-touching commits: $(git log --oneline -- kc/decorators/ | wc -l)"
echo ""

echo "=== Phase 2: filter-repo --subdirectory-filter kc/decorators/ ==="
git filter-repo --subdirectory-filter kc/decorators/ --tag-rename ':decorators-v' --force 2>&1 | tail -10
echo ""

echo "=== Phase 3: Result inspection ==="
echo "Post-extract HEAD: $(git rev-parse HEAD)"
echo "Post-extract commits: $(git log --oneline | wc -l)"
echo ""

echo "=== Phase 4: Top-level structure (now kc/decorators/ is repo root) ==="
ls -la
echo ""

echo "=== Phase 5: Commit timeline ==="
git log --oneline --reverse
echo ""

echo "=== Phase 6: Module skeleton verification ==="
[ -f go.mod ] && head -3 go.mod
echo ""
echo "Go files:"
find . -maxdepth 1 -name '*.go' -type f | sort
echo ""
