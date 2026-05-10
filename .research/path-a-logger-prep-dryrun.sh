#!/usr/bin/env bash
# Path A.7 — kc/logger extraction dry-run.

set -euo pipefail

SCRATCH=/tmp/algo2go-logger-extract-dryrun
SOURCE=/mnt/d/Sundeep/projects/kite-mcp-server

echo "=== Setup ==="
rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"
cd "$SCRATCH"

echo "=== Phase 1: Fresh clone ==="
git clone -q "$SOURCE" kite-mcp-logger-extract
cd kite-mcp-logger-extract
echo "Fresh clone HEAD: $(git rev-parse HEAD)"
echo "Total commits: $(git log --oneline | wc -l)"
echo "kc/logger-touching commits: $(git log --oneline -- kc/logger/ | wc -l)"
echo ""

echo "=== Phase 2: filter-repo --subdirectory-filter kc/logger/ ==="
git filter-repo --subdirectory-filter kc/logger/ --tag-rename ':logger-v' --force 2>&1 | tail -10
echo ""

echo "=== Phase 3: Result ==="
echo "Post-extract HEAD: $(git rev-parse HEAD)"
echo "Post-extract commits: $(git log --oneline | wc -l)"
echo ""

echo "=== Phase 4: Top-level structure ==="
ls -la
echo ""

echo "=== Phase 5: Commit timeline ==="
git log --oneline --reverse | head -10
echo ""

echo "=== Phase 6: Module skeleton ==="
[ -f go.mod ] && head -10 go.mod
echo ""
echo "Go files:"
find . -maxdepth 1 -name '*.go' -type f | sort
