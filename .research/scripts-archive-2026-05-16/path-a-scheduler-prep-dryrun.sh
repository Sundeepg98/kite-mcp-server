#!/usr/bin/env bash
# Path A.6.2 — kc/scheduler extraction dry-run.

set -euo pipefail

SCRATCH=/tmp/algo2go-scheduler-extract-dryrun
SOURCE=/mnt/d/Sundeep/projects/kite-mcp-server

echo "=== Setup ==="
rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"
cd "$SCRATCH"

echo "=== Phase 1: Fresh clone ==="
git clone -q "$SOURCE" kite-mcp-scheduler-extract
cd kite-mcp-scheduler-extract
echo "Fresh clone HEAD: $(git rev-parse HEAD)"
echo "Total commits: $(git log --oneline | wc -l)"
echo "kc/scheduler-touching commits: $(git log --oneline -- kc/scheduler/ | wc -l)"
echo ""

echo "=== Phase 2: filter-repo --subdirectory-filter kc/scheduler/ ==="
git filter-repo --subdirectory-filter kc/scheduler/ --tag-rename ':scheduler-v' --force 2>&1 | tail -10
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
