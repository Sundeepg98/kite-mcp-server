#!/usr/bin/env bash
# Path A.6.1 — kc/isttz extraction dry-run.
# Mirror of path-a-legaldocs-prep-dryrun.sh.

set -euo pipefail

SCRATCH=/tmp/algo2go-isttz-extract-dryrun
SOURCE=/mnt/d/Sundeep/projects/kite-mcp-server

echo "=== Setup ==="
rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"
cd "$SCRATCH"

echo "=== Phase 1: Fresh clone ==="
git clone -q "$SOURCE" kite-mcp-isttz-extract
cd kite-mcp-isttz-extract
echo "Fresh clone HEAD: $(git rev-parse HEAD)"
echo "Total commits: $(git log --oneline | wc -l)"
echo "kc/isttz-touching commits: $(git log --oneline -- kc/isttz/ | wc -l)"
echo ""

echo "=== Phase 2: filter-repo --subdirectory-filter kc/isttz/ ==="
git filter-repo --subdirectory-filter kc/isttz/ --tag-rename ':isttz-v' --force 2>&1 | tail -10
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
find . -maxdepth 1 -name '*.go' -type f | sort
