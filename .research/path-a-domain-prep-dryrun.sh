#!/usr/bin/env bash
# Path A.10 — kc/domain extraction dry-run.

set -euo pipefail

SCRATCH=/tmp/algo2go-domain-extract-dryrun
SOURCE=/mnt/d/Sundeep/projects/kite-mcp-server

echo "=== Setup ==="
rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"
cd "$SCRATCH"

echo "=== Phase 1: Fresh clone ==="
git clone -q "$SOURCE" kite-mcp-domain-extract
cd kite-mcp-domain-extract
echo "Fresh clone HEAD: $(git rev-parse HEAD)"
echo "Total commits: $(git log --oneline | wc -l)"
echo "kc/domain-touching commits: $(git log --oneline -- kc/domain/ | wc -l)"
echo ""

echo "=== Phase 2: filter-repo --subdirectory-filter kc/domain/ ==="
git filter-repo --subdirectory-filter kc/domain/ --tag-rename ':domain-v' --force 2>&1 | tail -10
echo ""

echo "=== Phase 3: Result ==="
echo "Post-extract HEAD: $(git rev-parse HEAD)"
echo "Post-extract commits: $(git log --oneline | wc -l)"
echo ""

echo "=== Phase 4: Top-level structure ==="
ls -la
echo ""

echo "=== Phase 5: Commit timeline (first 10) ==="
git log --oneline --reverse | head -10
echo ""

echo "=== Phase 6: Module skeleton ==="
[ -f go.mod ] && head -15 go.mod
echo ""
echo "Go files:"
find . -maxdepth 1 -name '*.go' -type f | sort | head -15
