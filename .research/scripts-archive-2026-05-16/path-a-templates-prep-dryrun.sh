#!/usr/bin/env bash
# Path A.8' — kc/templates extraction dry-run.

set -euo pipefail

SCRATCH=/tmp/algo2go-templates-extract-dryrun
SOURCE=/mnt/d/Sundeep/projects/kite-mcp-server

echo "=== Setup ==="
rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"
cd "$SCRATCH"

echo "=== Phase 1: Fresh clone ==="
git clone -q "$SOURCE" kite-mcp-templates-extract
cd kite-mcp-templates-extract
echo "Fresh clone HEAD: $(git rev-parse HEAD)"
echo "Total commits: $(git log --oneline | wc -l)"
echo "kc/templates-touching commits: $(git log --oneline -- kc/templates/ | wc -l)"
echo ""

echo "=== Phase 2: filter-repo --subdirectory-filter kc/templates/ ==="
git filter-repo --subdirectory-filter kc/templates/ --tag-rename ':templates-v' --force 2>&1 | tail -10
echo ""

echo "=== Phase 3: Result ==="
echo "Post-extract HEAD: $(git rev-parse HEAD)"
echo "Post-extract commits: $(git log --oneline | wc -l)"
echo ""

echo "=== Phase 4: Top-level structure ==="
ls -la | head -20
echo ""
echo "Total files: $(find . -type f -not -path './.git/*' | wc -l)"
echo ""

echo "=== Phase 5: Commit timeline (first 10) ==="
git log --oneline --reverse | head -10
echo ""

echo "=== Phase 6: Module skeleton ==="
[ -f go.mod ] && cat go.mod
echo ""
echo "Go files:"
find . -maxdepth 1 -name '*.go' -type f | sort
