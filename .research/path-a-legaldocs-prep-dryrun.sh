#!/usr/bin/env bash
# Path A.5 — kc/legaldocs extraction dry-run.
# Mirror of path-a-i18n-prep-dryrun.sh.

set -euo pipefail

SCRATCH=/tmp/algo2go-legaldocs-extract-dryrun
SOURCE=/mnt/d/Sundeep/projects/kite-mcp-server

echo "=== Setup ==="
rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"
cd "$SCRATCH"

echo "=== Phase 1: Fresh clone ==="
git clone -q "$SOURCE" kite-mcp-legaldocs-extract
cd kite-mcp-legaldocs-extract
echo "Fresh clone HEAD: $(git rev-parse HEAD)"
echo "Total commits: $(git log --oneline | wc -l)"
echo "kc/legaldocs-touching commits: $(git log --oneline -- kc/legaldocs/ | wc -l)"
echo ""

echo "=== Phase 2: filter-repo --subdirectory-filter kc/legaldocs/ ==="
git filter-repo --subdirectory-filter kc/legaldocs/ --tag-rename ':legaldocs-v' --force 2>&1 | tail -10
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
echo "Markdown files:"
find . -maxdepth 1 -name '*.md' -type f | sort
