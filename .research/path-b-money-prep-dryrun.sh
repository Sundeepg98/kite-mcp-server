#!/usr/bin/env bash
# Path B alt-1 — kc/money extraction dry-run.
# Mirrors path-a-prep-dryrun.sh but for kc/money instead of broker.
# Idempotent: nukes the scratch dir each run. Does NOT touch master.

set -euo pipefail

SCRATCH=/tmp/algo2go-money-extract-dryrun
SOURCE=/mnt/d/Sundeep/projects/kite-mcp-server

echo "=== Setup ==="
rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"
cd "$SCRATCH"

echo "=== Phase 1: Fresh clone (local file:// — no network) ==="
git clone -q "$SOURCE" kite-mcp-money-extract
cd kite-mcp-money-extract
echo "Fresh clone HEAD: $(git rev-parse HEAD)"
echo "Total commits: $(git log --oneline | wc -l)"
echo "kc/money-touching commits: $(git log --oneline -- kc/money/ | wc -l)"
echo ""

echo "=== Phase 2: filter-repo --subdirectory-filter kc/money/ ==="
git filter-repo --subdirectory-filter kc/money/ --tag-rename ':money-v' --force 2>&1 | tail -15
echo ""

echo "=== Phase 3: Result inspection ==="
echo "Post-extract HEAD: $(git rev-parse HEAD)"
echo "Post-extract commits: $(git log --oneline | wc -l)"
echo ""

echo "=== Phase 4: Top-level structure (now kc/money/ is repo root) ==="
ls -la
echo ""

echo "=== Phase 5: Commit timeline (full — only 2 commits expected) ==="
git log --oneline --reverse
echo ""

echo "=== Phase 6: Module skeleton verification ==="
echo "go.mod exists:" && [ -f go.mod ] && head -3 go.mod
echo ""
echo "Go files:"
find . -maxdepth 1 -name '*.go' -type f | sort
echo ""
