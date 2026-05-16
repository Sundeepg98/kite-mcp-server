#!/usr/bin/env bash
# Path A inauguration prep — dry-run extraction of broker/ subtree.
# Run via WSL2: wsl bash /mnt/d/Sundeep/projects/kite-mcp-server/.research/path-a-prep-dryrun.sh
# Idempotent: nukes the scratch dir each run. Does NOT touch master.

set -euo pipefail

SCRATCH=/tmp/algo2go-broker-extract-dryrun
SOURCE=/mnt/d/Sundeep/projects/kite-mcp-server

echo "=== Setup ==="
rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"
cd "$SCRATCH"

echo "=== Phase 1: Fresh clone (local file:// — no network) ==="
git clone -q "$SOURCE" kite-mcp-broker-extract
cd kite-mcp-broker-extract
echo "Fresh clone HEAD: $(git rev-parse HEAD)"
echo "Total commits: $(git log --oneline | wc -l)"
echo "Broker-touching commits: $(git log --oneline -- broker/ | wc -l)"
echo ""

echo "=== Phase 2: filter-repo --subdirectory-filter broker/ ==="
git filter-repo --subdirectory-filter broker/ --tag-rename ':broker-v' --force 2>&1 | tail -15
echo ""

echo "=== Phase 3: Result inspection ==="
echo "Post-extract HEAD: $(git rev-parse HEAD)"
echo "Post-extract commits: $(git log --oneline | wc -l)"
echo ""

echo "=== Phase 4: Top-level structure (now broker/ is repo root) ==="
ls -la
echo ""

echo "=== Phase 5: Commit timeline sample (first 5 oldest) ==="
git log --oneline --reverse | head -5
echo ""

echo "=== Phase 6: Commit timeline sample (5 newest) ==="
git log --oneline | head -5
echo ""

echo "=== Phase 7: Renamed tags ==="
git tag | head -20
echo ""

echo "=== Phase 8: Module skeleton verification ==="
echo "go.mod exists:" && [ -f go.mod ] && head -3 go.mod
echo ""
echo "Top-level Go files:"
find . -maxdepth 1 -name '*.go' -type f | sort
echo ""
echo "Subdirectories:"
find . -maxdepth 1 -type d | grep -v '^\./\.git' | sort
