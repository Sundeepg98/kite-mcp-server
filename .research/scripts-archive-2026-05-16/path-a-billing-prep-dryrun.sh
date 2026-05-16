#!/usr/bin/env bash
# Path A.14 — kc/billing extraction dry-run.
set -euo pipefail
SCRATCH=/tmp/algo2go-billing-extract-dryrun
SOURCE=/mnt/d/Sundeep/projects/kite-mcp-server

rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"
cd "$SCRATCH"
git clone -q "$SOURCE" kite-mcp-billing-extract
cd kite-mcp-billing-extract
echo "Fresh clone HEAD: $(git rev-parse HEAD)"
echo "kc/billing-touching commits: $(git log --oneline -- kc/billing/ | wc -l)"
git filter-repo --subdirectory-filter kc/billing/ --tag-rename ':billing-v' --force 2>&1 | tail -10
echo ""
echo "=== Post-extract ==="
echo "Commits: $(git log --oneline | wc -l)"
ls | head
[ -f go.mod ] && head -10 go.mod
