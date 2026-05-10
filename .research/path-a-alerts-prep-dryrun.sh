#!/usr/bin/env bash
# Path A.11 — kc/alerts extraction dry-run.
set -euo pipefail
SCRATCH=/tmp/algo2go-alerts-extract-dryrun
SOURCE=/mnt/d/Sundeep/projects/kite-mcp-server

rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"
cd "$SCRATCH"
git clone -q "$SOURCE" kite-mcp-alerts-extract
cd kite-mcp-alerts-extract
echo "Fresh clone HEAD: $(git rev-parse HEAD)"
echo "kc/alerts-touching commits: $(git log --oneline -- kc/alerts/ | wc -l)"
git filter-repo --subdirectory-filter kc/alerts/ --tag-rename ':alerts-v' --force 2>&1 | tail -10
echo ""
echo "=== Post-extract ==="
echo "Commits: $(git log --oneline | wc -l)"
ls -la | head
[ -f go.mod ] && head -8 go.mod
