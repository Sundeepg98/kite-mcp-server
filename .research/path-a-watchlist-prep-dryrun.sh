#!/usr/bin/env bash
# Path A.15 — kc/watchlist extraction dry-run.
set -euo pipefail
SCRATCH=/tmp/algo2go-watchlist-extract-dryrun
SOURCE=/mnt/d/Sundeep/projects/kite-mcp-server

rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"
cd "$SCRATCH"
git clone -q "$SOURCE" kite-mcp-watchlist-extract
cd kite-mcp-watchlist-extract
echo "Fresh clone HEAD: $(git rev-parse HEAD)"
echo "kc/watchlist-touching commits: $(git log --oneline -- kc/watchlist/ | wc -l)"
git filter-repo --subdirectory-filter kc/watchlist/ --tag-rename ':watchlist-v' --force 2>&1 | tail -10
echo ""
echo "=== Post-extract ==="
echo "Commits: $(git log --oneline | wc -l)"
ls
[ -f go.mod ] && head -8 go.mod
