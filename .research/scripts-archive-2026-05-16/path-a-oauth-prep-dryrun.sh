#!/usr/bin/env bash
# Path A.13 — oauth extraction dry-run.
set -euo pipefail
SCRATCH=/tmp/algo2go-oauth-extract-dryrun
SOURCE=/mnt/d/Sundeep/projects/kite-mcp-server

rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"
cd "$SCRATCH"
git clone -q "$SOURCE" kite-mcp-oauth-extract
cd kite-mcp-oauth-extract
echo "Fresh clone HEAD: $(git rev-parse HEAD)"
echo "oauth-touching commits: $(git log --oneline -- oauth/ | wc -l)"
git filter-repo --subdirectory-filter oauth/ --tag-rename ':oauth-v' --force 2>&1 | tail -10
echo ""
echo "=== Post-extract ==="
echo "Commits: $(git log --oneline | wc -l)"
ls | head -10
[ -f go.mod ] && head -10 go.mod
