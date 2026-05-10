#!/usr/bin/env bash
# Path A.12 — kc/users extraction dry-run.
set -euo pipefail
SCRATCH=/tmp/algo2go-users-extract-dryrun
SOURCE=/mnt/d/Sundeep/projects/kite-mcp-server

rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"
cd "$SCRATCH"
git clone -q "$SOURCE" kite-mcp-users-extract
cd kite-mcp-users-extract
echo "Fresh clone HEAD: $(git rev-parse HEAD)"
echo "kc/users-touching commits: $(git log --oneline -- kc/users/ | wc -l)"
git filter-repo --subdirectory-filter kc/users/ --tag-rename ':users-v' --force 2>&1 | tail -10
echo ""
echo "=== Post-extract ==="
echo "Commits: $(git log --oneline | wc -l)"
ls -la | head
[ -f go.mod ] && head -10 go.mod
