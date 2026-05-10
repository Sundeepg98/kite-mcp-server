#!/usr/bin/env bash
set -euo pipefail
SCRATCH=/tmp/algo2go-audit-extract-dryrun
SOURCE=/mnt/d/Sundeep/projects/kite-mcp-server

rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"
cd "$SCRATCH"
git clone -q "$SOURCE" kite-mcp-audit-extract
cd kite-mcp-audit-extract
echo "Fresh clone HEAD: $(git rev-parse HEAD)"
echo "kc/audit-touching commits: $(git log --oneline -- kc/audit/ | wc -l)"
git filter-repo --subdirectory-filter kc/audit/ --tag-rename ':audit-v' --force 2>&1 | tail -10
echo "Commits: $(git log --oneline | wc -l)"
ls
[ -f go.mod ] && head -8 go.mod
