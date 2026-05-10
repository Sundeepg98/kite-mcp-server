#!/usr/bin/env bash
set -euo pipefail
SCRATCH=/tmp/algo2go-sectors-extract-dryrun
SOURCE=/mnt/d/Sundeep/projects/kite-mcp-server

rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"
cd "$SCRATCH"
git clone -q "$SOURCE" kite-mcp-sectors-extract
cd kite-mcp-sectors-extract
echo "Fresh clone HEAD: $(git rev-parse HEAD)"
echo "kc/sectors-touching commits: $(git log --oneline -- kc/sectors/ | wc -l)"
git filter-repo --subdirectory-filter kc/sectors/ --tag-rename ':sectors-v' --force 2>&1 | tail -10
echo "Commits: $(git log --oneline | wc -l)"
ls
[ -f go.mod ] && head -8 go.mod
