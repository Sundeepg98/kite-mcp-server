#!/usr/bin/env bash
set -euo pipefail
SCRATCH=/tmp/algo2go-registry-extract-dryrun
SOURCE=/mnt/d/Sundeep/projects/kite-mcp-server

rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"
cd "$SCRATCH"
git clone -q "$SOURCE" kite-mcp-registry-extract
cd kite-mcp-registry-extract
echo "Fresh clone HEAD: $(git rev-parse HEAD)"
echo "kc/registry-touching commits: $(git log --oneline -- kc/registry/ | wc -l)"
git filter-repo --subdirectory-filter kc/registry/ --tag-rename ':registry-v' --force 2>&1 | tail -10
echo "Commits: $(git log --oneline | wc -l)"
ls
[ -f go.mod ] && head -8 go.mod
