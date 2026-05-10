#!/usr/bin/env bash
set -euo pipefail
SCRATCH=/tmp/algo2go-usecases-extract-dryrun
SOURCE=/mnt/d/Sundeep/projects/kite-mcp-server

rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"
cd "$SCRATCH"
git clone -q "$SOURCE" kite-mcp-usecases-extract
cd kite-mcp-usecases-extract
echo "Fresh clone HEAD: $(git rev-parse HEAD)"
echo "kc/usecases-touching commits: $(git log --oneline -- kc/usecases/ | wc -l)"
git filter-repo --subdirectory-filter kc/usecases/ --tag-rename ':usecases-v' --force 2>&1 | tail -10
echo "Commits: $(git log --oneline | wc -l)"
ls
[ -f go.mod ] && head -8 go.mod
