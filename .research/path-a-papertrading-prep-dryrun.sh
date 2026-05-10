#!/usr/bin/env bash
set -euo pipefail
SCRATCH=/tmp/algo2go-papertrading-extract-dryrun
SOURCE=/mnt/d/Sundeep/projects/kite-mcp-server

rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"
cd "$SCRATCH"
git clone -q "$SOURCE" kite-mcp-papertrading-extract
cd kite-mcp-papertrading-extract
echo "Fresh clone HEAD: $(git rev-parse HEAD)"
echo "kc/papertrading-touching commits: $(git log --oneline -- kc/papertrading/ | wc -l)"
git filter-repo --subdirectory-filter kc/papertrading/ --tag-rename ':papertrading-v' --force 2>&1 | tail -10
echo "Commits: $(git log --oneline | wc -l)"
ls
[ -f go.mod ] && head -8 go.mod
