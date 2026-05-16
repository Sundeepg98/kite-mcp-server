#!/usr/bin/env bash
set -euo pipefail
SCRATCH=/tmp/algo2go-cqrs-extract-dryrun
SOURCE=/mnt/d/Sundeep/projects/kite-mcp-server

rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"
cd "$SCRATCH"
git clone -q "$SOURCE" kite-mcp-cqrs-extract
cd kite-mcp-cqrs-extract
echo "Fresh clone HEAD: $(git rev-parse HEAD)"
echo "kc/cqrs-touching commits: $(git log --oneline -- kc/cqrs/ | wc -l)"
git filter-repo --subdirectory-filter kc/cqrs/ --tag-rename ':cqrs-v' --force 2>&1 | tail -10
echo "Commits: $(git log --oneline | wc -l)"
ls
[ -f go.mod ] && head -8 go.mod
