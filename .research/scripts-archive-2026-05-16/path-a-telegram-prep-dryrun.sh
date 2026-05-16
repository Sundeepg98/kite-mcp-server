#!/usr/bin/env bash
set -euo pipefail
SCRATCH=/tmp/algo2go-telegram-extract-dryrun
SOURCE=/mnt/d/Sundeep/projects/kite-mcp-server

rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"
cd "$SCRATCH"
git clone -q "$SOURCE" kite-mcp-telegram-extract
cd kite-mcp-telegram-extract
echo "Fresh clone HEAD: $(git rev-parse HEAD)"
echo "kc/telegram-touching commits: $(git log --oneline -- kc/telegram/ | wc -l)"
git filter-repo --subdirectory-filter kc/telegram/ --tag-rename ':telegram-v' --force 2>&1 | tail -10
echo "Commits: $(git log --oneline | wc -l)"
ls
[ -f go.mod ] && head -8 go.mod
