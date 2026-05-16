#!/usr/bin/env bash
set -euo pipefail
SCRATCH=/tmp/algo2go-eventsourcing-extract-dryrun
SOURCE=/mnt/d/Sundeep/projects/kite-mcp-server

rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"
cd "$SCRATCH"
git clone -q "$SOURCE" kite-mcp-eventsourcing-extract
cd kite-mcp-eventsourcing-extract
echo "Fresh clone HEAD: $(git rev-parse HEAD)"
echo "kc/eventsourcing-touching commits: $(git log --oneline -- kc/eventsourcing/ | wc -l)"
git filter-repo --subdirectory-filter kc/eventsourcing/ --tag-rename ':eventsourcing-v' --force 2>&1 | tail -10
echo "Commits: $(git log --oneline | wc -l)"
ls
[ -f go.mod ] && head -8 go.mod
