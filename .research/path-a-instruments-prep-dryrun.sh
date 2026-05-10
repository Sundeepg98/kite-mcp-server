#!/usr/bin/env bash
# Path A.16 — kc/instruments extraction dry-run.
set -euo pipefail
SCRATCH=/tmp/algo2go-instruments-extract-dryrun
SOURCE=/mnt/d/Sundeep/projects/kite-mcp-server

rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"
cd "$SCRATCH"
git clone -q "$SOURCE" kite-mcp-instruments-extract
cd kite-mcp-instruments-extract
echo "Fresh clone HEAD: $(git rev-parse HEAD)"
echo "kc/instruments-touching commits: $(git log --oneline -- kc/instruments/ | wc -l)"
git filter-repo --subdirectory-filter kc/instruments/ --tag-rename ':instruments-v' --force 2>&1 | tail -10
echo ""
echo "=== Post-extract ==="
echo "Commits: $(git log --oneline | wc -l)"
ls
[ -f go.mod ] && head -8 go.mod
