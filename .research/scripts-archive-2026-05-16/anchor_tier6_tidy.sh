#!/bin/bash
# Tier 6 plugins extraction — tidy + work sync
set -e
export PATH="/usr/local/go/bin:$PATH"
cd /mnt/d/Sundeep/projects/kite-mcp-server

echo "--- go mod tidy in plugins/ ---"
cd plugins
go mod tidy 2>&1 | head -30
echo "--- exit $? ---"

cd ..
echo "--- go work sync ---"
go work sync 2>&1 | head -30
echo "--- exit $? ---"

echo "--- git status (any peer-module changes from go work sync?) ---"
git status --porcelain | grep -v '^??' | head -20
