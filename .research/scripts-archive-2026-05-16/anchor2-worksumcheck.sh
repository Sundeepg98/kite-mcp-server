#!/bin/bash
set -e
export PATH=/usr/local/go/bin:/usr/bin:/bin
cd /mnt/d/Sundeep/projects/kite-mcp-server
echo "=== go work sync ==="
go work sync 2>&1 | tail -10
echo "=== git diff go.work.sum ==="
git diff go.work.sum 2>&1 | head -20
