#!/bin/bash
set -e
export PATH=/usr/local/go/bin:/usr/bin:/bin
cd /mnt/d/Sundeep/projects/kite-mcp-server
echo "=== go work sync ==="
go work sync 2>&1 | tail -10
echo "=== go mod tidy at app/providers ==="
cd app/providers
go mod tidy 2>&1 | tail -20
cd ../..
echo "=== go work sync after tidy ==="
go work sync 2>&1 | tail -10
echo "=== go build ./app/providers/... ==="
go build ./app/providers/... 2>&1 | tail -10
echo "=== go build ./... (root) ==="
go build ./... 2>&1 | tail -10
