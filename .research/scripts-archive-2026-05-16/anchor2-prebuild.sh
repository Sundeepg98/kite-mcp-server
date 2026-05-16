#!/bin/bash
set -e
export PATH=/usr/local/go/bin:/usr/bin:/bin
cd /mnt/d/Sundeep/projects/kite-mcp-server
echo "=== go work sync ==="
go work sync 2>&1 | tail -5
echo "=== build ./app/providers/... ==="
go build ./app/providers/... 2>&1 | tail -5
echo "=== build ./... ==="
go build ./... 2>&1 | tail -10
echo "=== test ./app/providers/... ==="
go test -count=1 ./app/providers/... 2>&1 | tail -10
