#!/bin/bash
set -e
export PATH=/usr/local/go/bin:/usr/bin:/bin
cd /mnt/d/Sundeep/projects/kite-mcp-server
echo "=== go vet ./app/providers/... ==="
go vet ./app/providers/... 2>&1 | tail -10
echo "=== go vet ./... (root) ==="
go vet ./... 2>&1 | tail -10
echo "=== go test -count=1 ./app/providers/... ==="
go test -count=1 ./app/providers/... 2>&1 | tail -10
echo "=== TestHTTPRoundtrip_InitToolsList ==="
go test -run '^TestHTTPRoundtrip_InitToolsList$' -count=1 -v ./mcp/ 2>&1 | tail -10
echo "=== test ./app/... (root app) ==="
go test -count=1 -short ./app/ 2>&1 | tail -15
