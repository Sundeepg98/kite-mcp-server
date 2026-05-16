#!/bin/bash
# Verify lint cleanup didn't break anything
export PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
set -e
cd /mnt/d/Sundeep/projects/kite-mcp-server || exit 1
echo "=== go build (workspace mode) ==="
go build ./... 2>&1 | tail -10
echo "=== go vet ==="
go vet ./... 2>&1 | tail -10
echo "=== Tools registration count ==="
grep -rE 'mcp\.NewTool\("' mcp/ --include='*.go' | grep -vE '_test\.go' | wc -l
echo "=== TestHTTPRoundtrip_InitToolsList (if exists) ==="
go test -run TestHTTPRoundtrip_InitToolsList -count=1 ./app/... 2>&1 | tail -15
