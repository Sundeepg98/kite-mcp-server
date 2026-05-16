#!/bin/bash
export PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
cd /mnt/d/Sundeep/projects/kite-mcp-server || exit 1
echo "=== mcp/portfolio test ==="
go test -count=1 ./mcp/portfolio/... 2>&1 | tail -10
echo "=== root build ==="
go build ./... 2>&1 | tail -10
echo "=== root vet ==="
go vet ./... 2>&1 | tail -10
echo "=== Tools count ==="
grep -rE 'mcp\.NewTool\("' mcp/ --include='*.go' | grep -vE '_test\.go' | wc -l
