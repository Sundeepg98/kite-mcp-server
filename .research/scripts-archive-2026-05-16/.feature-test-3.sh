#!/bin/bash
export PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
cd /mnt/d/Sundeep/projects/kite-mcp-server || exit 1
echo "=== kc/ops full test ==="
go test -count=1 ./kc/ops/... 2>&1 | tail -15
echo "=== kc/audit full test ==="
go test -count=1 ./kc/audit/... 2>&1 | tail -5
echo "=== root build ==="
go build ./... 2>&1 | tail -5
echo "=== root vet ==="
go vet ./... 2>&1 | tail -5
echo "=== Tools count ==="
grep -rE 'mcp\.NewTool\("' mcp/ --include='*.go' | grep -vE '_test\.go' | wc -l
