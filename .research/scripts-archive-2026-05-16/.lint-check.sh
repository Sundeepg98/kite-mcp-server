#!/bin/bash
export PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
cd /mnt/d/Sundeep/projects/kite-mcp-server || exit 1
echo "=== go vet ==="
go vet ./... 2>&1 | tail -30
echo ""
echo "=== HEAD ==="
git rev-parse HEAD
