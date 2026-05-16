#!/bin/bash
# Mechanical lint cleanup: go mod tidy + verify nothing breaks
export PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
set -e
cd /mnt/d/Sundeep/projects/kite-mcp-server || exit 1
echo "=== go mod tidy ==="
go mod tidy 2>&1 | head -10
echo ""
echo "=== go.mod jwt indirect status (post-tidy) ==="
grep "jwt" go.mod | head -5
