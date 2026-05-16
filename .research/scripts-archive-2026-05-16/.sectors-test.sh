#!/bin/bash
export PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
cd /mnt/d/Sundeep/projects/kite-mcp-server || exit 1
echo "=== sectors TDD red phase (must fail) ==="
go test -count=1 ./kc/sectors/... 2>&1 | tail -15
