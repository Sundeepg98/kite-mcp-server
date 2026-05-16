#!/bin/bash
export PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
cd /mnt/d/Sundeep/projects/kite-mcp-server || exit 1
echo "=== Scanner TDD red phase (must fail) ==="
go test -count=1 -run TestScanner ./kc/ops/... 2>&1 | tail -25
