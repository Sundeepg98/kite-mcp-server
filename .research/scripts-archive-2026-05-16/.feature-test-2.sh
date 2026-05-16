#!/bin/bash
export PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
cd /mnt/d/Sundeep/projects/kite-mcp-server || exit 1
echo "=== Running new TDD test (must fail before implementation) ==="
go test -count=1 -run TestMax_ActivityAPI_WithToolNameFilter ./kc/ops/... 2>&1 | tail -20
