#!/bin/bash
set -e
export PATH=/usr/local/go/bin:/usr/bin:/bin
cd /mnt/d/Sundeep/projects/kite-mcp-server
echo "=== TestHTTPRoundtrip_InitToolsList ==="
go test -run '^TestHTTPRoundtrip_InitToolsList$' -count=1 ./mcp/ -v 2>&1 | tail -30
