#!/bin/bash
# Tier 6 plugins extraction — baseline tools=111 invariant
set -e
export PATH="/usr/local/go/bin:$PATH"
cd /mnt/d/Sundeep/projects/kite-mcp-server
echo "--- Run TestHTTPRoundtrip_InitToolsList ---"
go test ./mcp/ -run TestHTTPRoundtrip_InitToolsList -v -count=1 2>&1 | tail -30
