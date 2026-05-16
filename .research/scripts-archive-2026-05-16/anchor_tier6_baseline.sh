#!/bin/bash
# Tier 6 plugins extraction — baseline build verification
set -e
export PATH="/usr/local/go/bin:$PATH"
cd /mnt/d/Sundeep/projects/kite-mcp-server
go version
echo "--- go build ./... ---"
go build ./... 2>&1 | head -20
echo "--- exit $? ---"
