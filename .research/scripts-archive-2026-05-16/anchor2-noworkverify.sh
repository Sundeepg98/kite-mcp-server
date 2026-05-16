#!/bin/bash
set -e
export PATH=/usr/local/go/bin:/usr/bin:/bin
export GOWORK=off
cd /mnt/d/Sundeep/projects/kite-mcp-server
echo "=== GOWORK=off go build ./app/providers/... ==="
cd app/providers
go build ./... 2>&1 | tail -10
cd ../..
echo "=== GOWORK=off go build ./... (root) ==="
go build ./... 2>&1 | tail -10
