#!/bin/bash
set -e
export PATH=/usr/local/go/bin:/usr/bin:/bin
cd /mnt/d/Sundeep/projects/kite-mcp-server
echo "=== Simulate Dockerfile path: GOWORK=off go mod download in root ==="
GOWORK=off go mod download 2>&1 | tail -10
echo "=== GOWORK=off go build ./... ==="
GOWORK=off go build ./... 2>&1 | tail -10
