#!/bin/bash
# Baseline check for Anchor 2 — app/providers extraction
set -e
export PATH=/usr/local/go/bin:/usr/bin:/bin
cd /mnt/d/Sundeep/projects/kite-mcp-server
echo "=== go version ==="
go version
echo "=== go vet ./app/providers/... ==="
go vet ./app/providers/... 2>&1 | tail -20
echo "=== go vet ./app/... ==="
go vet ./app/... 2>&1 | tail -20
