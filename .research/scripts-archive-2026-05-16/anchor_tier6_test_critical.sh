#!/bin/bash
# Tier 6 plugins extraction — critical-path tests
# Scope narrowed per "narrow agent test scope" rule:
# - plugins/* (the new module)
# - mcp/ (where tools=111 lives + plugin imports)
# - app/ (where wire.go imports plugins)
# Avoid full ./... per "narrow scope" rule.
set -e
export PATH="/usr/local/go/bin:$PATH"
cd /mnt/d/Sundeep/projects/kite-mcp-server

echo "=== plugins/ ==="
go test ./plugins/... -count=1 2>&1 | tail -10
echo ""

echo "=== mcp/ (where tools=111 lives + uses plugin registry) ==="
go test ./mcp/ -count=1 -timeout 120s 2>&1 | tail -10
echo ""

echo "=== app/ (where wire.go imports plugins) ==="
go test ./app/... -count=1 -timeout 120s 2>&1 | tail -20
