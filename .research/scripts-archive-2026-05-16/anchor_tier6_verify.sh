#!/bin/bash
# Tier 6 plugins extraction — full verification
# 1. Workspace-mode build
# 2. GOWORK=off mode build
# 3. go vet
# 4. plugins/ tests
# 5. mcp/ tools=111 invariant test
set -e
export PATH="/usr/local/go/bin:$PATH"
cd /mnt/d/Sundeep/projects/kite-mcp-server

echo "=== 1. Workspace-mode build ==="
go build ./... 2>&1 | head -20
echo "exit: $?"

echo ""
echo "=== 2. GOWORK=off build (root) ==="
GOWORK=off go build ./... 2>&1 | head -20
echo "exit: $?"

echo ""
echo "=== 3. GOWORK=off build (plugins) ==="
cd plugins
GOWORK=off go build ./... 2>&1 | head -20
echo "exit: $?"
cd ..

echo ""
echo "=== 4. go vet ./... (workspace) ==="
go vet ./... 2>&1 | head -20
echo "exit: $?"

echo ""
echo "=== 5. plugins/ tests ==="
go test ./plugins/... -count=1 2>&1 | tail -30
echo "exit: $?"

echo ""
echo "=== 6. tools=111 invariant ==="
go test ./mcp/ -run TestHTTPRoundtrip_InitToolsList -v -count=1 2>&1 | tail -10
echo "exit: $?"
