#!/usr/bin/env bash
# Path A.14 — kc/billing rewrite dry-run.
# Drops stale 'replace ../..' + 'replace ../../testutil' workspace artifacts.

set -euo pipefail
SCRATCH=/tmp/algo2go-billing-extract-dryrun/kite-mcp-billing-extract
[ -d "$SCRATCH" ] || { echo "ERROR: run prep first"; exit 1; }
cd "$SCRATCH"

echo "=== Phase 9: Rewrite kc/billing self-imports + go.mod module path ==="
find . -name '*.go' -type f -exec sed -i 's#github.com/zerodha/kite-mcp-server/kc/billing#github.com/algo2go/kite-mcp-billing#g' {} \;
sed -i 's#^module github.com/zerodha/kite-mcp-server/kc/billing$#module github.com/algo2go/kite-mcp-billing#' go.mod

echo "=== Phase 9b: Drop stale workspace artifacts ==="
sed -i '/github\.com\/zerodha\/kite-mcp-server v0\.0\.0-/d' go.mod
sed -i '/github\.com\/zerodha\/kite-mcp-server\/testutil v0\.0\.0-/d' go.mod
sed -i '/github\.com\/zerodha\/kite-mcp-server => /d' go.mod
sed -i '/github\.com\/zerodha\/kite-mcp-server\/testutil => /d' go.mod

echo "=== Updated go.mod ==="
cat go.mod
echo ""

echo "=== Stale-reference scan ==="
stale=$(grep -rE 'github.com/zerodha/kite-mcp-server' --include='*.go' --include='go.mod' -l 2>/dev/null || true)
stale_count=$(echo -n "$stale" | grep -c . || true)
echo "Stale refs: $stale_count (target 0)"
[ -n "$stale" ] && echo "$stale"
echo ""

echo "=== Build sanity ==="
GO=/usr/local/go/bin/go
$GO mod tidy 2>&1 | tail -5
echo ""
$GO build ./... 2>&1 | tail -3
echo "build exit: $?"
echo ""
$GO test -count=1 -timeout 120s ./... 2>&1 | tail -5
