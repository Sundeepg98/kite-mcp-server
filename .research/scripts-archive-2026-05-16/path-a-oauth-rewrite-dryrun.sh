#!/usr/bin/env bash
# Path A.13 — oauth rewrite dry-run.
# Drops stale 'replace zerodha/kite-mcp-server => ../' + 'replace .../testutil'
# (workspace artifacts; oauth has zero actual root + zero testutil imports).

set -euo pipefail
SCRATCH=/tmp/algo2go-oauth-extract-dryrun/kite-mcp-oauth-extract
[ -d "$SCRATCH" ] || { echo "ERROR: run prep first"; exit 1; }
cd "$SCRATCH"

echo "=== Phase 9: Rewrite oauth self-imports + go.mod module path ==="
find . -name '*.go' -type f -exec sed -i 's#github.com/zerodha/kite-mcp-server/oauth#github.com/algo2go/kite-mcp-oauth#g' {} \;
sed -i 's#^module github.com/zerodha/kite-mcp-server/oauth$#module github.com/algo2go/kite-mcp-oauth#' go.mod
echo "Step 9: rewrites applied"
echo ""

echo "=== Phase 9b: Drop stale root + testutil replace (workspace artifacts) ==="
sed -i '/github\.com\/zerodha\/kite-mcp-server v0\.0\.0-/d' go.mod
sed -i '/github\.com\/zerodha\/kite-mcp-server\/testutil v0\.0\.0-/d' go.mod
sed -i '/github\.com\/zerodha\/kite-mcp-server => /d' go.mod
sed -i '/github\.com\/zerodha\/kite-mcp-server\/testutil => /d' go.mod
echo "Step 9b: stale workspace artifacts dropped"
echo ""

echo "=== Updated go.mod ==="
cat go.mod
echo ""

echo "=== Stale-reference scan (target 0) ==="
stale=$(grep -rE 'github.com/zerodha/kite-mcp-server' --include='*.go' --include='go.mod' -l 2>/dev/null || true)
stale_count=$(echo -n "$stale" | grep -c . || true)
echo "Files with stale 'zerodha/kite-mcp-server' refs: $stale_count (target: 0)"
[ -n "$stale" ] && echo "$stale"
echo ""

echo "=== Compilation sanity ==="
GO=/usr/local/go/bin/go
$GO mod tidy 2>&1 | tail -5
echo ""
$GO build ./... 2>&1 | tail -5
echo "build exit: $?"
echo ""
$GO test -count=1 -timeout 120s ./... 2>&1 | tail -5
echo ""
echo "=== Dry-run complete ==="
