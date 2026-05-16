#!/usr/bin/env bash
# Path A.12 — kc/users rewrite dry-run.
# Drops the stale `require zerodha/kite-mcp-server` + `replace ../..`
# (dead workspace artifacts; zero actual root imports in source).

set -euo pipefail
SCRATCH=/tmp/algo2go-users-extract-dryrun/kite-mcp-users-extract
[ -d "$SCRATCH" ] || { echo "ERROR: run prep first"; exit 1; }
cd "$SCRATCH"

echo "=== Phase 9: Rewrite kc/users self-imports + go.mod module path ==="
find . -name '*.go' -type f -exec sed -i 's#github.com/zerodha/kite-mcp-server/kc/users#github.com/algo2go/kite-mcp-users#g' {} \;
sed -i 's#^module github.com/zerodha/kite-mcp-server/kc/users$#module github.com/algo2go/kite-mcp-users#' go.mod
echo "Step 9: rewrites applied"
echo ""

echo "=== Phase 9b: Drop stale root require + replace (dead workspace artifact) ==="
# kc/users.go has zero actual imports of zerodha/kite-mcp-server
# (verified empirically). The require + replace are leftover workspace
# bookkeeping. Drop both — go mod tidy will confirm by not re-adding.
sed -i '/github\.com\/zerodha\/kite-mcp-server v0\.0\.0-/d' go.mod
sed -i '/github\.com\/zerodha\/kite-mcp-server => /d' go.mod
echo "Step 9b: stale root require + replace dropped"
echo ""

echo "=== Updated go.mod ==="
cat go.mod
echo ""

echo "=== Stale-reference scan (target 0 in .go + go.mod) ==="
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
$GO test -count=1 ./... 2>&1 | tail -5
echo ""
echo "=== Dry-run complete ==="
