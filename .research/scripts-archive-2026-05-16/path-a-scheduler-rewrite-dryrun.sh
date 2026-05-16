#!/usr/bin/env bash
# Path A.6.2 — kc/scheduler rewrite dry-run.
# IMPORTANT: scheduler depends on kc/isttz. Rewrite must:
# 1. Rename module path scheduler self-refs
# 2. Drop the relative `replace ../isttz` directive (no longer valid in
#    standalone repo — fetches algo2go/kite-mcp-isttz v0.1.0 from GOPROXY)
# 3. Keep `require algo2go/kite-mcp-isttz v0.1.0` (already pinned by
#    Path A.6.1 cutover)

set -euo pipefail

SCRATCH=/tmp/algo2go-scheduler-extract-dryrun/kite-mcp-scheduler-extract

if [ ! -d "$SCRATCH" ]; then
	echo "ERROR: $SCRATCH not found. Run path-a-scheduler-prep-dryrun.sh first."
	exit 1
fi

cd "$SCRATCH"

echo "=== Phase 9: Rewrite kc/scheduler self-imports + go.mod module path ==="

find . -name '*.go' -type f -exec sed -i 's#github.com/zerodha/kite-mcp-server/kc/scheduler#github.com/algo2go/kite-mcp-scheduler#g' {} \;
echo "Step 9a: kc/scheduler self-refs rewritten in .go files"

sed -i 's#^module github.com/zerodha/kite-mcp-server/kc/scheduler$#module github.com/algo2go/kite-mcp-scheduler#' go.mod
echo "Step 9b: go.mod module path rewritten"

echo ""
echo "=== Phase 9c: Drop relative replace ../isttz directive ==="
# Remove the `replace github.com/algo2go/kite-mcp-isttz => ../isttz` line.
# In the standalone repo, ../isttz doesn't exist — the require must
# resolve via GOPROXY (algo2go/kite-mcp-isttz v0.1.0 is already published).
sed -i '/replace github\.com\/algo2go\/kite-mcp-isttz => \.\.\/isttz/d' go.mod
echo "Step 9c: relative ../isttz replace removed"

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
$GO build ./... 2>&1 | head -10
echo "build exit: $?"
echo ""
$GO test ./... 2>&1 | tail -5
echo ""
echo "=== Dry-run complete ==="
