#!/usr/bin/env bash
# Path A.6.1 — kc/isttz rewrite dry-run.

set -euo pipefail

SCRATCH=/tmp/algo2go-isttz-extract-dryrun/kite-mcp-isttz-extract

if [ ! -d "$SCRATCH" ]; then
	echo "ERROR: $SCRATCH not found. Run path-a-isttz-prep-dryrun.sh first."
	exit 1
fi

cd "$SCRATCH"

echo "=== Phase 9: Rewrite kc/isttz self-imports + go.mod module path ==="

find . -name '*.go' -type f -exec sed -i 's#github.com/zerodha/kite-mcp-server/kc/isttz#github.com/algo2go/kite-mcp-isttz#g' {} \;
echo "Step 9a: kc/isttz self-refs rewritten in .go files (likely 0 — leaf)"

sed -i 's#^module github.com/zerodha/kite-mcp-server/kc/isttz$#module github.com/algo2go/kite-mcp-isttz#' go.mod
echo "Step 9b: go.mod module path rewritten"

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
$GO build ./... 2>&1 | head -10
echo "build exit: $?"
echo ""
echo "=== Dry-run complete ==="
