#!/usr/bin/env bash
# Path A.10 — kc/domain rewrite dry-run.

set -euo pipefail

SCRATCH=/tmp/algo2go-domain-extract-dryrun/kite-mcp-domain-extract

if [ ! -d "$SCRATCH" ]; then
	echo "ERROR: $SCRATCH not found. Run path-a-domain-prep-dryrun.sh first."
	exit 1
fi

cd "$SCRATCH"

echo "=== Phase 9: Rewrite kc/domain self-imports + go.mod module path ==="

find . -name '*.go' -type f -exec sed -i 's#github.com/zerodha/kite-mcp-server/kc/domain#github.com/algo2go/kite-mcp-domain#g' {} \;
echo "Step 9a: kc/domain self-refs rewritten in .go files"

sed -i 's#^module github.com/zerodha/kite-mcp-server/kc/domain$#module github.com/algo2go/kite-mcp-domain#' go.mod
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
$GO mod tidy 2>&1 | tail -5
echo ""
$GO build ./... 2>&1 | tail -3
echo "build exit: $?"
echo ""
$GO test ./... 2>&1 | tail -5
echo ""
echo "=== Dry-run complete ==="
