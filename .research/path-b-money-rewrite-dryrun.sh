#!/usr/bin/env bash
# Path B alt-1 — kc/money extracted-repo rewrite dry-run.
# Mirrors path-a-prep-rewrite-dryrun.sh.
# Pre-condition: path-b-money-prep-dryrun.sh already executed.

set -euo pipefail

SCRATCH=/tmp/algo2go-money-extract-dryrun/kite-mcp-money-extract

if [ ! -d "$SCRATCH" ]; then
	echo "ERROR: $SCRATCH not found. Run path-b-money-prep-dryrun.sh first."
	exit 1
fi

cd "$SCRATCH"

echo "=== Phase 9: Rewrite kc/money self-imports + go.mod module path ==="

# Rewrite any github.com/zerodha/kite-mcp-server/kc/money refs in *.go files
# (kc/money is a leaf — has no self-imports beyond its own package — but
# this is defensive in case future extracts have them).
find . -name '*.go' -type f -exec sed -i 's#github.com/zerodha/kite-mcp-server/kc/money#github.com/algo2go/kite-mcp-money#g' {} \;
echo "Step 9a: kc/money self-refs rewritten in .go files (likely 0 hits since leaf)"

# Rewrite the module declaration in go.mod (anchored to start-of-line via ^).
sed -i 's#^module github.com/zerodha/kite-mcp-server/kc/money$#module github.com/algo2go/kite-mcp-money#' go.mod
echo "Step 9b: go.mod module path rewritten"

echo ""
echo "=== Updated go.mod ==="
cat go.mod
echo ""

echo "=== Stale-reference scan (target 0) ==="
stale=$(grep -rE 'github.com/zerodha/kite-mcp-server' --include='*.go' --include='go.mod' -l 2>/dev/null || true)
stale_count=$(echo -n "$stale" | grep -c . || true)
echo "Files with any stale 'zerodha/kite-mcp-server' refs: $stale_count (target: 0)"
[ -n "$stale" ] && echo "$stale"
echo ""

echo "=== Self-ref scan ==="
fresh=$(grep -rE 'github.com/algo2go/kite-mcp-money' --include='*.go' -l 2>/dev/null || true)
fresh_count=$(echo -n "$fresh" | grep -c . || true)
echo "Files now using algo2go/kite-mcp-money: $fresh_count"
echo ""

echo "=== Phase 10: Final repo state ==="
ls -la
echo ""
echo "=== Compilation sanity ==="
GO=""
for candidate in go /usr/local/go/bin/go /opt/go/bin/go; do
	if "$candidate" version >/dev/null 2>&1; then
		GO="$candidate"
		break
	fi
done
if [ -n "$GO" ]; then
	echo "Using $GO; running 'go build ./...' (kc/money is a leaf — no internal deps)"
	"$GO" build ./... 2>&1 | head -10
	echo "exit: $?"
	echo ""
	echo "Running 'go test ./...':"
	"$GO" test ./... 2>&1 | tail -10
else
	echo "SKIP: go not in PATH"
fi
echo ""
echo "=== Dry-run complete. Scratch dir: $SCRATCH ==="
