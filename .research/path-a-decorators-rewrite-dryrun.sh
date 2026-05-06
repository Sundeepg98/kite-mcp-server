#!/usr/bin/env bash
# Path A — kc/decorators rewrite dry-run.
# Mirror of path-b-money-rewrite-dryrun.sh.

set -euo pipefail

SCRATCH=/tmp/algo2go-decorators-extract-dryrun/kite-mcp-decorators-extract

if [ ! -d "$SCRATCH" ]; then
	echo "ERROR: $SCRATCH not found. Run path-a-decorators-prep-dryrun.sh first."
	exit 1
fi

cd "$SCRATCH"

echo "=== Phase 9: Rewrite kc/decorators self-imports + go.mod module path ==="

find . -name '*.go' -type f -exec sed -i 's#github.com/zerodha/kite-mcp-server/kc/decorators#github.com/algo2go/kite-mcp-decorators#g' {} \;
echo "Step 9a: kc/decorators self-refs rewritten in .go files (likely 0 — leaf)"

sed -i 's#^module github.com/zerodha/kite-mcp-server/kc/decorators$#module github.com/algo2go/kite-mcp-decorators#' go.mod
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
GO=""
for candidate in go /usr/local/go/bin/go /opt/go/bin/go; do
	if "$candidate" version >/dev/null 2>&1; then
		GO="$candidate"
		break
	fi
done
if [ -n "$GO" ]; then
	echo "Using $GO; running 'go build ./...'"
	"$GO" build ./... 2>&1 | head -10
	echo "build exit: $?"
	echo ""
	echo "Running 'go test ./...':"
	"$GO" test ./... 2>&1 | tail -5
fi
echo ""
echo "=== Dry-run complete. Scratch: $SCRATCH ==="
