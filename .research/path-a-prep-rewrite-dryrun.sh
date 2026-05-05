#!/usr/bin/env bash
# Path A inauguration — Phase 9-10 rewrite dry-run.
# Continues from path-a-prep-dryrun.sh's extracted scratch repo.
# Idempotent IFF run after path-a-prep-dryrun.sh.

set -euo pipefail

SCRATCH=/tmp/algo2go-broker-extract-dryrun/kite-mcp-broker-extract

if [ ! -d "$SCRATCH" ]; then
	echo "ERROR: $SCRATCH not found. Run path-a-prep-dryrun.sh first."
	exit 1
fi

cd "$SCRATCH"

echo "=== Phase 9: Rewrite broker self-imports + go.mod module path ==="

# Order matters — rename the longer prefix first (broker subtree),
# then handle kc/money references which share a parent prefix.
# Broker self-refs become github.com/algo2go/kite-mcp-broker.
find . -name '*.go' -type f -exec sed -i 's#github.com/zerodha/kite-mcp-server/broker#github.com/algo2go/kite-mcp-broker#g' {} \;
echo "Step 9a: broker self-refs rewritten in .go files"

# Rewrite the module declaration in go.mod (anchored to start-of-line via ^).
sed -i 's#^module github.com/zerodha/kite-mcp-server/broker$#module github.com/algo2go/kite-mcp-broker#' go.mod
echo "Step 9b: go.mod module path rewritten"

# Update kc/money references to placeholder algo2go/kite-mcp-money path.
# Per runbook section 3, this becomes the transitional require + replace.
find . -name '*.go' -type f -exec sed -i 's#github.com/zerodha/kite-mcp-server/kc/money#github.com/algo2go/kite-mcp-money#g' {} \;
sed -i 's#github.com/zerodha/kite-mcp-server/kc/money#github.com/algo2go/kite-mcp-money#g' go.mod
echo "Step 9c: kc/money refs rewritten to algo2go placeholder"

echo ""
echo "=== Updated go.mod ==="
cat go.mod
echo ""

echo "=== Stale-reference scan (target 0) ==="
# grep returns 1 if no matches; "|| true" prevents -e from aborting
stale=$(grep -rE 'github.com/zerodha/kite-mcp-server' --include='*.go' --include='go.mod' -l 2>/dev/null || true)
stale_count=$(echo -n "$stale" | grep -c . || true)
echo "Files with any stale 'zerodha/kite-mcp-server' refs: $stale_count (target: 0)"
[ -n "$stale" ] && echo "$stale"
echo ""

echo "=== Self-ref scan (target: every broker file imports algo2go/kite-mcp-broker) ==="
fresh=$(grep -rE 'github.com/algo2go/kite-mcp-broker' --include='*.go' -l 2>/dev/null || true)
fresh_count=$(echo -n "$fresh" | grep -c . || true)
echo "Files now using algo2go/kite-mcp-broker: $fresh_count"
echo ""

echo "=== Phase 10: Final repo state ==="
ls -la
echo ""
echo "=== gofmt check (mechanical rewrite must remain syntactically clean) ==="
if command -v gofmt >/dev/null 2>&1; then
	unformatted=$(gofmt -l . 2>&1 | head -20)
	if [ -z "$unformatted" ]; then
		echo "All .go files are gofmt-clean post-rewrite"
	else
		echo "WARNING: files needing gofmt:"
		echo "$unformatted"
	fi
else
	echo "SKIP: gofmt not in PATH (Go toolchain not installed in WSL2 — informational only)"
fi
echo ""
echo "=== Compilation sanity ==="
echo "Note: broker module needs kc/money source. To build offline we would set:"
echo "  replace github.com/algo2go/kite-mcp-money => /mnt/d/Sundeep/projects/kite-mcp-server/kc/money"
echo "  in go.mod and 'go build ./...'. Skipping full build in dry-run — covered by"
echo "  consumer's transitive replace block in the runbook §5 Phase A."
echo ""
echo "=== Dry-run complete. Scratch dir: $SCRATCH ==="
