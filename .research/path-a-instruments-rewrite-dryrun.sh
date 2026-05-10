#!/usr/bin/env bash
# Path A.16 — kc/instruments rewrite dry-run.
set -euo pipefail
SCRATCH=/tmp/algo2go-instruments-extract-dryrun/kite-mcp-instruments-extract
[ -d "$SCRATCH" ] || { echo "ERROR: run prep first"; exit 1; }
cd "$SCRATCH"

echo "=== Phase 9: Rewrite kc/instruments self-imports + go.mod module path ==="
find . -name '*.go' -type f -exec sed -i 's#github.com/zerodha/kite-mcp-server/kc/instruments#github.com/algo2go/kite-mcp-instruments#g' {} \;
sed -i 's#^module github.com/zerodha/kite-mcp-server/kc/instruments$#module github.com/algo2go/kite-mcp-instruments#' go.mod

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
$GO mod tidy 2>&1 | tail -3
$GO build ./... 2>&1 | tail -3
echo "build exit: $?"
# Skip running tests (DNS-bound flakes per kc/instruments/go.mod comment)
echo "(test run skipped — pre-existing WSL2 DNS-bound flakes documented)"
