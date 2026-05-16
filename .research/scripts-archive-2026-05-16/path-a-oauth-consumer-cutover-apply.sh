#!/usr/bin/env bash
# Path A.13 — oauth consumer cutover ON MASTER.

set -euo pipefail

ROOT=/mnt/d/Sundeep/projects/kite-mcp-server
cd "$ROOT"

HEAD_BEFORE=$(git rev-parse HEAD)
BRANCH=$(git rev-parse --abbrev-ref HEAD)
echo "HEAD: $HEAD_BEFORE"
[ "$BRANCH" != "master" ] && { echo "ERROR: not on master"; exit 1; }

echo ""
echo "=== Phase 1: Pre-rewrite census ==="
total=$(grep -rE 'github.com/zerodha/kite-mcp-server/oauth' --include='*.go' --include='*.mod' -l 2>/dev/null | wc -l)
echo "Files with oauth import: $total"

echo ""
echo "=== Phase 2: Rewrite consumer .go files ==="
find . -name '*.go' -type f -not -path './oauth/*' -not -path './.research/*' \
	-exec sed -i 's#github.com/zerodha/kite-mcp-server/oauth#github.com/algo2go/kite-mcp-oauth#g' {} \;

echo ""
echo "=== Phase 3: Rewrite oauth subtree (Phase A canary) ==="
find ./oauth -name '*.go' -type f \
	-exec sed -i 's#github.com/zerodha/kite-mcp-server/oauth#github.com/algo2go/kite-mcp-oauth#g' {} \;
sed -i 's#^module github.com/zerodha/kite-mcp-server/oauth$#module github.com/algo2go/kite-mcp-oauth#' oauth/go.mod

echo ""
echo "=== Phase 4: Rewrite root go.mod ==="
sed -i 's#github.com/zerodha/kite-mcp-server/oauth#github.com/algo2go/kite-mcp-oauth#g' go.mod

echo ""
echo "=== Phase 5: Sweep peer-module go.mod files ==="
find . -path ./oauth -prune -o -path ./.research -prune -o -name 'go.mod' -type f -print | while read -r mod; do
	if grep -q 'github.com/zerodha/kite-mcp-server/oauth' "$mod" 2>/dev/null; then
		sed -i 's#github.com/zerodha/kite-mcp-server/oauth#github.com/algo2go/kite-mcp-oauth#g' "$mod"
		echo "  rewrote: $mod"
	fi
done

echo ""
echo "=== Phase 6: Pin require to v0.1.0 ==="
sed -i 's#github.com/algo2go/kite-mcp-oauth v0.0.0-00010101000000-000000000000#github.com/algo2go/kite-mcp-oauth v0.1.0#g' go.mod
find . -path ./oauth -prune -o -path ./.research -prune -o -name 'go.mod' -type f -print | while read -r mod; do
	sed -i 's#github.com/algo2go/kite-mcp-oauth v0.0.0-00010101000000-000000000000#github.com/algo2go/kite-mcp-oauth v0.1.0#g' "$mod"
done

echo ""
echo "=== Phase 7: Stale check ==="
stale=$(grep -rE 'github.com/zerodha/kite-mcp-server/oauth' --include='*.go' --include='*.mod' -l 2>/dev/null || true)
stale_count=$(echo -n "$stale" | grep -c . || true)
[ "$stale_count" -ne 0 ] && { echo "ERROR: stale refs:"; echo "$stale"; exit 1; }
echo "OK: zero stale refs"

echo ""
echo "=== Phase 8: WSL2 verify ==="
GO=/usr/local/go/bin/go
$GO build ./...
echo "BUILD: PASS"
$GO test -run "^TestHTTPRoundtrip_InitToolsList$" -count=1 -timeout 60s ./mcp/ 2>&1 | tail -3

echo ""
echo "Files changed: $(git status --short | grep -vE '^\?\?' | wc -l)"
