#!/usr/bin/env bash
# Path A.15 — kc/watchlist consumer cutover ON MASTER.
set -euo pipefail
ROOT=/mnt/d/Sundeep/projects/kite-mcp-server
cd "$ROOT"
[ "$(git rev-parse --abbrev-ref HEAD)" != "master" ] && { echo "ERROR: not on master"; exit 1; }
echo "HEAD: $(git rev-parse HEAD)"

echo "=== Phase 1: Pre-rewrite census ==="
total=$(grep -rE 'github.com/zerodha/kite-mcp-server/kc/watchlist' --include='*.go' --include='*.mod' -l 2>/dev/null | wc -l)
echo "Files with kc/watchlist import: $total"

echo "=== Phase 2: Rewrite consumer .go files ==="
find . -name '*.go' -type f -not -path './kc/watchlist/*' -not -path './.research/*' \
	-exec sed -i 's#github.com/zerodha/kite-mcp-server/kc/watchlist#github.com/algo2go/kite-mcp-watchlist#g' {} \;

echo "=== Phase 3: Rewrite kc/watchlist subtree ==="
find ./kc/watchlist -name '*.go' -type f \
	-exec sed -i 's#github.com/zerodha/kite-mcp-server/kc/watchlist#github.com/algo2go/kite-mcp-watchlist#g' {} \;
sed -i 's#^module github.com/zerodha/kite-mcp-server/kc/watchlist$#module github.com/algo2go/kite-mcp-watchlist#' kc/watchlist/go.mod

echo "=== Phase 4: Rewrite root go.mod ==="
sed -i 's#github.com/zerodha/kite-mcp-server/kc/watchlist#github.com/algo2go/kite-mcp-watchlist#g' go.mod

echo "=== Phase 5: Sweep peer-module go.mod files ==="
find . -path ./kc/watchlist -prune -o -path ./.research -prune -o -name 'go.mod' -type f -print | while read -r mod; do
	if grep -q 'github.com/zerodha/kite-mcp-server/kc/watchlist' "$mod" 2>/dev/null; then
		sed -i 's#github.com/zerodha/kite-mcp-server/kc/watchlist#github.com/algo2go/kite-mcp-watchlist#g' "$mod"
		echo "  rewrote: $mod"
	fi
done

echo "=== Phase 6: Pin require to v0.1.0 ==="
sed -i 's#github.com/algo2go/kite-mcp-watchlist v0.0.0-00010101000000-000000000000#github.com/algo2go/kite-mcp-watchlist v0.1.0#g' go.mod
find . -path ./kc/watchlist -prune -o -path ./.research -prune -o -name 'go.mod' -type f -print | while read -r mod; do
	sed -i 's#github.com/algo2go/kite-mcp-watchlist v0.0.0-00010101000000-000000000000#github.com/algo2go/kite-mcp-watchlist v0.1.0#g' "$mod"
done

echo "=== Phase 7: Stale check ==="
stale=$(grep -rE 'github.com/zerodha/kite-mcp-server/kc/watchlist' --include='*.go' --include='*.mod' -l 2>/dev/null || true)
stale_count=$(echo -n "$stale" | grep -c . || true)
[ "$stale_count" -ne 0 ] && { echo "ERROR: stale: $stale"; exit 1; }
echo "OK: 0 stale"

echo "=== Phase 8: WSL2 verify ==="
GO=/usr/local/go/bin/go
$GO build ./...
echo "BUILD: PASS"
$GO test -run "^TestHTTPRoundtrip_InitToolsList$" -count=1 -timeout 60s ./mcp/ 2>&1 | tail -3

echo "Files changed: $(git status --short | grep -vE '^\?\?' | wc -l)"
