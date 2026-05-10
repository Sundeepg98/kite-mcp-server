#!/usr/bin/env bash
set -euo pipefail
ROOT=/mnt/d/Sundeep/projects/kite-mcp-server
cd "$ROOT"
[ "$(git rev-parse --abbrev-ref HEAD)" != "master" ] && { echo "ERROR: not on master"; exit 1; }
echo "HEAD: $(git rev-parse HEAD)"

total=$(grep -rE 'github.com/zerodha/kite-mcp-server/kc/ticker' --include='*.go' --include='*.mod' -l 2>/dev/null | wc -l)
echo "Files with kc/ticker import: $total"

find . -name '*.go' -type f -not -path './kc/ticker/*' -not -path './.research/*' \
	-exec sed -i 's#github.com/zerodha/kite-mcp-server/kc/ticker#github.com/algo2go/kite-mcp-ticker#g' {} \;

find ./kc/ticker -name '*.go' -type f \
	-exec sed -i 's#github.com/zerodha/kite-mcp-server/kc/ticker#github.com/algo2go/kite-mcp-ticker#g' {} \;
sed -i 's#^module github.com/zerodha/kite-mcp-server/kc/ticker$#module github.com/algo2go/kite-mcp-ticker#' kc/ticker/go.mod

sed -i 's#github.com/zerodha/kite-mcp-server/kc/ticker#github.com/algo2go/kite-mcp-ticker#g' go.mod

find . -path ./kc/ticker -prune -o -path ./.research -prune -o -name 'go.mod' -type f -print | while read -r mod; do
	if grep -q 'github.com/zerodha/kite-mcp-server/kc/ticker' "$mod" 2>/dev/null; then
		sed -i 's#github.com/zerodha/kite-mcp-server/kc/ticker#github.com/algo2go/kite-mcp-ticker#g' "$mod"
		echo "  rewrote: $mod"
	fi
done

sed -i 's#github.com/algo2go/kite-mcp-ticker v0.0.0-00010101000000-000000000000#github.com/algo2go/kite-mcp-ticker v0.1.0#g' go.mod
find . -path ./kc/ticker -prune -o -path ./.research -prune -o -name 'go.mod' -type f -print | while read -r mod; do
	sed -i 's#github.com/algo2go/kite-mcp-ticker v0.0.0-00010101000000-000000000000#github.com/algo2go/kite-mcp-ticker v0.1.0#g' "$mod"
done

stale=$(grep -rE 'github.com/zerodha/kite-mcp-server/kc/ticker' --include='*.go' --include='*.mod' -l 2>/dev/null || true)
stale_count=$(echo -n "$stale" | grep -c . || true)
[ "$stale_count" -ne 0 ] && { echo "ERROR: stale: $stale"; exit 1; }
echo "OK: 0 stale"

GO=/usr/local/go/bin/go
$GO build ./...
echo "BUILD: PASS"
$GO test -run "^TestHTTPRoundtrip_InitToolsList$" -count=1 -timeout 60s ./mcp/ 2>&1 | tail -3

echo "Files changed: $(git status --short | grep -vE '^\?\?' | wc -l)"
