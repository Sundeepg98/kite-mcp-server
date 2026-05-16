#!/usr/bin/env bash
set -euo pipefail
ROOT=/mnt/d/Sundeep/projects/kite-mcp-server
cd "$ROOT"
[ "$(git rev-parse --abbrev-ref HEAD)" != "master" ] && { echo "ERROR: not on master"; exit 1; }
echo "HEAD: $(git rev-parse HEAD)"

total=$(grep -rE 'github.com/zerodha/kite-mcp-server/kc/cqrs' --include='*.go' --include='*.mod' -l 2>/dev/null | wc -l)
echo "Files with kc/cqrs import: $total"

find . -name '*.go' -type f -not -path './kc/cqrs/*' -not -path './.research/*' \
	-exec sed -i 's#github.com/zerodha/kite-mcp-server/kc/cqrs#github.com/algo2go/kite-mcp-cqrs#g' {} \;

find ./kc/cqrs -name '*.go' -type f \
	-exec sed -i 's#github.com/zerodha/kite-mcp-server/kc/cqrs#github.com/algo2go/kite-mcp-cqrs#g' {} \;
sed -i 's#^module github.com/zerodha/kite-mcp-server/kc/cqrs$#module github.com/algo2go/kite-mcp-cqrs#' kc/cqrs/go.mod

sed -i 's#github.com/zerodha/kite-mcp-server/kc/cqrs#github.com/algo2go/kite-mcp-cqrs#g' go.mod

find . -path ./kc/cqrs -prune -o -path ./.research -prune -o -name 'go.mod' -type f -print | while read -r mod; do
	if grep -q 'github.com/zerodha/kite-mcp-server/kc/cqrs' "$mod" 2>/dev/null; then
		sed -i 's#github.com/zerodha/kite-mcp-server/kc/cqrs#github.com/algo2go/kite-mcp-cqrs#g' "$mod"
		echo "  rewrote: $mod"
	fi
done

sed -i 's#github.com/algo2go/kite-mcp-cqrs v0.0.0-00010101000000-000000000000#github.com/algo2go/kite-mcp-cqrs v0.1.0#g' go.mod
find . -path ./kc/cqrs -prune -o -path ./.research -prune -o -name 'go.mod' -type f -print | while read -r mod; do
	sed -i 's#github.com/algo2go/kite-mcp-cqrs v0.0.0-00010101000000-000000000000#github.com/algo2go/kite-mcp-cqrs v0.1.0#g' "$mod"
done

stale=$(grep -rE 'github.com/zerodha/kite-mcp-server/kc/cqrs' --include='*.go' --include='*.mod' -l 2>/dev/null || true)
stale_count=$(echo -n "$stale" | grep -c . || true)
[ "$stale_count" -ne 0 ] && { echo "ERROR: stale: $stale"; exit 1; }
echo "OK: 0 stale"

GO=/usr/local/go/bin/go
$GO build ./...
echo "BUILD: PASS"
$GO test -run "^TestHTTPRoundtrip_InitToolsList$" -count=1 -timeout 60s ./mcp/ 2>&1 | tail -3

echo "Files changed: $(git status --short | grep -vE '^\?\?' | wc -l)"
