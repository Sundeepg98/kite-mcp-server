#!/usr/bin/env bash
# Path A.12 — kc/users consumer cutover ON MASTER.

set -euo pipefail

ROOT=/mnt/d/Sundeep/projects/kite-mcp-server

cd "$ROOT"

echo "=== Phase 0: Pre-flight ==="
HEAD_BEFORE=$(git rev-parse HEAD)
BRANCH=$(git rev-parse --abbrev-ref HEAD)
echo "HEAD before: $HEAD_BEFORE"
[ "$BRANCH" != "master" ] && { echo "ERROR: not on master"; exit 1; }

echo ""
echo "=== Phase 1: Pre-rewrite census ==="
total=$(grep -rE 'github.com/zerodha/kite-mcp-server/kc/users' --include='*.go' --include='*.mod' -l 2>/dev/null | wc -l)
occurrences=$(grep -rE 'github.com/zerodha/kite-mcp-server/kc/users' --include='*.go' --include='*.mod' -h 2>/dev/null | wc -l)
echo "Files with kc/users import: $total"
echo "Total occurrences: $occurrences"

echo ""
echo "=== Phase 2: Rewrite consumer .go files ==="
find . -name '*.go' -type f -not -path './kc/users/*' -not -path './.research/*' \
	-exec sed -i 's#github.com/zerodha/kite-mcp-server/kc/users#github.com/algo2go/kite-mcp-users#g' {} \;
echo "Step 2: consumer .go files rewritten"

echo ""
echo "=== Phase 3: Rewrite kc/users subtree (Phase A canary) ==="
find ./kc/users -name '*.go' -type f \
	-exec sed -i 's#github.com/zerodha/kite-mcp-server/kc/users#github.com/algo2go/kite-mcp-users#g' {} \;
sed -i 's#^module github.com/zerodha/kite-mcp-server/kc/users$#module github.com/algo2go/kite-mcp-users#' kc/users/go.mod
echo "Step 3: in-tree subtree + kc/users/go.mod rewritten"

echo ""
echo "=== Phase 4: Rewrite root go.mod ==="
sed -i 's#github.com/zerodha/kite-mcp-server/kc/users#github.com/algo2go/kite-mcp-users#g' go.mod
echo "Step 4: root go.mod rewritten"

echo ""
echo "=== Phase 5: Sweep peer-module go.mod files ==="
find . -path ./kc/users -prune -o -path ./.research -prune -o -name 'go.mod' -type f -print | while read -r mod; do
	if grep -q 'github.com/zerodha/kite-mcp-server/kc/users' "$mod" 2>/dev/null; then
		sed -i 's#github.com/zerodha/kite-mcp-server/kc/users#github.com/algo2go/kite-mcp-users#g' "$mod"
		echo "  rewrote: $mod"
	fi
done
echo "Step 5: peer go.mod sweep complete"

echo ""
echo "=== Phase 6: Pin require to v0.1.0 ==="
sed -i 's#github.com/algo2go/kite-mcp-users v0.0.0-00010101000000-000000000000#github.com/algo2go/kite-mcp-users v0.1.0#g' go.mod
find . -path ./kc/users -prune -o -path ./.research -prune -o -name 'go.mod' -type f -print | while read -r mod; do
	sed -i 's#github.com/algo2go/kite-mcp-users v0.0.0-00010101000000-000000000000#github.com/algo2go/kite-mcp-users v0.1.0#g' "$mod"
done
echo "Step 6: require pins to v0.1.0"

echo ""
echo "=== Phase 7: Post-rewrite stale check ==="
stale=$(grep -rE 'github.com/zerodha/kite-mcp-server/kc/users' --include='*.go' --include='*.mod' -l 2>/dev/null || true)
stale_count=$(echo -n "$stale" | grep -c . || true)
if [ "$stale_count" -ne 0 ]; then
	echo "ERROR: stale refs remaining ($stale_count):"
	echo "$stale"
	exit 1
fi
echo "OK: zero stale refs"

echo ""
echo "=== Phase 8: Verify root go.mod ==="
echo "--- require ---"
grep -E '^\s+github\.com/algo2go/kite-mcp-users' go.mod
echo "--- replace ---"
grep -E 'github\.com/algo2go/kite-mcp-users => \./kc/users' go.mod

echo ""
echo "=== Phase 9: Verify kc/users/go.mod ==="
head -3 kc/users/go.mod

echo ""
echo "=== Phase 10: WSL2 build verification ==="
GO=/usr/local/go/bin/go
$GO version
echo ""
echo "--- workspace go build ./... ---"
$GO build ./...
echo "BUILD: PASS"

echo ""
echo "=== Phase 11: Tools=111 invariant test ==="
$GO test -run "^TestHTTPRoundtrip_InitToolsList$" -count=1 -timeout 60s ./mcp/ 2>&1 | tail -3

echo ""
echo "=== Phase 12: Summary ==="
echo "Files changed: $(git status --short | grep -vE '^\?\?' | wc -l)"
