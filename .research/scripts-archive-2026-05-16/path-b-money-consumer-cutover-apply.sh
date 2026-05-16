#!/usr/bin/env bash
# Path B alt-1 A.2.4-A.2.5 — apply kc/money consumer cutover ON MASTER.
# Mirror of path-a-consumer-cutover-apply.sh (which did the same for broker).
#
# This is the ONE script that mutates the working tree (no scratch).
# Operates on /mnt/d/Sundeep/projects/kite-mcp-server directly.
#
# Pre-conditions:
#   - master HEAD synced
#   - working tree clean for paths to be touched
#   - algo2go/kite-mcp-money@v0.1.0 already published
#
# Post-conditions:
#   - All kc/money import occurrences in .go files rewritten to the
#     algo2go path
#   - Root go.mod require + replace blocks updated:
#       require github.com/algo2go/kite-mcp-money v0.1.0
#       replace github.com/algo2go/kite-mcp-money => ./kc/money
#     (Phase A canary mode — keeps in-tree ./kc/money canonical)
#   - kc/money/go.mod's module declaration flipped to algo2go path
#   - Peer go.mod files swept (oauth, app/providers, testutil, plugins,
#     broker, kc/{telegram,domain,usecases,audit,alerts,ticker,
#     eventsourcing,papertrading,cqrs,registry,users,billing,riskguard})
#   - Working tree DIRTY; ready for commit + push

set -euo pipefail

ROOT=/mnt/d/Sundeep/projects/kite-mcp-server

cd "$ROOT"

echo "=== Phase 0: Pre-flight ==="
HEAD_BEFORE=$(git rev-parse HEAD)
BRANCH=$(git rev-parse --abbrev-ref HEAD)
echo "HEAD before: $HEAD_BEFORE"
echo "Branch: $BRANCH"
if [ "$BRANCH" != "master" ]; then
	echo "ERROR: must run on master branch, got $BRANCH"
	exit 1
fi

echo ""
echo "=== Phase 1: Pre-rewrite census ==="
total=$(grep -rE 'github.com/zerodha/kite-mcp-server/kc/money' --include='*.go' --include='*.mod' -l 2>/dev/null | wc -l)
occurrences=$(grep -rE 'github.com/zerodha/kite-mcp-server/kc/money' --include='*.go' --include='*.mod' -h 2>/dev/null | wc -l)
echo "Files with kc/money import: $total"
echo "Total occurrences: $occurrences"

echo ""
echo "=== Phase 2: Rewrite consumer .go files ==="
# Skip kc/money/ subtree — handled separately for clarity.
# Skip .research/ scratch artifacts.
find . -name '*.go' -type f -not -path './kc/money/*' -not -path './.research/*' \
	-exec sed -i 's#github.com/zerodha/kite-mcp-server/kc/money#github.com/algo2go/kite-mcp-money#g' {} \;
echo "Step 2: consumer .go files rewritten"

echo ""
echo "=== Phase 3: Rewrite kc/money subtree (kept in-tree as Phase A canary) ==="
find ./kc/money -name '*.go' -type f \
	-exec sed -i 's#github.com/zerodha/kite-mcp-server/kc/money#github.com/algo2go/kite-mcp-money#g' {} \;
sed -i 's#^module github.com/zerodha/kite-mcp-server/kc/money$#module github.com/algo2go/kite-mcp-money#' kc/money/go.mod
echo "Step 3: in-tree kc/money subtree + kc/money/go.mod rewritten"

echo ""
echo "=== Phase 4: Rewrite root go.mod (require + replace) ==="
sed -i 's#github.com/zerodha/kite-mcp-server/kc/money#github.com/algo2go/kite-mcp-money#g' go.mod
echo "Step 4: root go.mod rewritten"

echo ""
echo "=== Phase 5: Sweep 17 peer-module go.mod files ==="
find . -path ./kc/money -prune -o -path ./.research -prune -o -name 'go.mod' -type f -print | while read -r mod; do
	if grep -q 'github.com/zerodha/kite-mcp-server/kc/money' "$mod" 2>/dev/null; then
		sed -i 's#github.com/zerodha/kite-mcp-server/kc/money#github.com/algo2go/kite-mcp-money#g' "$mod"
		echo "  rewrote: $mod"
	fi
done
echo "Step 5: peer go.mod sweep complete"

echo ""
echo "=== Phase 5b: Also handle broker subtree — its own go.mod + source ==="
# At this point broker subtree was already swept in Phase 2 (find without
# kc/money exclusion still hits broker/*.go). But broker/go.mod has its
# own require kc/money replace ../kc/money — that needs the algo2go path.
# Phase 5 above also caught it via the find go.mod sweep. Verify:
echo "broker/go.mod kc-money refs (should be algo2go path now):"
grep -E 'kite-mcp-money|kc/money' broker/go.mod | head -5

echo ""
echo "=== Phase 6: Pin require to v0.1.0 ==="
sed -i 's#github.com/algo2go/kite-mcp-money v0.0.0-00010101000000-000000000000#github.com/algo2go/kite-mcp-money v0.1.0#g' go.mod
# Same for peer go.mods that had the placeholder version:
find . -path ./kc/money -prune -o -path ./.research -prune -o -name 'go.mod' -type f -print | while read -r mod; do
	sed -i 's#github.com/algo2go/kite-mcp-money v0.0.0-00010101000000-000000000000#github.com/algo2go/kite-mcp-money v0.1.0#g' "$mod"
done
echo "Step 6: require pins to v0.1.0"

echo ""
echo "=== Phase 7: Post-rewrite stale check ==="
stale=$(grep -rE 'github.com/zerodha/kite-mcp-server/kc/money' --include='*.go' --include='*.mod' -l 2>/dev/null || true)
stale_count=$(echo -n "$stale" | grep -c . || true)
if [ "$stale_count" -ne 0 ]; then
	echo "ERROR: stale 'zerodha/kite-mcp-server/kc/money' refs remaining ($stale_count):"
	echo "$stale"
	exit 1
fi
echo "OK: zero stale refs"

echo ""
echo "=== Phase 8: Verify root go.mod has algo2go on require + replace ==="
echo "--- require block ---"
grep -E '^\s+github\.com/algo2go/kite-mcp-money' go.mod
echo "--- replace block ---"
grep -E 'github\.com/algo2go/kite-mcp-money => \./kc/money' go.mod

echo ""
echo "=== Phase 9: Verify kc/money/go.mod ==="
head -3 kc/money/go.mod

echo ""
echo "=== Phase 10: WSL2 build verification ==="
GOBIN=""
for candidate in go /usr/local/go/bin/go /opt/go/bin/go; do
	if "$candidate" version >/dev/null 2>&1; then
		GOBIN="$candidate"
		break
	fi
done
if [ -z "$GOBIN" ]; then
	echo "ERROR: no Go toolchain in WSL2 PATH"
	exit 1
fi
echo "Using Go: $GOBIN"
"$GOBIN" version
echo ""
echo "--- workspace build ./... ---"
"$GOBIN" build ./...
echo "BUILD: PASS"

echo ""
echo "=== Phase 11: Tools=111 invariant test ==="
"$GOBIN" test -run "^TestHTTPRoundtrip_InitToolsList$" -count=1 -timeout 60s ./mcp/ 2>&1 | tail -5

echo ""
echo "=== Phase 12: Summary ==="
echo "Files changed: $(git status --short | grep -vE '^\?\?' | wc -l)"
echo ""
echo "=== A.2.4-A.2.5 cutover applied to master working tree. NOT YET committed. ==="
