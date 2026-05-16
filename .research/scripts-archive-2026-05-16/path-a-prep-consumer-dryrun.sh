#!/usr/bin/env bash
# Path A inauguration — Phase 5 consumer rewrite dry-run.
# Models the kite-mcp-server cutover (runbook §5 Phase A) WITHOUT touching master.
# Operates on a fresh clone in /tmp/algo2go-consumer-cutover-dryrun.
# Idempotent — wipes scratch dir on re-run.

set -euo pipefail

SCRATCH=/tmp/algo2go-consumer-cutover-dryrun
SOURCE=/mnt/d/Sundeep/projects/kite-mcp-server

echo "=== Phase 0: Setup ==="
rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"

echo "=== Phase 1: Fresh clone (local file://) ==="
git clone -q "$SOURCE" "$SCRATCH/kite-mcp-server"
cd "$SCRATCH/kite-mcp-server"
echo "Fresh clone HEAD: $(git rev-parse HEAD)"

echo ""
echo "=== Phase 2: Pre-rewrite census ==="
total=$(grep -rE 'github.com/zerodha/kite-mcp-server/broker' --include='*.go' --include='*.mod' --include='*.work' -l 2>/dev/null | wc -l)
echo "Files with broker import: $total"
occurrences=$(grep -rE 'github.com/zerodha/kite-mcp-server/broker' --include='*.go' --include='*.mod' --include='*.work' -h 2>/dev/null | wc -l)
echo "Total occurrences: $occurrences"

echo ""
echo "=== Phase 3: Rewrite import paths ==="
# Use a per-find pass to keep the rewrite mechanical and easy to inspect.
find . -name '*.go' -type f -not -path './broker/*' -exec sed -i 's#github.com/zerodha/kite-mcp-server/broker#github.com/algo2go/kite-mcp-broker#g' {} \;
echo "Step 3a: All consumer .go files rewritten (broker/ subtree skipped — handled by extracted repo)"

# Update root go.mod: replace require + replace block entries
sed -i 's#github.com/zerodha/kite-mcp-server/broker#github.com/algo2go/kite-mcp-broker#g' go.mod
echo "Step 3b: root go.mod rewritten"

# Same for go.work — but go.work uses './broker' (path-style), so no rewrite needed.
# We'll still drop broker from the use block in Phase 6.

# Update broker subtree's own self-references (parallel to extracted repo path)
find ./broker -name '*.go' -type f -exec sed -i 's#github.com/zerodha/kite-mcp-server/broker#github.com/algo2go/kite-mcp-broker#g' {} \;
sed -i 's#^module github.com/zerodha/kite-mcp-server/broker$#module github.com/algo2go/kite-mcp-broker#' broker/go.mod
echo "Step 3c: in-tree broker subtree also rewritten (kept as Phase A canonical via replace directive)"

# RUNBOOK GAP DISCOVERED IN DRY-RUN: 17 peer-module go.mod files (oauth, app/providers,
# testutil, plugins, kc/{telegram,domain,usecases,audit,alerts,ticker,eventsourcing,
# papertrading,cqrs,registry,users,billing,riskguard}) declare transitive deps on
# broker via require + replace blocks. Runbook §5's '*.go'-only sed rewrite would
# leave these stale, breaking workspace builds. Add explicit go.mod sweep.
find . -path ./broker -prune -o -name 'go.mod' -type f -print | while read -r mod; do
	sed -i 's#github.com/zerodha/kite-mcp-server/broker#github.com/algo2go/kite-mcp-broker#g' "$mod"
done
echo "Step 3d: 17 peer-module go.mod files swept for broker refs (runbook gap)"

echo ""
echo "=== Phase 4: Post-rewrite stale check ==="
stale=$(grep -rE 'github.com/zerodha/kite-mcp-server/broker' --include='*.go' --include='*.mod' -l 2>/dev/null || true)
stale_count=$(echo -n "$stale" | grep -c . || true)
echo "Stale 'zerodha/kite-mcp-server/broker' refs remaining: $stale_count (target 0)"
[ -n "$stale" ] && echo "$stale"

echo ""
echo "=== Phase 5: Verify root go.mod has algo2go/kite-mcp-broker on require + replace ==="
echo "--- require block ---"
grep -E '^\s+github\.com/algo2go/kite-mcp-broker' go.mod || echo "MISSING"
echo "--- replace block ---"
grep -E 'github\.com/algo2go/kite-mcp-broker => \./broker' go.mod || echo "MISSING"

echo ""
echo "=== Phase 6: Verify broker/go.mod module declaration flipped ==="
head -3 broker/go.mod

echo ""
echo "=== Phase 7: Sample rewritten import to confirm ==="
echo "--- app/app.go imports ---"
grep -E 'algo2go/kite-mcp-broker' app/app.go | head -3 || echo "MISSING"
echo "--- mcp/common/broker_resolver.go imports ---"
grep -E 'algo2go/kite-mcp-broker' mcp/common/broker_resolver.go | head -3 || echo "MISSING"

echo ""
echo "=== Phase 8: Compile attempt (workspace mode) ==="
# Locate Go toolchain (WSL2 may not put it in default PATH)
GOBIN=""
for candidate in go /usr/local/go/bin/go /opt/go/bin/go; do
	if "$candidate" version >/dev/null 2>&1; then
		GOBIN="$candidate"
		break
	fi
done

if [ -n "$GOBIN" ]; then
	echo "Using Go at: $GOBIN"
	"$GOBIN" version
	echo ""
	echo "--- workspace build ---"
	if "$GOBIN" build ./... 2>&1 | tee /tmp/_build-out.txt; then
		echo "BUILD: PASS (workspace mode)"
	else
		echo "BUILD: FAIL — see /tmp/_build-out.txt"
	fi
else
	echo "SKIP: 'go' not in WSL PATH. Compile must be verified separately."
fi

echo ""
echo "=== Dry-run complete. Scratch dir: $SCRATCH ==="
echo "NOTE: this scratch tree is throwaway. Do NOT push anywhere."
