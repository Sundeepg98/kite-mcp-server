#!/usr/bin/env bash
# Path A inauguration A.2.4-A.2.5 — apply consumer cutover ON MASTER.
# This is the ONE script that actually mutates the working tree (no scratch).
# Mirrors path-a-prep-consumer-dryrun.sh's rewrites but operates on
# /mnt/d/Sundeep/projects/kite-mcp-server directly.
#
# Pre-conditions:
#   - master HEAD synced (git pull --ff-only origin master)
#   - working tree clean for paths to be touched (ok to have untracked
#     scratch files in .research/)
#   - algo2go/kite-mcp-broker@v0.1.0 already published
#
# Post-conditions:
#   - 192 broker-import occurrences across 153 .go files rewritten
#   - root go.mod require + replace blocks point at algo2go/kite-mcp-broker
#   - broker/ subtree's go.mod + 20 self-importing files rewritten (kept
#     in-tree as Phase A canonical via replace directive)
#   - 17 peer go.mod files swept
#   - Working tree DIRTY; ready for commit + WSL2 build verification
#
# Idempotent IFF re-run before any commits land.

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
total=$(grep -rE 'github.com/zerodha/kite-mcp-server/broker' --include='*.go' --include='*.mod' --include='*.work' -l 2>/dev/null | wc -l)
occurrences=$(grep -rE 'github.com/zerodha/kite-mcp-server/broker' --include='*.go' --include='*.mod' --include='*.work' -h 2>/dev/null | wc -l)
echo "Files with broker import: $total"
echo "Total occurrences: $occurrences"

echo ""
echo "=== Phase 2: Rewrite consumer .go files ==="
# Skip broker/ subtree — handled separately for clarity.
find . -name '*.go' -type f -not -path './broker/*' -not -path './.research/*' \
	-exec sed -i 's#github.com/zerodha/kite-mcp-server/broker#github.com/algo2go/kite-mcp-broker#g' {} \;
echo "Step 2: consumer .go files rewritten"

echo ""
echo "=== Phase 3: Rewrite broker subtree (kept in-tree as Phase A canonical) ==="
find ./broker -name '*.go' -type f \
	-exec sed -i 's#github.com/zerodha/kite-mcp-server/broker#github.com/algo2go/kite-mcp-broker#g' {} \;
sed -i 's#^module github.com/zerodha/kite-mcp-server/broker$#module github.com/algo2go/kite-mcp-broker#' broker/go.mod
echo "Step 3: in-tree broker subtree + broker/go.mod rewritten"

echo ""
echo "=== Phase 4: Rewrite root go.mod (require + replace) ==="
sed -i 's#github.com/zerodha/kite-mcp-server/broker#github.com/algo2go/kite-mcp-broker#g' go.mod
echo "Step 4: root go.mod rewritten"

echo ""
echo "=== Phase 5: Sweep 17 peer-module go.mod files (RUNBOOK GAP from prep dry-run) ==="
find . -path ./broker -prune -o -path ./.research -prune -o -name 'go.mod' -type f -print | while read -r mod; do
	if grep -q 'github.com/zerodha/kite-mcp-server/broker' "$mod" 2>/dev/null; then
		sed -i 's#github.com/zerodha/kite-mcp-server/broker#github.com/algo2go/kite-mcp-broker#g' "$mod"
		echo "  rewrote: $mod"
	fi
done
echo "Step 5: peer go.mod sweep complete"

echo ""
echo "=== Phase 6: Pin require to v0.1.0 (replace stays for Phase A canary) ==="
# The dry-run left require at the dummy v0.0.0-... timestamp because the
# replace directive overrides it. For the published-version paper trail,
# pin require to v0.1.0 — when Phase B drops the replace, this becomes
# the operative version. The replace stays intact => actual builds pull
# from ./broker as before.
sed -i 's#github.com/algo2go/kite-mcp-broker v0.0.0-00010101000000-000000000000#github.com/algo2go/kite-mcp-broker v0.1.0#' go.mod
echo "Step 6: root go.mod require pinned to v0.1.0"

echo ""
echo "=== Phase 7: Post-rewrite stale check ==="
stale=$(grep -rE 'github.com/zerodha/kite-mcp-server/broker' --include='*.go' --include='*.mod' -l 2>/dev/null || true)
stale_count=$(echo -n "$stale" | grep -c . || true)
if [ "$stale_count" -ne 0 ]; then
	echo "ERROR: stale 'zerodha/kite-mcp-server/broker' refs remaining ($stale_count):"
	echo "$stale"
	exit 1
fi
echo "OK: zero stale refs"

echo ""
echo "=== Phase 8: Verify root go.mod has algo2go on require + replace ==="
echo "--- require block ---"
grep -E '^\s+github\.com/algo2go/kite-mcp-broker' go.mod
echo "--- replace block ---"
grep -E 'github\.com/algo2go/kite-mcp-broker => \./broker' go.mod

echo ""
echo "=== Phase 9: Verify broker/go.mod ==="
head -3 broker/go.mod

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
"$GOBIN" test -run "TestHTTPRoundtrip_InitToolsList|TestToolDefinitions_Coverage|TestToolSchemaLock_PerTool|TestApp_GetAllToolsForRegistry" \
	./app/... ./mcp/... -count=1 -timeout 180s 2>&1 | tail -10
echo ""

echo "=== Phase 12: Summary ==="
echo "Files changed (git status --short):"
git status --short | head -30
echo ""
echo "Total changes: $(git status --short | wc -l) files"
echo ""
echo "=== A.2.4-A.2.5 cutover applied to master working tree. NOT YET committed. ==="
echo "Next: commit via 'git commit -o -- <paths>' per standing rule, then WSL2-green push."
