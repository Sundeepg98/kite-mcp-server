#!/usr/bin/env bash
# Path B alt-1 step 10-11 — RESUME canary deletion.
# Drops both replace directives + deletes ./broker/ + ./kc/money/.
# Fetches both modules from algo2go GitHub repos via GOPROXY.
#
# Pre-conditions:
#   - master HEAD has both Phase A cutovers (broker @ b92173b's parent;
#     kc/money @ b92173b)
#   - algo2go/kite-mcp-broker@v0.1.0 + algo2go/kite-mcp-money@v0.1.0
#     both LIVE on GitHub + fetchable via GOPROXY
#   - working tree clean

set -euo pipefail

ROOT=/mnt/d/Sundeep/projects/kite-mcp-server

cd "$ROOT"

echo "=== Phase 0: Pre-flight ==="
HEAD_BEFORE=$(git rev-parse HEAD)
BRANCH=$(git rev-parse --abbrev-ref HEAD)
echo "HEAD before: $HEAD_BEFORE"
echo "Branch: $BRANCH"
if [ "$BRANCH" != "master" ]; then
	echo "ERROR: must run on master, got $BRANCH"
	exit 1
fi

echo ""
echo "=== Phase 1: Drop replace directives in root go.mod ==="
sed -i '/github\.com\/algo2go\/kite-mcp-broker => \.\/broker/d' go.mod
sed -i '/github\.com\/algo2go\/kite-mcp-money => \.\/kc\/money/d' go.mod
echo "  root go.mod replace directives dropped"
grep -E 'algo2go/kite-mcp-(broker|money)' go.mod | head -5
echo ""

echo "=== Phase 2: Drop replace directives in 17 peer go.mod files ==="
find . -path ./broker -prune -o -path ./kc/money -prune -o -path ./.research -prune \
	-o -name 'go.mod' -type f -print | while read -r mod; do
	# Drop both broker and money replace lines (any path-style)
	if grep -qE 'github\.com/algo2go/kite-mcp-(broker|money) => ' "$mod" 2>/dev/null; then
		sed -i '/github\.com\/algo2go\/kite-mcp-broker => /d' "$mod"
		sed -i '/github\.com\/algo2go\/kite-mcp-money => /d' "$mod"
		echo "  patched: $mod"
	fi
done
echo ""

echo "=== Phase 3: Drop ./broker and ./kc/money from go.work use block ==="
# Note: go.work has CRLF line endings on Windows-checked-out trees, so $
# anchor doesn't match (\r is part of line content). Use \b word boundary.
sed -i '/^[[:space:]]\+\.\/broker\b/d' go.work
sed -i '/^[[:space:]]\+\.\/kc\/money\b/d' go.work
echo "  go.work member count after deletion: $(grep -cE '^[[:space:]]+\./' go.work)"
echo ""

echo "=== Phase 4: Drop broker + kc/money pre-stage lines in Dockerfile ==="
# Match by line content; Dockerfile uses LF endings.
sed -i '/^COPY broker\/go\.mod broker\/go\.sum/d' Dockerfile
sed -i '/^COPY kc\/money\/go\.mod kc\/money\/go\.sum/d' Dockerfile
echo "  Dockerfile broker + kc/money pre-stage lines dropped"
echo ""

echo "=== Phase 5: Delete ./broker/ and ./kc/money/ directories ==="
git rm -rq broker/
git rm -rq kc/money/
echo "  directories deleted"
echo ""

echo "=== Phase 5b: Pin placeholder versions in peer go.mods to v0.1.0 ==="
# Phase A's cutover only pinned root go.mod's require versions because
# the in-tree replace directives overrode them everywhere else. Now
# that replaces are dropped, peer placeholder versions (v0.0.0-...) are
# exposed and need pinning to the published v0.1.0 tag.
find . -path ./broker -prune -o -path ./kc/money -prune -o -path ./.research -prune \
	-o -name 'go.mod' -type f -print | while read -r mod; do
	if grep -qE 'github\.com/algo2go/kite-mcp-(broker|money) v0\.0\.0-00010101000000-000000000000' "$mod" 2>/dev/null; then
		sed -i 's#github\.com/algo2go/kite-mcp-broker v0\.0\.0-00010101000000-000000000000#github.com/algo2go/kite-mcp-broker v0.1.0#g' "$mod"
		sed -i 's#github\.com/algo2go/kite-mcp-money v0\.0\.0-00010101000000-000000000000#github.com/algo2go/kite-mcp-money v0.1.0#g' "$mod"
		echo "  pinned: $mod"
	fi
done
echo ""

echo "=== Phase 6: WSL2 build verification (modules now fetched from GOPROXY) ==="
GO=/usr/local/go/bin/go
$GO version
echo ""
# Need go mod download first since require lines now resolve to upstream
echo "--- go mod download ---"
$GO mod download github.com/algo2go/kite-mcp-broker github.com/algo2go/kite-mcp-money 2>&1 | tail -5
echo ""
echo "--- workspace go build ./... ---"
$GO build ./... 2>&1 | tail -10
echo "BUILD: exit $?"
echo ""

echo "=== Phase 7: Tools=111 invariant test ==="
$GO test -run "^TestHTTPRoundtrip_InitToolsList$" -count=1 -timeout 60s ./mcp/ 2>&1 | tail -5
echo ""

echo "=== Phase 8: Full mcp/ test suite ==="
$GO test -timeout 180s -count=1 ./mcp/ 2>&1 | tail -5
echo ""

echo "=== Phase 9: TestToolDefinitions_Coverage ==="
$GO test -run '^TestToolDefinitions_Coverage$' -count=1 -timeout 60s ./mcp/ 2>&1 | tail -5
echo ""

echo "=== Phase 10: Summary ==="
echo "Files changed: $(git status --short | grep -vE '^\?\?' | wc -l)"
git status --short | grep -vE '^\?\?' | head -25
