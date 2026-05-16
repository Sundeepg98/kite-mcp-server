#!/usr/bin/env bash
# Path A.4 — kc/i18n Phase B canary deletion ON MASTER.
# Mirror of path-a-decorators-canary-delete.sh.

set -euo pipefail

ROOT=/mnt/d/Sundeep/projects/kite-mcp-server

cd "$ROOT"

echo "=== Phase 0: Pre-flight ==="
HEAD_BEFORE=$(git rev-parse HEAD)
BRANCH=$(git rev-parse --abbrev-ref HEAD)
echo "HEAD before: $HEAD_BEFORE"
[ "$BRANCH" != "master" ] && { echo "ERROR: not on master"; exit 1; }

echo ""
echo "=== Phase 1: Drop replace directive in root go.mod ==="
sed -i '/github\.com\/algo2go\/kite-mcp-i18n => \.\/kc\/i18n/d' go.mod
grep -nE 'algo2go/kite-mcp-i18n' go.mod | head -3

echo ""
echo "=== Phase 2: Drop replace directives in peer go.mod files ==="
find . -path ./kc/i18n -prune -o -path ./.research -prune -o -name 'go.mod' -type f -print | while read -r mod; do
	if grep -qE 'github\.com/algo2go/kite-mcp-i18n => ' "$mod" 2>/dev/null; then
		sed -i '/github\.com\/algo2go\/kite-mcp-i18n => /d' "$mod"
		echo "  patched: $mod"
	fi
done

echo ""
echo "=== Phase 3: Drop ./kc/i18n from go.work (CRLF-safe) ==="
sed -i '/^[[:space:]]\+\.\/kc\/i18n\b/d' go.work
echo "go.work member count: $(grep -cE '^[[:space:]]+\./' go.work)"

echo ""
echo "=== Phase 4: Drop kc/i18n COPY line from Dockerfile ==="
sed -i '/^COPY kc\/i18n\/go\.mod kc\/i18n\/go\.sum/d' Dockerfile
echo "Dockerfile i18n lines: $(grep -c 'kc/i18n' Dockerfile || true)"

echo ""
echo "=== Phase 5: Delete ./kc/i18n/ ==="
git rm -rq kc/i18n/

echo ""
echo "=== Phase 5b: Pin placeholder versions in peer go.mods ==="
find . -path ./.research -prune -o -name 'go.mod' -type f -print | while read -r mod; do
	if grep -qE 'github\.com/algo2go/kite-mcp-i18n v0\.0\.0-00010101000000-000000000000' "$mod" 2>/dev/null; then
		sed -i 's#github\.com/algo2go/kite-mcp-i18n v0\.0\.0-00010101000000-000000000000#github.com/algo2go/kite-mcp-i18n v0.1.0#g' "$mod"
		echo "  pinned: $mod"
	fi
done

echo ""
echo "=== Phase 6: WSL2 build verification ==="
GO=/usr/local/go/bin/go
$GO version
echo ""
echo "--- go mod tidy ---"
$GO mod tidy 2>&1 | tail -5
echo ""
echo "--- workspace go build ./... ---"
$GO build ./...
echo "BUILD: PASS"
echo ""
echo "--- GOWORK=off go build ./... ---"
GOWORK=off $GO build ./...
echo "BUILD: PASS"

echo ""
echo "=== Phase 7: Tools=111 invariant test ==="
$GO test -run "^TestHTTPRoundtrip_InitToolsList$" -count=1 -timeout 60s ./mcp/ 2>&1 | tail -3

echo ""
echo "=== Phase 8: Full mcp/ + kc/riskguard test ==="
$GO test -timeout 180s -count=1 ./mcp/ ./kc/riskguard/ 2>&1 | tail -5

echo ""
echo "=== Phase 9: TestToolDefinitions_Coverage ==="
$GO test -run '^TestToolDefinitions_Coverage$' -count=1 -timeout 60s ./mcp/ 2>&1 | tail -3

echo ""
echo "=== Phase 10: Summary ==="
echo "Files changed: $(git status --short | grep -vE '^\?\?' | wc -l)"
git status --short | grep -vE '^\?\?' | head -10
