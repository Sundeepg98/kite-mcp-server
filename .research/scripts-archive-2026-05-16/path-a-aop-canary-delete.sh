#!/usr/bin/env bash
# Path A.9 — kc/aop Phase B canary deletion ON MASTER.
# Use `set -uo pipefail` (no -e) for find-loop sections per A.6 lesson.

set -uo pipefail

ROOT=/mnt/d/Sundeep/projects/kite-mcp-server

cd "$ROOT"

echo "=== Phase 0: Pre-flight ==="
HEAD_BEFORE=$(git rev-parse HEAD)
BRANCH=$(git rev-parse --abbrev-ref HEAD)
echo "HEAD before: $HEAD_BEFORE"
[ "$BRANCH" != "master" ] && { echo "ERROR: not on master"; exit 1; }

echo ""
echo "=== Phase 1: Drop replace directive in root go.mod ==="
sed -i '/github\.com\/algo2go\/kite-mcp-aop => \.\/kc\/aop/d' go.mod
grep -nE 'algo2go/kite-mcp-aop' go.mod | head -3

echo ""
echo "=== Phase 2: Drop replace directives in peer go.mod files ==="
find . -path ./kc/aop -prune -o -path ./.research -prune -o -name 'go.mod' -type f -print | while read -r mod; do
	if grep -qE 'github\.com/algo2go/kite-mcp-aop => ' "$mod" 2>/dev/null; then
		sed -i '/github\.com\/algo2go\/kite-mcp-aop => /d' "$mod"
		echo "  patched: $mod"
	fi
done

echo ""
echo "=== Phase 3: Drop ./kc/aop from go.work (CRLF-safe) ==="
sed -i '/^[[:space:]]\+\.\/kc\/aop\b/d' go.work
echo "go.work member count: $(grep -cE '^[[:space:]]+\./' go.work)"

echo ""
echo "=== Phase 4: Drop kc/aop COPY line from Dockerfile ==="
sed -i '/^COPY kc\/aop\/go\.mod kc\/aop\/go\.sum/d' Dockerfile
echo "Dockerfile aop lines: $(grep -c 'kc/aop' Dockerfile || true)"

echo ""
echo "=== Phase 5: Delete ./kc/aop/ ==="
git rm -rq kc/aop/

echo ""
echo "=== Phase 6: WSL2 build verification ==="
GO=/usr/local/go/bin/go
$GO version
echo ""
echo "--- go mod tidy ---"
$GO mod tidy 2>&1 | tail -5
echo ""
echo "--- workspace go build ./... ---"
$GO build ./... 2>&1 | tail -5
echo "--- GOWORK=off go build ./... ---"
GOWORK=off $GO build ./... 2>&1 | tail -5

echo ""
echo "=== Phase 7: Tools=111 invariant test ==="
$GO test -run "^TestHTTPRoundtrip_InitToolsList$" -count=1 -timeout 60s ./mcp/ 2>&1 | tail -3

echo ""
echo "=== Phase 8: Full mcp/ + app/ ==="
$GO test -timeout 240s -count=1 ./mcp/ ./app/ 2>&1 | tail -5

echo ""
echo "=== Phase 9: TestToolDefinitions_Coverage ==="
$GO test -run '^TestToolDefinitions_Coverage$' -count=1 -timeout 60s ./mcp/ 2>&1 | tail -3

echo ""
echo "=== Phase 10: Summary ==="
echo "Files changed: $(git status --short | grep -vE '^\?\?' | wc -l)"
git status --short | grep -vE '^\?\?' | head -10
