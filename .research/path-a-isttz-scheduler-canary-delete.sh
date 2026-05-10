#!/usr/bin/env bash
# Path A.6 — DUAL Phase B canary deletion ON MASTER for kc/isttz + kc/scheduler.
# Combined into one script (broker+money pattern from Phase B kc/money halt resolution).

set -euo pipefail

ROOT=/mnt/d/Sundeep/projects/kite-mcp-server

cd "$ROOT"

echo "=== Phase 0: Pre-flight ==="
HEAD_BEFORE=$(git rev-parse HEAD)
BRANCH=$(git rev-parse --abbrev-ref HEAD)
echo "HEAD before: $HEAD_BEFORE"
[ "$BRANCH" != "master" ] && { echo "ERROR: not on master"; exit 1; }

echo ""
echo "=== Phase 1: Drop replace directives in root go.mod ==="
sed -i '/github\.com\/algo2go\/kite-mcp-isttz => \.\/kc\/isttz/d' go.mod
sed -i '/github\.com\/algo2go\/kite-mcp-scheduler => \.\/kc\/scheduler/d' go.mod
echo "Root go.mod replaces dropped"
grep -nE 'algo2go/kite-mcp-(isttz|scheduler)' go.mod | head -5

echo ""
echo "=== Phase 2: Drop replace directives in peer go.mod files ==="
find . -path ./kc/isttz -prune -o -path ./kc/scheduler -prune -o -path ./.research -prune -o -name 'go.mod' -type f -print | while read -r mod; do
	patched=0
	if grep -qE 'github\.com/algo2go/kite-mcp-(isttz|scheduler) => ' "$mod" 2>/dev/null; then
		sed -i '/github\.com\/algo2go\/kite-mcp-isttz => /d' "$mod"
		sed -i '/github\.com\/algo2go\/kite-mcp-scheduler => /d' "$mod"
		patched=1
	fi
	[ "$patched" = "1" ] && echo "  patched: $mod"
done

echo ""
echo "=== Phase 3: Drop ./kc/isttz + ./kc/scheduler from go.work (CRLF-safe) ==="
sed -i '/^[[:space:]]\+\.\/kc\/isttz\b/d' go.work
sed -i '/^[[:space:]]\+\.\/kc\/scheduler\b/d' go.work
echo "go.work member count: $(grep -cE '^[[:space:]]+\./' go.work)"

echo ""
echo "=== Phase 4: Drop COPY lines from Dockerfile ==="
sed -i '/^COPY kc\/isttz\/go\.mod kc\/isttz\/go\.sum/d' Dockerfile
sed -i '/^COPY kc\/scheduler\/go\.mod kc\/scheduler\/go\.sum/d' Dockerfile
echo "Dockerfile isttz lines: $(grep -c 'kc/isttz' Dockerfile || true)"
echo "Dockerfile scheduler lines: $(grep -c 'kc/scheduler' Dockerfile || true)"

echo ""
echo "=== Phase 5: Delete ./kc/isttz/ + ./kc/scheduler/ ==="
git rm -rq kc/isttz/
git rm -rq kc/scheduler/

echo ""
echo "=== Phase 5b: Pin placeholder versions ==="
find . -path ./.research -prune -o -name 'go.mod' -type f -print | while read -r mod; do
	pinned=0
	if grep -qE 'github\.com/algo2go/kite-mcp-(isttz|scheduler) v0\.0\.0-00010101000000-000000000000' "$mod" 2>/dev/null; then
		sed -i 's#github\.com/algo2go/kite-mcp-isttz v0\.0\.0-00010101000000-000000000000#github.com/algo2go/kite-mcp-isttz v0.1.0#g' "$mod"
		sed -i 's#github\.com/algo2go/kite-mcp-scheduler v0\.0\.0-00010101000000-000000000000#github.com/algo2go/kite-mcp-scheduler v0.1.0#g' "$mod"
		pinned=1
	fi
	[ "$pinned" = "1" ] && echo "  pinned: $mod"
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
echo "=== Phase 8: Full mcp/ + app/ tests ==="
$GO test -timeout 240s -count=1 ./mcp/ ./app/ 2>&1 | tail -5

echo ""
echo "=== Phase 9: TestToolDefinitions_Coverage ==="
$GO test -run '^TestToolDefinitions_Coverage$' -count=1 -timeout 60s ./mcp/ 2>&1 | tail -3

echo ""
echo "=== Phase 10: Summary ==="
echo "Files changed: $(git status --short | grep -vE '^\?\?' | wc -l)"
git status --short | grep -vE '^\?\?' | head -15
