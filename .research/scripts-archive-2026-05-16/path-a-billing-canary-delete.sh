#!/usr/bin/env bash
# Path A.14 — kc/billing Phase B canary deletion ON MASTER.
# Use `set -uo pipefail` (no -e) for find-loop sections per A.6 lesson.

set -uo pipefail

ROOT=/mnt/d/Sundeep/projects/kite-mcp-server
cd "$ROOT"

[ "$(git rev-parse --abbrev-ref HEAD)" != "master" ] && { echo "ERROR: not on master"; exit 1; }
echo "HEAD: $(git rev-parse HEAD)"

echo "=== Phase 1: Drop replace in root go.mod ==="
sed -i '/github\.com\/algo2go\/kite-mcp-billing => \.\/kc\/billing/d' go.mod

echo "=== Phase 2: Drop replace in peer go.mods ==="
find . -path ./kc/billing -prune -o -path ./.research -prune -o -name 'go.mod' -type f -print | while read -r mod; do
	if grep -qE 'github\.com/algo2go/kite-mcp-billing => ' "$mod" 2>/dev/null; then
		sed -i '/github\.com\/algo2go\/kite-mcp-billing => /d' "$mod"
		echo "  patched: $mod"
	fi
done

echo "=== Phase 3: Drop ./kc/billing from go.work ==="
sed -i '/^[[:space:]]\+\.\/kc\/billing\b/d' go.work
echo "go.work members: $(grep -cE '^[[:space:]]+\./' go.work)"

echo "=== Phase 4: Drop kc/billing COPY from Dockerfile ==="
sed -i '/^COPY kc\/billing\/go\.mod kc\/billing\/go\.sum/d' Dockerfile

echo "=== Phase 5: Delete ./kc/billing/ ==="
git rm -rq kc/billing/

echo "=== Phase 5b: Pin placeholder versions ==="
find . -path ./.research -prune -o -name 'go.mod' -type f -print | while read -r mod; do
	if grep -qE 'github\.com/algo2go/kite-mcp-billing v0\.0\.0-00010101000000-000000000000' "$mod" 2>/dev/null; then
		sed -i 's#github\.com/algo2go/kite-mcp-billing v0\.0\.0-00010101000000-000000000000#github.com/algo2go/kite-mcp-billing v0.1.0#g' "$mod"
		echo "  pinned: $mod"
	fi
done

echo "=== Phase 6: WSL2 verify ==="
GO=/usr/local/go/bin/go
$GO mod tidy 2>&1 | tail -3
$GO build ./... 2>&1 | tail -3
echo "BUILD: PASS"
GOWORK=off $GO build ./... 2>&1 | tail -3
echo "GOWORK=off BUILD: PASS"
$GO test -run "^TestHTTPRoundtrip_InitToolsList$" -count=1 -timeout 60s ./mcp/ 2>&1 | tail -3
$GO test -timeout 240s -count=1 ./mcp/ ./app/ 2>&1 | tail -5

echo "Files changed: $(git status --short | grep -vE '^\?\?' | wc -l)"
