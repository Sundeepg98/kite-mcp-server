#!/usr/bin/env bash
# Path A.9 — Phase B viability test for kc/aop in scratch.

set -euo pipefail

SCRATCH=/tmp/aop-phase-b-test
SOURCE=/mnt/d/Sundeep/projects/kite-mcp-server

rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"

echo "=== Phase 1: Fresh clone ==="
git clone -q "$SOURCE" "$SCRATCH/kite-mcp-server"
cd "$SCRATCH/kite-mcp-server"
echo "HEAD: $(git rev-parse HEAD)"

echo ""
echo "=== Phase 2: Apply Phase B mutations ==="
echo "Step 2a: drop replace algo2go/kite-mcp-aop in root go.mod"
sed -i '/github\.com\/algo2go\/kite-mcp-aop => \.\/kc\/aop/d' go.mod

echo "Step 2b: drop replace + pin v0.1.0 in peer go.mods (no v0.0.0 placeholders for aop)"
find . -path ./kc/aop -prune -o -path ./.research -prune -o -name 'go.mod' -type f -print | while read -r mod; do
	sed -i '/github\.com\/algo2go\/kite-mcp-aop => /d' "$mod"
done

echo "Step 2c: drop ./kc/aop from go.work (CRLF-safe \\b)"
sed -i '/^[[:space:]]\+\.\/kc\/aop\b/d' go.work
echo "go.work member count: $(grep -cE '^[[:space:]]+\./' go.work)"

echo "Step 2d: rename ./kc/aop out of the way"
mv kc/aop kc/aop.MOVED-FOR-PHASE-B-TEST

echo "Step 2e: drop kc/aop COPY line from Dockerfile"
sed -i '/^COPY kc\/aop\/go\.mod kc\/aop\/go\.sum/d' Dockerfile

echo ""
echo "=== Phase 3: go mod tidy + build ==="
GO=/usr/local/go/bin/go
$GO mod tidy 2>&1 | tail -5
echo ""
echo "--- workspace go build ./... ---"
$GO build ./... 2>&1 | tail -5
echo ""
echo "--- GOWORK=off go build ./... ---"
GOWORK=off $GO build ./... 2>&1 | tail -5

echo ""
echo "=== Phase 4: Tools=111 invariant test ==="
$GO test -run "^TestHTTPRoundtrip_InitToolsList$" -count=1 -timeout 60s ./mcp/ 2>&1 | tail -3

echo ""
echo "=== Test complete ==="
