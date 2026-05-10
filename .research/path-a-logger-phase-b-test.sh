#!/usr/bin/env bash
# Path A.7 — Phase B viability test for kc/logger in scratch.

set -euo pipefail

SCRATCH=/tmp/logger-phase-b-test
SOURCE=/mnt/d/Sundeep/projects/kite-mcp-server

rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"

echo "=== Phase 1: Fresh clone ==="
git clone -q "$SOURCE" "$SCRATCH/kite-mcp-server"
cd "$SCRATCH/kite-mcp-server"
echo "HEAD: $(git rev-parse HEAD)"

echo ""
echo "=== Phase 2: Apply Phase B mutations ==="
echo "Step 2a: drop replace algo2go/kite-mcp-logger in root go.mod"
sed -i '/github\.com\/algo2go\/kite-mcp-logger => \.\/kc\/logger/d' go.mod
grep -nE 'algo2go/kite-mcp-logger' go.mod | head -3

echo ""
echo "Step 2b: drop replace + pin v0.1.0 in peer go.mods"
find . -path ./kc/logger -prune -o -path ./.research -prune -o -name 'go.mod' -type f -print | while read -r mod; do
	sed -i '/github\.com\/algo2go\/kite-mcp-logger => /d' "$mod"
	sed -i 's#github\.com/algo2go/kite-mcp-logger v0\.0\.0-00010101000000-000000000000#github.com/algo2go/kite-mcp-logger v0.1.0#g' "$mod"
done

echo ""
echo "Step 2c: drop ./kc/logger from go.work (CRLF-safe \\b)"
sed -i '/^[[:space:]]\+\.\/kc\/logger\b/d' go.work
echo "go.work member count: $(grep -cE '^[[:space:]]+\./' go.work)"

echo ""
echo "Step 2d: rename ./kc/logger out of the way (test-only)"
mv kc/logger kc/logger.MOVED-FOR-PHASE-B-TEST

echo ""
echo "Step 2e: drop kc/logger COPY line from Dockerfile"
sed -i '/^COPY kc\/logger\/go\.mod kc\/logger\/go\.sum/d' Dockerfile

echo ""
echo "=== Phase 3: go mod tidy + build ==="
GO=/usr/local/go/bin/go
$GO mod tidy 2>&1 | tail -5
echo ""
echo "--- workspace go build ./... ---"
$GO build ./... 2>&1 | tee /tmp/_lg-pb-build.txt | tail -10
echo ""
echo "--- GOWORK=off go build ./... ---"
GOWORK=off $GO build ./... 2>&1 | tee /tmp/_lg-pb-build-off.txt | tail -10

echo ""
echo "=== Phase 4: Tools=111 invariant test ==="
$GO test -run "^TestHTTPRoundtrip_InitToolsList$" -count=1 -timeout 60s ./mcp/ 2>&1 | tail -3

echo ""
echo "=== Test complete ==="
