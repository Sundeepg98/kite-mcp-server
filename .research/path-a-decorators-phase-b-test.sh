#!/usr/bin/env bash
# Path A — Phase B viability test for kc/decorators in scratch.
# Mirrors path-b-money-shim-test.sh but for decorators.
# Tests whether dropping the in-tree replace + ./kc/decorators/ would
# break the build (type-identity issue from kc/money's Phase B halt).

set -euo pipefail

SCRATCH=/tmp/decorators-phase-b-test
SOURCE=/mnt/d/Sundeep/projects/kite-mcp-server

rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"

echo "=== Phase 1: Fresh clone ==="
git clone -q "$SOURCE" "$SCRATCH/kite-mcp-server"
cd "$SCRATCH/kite-mcp-server"
echo "HEAD: $(git rev-parse HEAD)"

echo ""
echo "=== Phase 2: Apply Phase B mutations ==="
echo "Step 2a: drop replace algo2go/kite-mcp-decorators in root go.mod"
sed -i '/github\.com\/algo2go\/kite-mcp-decorators => \.\/kc\/decorators/d' go.mod
grep -nE 'algo2go/kite-mcp-decorators' go.mod | head -3

echo ""
echo "Step 2b: drop replace in peer go.mods"
find . -path ./kc/decorators -prune -o -path ./.research -prune -o -name 'go.mod' -type f -print | while read -r mod; do
	sed -i '/github\.com\/algo2go\/kite-mcp-decorators => /d' "$mod"
	sed -i 's#github\.com/algo2go/kite-mcp-decorators v0\.0\.0-00010101000000-000000000000#github.com/algo2go/kite-mcp-decorators v0.1.0#g' "$mod"
done

echo ""
echo "Step 2c: drop ./kc/decorators from go.work (CRLF-safe \\b)"
sed -i '/^[[:space:]]\+\.\/kc\/decorators\b/d' go.work
echo "go.work member count: $(grep -cE '^[[:space:]]+\./' go.work)"

echo ""
echo "Step 2d: rename ./kc/decorators out of the way (test-only)"
mv kc/decorators kc/decorators.MOVED-FOR-PHASE-B-TEST

echo ""
echo "Step 2e: drop kc/decorators COPY line from Dockerfile"
sed -i '/^COPY kc\/decorators\/go\.mod kc\/decorators\/go\.sum/d' Dockerfile

echo ""
echo "=== Phase 3: go mod tidy + build attempt ==="
GO=/usr/local/go/bin/go
$GO mod tidy 2>&1 | tail -5
echo ""
echo "--- workspace go build ./... ---"
$GO build ./... 2>&1 | tee /tmp/_dec-pb-build.txt | tail -10
echo ""
echo "--- GOWORK=off go build ./... ---"
GOWORK=off $GO build ./... 2>&1 | tee /tmp/_dec-pb-build-off.txt | tail -10

echo ""
echo "=== Phase 4: Tools=111 invariant test ==="
$GO test -run "^TestHTTPRoundtrip_InitToolsList$" -count=1 -timeout 60s ./mcp/ 2>&1 | tail -5

echo ""
echo "=== Test complete. Scratch: $SCRATCH ==="
