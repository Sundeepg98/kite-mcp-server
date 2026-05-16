#!/usr/bin/env bash
# Path A.6 — dual Phase B viability test for kc/isttz + kc/scheduler.
# Mirror of path-a-legaldocs-phase-b-test.sh but for both modules.

set -euo pipefail

SCRATCH=/tmp/isttz-scheduler-phase-b-test
SOURCE=/mnt/d/Sundeep/projects/kite-mcp-server

rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"

echo "=== Phase 1: Fresh clone ==="
git clone -q "$SOURCE" "$SCRATCH/kite-mcp-server"
cd "$SCRATCH/kite-mcp-server"
echo "HEAD: $(git rev-parse HEAD)"

echo ""
echo "=== Phase 2: Apply dual Phase B mutations ==="

echo "Step 2a: drop replace algo2go/kite-mcp-isttz + algo2go/kite-mcp-scheduler in root go.mod"
sed -i '/github\.com\/algo2go\/kite-mcp-isttz => \.\/kc\/isttz/d' go.mod
sed -i '/github\.com\/algo2go\/kite-mcp-scheduler => \.\/kc\/scheduler/d' go.mod

echo ""
echo "Step 2b: drop replaces + pin v0.1.0 in peer go.mods"
find . -path ./kc/isttz -prune -o -path ./kc/scheduler -prune -o -path ./.research -prune -o -name 'go.mod' -type f -print | while read -r mod; do
	sed -i '/github\.com\/algo2go\/kite-mcp-isttz => /d' "$mod"
	sed -i '/github\.com\/algo2go\/kite-mcp-scheduler => /d' "$mod"
	sed -i 's#github\.com/algo2go/kite-mcp-isttz v0\.0\.0-00010101000000-000000000000#github.com/algo2go/kite-mcp-isttz v0.1.0#g' "$mod"
	sed -i 's#github\.com/algo2go/kite-mcp-scheduler v0\.0\.0-00010101000000-000000000000#github.com/algo2go/kite-mcp-scheduler v0.1.0#g' "$mod"
done

echo ""
echo "Step 2c: drop ./kc/isttz + ./kc/scheduler from go.work"
sed -i '/^[[:space:]]\+\.\/kc\/isttz\b/d' go.work
sed -i '/^[[:space:]]\+\.\/kc\/scheduler\b/d' go.work
echo "go.work member count: $(grep -cE '^[[:space:]]+\./' go.work)"

echo ""
echo "Step 2d: rename ./kc/isttz + ./kc/scheduler out of the way"
mv kc/isttz kc/isttz.MOVED-FOR-PHASE-B-TEST
mv kc/scheduler kc/scheduler.MOVED-FOR-PHASE-B-TEST

echo ""
echo "Step 2e: drop COPY lines from Dockerfile"
sed -i '/^COPY kc\/isttz\/go\.mod kc\/isttz\/go\.sum/d' Dockerfile
sed -i '/^COPY kc\/scheduler\/go\.mod kc\/scheduler\/go\.sum/d' Dockerfile

echo ""
echo "=== Phase 3: go mod tidy + build ==="
GO=/usr/local/go/bin/go
$GO mod tidy 2>&1 | tail -5
echo ""
echo "--- workspace go build ./... ---"
$GO build ./... 2>&1 | tee /tmp/_isch-pb-build.txt | tail -10
echo ""
echo "--- GOWORK=off go build ./... ---"
GOWORK=off $GO build ./... 2>&1 | tee /tmp/_isch-pb-build-off.txt | tail -10

echo ""
echo "=== Phase 4: Tools=111 invariant test ==="
$GO test -run "^TestHTTPRoundtrip_InitToolsList$" -count=1 -timeout 60s ./mcp/ 2>&1 | tail -3

echo ""
echo "=== Test complete ==="
