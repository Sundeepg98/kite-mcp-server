#!/usr/bin/env bash
# Path A.11 — Phase B viability test for kc/alerts in scratch.

set -euo pipefail

SCRATCH=/tmp/alerts-phase-b-test
SOURCE=/mnt/d/Sundeep/projects/kite-mcp-server

rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"

echo "=== Phase 1: Fresh clone ==="
git clone -q "$SOURCE" "$SCRATCH/kite-mcp-server"
cd "$SCRATCH/kite-mcp-server"
echo "HEAD: $(git rev-parse HEAD)"

echo ""
echo "=== Phase 2: Apply Phase B mutations ==="
sed -i '/github\.com\/algo2go\/kite-mcp-alerts => \.\/kc\/alerts/d' go.mod
find . -path ./kc/alerts -prune -o -path ./.research -prune -o -name 'go.mod' -type f -print | while read -r mod; do
	sed -i '/github\.com\/algo2go\/kite-mcp-alerts => /d' "$mod"
	sed -i 's#github\.com/algo2go/kite-mcp-alerts v0\.0\.0-00010101000000-000000000000#github.com/algo2go/kite-mcp-alerts v0.1.0#g' "$mod"
done
sed -i '/^[[:space:]]\+\.\/kc\/alerts\b/d' go.work
echo "go.work member count: $(grep -cE '^[[:space:]]+\./' go.work)"
mv kc/alerts kc/alerts.MOVED-FOR-PHASE-B-TEST
sed -i '/^COPY kc\/alerts\/go\.mod kc\/alerts\/go\.sum/d' Dockerfile

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
echo "=== Phase 4: Tools=111 invariant ==="
$GO test -run "^TestHTTPRoundtrip_InitToolsList$" -count=1 -timeout 60s ./mcp/ 2>&1 | tail -3

echo ""
echo "=== Test complete ==="
