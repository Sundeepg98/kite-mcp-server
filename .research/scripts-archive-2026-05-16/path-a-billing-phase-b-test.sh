#!/usr/bin/env bash
# Path A.14 — Phase B viability test for kc/billing in scratch.

set -euo pipefail
SCRATCH=/tmp/billing-phase-b-test
SOURCE=/mnt/d/Sundeep/projects/kite-mcp-server

rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"
git clone -q "$SOURCE" "$SCRATCH/kite-mcp-server"
cd "$SCRATCH/kite-mcp-server"
echo "HEAD: $(git rev-parse HEAD)"

echo "=== Apply Phase B mutations ==="
sed -i '/github\.com\/algo2go\/kite-mcp-billing => \.\/kc\/billing/d' go.mod
find . -path ./kc/billing -prune -o -path ./.research -prune -o -name 'go.mod' -type f -print | while read -r mod; do
	sed -i '/github\.com\/algo2go\/kite-mcp-billing => /d' "$mod"
	sed -i 's#github\.com/algo2go/kite-mcp-billing v0\.0\.0-00010101000000-000000000000#github.com/algo2go/kite-mcp-billing v0.1.0#g' "$mod"
done
sed -i '/^[[:space:]]\+\.\/kc\/billing\b/d' go.work
echo "go.work members: $(grep -cE '^[[:space:]]+\./' go.work)"
mv kc/billing kc/billing.MOVED-FOR-PHASE-B-TEST
sed -i '/^COPY kc\/billing\/go\.mod kc\/billing\/go\.sum/d' Dockerfile

echo "=== build ==="
GO=/usr/local/go/bin/go
$GO mod tidy 2>&1 | tail -3
$GO build ./... 2>&1 | tail -3
GOWORK=off $GO build ./... 2>&1 | tail -3
$GO test -run "^TestHTTPRoundtrip_InitToolsList$" -count=1 -timeout 60s ./mcp/ 2>&1 | tail -3
echo "=== Test complete ==="
