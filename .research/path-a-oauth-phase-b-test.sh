#!/usr/bin/env bash
# Path A.13 — Phase B viability test for oauth in scratch.

set -euo pipefail
SCRATCH=/tmp/oauth-phase-b-test
SOURCE=/mnt/d/Sundeep/projects/kite-mcp-server

rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"
git clone -q "$SOURCE" "$SCRATCH/kite-mcp-server"
cd "$SCRATCH/kite-mcp-server"
echo "HEAD: $(git rev-parse HEAD)"

echo ""
echo "=== Apply Phase B mutations ==="
sed -i '/github\.com\/algo2go\/kite-mcp-oauth => \.\/oauth/d' go.mod
find . -path ./oauth -prune -o -path ./.research -prune -o -name 'go.mod' -type f -print | while read -r mod; do
	sed -i '/github\.com\/algo2go\/kite-mcp-oauth => /d' "$mod"
	sed -i 's#github\.com/algo2go/kite-mcp-oauth v0\.0\.0-00010101000000-000000000000#github.com/algo2go/kite-mcp-oauth v0.1.0#g' "$mod"
done
sed -i '/^[[:space:]]\+\.\/oauth\b/d' go.work
echo "go.work member count: $(grep -cE '^[[:space:]]+\./' go.work)"
mv oauth oauth.MOVED-FOR-PHASE-B-TEST
sed -i '/^COPY oauth\/go\.mod oauth\/go\.sum/d' Dockerfile

echo ""
echo "=== build ==="
GO=/usr/local/go/bin/go
$GO mod tidy 2>&1 | tail -3
$GO build ./... 2>&1 | tail -3
echo "=== GOWORK=off ==="
GOWORK=off $GO build ./... 2>&1 | tail -3
echo "=== tools=111 ==="
$GO test -run "^TestHTTPRoundtrip_InitToolsList$" -count=1 -timeout 60s ./mcp/ 2>&1 | tail -3
echo "=== Test complete ==="
