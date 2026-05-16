#!/usr/bin/env bash
set -euo pipefail
SCRATCH=/tmp/rg-phase-b-test
SOURCE=/mnt/d/Sundeep/projects/kite-mcp-server

rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"
git clone -q "$SOURCE" "$SCRATCH/kite-mcp-server"
cd "$SCRATCH/kite-mcp-server"
echo "HEAD: $(git rev-parse HEAD)"

sed -i '/github\.com\/algo2go\/kite-mcp-riskguard => \.\/kc\/riskguard/d' go.mod
find . -path ./kc/riskguard -prune -o -path ./.research -prune -o -name 'go.mod' -type f -print | while read -r mod; do
	sed -i '/github\.com\/algo2go\/kite-mcp-riskguard => /d' "$mod"
	sed -i 's#github\.com/algo2go/kite-mcp-riskguard v0\.0\.0-00010101000000-000000000000#github.com/algo2go/kite-mcp-riskguard v0.1.0#g' "$mod"
done
sed -i '/^[[:space:]]\+\.\/kc\/riskguard\b/d' go.work
echo "go.work members: $(grep -cE '^[[:space:]]+\./' go.work)"
mv kc/riskguard kc/riskguard.MOVED-FOR-PHASE-B-TEST
sed -i '/^COPY kc\/riskguard\/go\.mod kc\/riskguard\/go\.sum/d' Dockerfile

GO=/usr/local/go/bin/go
$GO mod tidy 2>&1 | tail -3
$GO build ./... 2>&1 | tail -3
GOWORK=off $GO build ./... 2>&1 | tail -3
$GO test -run "^TestHTTPRoundtrip_InitToolsList$" -count=1 -timeout 60s ./mcp/ 2>&1 | tail -3
echo "=== Test complete ==="
