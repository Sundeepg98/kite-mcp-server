#!/usr/bin/env bash
set -euo pipefail
SCRATCH=/tmp/tk-phase-b-test
SOURCE=/mnt/d/Sundeep/projects/kite-mcp-server

rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"
git clone -q "$SOURCE" "$SCRATCH/kite-mcp-server"
cd "$SCRATCH/kite-mcp-server"
echo "HEAD: $(git rev-parse HEAD)"

sed -i '/github\.com\/algo2go\/kite-mcp-ticker => \.\/kc\/ticker/d' go.mod
find . -path ./kc/ticker -prune -o -path ./.research -prune -o -name 'go.mod' -type f -print | while read -r mod; do
	sed -i '/github\.com\/algo2go\/kite-mcp-ticker => /d' "$mod"
	sed -i 's#github\.com/algo2go/kite-mcp-ticker v0\.0\.0-00010101000000-000000000000#github.com/algo2go/kite-mcp-ticker v0.1.0#g' "$mod"
done
sed -i '/^[[:space:]]\+\.\/kc\/ticker\b/d' go.work
echo "go.work members: $(grep -cE '^[[:space:]]+\./' go.work)"
mv kc/ticker kc/ticker.MOVED-FOR-PHASE-B-TEST
sed -i '/^COPY kc\/ticker\/go\.mod kc\/ticker\/go\.sum/d' Dockerfile

GO=/usr/local/go/bin/go
$GO mod tidy 2>&1 | tail -3
$GO build ./... 2>&1 | tail -3
GOWORK=off $GO build ./... 2>&1 | tail -3
$GO test -run "^TestHTTPRoundtrip_InitToolsList$" -count=1 -timeout 60s ./mcp/ 2>&1 | tail -3
echo "=== Test complete ==="
