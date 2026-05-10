#!/usr/bin/env bash
set -euo pipefail
SCRATCH=/tmp/tg-phase-b-test
SOURCE=/mnt/d/Sundeep/projects/kite-mcp-server

rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"
git clone -q "$SOURCE" "$SCRATCH/kite-mcp-server"
cd "$SCRATCH/kite-mcp-server"
echo "HEAD: $(git rev-parse HEAD)"

sed -i '/github\.com\/algo2go\/kite-mcp-telegram => \.\/kc\/telegram/d' go.mod
find . -path ./kc/telegram -prune -o -path ./.research -prune -o -name 'go.mod' -type f -print | while read -r mod; do
	sed -i '/github\.com\/algo2go\/kite-mcp-telegram => /d' "$mod"
	sed -i 's#github\.com/algo2go/kite-mcp-telegram v0\.0\.0-00010101000000-000000000000#github.com/algo2go/kite-mcp-telegram v0.1.0#g' "$mod"
done
sed -i '/^[[:space:]]\+\.\/kc\/telegram\b/d' go.work
echo "go.work members: $(grep -cE '^[[:space:]]+\./' go.work)"
mv kc/telegram kc/telegram.MOVED-FOR-PHASE-B-TEST
sed -i '/^COPY kc\/telegram\/go\.mod kc\/telegram\/go\.sum/d' Dockerfile

GO=/usr/local/go/bin/go
$GO mod tidy 2>&1 | tail -3
$GO build ./... 2>&1 | tail -3
GOWORK=off $GO build ./... 2>&1 | tail -3
$GO test -run "^TestHTTPRoundtrip_InitToolsList$" -count=1 -timeout 60s ./mcp/ 2>&1 | tail -3
echo "=== Test complete ==="
