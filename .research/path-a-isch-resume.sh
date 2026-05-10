#!/usr/bin/env bash
# Resume Phase B canary delete after halt at Phase 5b.
set -uo pipefail

cd /mnt/d/Sundeep/projects/kite-mcp-server

echo "=== Phase 5b: pin placeholders to v0.1.0 ==="
find . -path ./.research -prune -o -name 'go.mod' -type f -print | while read -r mod; do
	sed -i 's#github\.com/algo2go/kite-mcp-isttz v0\.0\.0-00010101000000-000000000000#github.com/algo2go/kite-mcp-isttz v0.1.0#g' "$mod"
	sed -i 's#github\.com/algo2go/kite-mcp-scheduler v0\.0\.0-00010101000000-000000000000#github.com/algo2go/kite-mcp-scheduler v0.1.0#g' "$mod"
done
echo "pin done"

echo ""
echo "=== Phase 6: WSL2 build verification ==="
GO=/usr/local/go/bin/go
$GO version
echo ""
echo "--- go mod tidy ---"
$GO mod tidy 2>&1 | tail -5
echo ""
echo "--- workspace go build ./... ---"
$GO build ./... 2>&1 | tail -3
echo ""
echo "--- GOWORK=off go build ./... ---"
GOWORK=off $GO build ./... 2>&1 | tail -3

echo ""
echo "=== Phase 7: Tools=111 invariant test ==="
$GO test -run "^TestHTTPRoundtrip_InitToolsList$" -count=1 -timeout 60s ./mcp/ 2>&1 | tail -3

echo ""
echo "=== Phase 8: Full mcp/ + app/ ==="
$GO test -timeout 240s -count=1 ./mcp/ ./app/ 2>&1 | tail -5
