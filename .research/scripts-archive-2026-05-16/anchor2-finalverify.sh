#!/bin/bash
# Final verification — does NOT run go work sync (which propagates changes
# to peer modules). Just builds + tests.
set -e
export PATH=/usr/local/go/bin:/usr/bin:/bin
cd /mnt/d/Sundeep/projects/kite-mcp-server
echo "=== go vet ./app/providers/... ==="
go vet ./app/providers/... 2>&1 | tail -5
echo "=== go vet ./... (root) ==="
go vet ./... 2>&1 | tail -5
echo "=== go test -count=1 ./app/providers/... ==="
go test -count=1 ./app/providers/... 2>&1 | tail -5
echo "=== TestHTTPRoundtrip_InitToolsList ==="
go test -run '^TestHTTPRoundtrip_InitToolsList$' -count=1 -v ./mcp/ 2>&1 | tail -8
echo "=== go test -count=1 -short ./app/ ==="
go test -count=1 -short ./app/ 2>&1 | tail -5
echo "=== check git status (should only be the 4 expected files + 2 new) ==="
cd /mnt/d/Sundeep/projects/kite-mcp-server
git status --porcelain | grep -v '^??'
echo "=== untracked check ==="
git status --porcelain | grep '^??' | grep 'app/providers/' || echo "no providers untracked"
