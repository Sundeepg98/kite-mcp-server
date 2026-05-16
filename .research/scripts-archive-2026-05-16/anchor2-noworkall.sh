#!/bin/bash
set -e
export PATH=/usr/local/go/bin:/usr/bin:/bin
export GOWORK=off
cd /mnt/d/Sundeep/projects/kite-mcp-server
echo "=== GOWORK=off build all modified modules ==="
for d in . app/providers kc/audit kc/billing kc/cqrs kc/eventsourcing kc/registry kc/users; do
  echo "--- build $d ---"
  (cd $d && go build ./... 2>&1 | tail -5) || echo "FAIL: $d"
done
