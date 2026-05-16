#!/bin/bash
set -e
export PATH=/usr/local/go/bin:/usr/bin:/bin
export GOWORK=off
cd /mnt/d/Sundeep/projects/kite-mcp-server
echo "=== GOWORK=off build of unmodified extracted modules ==="
for d in . app/providers broker kc/money kc/audit kc/billing kc/riskguard oauth; do
  echo "--- build $d ---"
  (cd $d && go build ./... 2>&1 | tail -3) || echo "FAIL: $d"
done
