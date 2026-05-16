#!/bin/bash
set -e
export PATH=/usr/local/go/bin:/usr/bin:/bin
cd /mnt/d/Sundeep/projects/kite-mcp-server
echo "=== build all workspace members ==="
for d in . app/providers broker kc/alerts kc/aop kc/audit kc/billing kc/cqrs kc/decorators kc/domain kc/eventsourcing kc/i18n kc/instruments kc/isttz kc/legaldocs kc/logger kc/money kc/papertrading kc/registry kc/riskguard kc/scheduler kc/telegram kc/templates kc/ticker kc/usecases kc/users kc/watchlist oauth testutil; do
  echo "--- build $d ---"
  (cd $d && go build ./... 2>&1 | tail -3) || echo "FAIL: $d"
done
