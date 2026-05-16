#!/bin/bash
export PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
set -e
cd /mnt/d/Sundeep/projects/kite-mcp-server || exit 1
echo "=== mcp/portfolio tests (account_tools.go fix) ==="
go test -count=1 ./mcp/portfolio/... 2>&1 | tail -5
echo "=== mcp/analytics tests (indicators_tool.go fix) ==="
go test -count=1 ./mcp/analytics/... 2>&1 | tail -5
echo "=== mcp/alerts tests (composite_alert_tool_test.go fix) ==="
go test -count=1 ./mcp/alerts/... 2>&1 | tail -5
echo "=== mcp/trade tests (native_alert_tools.go fix) ==="
go test -count=1 ./mcp/trade/... 2>&1 | tail -5
echo "=== tool_surface_lock_test (the canonical tools=111 pin) ==="
go test -count=1 -run TestToolSurface ./mcp/... 2>&1 | tail -10
