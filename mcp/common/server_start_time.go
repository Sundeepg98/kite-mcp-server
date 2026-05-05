package common

import "time"

// ServerStartTime is the wall-clock time the process started. Used by
// status tools (admin_server_status, server_metrics, server_version,
// ext_apps status) to compute uptime. Captured at package init() so
// every tool sees the same value.
//
// Anchor 1 PR 1.4: relocated from mcp/observability_tool.go's package-
// private serverStartTime so cross-package callers (mcp/admin, mcp/trade,
// etc.) can compute uptime without depending on the mcp/ root package.
var ServerStartTime = time.Now()
