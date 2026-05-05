package mcp

import (
	"github.com/zerodha/kite-mcp-server/mcp/misc"
)

// Anchor 1 PR 1.10: backward-compat shims preserving the legacy
// lowercase symbols moved into mcp/misc. Pre-extraction tests in
// mcp/tools_pure_format_test.go and tools_validation_test.go
// continue to compile against package mcp without rewriting every
// call site.
//
// Canonical implementations live in mcp/misc; new code should call
// misc.X directly.

// formatINR is the legacy lowercase wrapper for misc.FormatINR.
func formatINR(v float64) string {
	return misc.FormatINR(v)
}
