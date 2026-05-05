package mcp

import "math"

// roundTo2 rounds a float64 to 2 decimal places.
//
// Anchor 1 PR 1.9 closure: previously lived inside mcp/context_tool.go (now
// moved to mcp/paper). The helper is still used by tax_tools.go (mcp/ root)
// and tools_pure_math_test.go, so it has to remain reachable from package
// mcp. mcp/analytics, mcp/portfolio, and mcp/paper each carry their own
// local copy because Go forbids relative-package imports inside the same
// module without a full common-helpers extraction (planned for a later
// cleanup PR; see context_tool.go's pre-move comment for history).
func roundTo2(v float64) float64 {
	return math.Round(v*100) / 100
}
