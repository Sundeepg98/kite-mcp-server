module github.com/zerodha/kite-mcp-server/kc/sectors

go 1.25.0

// kc/sectors is a zero-internal-dep stdlib-only leaf hosting the
// canonical NSE/BSE-symbol-to-sector mapping plus NormalizeSymbol +
// Lookup helpers. Replaces:
//   - mcp/portfolio.StockSectors  (canonical, ~150 symbols)
//   - kc/ops.dashboardStockSectors (duplicate, ~80-symbol subset;
//     duplicated to avoid importing mcp/portfolio from kc/ops which
//     would invert the dependency direction)
//
// Both consumers now import this leaf, eliminating the duplicate +
// unblocking the scanner sector-filter feature (Axis C C.F1 Phase 3
// per .research/abc-100pct-complete-paths.md).
//
// Pattern matches kc/isttz precedent (zero internal deps; only
// testify in test deps).
require github.com/stretchr/testify v1.10.0

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
