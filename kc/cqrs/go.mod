module github.com/zerodha/kite-mcp-server/kc/cqrs

go 1.25.0

// kc/cqrs is a moderate-fan-in module — CommandBus + dispatcher
// (in-memory + saga-friendly) + query handlers (read-side projections
// of orders/holdings/positions/widgets). Direct internal deps:
//   - kc/domain (still in root at this commit; PR 4.1 stub-adds
//     kc/domain/go.mod separately for revertability)
//   - kc/logger (extracted at commit 1b7dcbf)
//
// Transitive replace footprint: kc/domain reaches broker → kc/money,
// and kc/isttz directly. So this module's replace block must include
// root + broker + kc/isttz + kc/logger + kc/money — five entries —
// matching the kc/registry / kc/users shape from Tier 2 (per the
// empirical replace-line cost-curve documented in kc/users/go.mod
// commit f32629f).
//
// Tier 3 zero-monolith path (.research/zero-monolith-roadmap.md
// commit a5e7e76): moderate-fan-in packages extracted in a single
// dispatch. This is 17/24 (commit 1 of 4 in this dispatch).
require (
	github.com/stretchr/testify v1.10.0
	github.com/algo2go/kite-mcp-broker v0.1.0 // indirect
	github.com/zerodha/kite-mcp-server/kc/isttz v0.0.0-00010101000000-000000000000 // indirect
	github.com/zerodha/kite-mcp-server/kc/logger v0.0.0-00010101000000-000000000000
	github.com/algo2go/kite-mcp-money v0.1.0 // indirect
)

require github.com/zerodha/kite-mcp-server/kc/domain v0.0.0-00010101000000-000000000000

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace (
	github.com/zerodha/kite-mcp-server => ../..
	github.com/zerodha/kite-mcp-server/kc/domain => ../domain
	github.com/zerodha/kite-mcp-server/kc/isttz => ../isttz
	github.com/zerodha/kite-mcp-server/kc/logger => ../logger
)
