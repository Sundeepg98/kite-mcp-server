module github.com/zerodha/kite-mcp-server/kc/instruments

go 1.25.0

// kc/instruments is a single-internal-dep module — Kite instruments
// fetcher + cache (NSE/BSE symbol-to-token resolver). Direct internal
// dep = kc/isttz (already extracted at commit a2ad8e0). Same shape as
// kc/scheduler (commit e4d2349): replace count = 1 (kc/isttz only).
//
// Tier 2 zero-monolith path (.research/zero-monolith-roadmap.md
// commit a5e7e76): single-dep packages extracted in a single
// dispatch. Replace count: 1.
//
// Pre-existing WSL2 DNS-bound test failures (TestNew_*Instruments-
// Manager*, TestNewConfigConstructor, TestManager_MoreAccessors)
// hit api.kite.trade for live instrument fetch. They fail under
// WSL2 DNS resolution but pass on Fly.io BOM region with direct
// Kite egress. Documented across F1-F7 + 5/5 module dispatches —
// orthogonal to extraction itself.
require (
	github.com/zerodha/kite-mcp-server/kc/isttz v0.0.0-00010101000000-000000000000
	go.uber.org/goleak v1.3.0
)

require github.com/stretchr/testify v1.10.0 // indirect

replace github.com/zerodha/kite-mcp-server/kc/isttz => ../isttz
