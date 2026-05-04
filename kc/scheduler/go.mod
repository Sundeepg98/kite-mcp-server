module github.com/zerodha/kite-mcp-server/kc/scheduler

go 1.25.0

// kc/scheduler is a single-internal-dep module — daily cron scheduler
// (morning briefings, daily P&L) gated by IST market hours. Direct
// internal dep = kc/isttz (already extracted at commit a2ad8e0).
// kc/isttz is a stdlib-only leaf, so its replace points only at
// ../isttz — no further transitive workspace-member reach.
//
// Tier 2 zero-monolith path (.research/zero-monolith-roadmap.md
// commit a5e7e76): single-dep packages extracted in a single
// dispatch. Replace count: 1 (kc/isttz only).
require (
	github.com/zerodha/kite-mcp-server/kc/isttz v0.0.0-00010101000000-000000000000
	go.uber.org/goleak v1.3.0
)

require github.com/stretchr/testify v1.10.0 // indirect

replace github.com/zerodha/kite-mcp-server/kc/isttz => ../isttz
