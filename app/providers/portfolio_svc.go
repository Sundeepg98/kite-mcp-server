package providers

import (
	"github.com/zerodha/kite-mcp-server/kc"
)

// portfolio_svc.go — Anchor 6 PR 6.5 (per .research/tier-5-and-anchor-
// 6-pre-stage.md). Provides *kc.PortfolioService directly via Fx,
// sourced from the post-construction Manager. Mirrors PR 6.1
// (CredentialSvc) and PR 6.3 (SessionSvc) shape exactly.
//
// PURELY ADDITIVE — ZERO DELETION
//
// kc.Manager.PortfolioSvc() (kc/manager_accessors.go:33) stays in
// place. Future PR 6.6 will delete the Manager method after a 24-hour
// deploy observation gate confirms PR 6.5's Fx wiring is healthy.
//
// PATTERN
//
// Pure-function provider — extract the field from the post-
// construction *InitializedManager wrapper. No I/O, no goroutines,
// no error path. Returns the concrete *kc.PortfolioService per the
// audit's "extract concrete, then port" cadence.
//
// CONSUMERS
//
// No consumer migration in this PR. PortfolioService is consumed by
// the read-side query handlers (CQRS query_dispatcher) and a small
// number of mcp/ tool handlers; PR 6.6's follow-on will switch them
// to take *kc.PortfolioService directly via Fx.
//
// LIFECYCLE
//
// PortfolioService has no Shutdown / Close — owned by kc.Manager.
// No fx.Lifecycle hook required.

// ProvidePortfolioSvc returns the post-construction
// *kc.PortfolioService extracted from the post-construction Manager
// wrapper.
func ProvidePortfolioSvc(initialized *InitializedManager) *kc.PortfolioService {
	if initialized == nil || initialized.Manager == nil {
		return nil
	}
	return initialized.Manager.PortfolioSvc()
}
