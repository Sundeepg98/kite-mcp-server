package providers

import (
	"github.com/zerodha/kite-mcp-server/kc"
)

// order_svc.go — Anchor 6 PR 6.7 (per .research/tier-5-and-anchor-
// 6-pre-stage.md). Provides *kc.OrderService directly via Fx,
// sourced from the post-construction Manager. Mirrors PR 6.1
// (CredentialSvc) shape exactly.
//
// PURELY ADDITIVE — ZERO DELETION
//
// kc.Manager.OrderSvc() (kc/manager_accessors.go:38) stays in place.
// Future PR 6.8 will delete the Manager method after a 24-hour deploy
// observation gate confirms PR 6.7's Fx wiring is healthy.
//
// NOTE: *kc.OrderService is the same type still referenced by
// kc/ports/order.go (Anchor 5 PR 5.7 left order.go intentionally
// importing kc parent — see anchor-5-prs-design.md PR 5.7). PR 6.7
// surfaces the service via Fx but does NOT touch the port file or
// the consumer-side OrderPort interface. The port-side migration is
// downstream work tracked separately under Anchor 6's "kc-root
// shrink" plan (post-Anchor-6 if a port is warranted).
//
// PATTERN
//
// Pure-function provider — extract the field from the post-
// construction *InitializedManager wrapper. No I/O, no goroutines,
// no error path. Returns the concrete *kc.OrderService per the
// audit's "extract concrete, then port" cadence.
//
// LIFECYCLE
//
// OrderService has no Shutdown / Close — owned by kc.Manager. No
// fx.Lifecycle hook required.

// ProvideOrderSvc returns the post-construction *kc.OrderService
// extracted from the post-construction Manager wrapper.
func ProvideOrderSvc(initialized *InitializedManager) *kc.OrderService {
	if initialized == nil || initialized.Manager == nil {
		return nil
	}
	return initialized.Manager.OrderSvc()
}
