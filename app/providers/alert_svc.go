package providers

import (
	"github.com/zerodha/kite-mcp-server/kc"
)

// alert_svc.go — Anchor 6 PR 6.9 (per .research/tier-5-and-anchor-
// 6-pre-stage.md). Provides *kc.AlertService directly via Fx,
// sourced from the post-construction Manager. Mirrors PR 6.1
// (CredentialSvc) shape exactly.
//
// PURELY ADDITIVE — ZERO DELETION
//
// kc.Manager.AlertSvc() (kc/manager_accessors.go:43) stays in place.
// Future PR 6.10 will delete the Manager method after a 24-hour
// deploy observation gate confirms PR 6.9's Fx wiring is healthy.
//
// PATTERN
//
// Pure-function provider — extract the field from the post-
// construction *InitializedManager wrapper. No I/O, no goroutines,
// no error path. Returns the concrete *kc.AlertService per the
// audit's "extract concrete, then port" cadence.
//
// LIFECYCLE
//
// AlertService has no Shutdown / Close — owned by kc.Manager. The
// adjacent alert subsystem (alertEvaluator goroutine, telegram
// notifier, trailing-stop manager) IS lifecycle-managed, but those
// are separate fields wired through Manager.Shutdown(). The
// AlertService itself is a stateless coordinator over those subsystems.
// No fx.Lifecycle hook required.

// ProvideAlertSvc returns the post-construction *kc.AlertService
// extracted from the post-construction Manager wrapper.
func ProvideAlertSvc(initialized *InitializedManager) *kc.AlertService {
	if initialized == nil || initialized.Manager == nil {
		return nil
	}
	return initialized.Manager.AlertSvc
}
