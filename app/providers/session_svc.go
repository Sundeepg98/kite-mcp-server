package providers

import (
	"github.com/zerodha/kite-mcp-server/kc"
)

// session_svc.go — Anchor 6 PR 6.3 (per .research/tier-5-and-anchor-
// 6-pre-stage.md). Provides *kc.SessionService directly via Fx,
// sourced from the post-construction Manager. Mirrors the PR 6.1
// (CredentialSvc) shape exactly.
//
// PURELY ADDITIVE — ZERO DELETION
//
// kc.Manager.SessionSvc() (kc/manager_accessors.go:28) stays in
// place. This PR does NOT modify a single existing file in kc/. It
// adds one new Fx provider that exposes the same *kc.SessionService
// pointer through a new graph node. Future PR 6.4 will delete the
// Manager method after a 24-hour deploy observation gate confirms
// PR 6.3's Fx wiring is healthy in prod.
//
// PATTERN
//
// Mirrors the audit_middleware.go + credential_svc.go pure-function
// provider shape: take the post-construction *InitializedManager
// wrapper, extract the field, return the same pointer. No I/O, no
// goroutines, safe to call from any provider context.
//
// CONSUMERS
//
// No consumer migration in this PR. PR 6.4's follow-on will switch
// the ~5 consumers (mcp/setup_tools.go, mcp/alert_tools.go,
// kc/callback_handler.go, kc/usecases/setup_usecases.go,
// mcp/admin_server_tools.go per Anchor 5 design) to take
// *kc.SessionService directly via Fx, then delete the Manager method.
//
// LIFECYCLE
//
// SessionService has no Shutdown / Close — its dependencies
// (sessionManager, tokenStore, credentialSvc, etc.) are all owned by
// kc.Manager whose lifecycle is already wired via app/wire.go. No
// fx.Lifecycle hook required.

// ProvideSessionSvc returns the post-construction *kc.SessionService
// extracted from the post-construction Manager wrapper. The provider
// is a pure projection — no construction, no state mutation, no
// error path.
//
// Returning the concrete *kc.SessionService (not an interface) is
// deliberate per the audit's "extract concrete, then port" cadence
// for Anchor 6 method-pairs. A port can be introduced post-Anchor-6
// if the consumer set warrants it.
func ProvideSessionSvc(initialized *InitializedManager) *kc.SessionService {
	if initialized == nil || initialized.Manager == nil {
		return nil
	}
	// Anchor 6 PR 6.4: Manager.SessionSvc() method deleted; the
	// underlying field sessionSvc was capitalised to SessionSvc
	// (now a public field) so Fx providers can access it without an
	// accessor method on the kc-root god-struct. Same field-exposure
	// pattern as PR 6.2 (CredentialSvc, commit 5514fa3).
	return initialized.Manager.SessionSvc
}
