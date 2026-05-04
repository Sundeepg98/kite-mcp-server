package providers

import (
	"github.com/zerodha/kite-mcp-server/kc"
)

// credential_svc.go — Anchor 6 PR 6.1 (per .research/tier-5-and-anchor-
// 6-pre-stage.md). Risk-floor PR for the kc-root god-struct decompo-
// sition: provides *kc.CredentialService directly via Fx, sourced from
// the post-construction Manager.
//
// PURELY ADDITIVE — ZERO DELETION
//
// kc.Manager.CredentialSvc() (kc/manager_accessors.go:23) stays in
// place. This PR does NOT modify a single existing file in kc/. It
// adds one new Fx provider that exposes the same *kc.CredentialService
// pointer through a new graph node. Future PR 6.2 will delete the
// Manager method after a 24-hour deploy observation gate confirms
// PR 6.1's Fx wiring is healthy in prod (per audit's 14-PR add+delete
// cadence — each method-pair = 1 add + 1 delete).
//
// PATTERN
//
// Mirrors the audit_middleware.go pure-function provider shape:
// take the post-construction *InitializedManager wrapper, extract
// the field, return the same pointer. No I/O, no goroutines, safe
// to call from any provider context. The InitializedManager.Manager
// field is always non-nil when the wrapper is non-nil (BuildManager
// returns nil-wrapper on error per app/providers/manager.go:166-171),
// so the unguarded Manager.CredentialSvc() dereference is sound.
//
// CONSUMERS
//
// No consumer migration in this PR. Existing call sites continue to
// reach CredentialService via Manager.CredentialSvc(). PR 6.2's
// follow-on will switch consumers to take *kc.CredentialService
// directly via Fx, then delete the Manager method.
//
// LIFECYCLE
//
// CredentialService has no Shutdown / Close — its dependencies
// (credentialStore, tokenStore, registryStore) are all owned by
// kc.Manager whose lifecycle is already wired via app/wire.go.
// No fx.Lifecycle hook required.

// ProvideCredentialSvc returns the post-construction
// *kc.CredentialService extracted from the post-construction Manager
// wrapper. The provider is a pure projection — no construction, no
// state mutation, no error path.
//
// Returning the concrete *kc.CredentialService (not an interface) is
// deliberate: the audit's anchor-6 design (PRs 6.1-6.14) follows the
// "extract concrete, then port" cadence — each method-pair first
// surfaces the concrete type via Fx, then a later PR (post-Anchor-6)
// can introduce a port if the consumer set warrants it. For
// CredentialService the consumer surface is small (kc-internal only
// today), so a port is not yet justified.
func ProvideCredentialSvc(initialized *InitializedManager) *kc.CredentialService {
	if initialized == nil || initialized.Manager == nil {
		return nil
	}
	return initialized.Manager.CredentialSvc()
}
