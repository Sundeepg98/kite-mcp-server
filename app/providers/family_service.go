package providers

import (
	"github.com/zerodha/kite-mcp-server/kc"
)

// family_service.go — Anchor 6 PR 6.11 (per .research/tier-5-and-
// anchor-6-pre-stage.md). Provides *kc.FamilyService directly via Fx,
// sourced from the post-construction Manager. Mirrors PR 6.1
// (CredentialSvc) shape with one nuance noted below.
//
// PURELY ADDITIVE — ZERO DELETION
//
// kc.Manager.FamilyService() (kc/manager_accessors.go:48) stays in
// place. Future PR 6.12 will delete the Manager method after a 24-hour
// deploy observation gate confirms PR 6.11's Fx wiring is healthy.
//
// NIL-TOLERANT
//
// Unlike the other Anchor 6 sub-services (CredentialSvc, SessionSvc,
// PortfolioSvc, OrderSvc, AlertSvc) which are always non-nil after
// successful Manager construction, *kc.FamilyService can legitimately
// be nil — the Manager.FamilyService() docstring says "or nil if not
// configured" and the field is set lazily via SetFamilyService (see
// kc/manager_accessors.go:67). Family billing is an optional feature
// gated by config.
//
// The provider passes through nil unchanged. Consumers must check for
// nil before invoking methods on the returned value, matching the
// existing call-site pattern at kc/manager_cqrs_register.go:158.
//
// PATTERN
//
// Pure-function provider — extract the field from the post-
// construction *InitializedManager wrapper. No I/O, no goroutines,
// no error path. Returns the concrete *kc.FamilyService (or nil if
// the field is unset) per the audit's "extract concrete, then port"
// cadence.
//
// LIFECYCLE
//
// FamilyService has no Shutdown / Close — owned by kc.Manager. No
// fx.Lifecycle hook required.

// ProvideFamilyService returns the post-construction *kc.FamilyService
// extracted from the post-construction Manager wrapper. May return nil
// if family billing is not configured for the deployment — this matches
// the Manager.FamilyService() contract.
func ProvideFamilyService(initialized *InitializedManager) *kc.FamilyService {
	if initialized == nil || initialized.Manager == nil {
		return nil
	}
	return initialized.Manager.FamilyService
}
