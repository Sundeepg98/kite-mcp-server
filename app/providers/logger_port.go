package providers

import (
	logport "github.com/algo2go/kite-mcp-logger"
)

// logger_port.go — Anchor 6 PR 6.13 (per .research/tier-5-and-anchor-
// 6-pre-stage.md). Provides logport.Logger directly via Fx, sourced
// from the post-construction Manager. Mirrors the PR 6.1
// (CredentialSvc) shape with one structural deviation noted below.
//
// PURELY ADDITIVE — ZERO DELETION
//
// kc.Manager.LoggerPort() (kc/manager_accessors.go:59) stays in
// place. Future PR 6.14 will delete the Manager method after a
// 24-hour deploy observation gate confirms PR 6.13's Fx wiring is
// healthy in prod.
//
// CONSTRUCTOR-PER-CALL DEVIATION
//
// Unlike the other Anchor 6 sub-services (CredentialSvc, SessionSvc,
// PortfolioSvc, OrderSvc, AlertSvc, FamilyService) which return a
// stored field pointer, Manager.LoggerPort() constructs a FRESH
// logport.NewSlog(m.Logger) wrapper on each call (or NewNoop() when
// m.Logger is nil). The wrapper is an *slogAdapter{l: m.Logger}
// allocation per call site.
//
// Functional equivalence is preserved: every wrapper points at the
// same underlying *slog.Logger field, so log records flow to the
// identical slog handler. Pointer-identity is NOT preserved across
// calls — the Anchor 6 graph receives ONE wrapper from this provider
// and the existing Manager.LoggerPort() call sites continue to
// construct new wrappers per call. Both wrappers wrap the same
// underlying *slog.Logger; observed logging behaviour is identical.
//
// This deviation is structural to the existing accessor design (see
// kc/manager_accessors.go:59-64) — not a flaw introduced by this PR.
// The follow-on PR 6.14 (delete the accessor) will eliminate the
// per-call construction overhead by routing all consumers through
// the single Fx-provided wrapper.
//
// PATTERN
//
// Pure-function provider — invoke the field-derived accessor on the
// post-construction *InitializedManager wrapper. No I/O, no
// goroutines, no error path.
//
// LIFECYCLE
//
// Logger has no Shutdown / Close — the underlying *slog.Logger is
// owned by the composition site (app/wire.go) and outlives this
// provider. No fx.Lifecycle hook required.

// ProvideLoggerPort returns the logport.Logger from the
// post-construction Manager wrapper. Always non-nil when the wrapper
// is non-nil (the constructor-per-call wrapper that Manager.LoggerPort()
// previously emitted is now constructed once, here, at Fx-injection
// time — the per-call construction overhead documented in PR 6.13's
// commit message is now eliminated).
//
// Returns nil only when the input wrapper itself is nil — the
// defensive case for direct-test callers.
//
// Anchor 6 PR 6.14: Manager.LoggerPort() method deleted; the wrapper
// is constructed inline here from the Manager.Logger *slog.Logger
// field. Same nil-fallback to NewNoop preserved (matches the prior
// kc/manager_accessors.go:60-62 contract). Per-call construction
// overhead eliminated — the Fx graph caches the resulting
// logport.Logger by virtue of Fx's singleton-by-default semantics.
func ProvideLoggerPort(initialized *InitializedManager) logport.Logger {
	if initialized == nil || initialized.Manager == nil {
		return nil
	}
	if initialized.Manager.Logger == nil {
		return logport.NewNoop()
	}
	return logport.NewSlog(initialized.Manager.Logger)
}
