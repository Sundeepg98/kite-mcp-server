package kc

import (
	"context"
	"log/slog"

	"github.com/zerodha/kite-mcp-server/app/metrics"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/billing"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
	"github.com/zerodha/kite-mcp-server/kc/users"
)

// options is the internal payload that Option functions mutate. A plain
// Config is embedded so every legacy setter (WithConfig) lands a full
// struct in one hop; the remaining fields extend configuration
// surface — today just Ctx, which is a first-class option rather than a
// Config field because kc.New previously had no context parameter at
// all and callers passing context.Background was implied.
type options struct {
	Config
	Ctx context.Context
}

// Option mutates the Manager construction payload. Returned from the
// With* helpers; consumed by NewWithOptions (and, as a backward-compat
// shim, by the deprecated New(Config)).
//
// Design notes:
//
//   - All options are additive. Later options win when they overlap
//     (e.g. WithConfig followed by WithLogger overrides Config.Logger
//     with the explicit logger). This matches how the rest of the
//     codebase uses functional options (testutil/kcfixture,
//     kc/ticker/config.go, kc/scheduler/provider.go) — predictable
//     last-wins rather than first-wins or accumulator.
//
//   - The receiver is *options (not options) so helpers that need to
//     inspect prior state to refine a field can read what earlier
//     options wrote. Not used today; kept for future flexibility.
//
//   - Error-returning options are not supported. Any validation that
//     COULD fail (credential parsing, logger nil-check, context
//     cancellation) is deferred to NewWithOptions' body so the Option
//     surface stays as pure data. This matches functional-option
//     convention in Go — errors flow through the constructor, not
//     through each setter.
type Option func(*options)

// WithConfig installs an entire Config struct in one hop. The primary
// backward-compat path: the deprecated New(cfg) shim delegates to
// NewWithOptions(ctx, WithConfig(cfg)), so every existing caller
// (app/wire.go, testutil/kcfixture, 40+ test files under app/, mcp/,
// kc/ops/) keeps compiling unchanged. New code should prefer the
// granular setters below unless it already holds a full Config from
// another source (e.g. env-parsing).
func WithConfig(cfg Config) Option {
	return func(o *options) {
		o.Config = cfg
	}
}

// WithContext attaches the caller's context to the Manager build.
// Today the context is not threaded into the init phases (each phase
// is synchronous and fast), but it is captured so future reshaping —
// cancellable init, tracing spans, deadline propagation — has the
// plumbing already in place. Defaults to context.Background() when
// NewWithOptions is called without this option.
func WithContext(ctx context.Context) Option {
	return func(o *options) {
		o.Ctx = ctx
	}
}

// WithLogger sets the structured logger. Required — NewWithOptions
// returns an error when the assembled options have a nil Logger,
// matching the legacy New(cfg) contract.
func WithLogger(logger *slog.Logger) Option {
	return func(o *options) {
		o.Config.Logger = logger
	}
}

// WithKiteCredentials installs the Kite API key + secret pair. These
// two always travel together (the Kite OAuth flow needs both) so a
// combined setter avoids the "set key, forget secret" error class.
// AccessToken (optional pre-set token bypass) has its own setter
// because it is semantically distinct: key+secret are app identity,
// AccessToken is user-session identity.
func WithKiteCredentials(apiKey, apiSecret string) Option {
	return func(o *options) {
		o.Config.APIKey = apiKey
		o.Config.APISecret = apiSecret
	}
}

// WithAccessToken sets a pre-authenticated Kite access token. Used by
// local-dev and single-user deployments to skip the browser login; on
// the hosted multi-user deployment this is always empty and tokens
// are acquired per-user via the OAuth flow.
func WithAccessToken(token string) Option {
	return func(o *options) {
		o.Config.AccessToken = token
	}
}

// WithMetrics attaches the metrics manager used for per-user tracking
// and Prometheus-style counters. Optional; Manager runs without
// metrics when this is nil.
func WithMetrics(m *metrics.Manager) Option {
	return func(o *options) {
		o.Config.Metrics = m
	}
}

// WithTelegramBotToken configures the Telegram bot used for alert
// notifications. Empty token disables Telegram — the notifier simply
// is not constructed.
func WithTelegramBotToken(token string) Option {
	return func(o *options) {
		o.Config.TelegramBotToken = token
	}
}

// WithAlertDBPath enables SQLite persistence for alerts, tokens,
// credentials, watchlists, users, registry, sessions, and the domain
// event store. When empty the server runs in-memory only; persistence
// is all-or-nothing because every store shares the same DB handle.
func WithAlertDBPath(path string) Option {
	return func(o *options) {
		o.Config.AlertDBPath = path
	}
}

// WithAppMode sets the transport mode — "stdio" (default, local),
// "http", or "sse". Drives IsLocalMode() which gates OpenBrowser and
// other local-only behaviours.
func WithAppMode(mode string) Option {
	return func(o *options) {
		o.Config.AppMode = mode
	}
}

// WithExternalURL sets the server's externally-reachable URL
// (e.g. "https://kite-mcp-server.fly.dev"). Used to construct
// dashboard links and OAuth redirect URIs.
func WithExternalURL(url string) Option {
	return func(o *options) {
		o.Config.ExternalURL = url
	}
}

// WithAdminSecretPath sets the admin endpoint's secret path segment
// so /admin/<secret>/ops can be generated by the dashboard link
// helpers. Empty disables the admin link emission.
func WithAdminSecretPath(path string) Option {
	return func(o *options) {
		o.Config.AdminSecretPath = path
	}
}

// WithEncryptionSecret supplies the secret used to derive the
// credential-encryption key (via HKDF in alerts.EnsureEncryptionSalt).
// Typically the same value as OAUTH_JWT_SECRET so operators manage
// one secret, not two. Empty disables credential encryption at rest
// — safe for dev, fatal for production (caller enforces).
func WithEncryptionSecret(secret string) Option {
	return func(o *options) {
		o.Config.EncryptionSecret = secret
	}
}

// WithDevMode toggles the mock-broker path. When true, the Manager
// constructs a broker/mock client and skips real Kite login; used by
// the devmode test suite and local dev without Kite credentials.
func WithDevMode(enabled bool) Option {
	return func(o *options) {
		o.Config.DevMode = enabled
	}
}

// WithInstrumentsManager installs a pre-built instruments manager so
// the Manager skips construction of a new one. Primary use: tests
// that share a seeded manager across multiple Manager instances for
// speed.
func WithInstrumentsManager(m *instruments.Manager) Option {
	return func(o *options) {
		o.Config.InstrumentsManager = m
	}
}

// WithInstrumentsConfig overrides the default instruments update
// configuration (refresh interval, timeout, TestData seed). Ignored
// when WithInstrumentsManager is also applied.
func WithInstrumentsConfig(cfg *instruments.UpdateConfig) Option {
	return func(o *options) {
		o.Config.InstrumentsConfig = cfg
	}
}

// WithInstrumentsSkipFetch sets the test-isolation seam so the
// auto-created instruments manager skips the HTTP fetch of
// api.kite.trade/instruments.json and loads an empty instrument map
// instead. Ignored when WithInstrumentsManager is applied.
func WithInstrumentsSkipFetch(skip bool) Option {
	return func(o *options) {
		o.Config.InstrumentsSkipFetch = skip
	}
}

// WithSessionSigner installs a pre-built HMAC session signer. When
// omitted the Manager generates a fresh signer at construction. Used
// by tests that need signature stability across multiple Manager
// instances.
func WithSessionSigner(s *SessionSigner) Option {
	return func(o *options) {
		o.Config.SessionSigner = s
	}
}

// WithBotFactory installs a per-Manager Telegram bot factory. When
// supplied, the manager constructs its TelegramNotifier via the factory
// instead of consulting the kc/alerts package-level newBotFunc global —
// this is the t.Parallel-safe entry point for tests that need a fake
// Telegram server. Production wiring omits this so the default
// tgbotapi.NewBotAPI path is used.
func WithBotFactory(factory alerts.BotFactory) Option {
	return func(o *options) {
		o.Config.BotFactory = factory
	}
}

// WithAlertDB threads a pre-opened *alerts.DB through Manager
// construction. When supplied, initPersistence skips the
// alerts.OpenDB(AlertDBPath) call and uses the externally-opened DB
// directly. This is the inversion seam for the AlertDB construction
// cycle: app/wire.go opens the DB once, constructs DB-backed stores
// (audit/riskguard/billing/invitation) via the matching With* options,
// then passes them all to NewWithOptions in one hop — eliminating the
// post-construction SetX setters that previously required
// kcManager.AlertDB() to be readable BEFORE the manager finished
// initialising.
//
// Lifetime: the manager does NOT close a DB it did not open. Callers
// that pass a DB via WithAlertDB own the DB lifecycle and are
// responsible for closing it during graceful shutdown. The
// app/lifecycle.go LifecycleManager handles this for app/wire.go.
func WithAlertDB(db *alerts.DB) Option {
	return func(o *options) {
		o.Config.AlertDB = db
	}
}

// WithAuditStore threads a pre-constructed audit.Store through Manager
// construction, eliminating the post-init kcManager.SetAuditStore call
// site in app/wire.go. The legacy SetAuditStore setter is retained as
// a deprecated shim so the ~5+ test sites that mutate the manager
// after construction continue to work unchanged.
func WithAuditStore(s *audit.Store) Option {
	return func(o *options) {
		o.Config.AuditStore = s
	}
}

// WithRiskGuard threads a pre-constructed riskguard.Guard through
// Manager construction. Same deprecation contract as WithAuditStore.
func WithRiskGuard(g *riskguard.Guard) Option {
	return func(o *options) {
		o.Config.RiskGuard = g
	}
}

// WithBillingStore threads a pre-constructed billing.Store through
// Manager construction. Same deprecation contract as WithAuditStore.
func WithBillingStore(s *billing.Store) Option {
	return func(o *options) {
		o.Config.BillingStore = s
	}
}

// WithInvitationStore threads a pre-constructed users.InvitationStore
// through Manager construction. Same deprecation contract as
// WithAuditStore.
func WithInvitationStore(s *users.InvitationStore) Option {
	return func(o *options) {
		o.Config.InvitationStore = s
	}
}
