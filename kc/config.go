package kc

import (
	"log/slog"

	"github.com/zerodha/kite-mcp-server/app/metrics"
	"github.com/algo2go/kite-mcp-alerts"
	"github.com/algo2go/kite-mcp-audit"
	"github.com/algo2go/kite-mcp-billing"
	"github.com/algo2go/kite-mcp-instruments"
	"github.com/algo2go/kite-mcp-riskguard"
	"github.com/algo2go/kite-mcp-users"
)

// Config holds configuration for creating a new kc Manager.
//
// Anchor 6 PR 6.15 relocated the canonical declaration from kc/manager.go
// to its own file so manager.go can stay focused on the constructors only.
// No behaviour change — pure file move.
type Config struct {
	APIKey             string                    // required
	APISecret          string                    // required
	AccessToken        string                    // optional: pre-set access token to bypass browser login
	Logger             *slog.Logger              // required
	InstrumentsConfig  *instruments.UpdateConfig // optional - defaults to instruments.DefaultUpdateConfig()
	InstrumentsManager *instruments.Manager      // optional - if provided, skips creating new instruments manager
	SessionSigner      *SessionSigner            // optional - if nil, creates new session signer
	Metrics            *metrics.Manager          // optional - for tracking user metrics
	TelegramBotToken   string                    // optional - for Telegram price alert notifications
	AlertDBPath        string                    // optional - SQLite path for alert persistence
	AppMode            string                    // optional - "stdio", "http", "sse"
	ExternalURL        string                    // optional - e.g. "https://kite-mcp-server.fly.dev"
	AdminSecretPath    string                    // optional - admin endpoint secret for ops dashboard URL
	EncryptionSecret   string                    // optional - secret for encrypting credentials at rest (typically OAUTH_JWT_SECRET)
	DevMode            bool                      // optional - use mock broker, no real Kite login required
	// InstrumentsSkipFetch causes the auto-created instruments manager to
	// skip the HTTP prefetch of api.kite.trade/instruments.json and load an
	// empty instrument map instead. Intended for tests that exercise the
	// full wiring (initializeServices) but do not need live instrument data
	// — isolates the test suite from external-API rate limits / outages.
	// Ignored when InstrumentsManager is already provided.
	InstrumentsSkipFetch bool

	// BotFactory is an optional per-Manager Telegram bot factory. When
	// non-nil, alerts.NewTelegramNotifierWithFactory is used to construct
	// the notifier — bypassing the kc/alerts package-level newBotFunc
	// global. Tests pass a fake-server-backed factory here to avoid the
	// global-mutex OverrideNewBotFunc pattern, unblocking t.Parallel.
	// Production wiring leaves this nil so the default tgbotapi.NewBotAPI
	// path is used.
	BotFactory alerts.BotFactory

	// AlertDB is an optional pre-opened SQLite database. When non-nil,
	// initPersistence uses this DB directly instead of calling
	// alerts.OpenDB(AlertDBPath). This is the inversion seam that lets
	// app/wire.go open the DB once and construct DB-backed stores
	// (audit, riskguard, billing, invitation) BEFORE kc.NewWithOptions —
	// breaking the cycle where those stores were post-wired via SetX
	// setters from the manager's own AlertDB() accessor. AlertDBPath is
	// ignored when this is non-nil (the manager does not close a DB it
	// did not open).
	AlertDB *alerts.DB

	// AuditStore, RiskGuard, BillingStore, InvitationStore are optional
	// pre-constructed stores. When non-nil, the manager populates the
	// matching field directly during init, replacing the post-construction
	// SetX setter pattern (which is retained as deprecated shims for
	// backward compatibility with the ~70+ test sites that still use it).
	//
	// Production wiring (app/wire.go) uses these in combination with
	// AlertDB to break the construction cycle. Tests that don't need
	// these stores can leave them nil and the manager runs without them
	// (matching legacy behaviour).
	AuditStore      *audit.Store
	RiskGuard       *riskguard.Guard
	BillingStore    *billing.Store
	InvitationStore *users.InvitationStore
}
