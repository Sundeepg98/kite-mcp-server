// Package kc — manager.go: Manager constructors only.
//
// Anchor 6 PR 6.15 collapsed manager.go to the constructor surface. The
// Manager struct + sentinel errors + KiteSessionData alias moved to
// kc/manager_struct.go; Config moved to kc/config.go; KiteConnect moved
// to kc/kite_connect.go; truncKey moved to kc/util.go. The remaining
// pointers (// X lives in Y) are listed at the bottom of the file as a
// roadmap for new contributors.
package kc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
)

// New creates a new kc Manager with the given configuration.
//
// Deprecated: prefer NewWithOptions(ctx, opts...) which uses the
// functional-options pattern consistent with the rest of the codebase
// (testutil/kcfixture, kc/ticker/config.go, kc/scheduler/provider.go).
// This function is retained as a thin backward-compat shim because
// 40+ test files across app/, mcp/, and kc/ops/ call it directly with
// literal kc.Config{…} structs; forcing all of them to migrate at once
// would ripple through three scopes owned by other active agents.
//
// New is equivalent to NewWithOptions(context.Background(), WithConfig(cfg)).
// It validates cfg.Logger is non-nil (matching pre-shim behaviour) before
// delegating — preserving the error class "logger is required" so
// existing tests that rely on that exact error message keep passing.
func New(cfg Config) (*Manager, error) {
	if cfg.Logger == nil {
		return nil, errors.New("logger is required")
	}
	return NewWithOptions(context.Background(), WithConfig(cfg))
}

// NewWithOptions creates a new kc Manager from a base context plus a
// list of functional options. Primary constructor for the Manager —
// backward-compat paths flow through New(Config) above.
//
// The body is a thin orchestrator over the init* helpers in
// kc/manager_init.go. Each helper is documented at its declaration
// site; the order below is load-bearing — downstream phases read
// state that earlier phases wrote. Do not reorder without re-reading
// the helper docs.
//
// ctx is currently stashed on the options payload for future use
// (cancellable init, tracing spans, deadline propagation); no init
// phase consumes it yet, but the plumbing is in place so that flip
// does not later become a breaking change.
func NewWithOptions(ctx context.Context, opts ...Option) (*Manager, error) {
	o := &options{Ctx: ctx}
	for _, opt := range opts {
		if opt != nil {
			opt(o)
		}
	}
	if o.Ctx == nil {
		o.Ctx = context.Background()
	}

	cfg := o.Config
	if cfg.Logger == nil {
		return nil, errors.New("logger is required")
	}
	if cfg.APIKey == "" || cfg.APISecret == "" {
		cfg.Logger.Warn("No Kite API credentials configured")
	}

	instrumentsManager, err := initInstrumentsManager(cfg)
	if err != nil {
		return nil, err
	}

	m := newEmptyManager(cfg)

	m.initAlertSystem(cfg)
	m.initPersistence(cfg)
	m.initCredentialWiring()
	m.initTelegramNotifier(cfg)
	m.initAlertEvaluator(cfg)
	m.initTrailingStop(cfg)
	m.initSideStores(cfg)
	m.initInjectedStores(cfg)    // populate auditStore/riskGuard/billingStore/invitationStore from cfg
	m.initCredentialService(cfg) // also wires trailing-stop order modifier
	m.initTickerService(cfg)

	if err := m.initializeTemplates(); err != nil {
		return nil, fmt.Errorf("failed to initialize Kite manager: %w", err)
	}
	if err := m.initializeSessionSigner(cfg.SessionSigner); err != nil {
		return nil, fmt.Errorf("failed to initialize session signer: %w", err)
	}

	m.initFocusedServices(cfg, instrumentsManager)
	m.initSessionPersistence(cfg)
	m.initTokenRotation()
	m.initProjector()

	// Wave D Slice D2: hoist order-write use cases from per-request
	// construction in registerOrderCommands to startup-once Manager fields.
	// Must run AFTER initFocusedServices (provides sessionSvc) and BEFORE
	// registerCQRSHandlers (consumes the fields).
	m.initOrderUseCases()

	// Register CQRS handlers on the bus. Tool handlers dispatch queries through
	// manager.QueryBus() rather than constructing use cases inline.
	if err := m.registerCQRSHandlers(); err != nil {
		return nil, fmt.Errorf("failed to register CQRS handlers: %w", err)
	}

	return m, nil
}

// NewManager creates a new manager with default configuration.
//
// Deprecated: Use New(Config{APIKey: apiKey, APISecret: apiSecret, Logger: logger}) instead.
// NOTE: Still used by kc/manager_test.go (TestNewManager). Remove once tests are migrated to New().
func NewManager(apiKey, apiSecret string, logger *slog.Logger) (*Manager, error) {
	return New(Config{
		APIKey:    apiKey,
		APISecret: apiSecret,
		Logger:    logger,
	})
}

// File-roadmap (declarations relocated from manager.go in Anchor 6 PR 6.15):
//   Config struct                              → kc/config.go
//   Manager struct + KiteSessionData alias     → kc/manager_struct.go
//   Constants + sentinel errors                → kc/manager_struct.go
//   KiteConnect struct + NewKiteConnect helper → kc/kite_connect.go
//   truncKey helper                            → kc/util.go
//   Service / accessor methods                 → kc/manager_accessors.go
//   IsLocalMode / ExternalURL / AdminSecretPath / DevMode / APIKey / OpenBrowser → kc/config_manager.go
//   initializeTemplates / initializeSessionSigner / Shutdown / setupTemplates / sessionDBAdapter → kc/manager_lifecycle.go
//   registerCQRSHandlers                       → kc/manager_cqrs_register.go
//   Reconstitution helpers                     → kc/manager_reconstitution.go
//   HandleKiteCallback + helpers + TemplateData → kc/callback_handler.go
