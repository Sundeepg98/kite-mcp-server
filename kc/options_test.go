package kc

import (
	"context"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
)

// newTestLogger returns a quiet logger for options tests — the init
// phases emit info/warn/error lines that would otherwise flood test
// output; discarding them keeps the signal clean.
func newTestOptionsLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestNewWithOptions_Empty_RequiresLogger(t *testing.T) {
	t.Parallel()

	_, err := NewWithOptions(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "logger is required")
}

func TestNewWithOptions_WithLogger_Succeeds(t *testing.T) {
	t.Parallel()

	logger := newTestOptionsLogger()
	mgr, err := NewWithOptions(context.Background(),
		WithLogger(logger),
		WithInstrumentsSkipFetch(true),
	)
	require.NoError(t, err)
	require.NotNil(t, mgr)
	assert.Same(t, logger, mgr.Logger, "logger threaded through to Manager")
}

func TestNewWithOptions_WithConfig_WholesaleShim(t *testing.T) {
	t.Parallel()

	logger := newTestOptionsLogger()
	cfg := Config{
		APIKey:               "test-key",
		APISecret:            "test-secret",
		Logger:               logger,
		DevMode:              true,
		AppMode:              "stdio",
		InstrumentsSkipFetch: true,
	}
	mgr, err := NewWithOptions(context.Background(), WithConfig(cfg))
	require.NoError(t, err)
	require.NotNil(t, mgr)
	assert.Equal(t, "test-key", mgr.APIKey())
	assert.True(t, mgr.DevMode())
	assert.True(t, mgr.IsLocalMode(), "AppMode=stdio → IsLocalMode")
}

func TestNewWithOptions_LastWinsOverlap(t *testing.T) {
	t.Parallel()

	logger := newTestOptionsLogger()

	// Place WithConfig BEFORE WithLogger so the explicit logger option
	// must override the Config.Logger field. This encodes the last-wins
	// rule documented on the Option type.
	cfgLogger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr, err := NewWithOptions(context.Background(),
		WithConfig(Config{APIKey: "k", APISecret: "s", Logger: cfgLogger}),
		WithLogger(logger),
		WithInstrumentsSkipFetch(true),
	)
	require.NoError(t, err)
	require.NotNil(t, mgr)
	assert.Same(t, logger, mgr.Logger, "later WithLogger overrides earlier WithConfig")
}

func TestNewWithOptions_NilOptionsAreSafe(t *testing.T) {
	t.Parallel()

	// A nil Option value in the variadic slice (e.g. a feature-flagged
	// optional setter that returned nil) must be silently skipped, not
	// panic. This is the "panic-safe against nil" contract that the
	// rest of the codebase's functional-option APIs also honour.
	var nilOpt Option
	mgr, err := NewWithOptions(context.Background(),
		WithLogger(newTestOptionsLogger()),
		nilOpt,
		WithInstrumentsSkipFetch(true),
	)
	require.NoError(t, err)
	require.NotNil(t, mgr)
}

func TestNewWithOptions_GranularSetters(t *testing.T) {
	t.Parallel()

	logger := newTestOptionsLogger()

	// Assemble the same config through granular setters as a caller
	// that is migrating piecemeal from kc.Config literals.
	mgr, err := NewWithOptions(context.Background(),
		WithLogger(logger),
		WithKiteCredentials("ak", "as"),
		WithAccessToken("at"),
		WithAppMode("http"),
		WithExternalURL("https://example.test"),
		WithAdminSecretPath("/admin/secret"),
		WithDevMode(false),
		WithInstrumentsSkipFetch(true),
	)
	require.NoError(t, err)
	require.NotNil(t, mgr)

	assert.Equal(t, "ak", mgr.APIKey())
	assert.False(t, mgr.DevMode())
	assert.Equal(t, "https://example.test", mgr.ExternalURL())
	assert.Equal(t, "/admin/secret", mgr.AdminSecretPath())
	assert.False(t, mgr.IsLocalMode(), "AppMode=http → not local")
}

func TestNew_BackwardCompat_DelegatesToNewWithOptions(t *testing.T) {
	t.Parallel()

	// Proves the legacy New(Config) shim returns a Manager indistinguishable
	// from one built via the new path — 40+ existing call sites rely on
	// this equivalence.
	logger := newTestOptionsLogger()
	cfg := Config{
		APIKey:               "legacy-key",
		APISecret:            "legacy-secret",
		Logger:               logger,
		DevMode:              true,
		InstrumentsSkipFetch: true,
	}

	mgrLegacy, err := New(cfg)
	require.NoError(t, err)
	require.NotNil(t, mgrLegacy)
	assert.Equal(t, "legacy-key", mgrLegacy.APIKey())
	assert.True(t, mgrLegacy.DevMode())

	// Same shape via the new path.
	mgrOptions, err := NewWithOptions(context.Background(), WithConfig(cfg))
	require.NoError(t, err)
	require.NotNil(t, mgrOptions)
	assert.Equal(t, mgrLegacy.APIKey(), mgrOptions.APIKey())
	assert.Equal(t, mgrLegacy.DevMode(), mgrOptions.DevMode())
	assert.Equal(t, mgrLegacy.IsLocalMode(), mgrOptions.IsLocalMode())
}

func TestNew_BackwardCompat_NilLoggerStillErrors(t *testing.T) {
	t.Parallel()

	// The legacy New(cfg) must preserve its pre-shim error message.
	_, err := New(Config{APIKey: "k", APISecret: "s"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "logger is required")
}

func TestWithInstrumentsManager_OverridesAutoBuild(t *testing.T) {
	t.Parallel()

	logger := newTestOptionsLogger()
	instMgr, err := instruments.New(instruments.Config{
		UpdateConfig: func() *instruments.UpdateConfig {
			c := instruments.DefaultUpdateConfig()
			c.EnableScheduler = false
			return c
		}(),
		Logger:   logger,
		TestData: map[uint32]*instruments.Instrument{},
	})
	require.NoError(t, err)

	mgr, err := NewWithOptions(context.Background(),
		WithLogger(logger),
		WithInstrumentsManager(instMgr),
	)
	require.NoError(t, err)
	assert.Same(t, instMgr, mgr.Instruments, "pre-built instruments manager threaded through")
}

// stubBotAPI is a minimal alerts.BotAPI for testing factory injection.
type stubBotAPI struct{}

func (stubBotAPI) Send(_ tgbotapi.Chattable) (tgbotapi.Message, error) {
	return tgbotapi.Message{}, nil
}
func (stubBotAPI) Request(_ tgbotapi.Chattable) (*tgbotapi.APIResponse, error) {
	return &tgbotapi.APIResponse{Ok: true}, nil
}

// TestWithBotFactory_PerManagerInjection verifies the per-Manager Telegram bot
// factory option threads through Manager construction without touching the
// kc/alerts package-level newBotFunc global. This is the t.Parallel-safe
// entry point — multiple Managers in parallel tests can each carry their own
// factory; the alerts.OverrideNewBotFunc global mutator is no longer required
// for cross-package wiring tests.
func TestWithBotFactory_PerManagerInjection(t *testing.T) {
	t.Parallel()

	logger := newTestOptionsLogger()

	var factoryCalled atomic.Int32
	factory := func(token string) (alerts.BotAPI, error) {
		factoryCalled.Add(1)
		assert.Equal(t, "per-manager-token", token, "factory receives the token from cfg.TelegramBotToken")
		return stubBotAPI{}, nil
	}

	mgr, err := NewWithOptions(context.Background(),
		WithLogger(logger),
		WithKiteCredentials("k", "s"),
		WithTelegramBotToken("per-manager-token"),
		WithBotFactory(factory),
		WithInstrumentsSkipFetch(true),
	)
	require.NoError(t, err)
	require.NotNil(t, mgr)

	assert.Equal(t, int32(1), factoryCalled.Load(), "injected factory must be invoked exactly once during Manager init")
	require.NotNil(t, mgr.TelegramNotifier(), "Manager.TelegramNotifier should be wired when token + factory are supplied")
}

// TestWithAlertDB_AcceptsExternallyOpened verifies that an *alerts.DB opened
// outside kc.NewWithOptions can be threaded through via WithAlertDB. This is
// the keystone of the AlertDB-cycle inversion: stores that depend on the DB
// (audit, riskguard, billing, invitation) can now be constructed in
// app/wire.go BEFORE kc.NewWithOptions runs and passed in via With* options
// instead of being post-construction-wired through SetX setters.
//
// Backward-compat: when WithAlertDB is omitted but cfg.AlertDBPath is set,
// the legacy path-open behaviour still applies. Verified by the existing
// AlertDBPath tests; this test pins the new option path.
func TestWithAlertDB_AcceptsExternallyOpened(t *testing.T) {
	t.Parallel()

	logger := newTestOptionsLogger()
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	mgr, err := NewWithOptions(context.Background(),
		WithLogger(logger),
		WithKiteCredentials("k", "s"),
		WithAlertDB(db),
		WithInstrumentsSkipFetch(true),
	)
	require.NoError(t, err)
	require.NotNil(t, mgr)

	// Manager must hold the SAME DB pointer — not open a duplicate.
	assert.Same(t, db, mgr.AlertDB(),
		"WithAlertDB must thread the externally-opened DB through; manager.AlertDB() returns the same pointer")
}
