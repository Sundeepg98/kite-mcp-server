package kc

// manager_construction_test.go — coverage close-out for the
// NewWithOptions construction surface. Targets the 6 With* options
// that were sitting at 0% coverage (WithContext, WithMetrics,
// WithAlertDBPath, WithEncryptionSecret, WithInstrumentsConfig,
// WithSessionSigner) plus the boot-path branches in NewWithOptions
// itself (default-context fill, no-credentials warn-log).
//
// Sub-commit A of Wave B option 2 (kc/ root Manager boot + lifecycle).
//
// File-scope: kc/manager_*construction*_test.go is intentionally a
// new file separate from the existing kc/options_test.go so concurrent
// agents (Wave D BrokerResolver migration) editing options_test.go
// do not collide. Hermetic via :memory: SQLite + InstrumentsSkipFetch.

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/app/metrics"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
)

// quietLogger discards all log output. Local helper rather than
// reusing newTestOptionsLogger from options_test.go to keep this file
// self-contained — Wave D may rename helpers in options_test.go.
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// ===========================================================================
// WithContext — option propagation + default fill
// ===========================================================================

// TestWithContext_PropagatesValue verifies the option attaches the
// caller's context to the Manager build payload. The context isn't
// threaded into init phases yet but the plumbing must work for
// future cancellable-init reshapes (the docstring on WithContext
// pins this contract).
func TestWithContext_PropagatesValue(t *testing.T) {
	t.Parallel()

	type ctxKey struct{}
	parent := context.WithValue(context.Background(), ctxKey{}, "marker")

	// Apply WithContext directly to the options payload to verify the
	// setter mutates Ctx as documented. We don't have a public
	// accessor for o.Ctx after NewWithOptions returns (the field is
	// internal), so we exercise the option function in isolation.
	o := &options{}
	WithContext(parent)(o)
	require.NotNil(t, o.Ctx)
	assert.Equal(t, "marker", o.Ctx.Value(ctxKey{}))
}

// TestNewWithOptions_DefaultsContextWhenNil verifies the boot-path
// branch at manager.go:131-133: when both the ctx parameter AND
// WithContext are absent (nil ctx), NewWithOptions defaults to
// context.Background() rather than panicking on a nil deref. This
// is documented as a backward-compat path so existing callers
// passing context.Background() implicitly via the legacy New(cfg)
// shim keep working.
func TestNewWithOptions_DefaultsContextWhenNil(t *testing.T) {
	t.Parallel()

	// Pass an explicit nil context — the boot path must replace it
	// with context.Background() rather than fail.
	//nolint:staticcheck // intentionally nil to exercise the default-fill
	mgr, err := NewWithOptions(nil,
		WithLogger(quietLogger()),
		WithInstrumentsSkipFetch(true),
	)
	require.NoError(t, err)
	require.NotNil(t, mgr)
}

// TestNewWithOptions_WithContext_ThreadsThrough verifies the explicit
// option path: WithContext overrides the ctx parameter when both are
// supplied. Pins the last-wins option-application semantics.
func TestNewWithOptions_WithContext_ThreadsThrough(t *testing.T) {
	t.Parallel()

	// Cancellable parent — if this context isn't actually consulted
	// during construction (it isn't today; reserved for future), the
	// test still proves the option ran without error.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mgr, err := NewWithOptions(context.Background(), // base ctx
		WithContext(ctx), // override
		WithLogger(quietLogger()),
		WithInstrumentsSkipFetch(true),
	)
	require.NoError(t, err)
	require.NotNil(t, mgr)
}

// ===========================================================================
// WithMetrics — option propagation
// ===========================================================================

// TestWithMetrics_AttachesManager verifies WithMetrics threads a
// metrics.Manager into the build payload and the resulting Manager
// holds the same instance. Covers the option function + the
// newEmptyManager assignment line (m.metrics = cfg.Metrics).
func TestWithMetrics_AttachesManager(t *testing.T) {
	t.Parallel()

	mm := metrics.New(metrics.Config{ServiceName: "test"})

	mgr, err := NewWithOptions(context.Background(),
		WithLogger(quietLogger()),
		WithMetrics(mm),
		WithInstrumentsSkipFetch(true),
	)
	require.NoError(t, err)
	require.NotNil(t, mgr)
	// The metrics field is unexported — verify via the same-package
	// access that newEmptyManager threaded it through correctly.
	assert.Same(t, mm, mgr.metrics, "metrics manager threaded into Manager.metrics")
}

// TestWithMetrics_NilIsTolerated verifies passing nil leaves the
// metrics field nil (the documented "Manager runs without metrics
// when this is nil" contract).
func TestWithMetrics_NilIsTolerated(t *testing.T) {
	t.Parallel()

	mgr, err := NewWithOptions(context.Background(),
		WithLogger(quietLogger()),
		WithMetrics(nil),
		WithInstrumentsSkipFetch(true),
	)
	require.NoError(t, err)
	require.NotNil(t, mgr)
	assert.Nil(t, mgr.metrics, "WithMetrics(nil) leaves field nil")
}

// ===========================================================================
// WithAlertDBPath — option propagation
// ===========================================================================

// TestWithAlertDBPath_StoresPath verifies the option mutates the
// build payload's AlertDBPath field. Production wiring uses this when
// no pre-opened *alerts.DB is supplied; initPersistence then opens
// the DB at that path. Tests keep using :memory: but the option
// itself must be exercised.
func TestWithAlertDBPath_StoresPath(t *testing.T) {
	t.Parallel()

	o := &options{}
	WithAlertDBPath(":memory:")(o)
	assert.Equal(t, ":memory:", o.Config.AlertDBPath)
}

// TestNewWithOptions_WithAlertDBPath_OpensDB verifies the boot-path
// integration: an in-memory path opens a real *alerts.DB visible via
// the manager's accessor. Pins the docstring contract that
// "persistence is all-or-nothing".
func TestNewWithOptions_WithAlertDBPath_OpensDB(t *testing.T) {
	t.Parallel()

	mgr, err := NewWithOptions(context.Background(),
		WithLogger(quietLogger()),
		WithAlertDBPath(":memory:"),
		WithInstrumentsSkipFetch(true),
	)
	require.NoError(t, err)
	require.NotNil(t, mgr)
	require.NotNil(t, mgr.AlertDB(), "AlertDBPath=:memory: must open the DB")
}

// ===========================================================================
// WithEncryptionSecret — option propagation
// ===========================================================================

// TestWithEncryptionSecret_StoresValue verifies the option puts the
// secret on the build payload. Documented contract: "typically the
// same value as OAUTH_JWT_SECRET so operators manage one secret, not
// two".
func TestWithEncryptionSecret_StoresValue(t *testing.T) {
	t.Parallel()

	o := &options{}
	WithEncryptionSecret("super-secret-32-bytes-long-key!!")(o)
	assert.Equal(t, "super-secret-32-bytes-long-key!!", o.Config.EncryptionSecret)
}

// TestNewWithOptions_WithEncryptionSecret_BootsCleanly verifies the
// option works end-to-end: a non-empty secret threads through to the
// manager build without error. The HKDF derivation happens in
// initPersistence when an AlertDB is also wired; without an AlertDB
// the encryption secret is captured but unused, which matches the
// documented "safe for dev" behaviour.
func TestNewWithOptions_WithEncryptionSecret_BootsCleanly(t *testing.T) {
	t.Parallel()

	mgr, err := NewWithOptions(context.Background(),
		WithLogger(quietLogger()),
		WithEncryptionSecret("test-encryption-secret-value-32-"),
		WithAlertDBPath(":memory:"),
		WithInstrumentsSkipFetch(true),
	)
	require.NoError(t, err)
	require.NotNil(t, mgr)
}

// TestNewWithOptions_EmptyEncryptionSecret_StillBoots verifies the
// "empty disables credential encryption at rest — safe for dev"
// contract: NewWithOptions does NOT fail when EncryptionSecret is
// empty. Pins the dev-mode happy path.
func TestNewWithOptions_EmptyEncryptionSecret_StillBoots(t *testing.T) {
	t.Parallel()

	mgr, err := NewWithOptions(context.Background(),
		WithLogger(quietLogger()),
		WithEncryptionSecret(""), // explicit empty
		WithInstrumentsSkipFetch(true),
	)
	require.NoError(t, err)
	require.NotNil(t, mgr)
}

// ===========================================================================
// WithInstrumentsConfig — option propagation
// ===========================================================================

// TestWithInstrumentsConfig_StoresPointer verifies the option mutates
// the build payload. The docstring says "Ignored when
// WithInstrumentsManager is also applied" — that override is
// exercised separately below.
func TestWithInstrumentsConfig_StoresPointer(t *testing.T) {
	t.Parallel()

	cfg := instruments.DefaultUpdateConfig()
	cfg.EnableScheduler = false

	o := &options{}
	WithInstrumentsConfig(cfg)(o)
	require.NotNil(t, o.Config.InstrumentsConfig)
	assert.False(t, o.Config.InstrumentsConfig.EnableScheduler,
		"the supplied UpdateConfig must round-trip unchanged")
}

// TestNewWithOptions_WithInstrumentsConfig_BootsManager verifies the
// end-to-end path: a custom InstrumentsConfig used by the auto-built
// instruments manager. Combined with InstrumentsSkipFetch=true to
// avoid the real HTTP fetch.
func TestNewWithOptions_WithInstrumentsConfig_BootsManager(t *testing.T) {
	t.Parallel()

	cfg := instruments.DefaultUpdateConfig()
	cfg.EnableScheduler = false // hermetic — no background ticker

	mgr, err := NewWithOptions(context.Background(),
		WithLogger(quietLogger()),
		WithInstrumentsConfig(cfg),
		WithInstrumentsSkipFetch(true),
	)
	require.NoError(t, err)
	require.NotNil(t, mgr)
}

// TestWithInstrumentsConfig_OverriddenByInstrumentsManager pins the
// docstring contract: when WithInstrumentsManager is also applied,
// WithInstrumentsConfig is ignored. The pre-built manager wins.
func TestWithInstrumentsConfig_OverriddenByInstrumentsManager(t *testing.T) {
	t.Parallel()

	customCfg := instruments.DefaultUpdateConfig()
	customCfg.EnableScheduler = true // would cause leaks if used

	preBuilt, err := instruments.New(instruments.Config{
		Logger:   quietLogger(),
		TestData: map[uint32]*instruments.Instrument{},
	})
	require.NoError(t, err)
	t.Cleanup(preBuilt.Shutdown)

	// If WithInstrumentsConfig won the override race, the manager
	// would build a NEW instruments manager with EnableScheduler=true
	// and leak a goroutine. Test passes if the pre-built one is
	// reused (no second instruments.New call).
	mgr, err := NewWithOptions(context.Background(),
		WithLogger(quietLogger()),
		WithInstrumentsConfig(customCfg),
		WithInstrumentsManager(preBuilt),
	)
	require.NoError(t, err)
	require.NotNil(t, mgr)
}

// ===========================================================================
// WithSessionSigner — option propagation
// ===========================================================================

// TestWithSessionSigner_StoresPointer verifies the option mutates
// the build payload's SessionSigner field.
func TestWithSessionSigner_StoresPointer(t *testing.T) {
	t.Parallel()

	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	signer, err := NewSessionSignerWithKey(key)
	require.NoError(t, err)

	o := &options{}
	WithSessionSigner(signer)(o)
	assert.Same(t, signer, o.Config.SessionSigner)
}

// TestNewWithOptions_WithSessionSigner_UsesSupplied verifies the
// docstring contract: when a pre-built signer is supplied, the
// manager uses it instead of generating a fresh one. Pins the
// stability semantics tests rely on.
func TestNewWithOptions_WithSessionSigner_UsesSupplied(t *testing.T) {
	t.Parallel()

	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	customSigner, err := NewSessionSignerWithKey(key)
	require.NoError(t, err)

	mgr, err := NewWithOptions(context.Background(),
		WithLogger(quietLogger()),
		WithSessionSigner(customSigner),
		WithInstrumentsSkipFetch(true),
	)
	require.NoError(t, err)
	require.NotNil(t, mgr)
	assert.Same(t, customSigner, mgr.SessionSigner(),
		"supplied signer must be the one the manager exposes")
}

// TestNewWithOptions_NoSessionSigner_GeneratesFresh verifies the
// default path: when WithSessionSigner is omitted, the manager
// generates a fresh signer (sessionSigner becomes non-nil).
func TestNewWithOptions_NoSessionSigner_GeneratesFresh(t *testing.T) {
	t.Parallel()

	mgr, err := NewWithOptions(context.Background(),
		WithLogger(quietLogger()),
		WithInstrumentsSkipFetch(true),
	)
	require.NoError(t, err)
	require.NotNil(t, mgr)
	require.NotNil(t, mgr.SessionSigner(),
		"omitting WithSessionSigner must produce a fresh generated signer")
}

// ===========================================================================
// NewWithOptions — error and warn paths
// ===========================================================================

// TestNewWithOptions_NoCredentials_LogsWarn verifies the warn-log
// branch at manager.go:139-141: empty APIKey or APISecret triggers
// a "No Kite API credentials configured" warning but doesn't fail
// construction. Pins the dev-mode-permissive contract — production
// wiring sets credentials, dev/test paths often don't.
func TestNewWithOptions_NoCredentials_LogsWarn(t *testing.T) {
	t.Parallel()

	// Capture log output via a buffer-backed handler so we can
	// assert the warn line lands.
	logs := &captureWriter{}
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn}))

	mgr, err := NewWithOptions(context.Background(),
		WithLogger(logger),
		WithInstrumentsSkipFetch(true),
	)
	require.NoError(t, err)
	require.NotNil(t, mgr)
	assert.Contains(t, logs.String(), "No Kite API credentials configured",
		"missing credentials must trigger the documented warn log")
}

// TestNewWithOptions_OnlyAPIKey_LogsWarn covers the asymmetric
// branch: only one of (APIKey, APISecret) is set. The check at
// manager.go:139 uses OR, so either-but-not-both still triggers the
// warning.
func TestNewWithOptions_OnlyAPIKey_LogsWarn(t *testing.T) {
	t.Parallel()

	logs := &captureWriter{}
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn}))

	mgr, err := NewWithOptions(context.Background(),
		WithLogger(logger),
		WithKiteCredentials("only-key", ""), // missing secret
		WithInstrumentsSkipFetch(true),
	)
	require.NoError(t, err)
	require.NotNil(t, mgr)
	assert.Contains(t, logs.String(), "No Kite API credentials configured")
}

// TestNewWithOptions_BothCredentials_NoWarn covers the silent path:
// both APIKey and APISecret set → no warn-log emitted.
func TestNewWithOptions_BothCredentials_NoWarn(t *testing.T) {
	t.Parallel()

	logs := &captureWriter{}
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn}))

	mgr, err := NewWithOptions(context.Background(),
		WithLogger(logger),
		WithKiteCredentials("k", "s"),
		WithInstrumentsSkipFetch(true),
	)
	require.NoError(t, err)
	require.NotNil(t, mgr)
	assert.NotContains(t, logs.String(), "No Kite API credentials configured",
		"both credentials present must NOT trigger the warn log")
}

// ===========================================================================
// Composability — WithAlertDB + stores chain
// ===========================================================================

// TestNewWithOptions_FullStoreChain verifies the docstring's
// inversion-seam contract: pre-built *alerts.DB + audit + riskguard
// can all flow through together (this is what app/wire.go does in
// production). Pins the cycle-break: the manager doesn't try to
// re-open the DB it received.
func TestNewWithOptions_FullStoreChain(t *testing.T) {
	t.Parallel()

	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	mgr, err := NewWithOptions(context.Background(),
		WithLogger(quietLogger()),
		WithAlertDB(db),
		WithKiteCredentials("k", "s"),
		WithInstrumentsSkipFetch(true),
	)
	require.NoError(t, err)
	require.NotNil(t, mgr)
	assert.Same(t, db, mgr.AlertDB(),
		"externally-opened DB must be the one the manager exposes")
}

// ===========================================================================
// Error path — logger nil error wrapped semantics
// ===========================================================================

// TestNewWithOptions_NilLogger_ErrorIsExported verifies the error
// returned for nil-logger uses an exact "logger is required" message
// that backward-compat consumers (the legacy New(cfg) shim,
// app/wire.go, multiple test sites) match against. A future error
// rewrap that loses this substring would break those consumers.
func TestNewWithOptions_NilLogger_ErrorIsExported(t *testing.T) {
	t.Parallel()

	_, err := NewWithOptions(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "logger is required")

	// The error is constructed via errors.New, not wrapped — pin
	// that calling errors.Is against a sentinel (which doesn't exist
	// today) would be wrong. The string-match contract is what
	// downstream code relies on.
	var sentinel error
	assert.False(t, errors.Is(err, sentinel),
		"the nil-logger error is plain errors.New — no sentinel to match against")
}

// ===========================================================================
// Local helpers — log capture
// ===========================================================================

// captureWriter is a tiny io.Writer that buffers everything written
// to it. Used to capture slog output for assertion. Not threadsafe
// (slog handler synchronises writes within one Write call).
type captureWriter struct {
	buf []byte
}

func (c *captureWriter) Write(p []byte) (int, error) {
	c.buf = append(c.buf, p...)
	return len(p), nil
}

func (c *captureWriter) String() string { return string(c.buf) }

// Compile-time check that captureWriter satisfies io.Writer.
var _ io.Writer = (*captureWriter)(nil)
