// Package kcfixture provides a shared factory for building *kc.Manager
// instances in tests. It lives in its own package so packages inside kc/ (and
// its subpackages) can import the base testutil package without creating an
// import cycle — only packages OUTSIDE the kc tree should import kcfixture.
package kcfixture

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
	"github.com/zerodha/kite-mcp-server/testutil"
)

// Option configures a test Manager.
type Option func(*managerOpts)

type managerOpts struct {
	mockKite  *testutil.MockKiteServer
	devMode   bool
	riskGuard bool
	alertDB   string
	apiKey    string
	apiSecret string
	testData  map[uint32]*instruments.Instrument
	fakeClock *testutil.FakeClock
}

// WithMockKite injects a MockKiteServer whose URL will be used as the Kite
// base URI. Tests that need to exercise real HTTP round-trips through the
// kiteconnect SDK should use this option.
func WithMockKite(s *testutil.MockKiteServer) Option {
	return func(o *managerOpts) { o.mockKite = s }
}

// WithDevMode enables the mock broker mode so the Manager does not require
// a real Kite login.
func WithDevMode() Option {
	return func(o *managerOpts) { o.devMode = true }
}

// WithRiskGuard attaches a default RiskGuard to the Manager.
func WithRiskGuard() Option {
	return func(o *managerOpts) { o.riskGuard = true }
}

// WithAlertDB sets the SQLite path for alert persistence.
func WithAlertDB(path string) Option {
	return func(o *managerOpts) { o.alertDB = path }
}

// WithAPIKey overrides the default test API key.
func WithAPIKey(key string) Option {
	return func(o *managerOpts) { o.apiKey = key }
}

// WithAPISecret overrides the default test API secret.
func WithAPISecret(secret string) Option {
	return func(o *managerOpts) { o.apiSecret = secret }
}

// WithTestData overrides the default instruments test data.
func WithTestData(data map[uint32]*instruments.Instrument) Option {
	return func(o *managerOpts) { o.testData = data }
}

// WithFakeClock attaches a deterministic fake clock to the Manager. When
// combined with WithRiskGuard, the Guard's time source is bound to the
// fake so off-hours / cooldown / dedup windows can be advanced via
// fc.Advance(d) without wall-clock sleeps. Without WithRiskGuard, the
// fake is still stored on the fixture for tests that want to pass it
// to other subsystems (rate-limit adapter, scheduler, etc.).
//
// Pass a *testutil.FakeClock created via testutil.NewFakeClock(start).
// The fixture does not seed it — tests control the start time.
func WithFakeClock(fc *testutil.FakeClock) Option {
	return func(o *managerOpts) { o.fakeClock = fc }
}

// DefaultTestData returns the standard instruments test data used by
// NewTestManager when no WithTestData option is provided.
func DefaultTestData() map[uint32]*instruments.Instrument {
	return map[uint32]*instruments.Instrument{
		256265: {
			InstrumentToken: 256265,
			Tradingsymbol:   "INFY",
			Name:            "INFOSYS",
			Exchange:        "NSE",
			Segment:         "NSE",
			InstrumentType:  "EQ",
		},
		408065: {
			InstrumentToken: 408065,
			Tradingsymbol:   "RELIANCE",
			Name:            "RELIANCE INDUSTRIES",
			Exchange:        "NSE",
			Segment:         "NSE",
			InstrumentType:  "EQ",
		},
		779521: {
			InstrumentToken: 779521,
			ExchangeToken:   3045,
			Tradingsymbol:   "SBIN",
			Name:            "STATE BANK OF INDIA",
			Exchange:        "NSE",
			Segment:         "NSE",
			InstrumentType:  "EQ",
			ISIN:            "INE062A01020",
		},
	}
}

// NewTestManager creates a kc.Manager suitable for tests. It never makes real
// HTTP calls (instruments are injected via TestData). The manager is
// automatically shut down when the test finishes.
func NewTestManager(t *testing.T, opts ...Option) *kc.Manager {
	t.Helper()

	o := &managerOpts{
		apiKey:    "test_key",
		apiSecret: "test_secret",
	}
	for _, opt := range opts {
		opt(o)
	}

	td := o.testData
	if td == nil {
		td = DefaultTestData()
	}

	logger := testutil.DiscardLogger()

	instCfg := instruments.DefaultUpdateConfig()
	instCfg.EnableScheduler = false

	instMgr, err := instruments.New(instruments.Config{
		UpdateConfig: instCfg,
		Logger:       logger,
		TestData:     td,
	})
	require.NoError(t, err)

	cfg := kc.Config{
		APIKey:             o.apiKey,
		APISecret:          o.apiSecret,
		Logger:             logger,
		InstrumentsManager: instMgr,
		DevMode:            o.devMode,
		AlertDBPath:        o.alertDB,
	}

	mgr, err := kc.New(cfg)
	require.NoError(t, err)

	if o.riskGuard {
		guard := riskguard.NewGuard(logger)
		// If a fake clock was supplied, wire it into the Guard so
		// off-hours / cooldown windows advance only when the test
		// calls fc.Advance. Guard.SetClock takes a `func() time.Time`,
		// so we adapt FakeClock.Now via a thin closure.
		if o.fakeClock != nil {
			fc := o.fakeClock
			guard.SetClock(fc.Now)
		}
		mgr.SetRiskGuard(guard)
	}

	t.Cleanup(mgr.Shutdown)
	return mgr
}
