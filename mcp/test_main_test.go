package mcp

import (
	"io"
	"log/slog"
	"os"
	"testing"

	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
)

// sharedTestManager is created once by TestMain and reused by read-only tests.
// Tests that mutate state (e.g. seedUsers, freeze) should NOT use this — they
// should call newTestManager(t) or newAdminTestManager(t) which create fresh instances.
var sharedTestManager *kc.Manager

func TestMain(m *testing.M) {
	sharedTestManager = newTestManagerOnce()
	os.Exit(m.Run())
}

// newTestManagerOnce creates a Manager suitable for read-only tests.
// Instruments are loaded from TestData so no HTTP calls are made.
func newTestManagerOnce() *kc.Manager {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	testData := map[uint32]*instruments.Instrument{
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
	}

	instMgr, err := instruments.New(instruments.Config{
		UpdateConfig: func() *instruments.UpdateConfig {
			c := instruments.DefaultUpdateConfig()
			c.EnableScheduler = false
			return c
		}(),
		Logger:   logger,
		TestData: testData,
	})
	if err != nil {
		panic("newTestManagerOnce: instruments.New: " + err.Error())
	}

	mgr, err := kc.New(kc.Config{
		APIKey:             "test_key",
		APISecret:          "test_secret",
		Logger:             logger,
		InstrumentsManager: instMgr,
	})
	if err != nil {
		panic("newTestManagerOnce: kc.New: " + err.Error())
	}

	mgr.SetRiskGuard(riskguard.NewGuard(logger))
	return mgr
}
