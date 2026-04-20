package mcp

import (
	"context"
	"io"
	"log/slog"
	"os"
	"testing"

	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
	"go.uber.org/goleak"
)

// sharedTestManager is created once by TestMain and reused by read-only tests.
// Tests that mutate state (e.g. seedUsers, freeze) should NOT use this — they
// should call newTestManager(t) or newAdminTestManager(t) which create fresh instances.
var sharedTestManager *kc.Manager

func TestMain(m *testing.M) {
	sharedTestManager = newTestManagerOnce()
	code := m.Run()
	// Shut down package-level background goroutines before goleak inspects.
	// sharedTestManager owns SessionRegistry cleanup + instruments scheduler
	// (disabled here but still joined) + token rotation timer. ltpCache
	// in market_tools.go spawns a 5-minute cleanup ticker.
	sharedTestManager.Shutdown()
	ShutdownLtpCache()
	if code != 0 {
		os.Exit(code)
	}
	// Package-wide goroutine-leak guard. Ignore list covers only 3rd-party
	// SDK goroutines that have no user-facing Close hook.
	if err := goleak.Find(
		goleak.IgnoreTopFunction("testing.(*T).Parallel"),
		// HTTP/2 + HTTP/1.1 idle keep-alive pools (Stripe SDK path, probe clients).
		goleak.IgnoreAnyFunction("net/http.(*http2ClientConn).readLoop"),
		goleak.IgnoreAnyFunction("net/http.(*persistConn).readLoop"),
		goleak.IgnoreAnyFunction("net/http.(*persistConn).writeLoop"),
		// gokiteconnect WebSocket ticker — same rationale as kc/ticker/leak_sentinel_test.go.
		goleak.IgnoreAnyFunction("github.com/zerodha/gokiteconnect/v4/ticker.(*Ticker).ServeWithContext"),
		goleak.IgnoreAnyFunction("github.com/zerodha/gokiteconnect/v4/ticker.(*Ticker).start"),
		goleak.IgnoreAnyFunction("github.com/gorilla/websocket.(*Conn).NextReader"),
	); err != nil {
		println("goleak: errors on successful test run:")
		println(err.Error())
		os.Exit(1)
	}
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

	mgr, err := kc.NewWithOptions(context.Background(),
		kc.WithLogger(logger),
		kc.WithKiteCredentials("test_key", "test_secret"),
		kc.WithInstrumentsManager(instMgr),
	)
	if err != nil {
		panic("newTestManagerOnce: kc.New: " + err.Error())
	}

	mgr.SetRiskGuard(riskguard.NewGuard(logger))
	return mgr
}
