package app

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
)

// newShutdownTestManager creates a lightweight kc.Manager for shutdown tests.
func newShutdownTestManager(t *testing.T) *kc.Manager {
	t.Helper()
	instrMgr, err := instruments.New(instruments.Config{
		Logger:   testLogger(),
		TestData: map[uint32]*instruments.Instrument{},
	})
	require.NoError(t, err)
	mgr, err := kc.NewWithOptions(context.Background(),
		kc.WithLogger(testLogger()),
		kc.WithKiteCredentials("test_key", "test_secret"),
		kc.WithDevMode(true),
		kc.WithInstrumentsManager(instrMgr),
		kc.WithAlertDBPath(":memory:"),
	)
	require.NoError(t, err)
	return mgr
}

// ===========================================================================
// shutdownCh — closing the channel triggers graceful shutdown sequence
// ===========================================================================

func TestSetupGracefulShutdown_ViaShutdownCh(t *testing.T) {
	mgr := newShutdownTestManager(t)
	t.Cleanup(mgr.Shutdown)

	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	app := newTestApp(t)
	app.auditStore = audit.New(db)
	require.NoError(t, app.auditStore.InitTable())
	app.auditStore.StartWorker()
	app.rateLimiters = newRateLimiters()

	// Inject shutdownCh so we can trigger shutdown without OS signals
	app.shutdownCh = make(chan struct{})

	// Start a real HTTP server on a free port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	listener.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	srv := &http.Server{Addr: addr, Handler: mux}

	// Start the server in background
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			t.Logf("server error: %v", err)
		}
	}()

	// Wait for server readiness (dial-poll instead of fixed sleep — ~1-5ms
	// typical, 2s budget for slow CI runners).
	waitForServerReady(t, addr)

	// Wire graceful shutdown
	app.setupGracefulShutdown(srv, mgr)

	// Verify server is alive
	resp, err := http.Get("http://" + addr + "/healthz")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Trigger shutdown via the injected channel
	close(app.shutdownCh)

	// Wait for shutdown to complete (dial-poll for connection-refused).
	waitForServerShutdown(t, addr, 5*time.Second)
}

// ===========================================================================
// shutdownCh — verify nil optional components don't panic
// ===========================================================================

func TestSetupGracefulShutdown_ViaShutdownCh_NilComponents(t *testing.T) {
	mgr := newShutdownTestManager(t)
	t.Cleanup(mgr.Shutdown)

	app := newTestApp(t)
	// All optional components nil
	app.scheduler = nil
	app.auditStore = nil
	app.telegramBot = nil
	app.oauthHandler = nil
	app.rateLimiters = nil

	app.shutdownCh = make(chan struct{})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	listener.Close()

	srv := &http.Server{Addr: addr, Handler: http.NewServeMux()}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			t.Logf("server error: %v", err)
		}
	}()

	waitForServerReady(t, addr)
	app.setupGracefulShutdown(srv, mgr)

	// Close shutdownCh — should not panic with nil components
	close(app.shutdownCh)

	// Wait for shutdown — 3s budget covers the sum of component Stop()s on
	// slow CI runners while still an order of magnitude faster than the
	// 200ms fixed sleep this replaces when all components are nil.
	waitForServerShutdown(t, addr, 3*time.Second)
}
