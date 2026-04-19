package app

import (
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
	mgr, err := kc.New(kc.Config{
		APIKey:             "test_key",
		APISecret:          "test_secret",
		Logger:             testLogger(),
		DevMode:            true,
		InstrumentsManager: instrMgr,
		AlertDBPath:        ":memory:",
	})
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

	// Wait for server readiness
	time.Sleep(50 * time.Millisecond)

	// Wire graceful shutdown
	app.setupGracefulShutdown(srv, mgr)

	// Verify server is alive
	resp, err := http.Get("http://" + addr + "/healthz")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Trigger shutdown via the injected channel
	close(app.shutdownCh)

	// Wait for shutdown to complete
	deadline := time.After(5 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("shutdown did not complete within 5 seconds")
		default:
		}
		_, err := http.Get("http://" + addr + "/healthz")
		if err != nil {
			// Connection refused → server shut down
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
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

	time.Sleep(50 * time.Millisecond)
	app.setupGracefulShutdown(srv, mgr)

	// Close shutdownCh — should not panic with nil components
	close(app.shutdownCh)

	// Give shutdown goroutine time to complete
	time.Sleep(200 * time.Millisecond)
}
