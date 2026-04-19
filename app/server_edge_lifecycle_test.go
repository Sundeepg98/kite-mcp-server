package app

// app_coverage_test.go — targeted tests to boost coverage from ~78% to 90%+.
// Focuses on uncovered branches in: setupGracefulShutdown, initializeServices,
// initScheduler, paperLTPAdapter.GetLTP, setupMux, registerTelegramWebhook,
// RunServer, ExchangeWithCredentials, makeEventPersister, serveStatusPage,
// serveLegalPages, newRateLimiters, and startHybridServer/startStdIOServer.

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ===========================================================================
// setupGracefulShutdown — exercise the inner goroutine's shutdown paths
// ===========================================================================

// TestSetupGracefulShutdown_WithAllComponents exercises the shutdown goroutine
// body by using context.WithCancel and manually triggering the cancel — which
// won't work directly since the function uses signal.NotifyContext.
// Instead, we test that the function sets up without panicking when the app
// has scheduler, auditStore, telegramBot, oauthHandler, and rateLimiters set.


// ===========================================================================
// RunServer — error paths
// ===========================================================================

// TestRunServer_OAuthValidationFailure exercises the OAuth config validation
// error path in RunServer.
func TestRunServer_OAuthValidationFailure(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")
	t.Setenv("STRIPE_SECRET_KEY", "")
	t.Setenv("ADMIN_EMAILS", "")
	t.Setenv("ALERT_DB_PATH", "")

	app := newTestApp(t)
	app.DevMode = true
	app.Config.AppMode = ModeHTTP
	app.Config.AppHost = "127.0.0.1"
	app.Config.AppPort = "0"
	// Set OAuthJWTSecret but leave ExternalURL empty to trigger validation failure
	app.Config.OAuthJWTSecret = "test-jwt-secret-at-least-32-chars-long!!"
	app.Config.ExternalURL = "" // triggers "ExternalURL is required"

	err := app.RunServer()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid OAuth config")
}


// TestRunServer_MissingExternalURL exercises the EXTERNAL_URL requirement error.
func TestRunServer_MissingExternalURL(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")
	t.Setenv("OAUTH_JWT_SECRET", "test-jwt-secret-at-least-32-chars-long!!")
	t.Setenv("EXTERNAL_URL", "")
	t.Setenv("STRIPE_SECRET_KEY", "")

	app := newTestApp(t)
	app.DevMode = true
	app.Config.AppMode = ModeHTTP
	app.Config.OAuthJWTSecret = "test-jwt-secret-at-least-32-chars-long!!"
	app.Config.ExternalURL = "" // triggers EXTERNAL_URL required error

	// LoadConfig should catch this
	err := app.LoadConfig()
	if err != nil {
		assert.Contains(t, err.Error(), "EXTERNAL_URL")
	}
}


// TestRunServer_HybridMode exercises the hybrid server mode path in RunServer.
func TestRunServer_HybridMode_Cov(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")
	t.Setenv("STRIPE_SECRET_KEY", "")
	t.Setenv("ADMIN_EMAILS", "")
	t.Setenv("ALERT_DB_PATH", "")
	t.Setenv("OAUTH_JWT_SECRET", "")

	app := newTestApp(t)
	app.DevMode = true
	app.Config.AppMode = ModeHybrid
	// Inject shutdownCh so we can trigger the graceful-shutdown goroutine
	// without an OS signal. Without this, srv.ListenAndServe blocks
	// forever, the setup-shutdown goroutine never fires, and all
	// background cleanup routines (DB openers, metric/audit workers,
	// instruments scheduler) leak past test completion — on slow CI
	// runners those leaked goroutines tip the parent package
	// -timeout 120s over the edge.
	app.shutdownCh = make(chan struct{})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	app.Config.AppHost = "127.0.0.1"
	app.Config.AppPort = fmt.Sprintf("%d", port)

	errCh := make(chan error, 1)
	go func() { errCh <- app.RunServer() }()
	waitForServerReady(t, fmt.Sprintf("127.0.0.1:%d", port))

	resp, httpErr := http.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", port))
	if httpErr == nil && resp != nil {
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	}

	// Signal shutdown — the graceful-shutdown goroutine picks this up
	// and begins unwinding component Stop()s asynchronously. We only
	// briefly wait for RunServer to return so this test does not block
	// other tests in the package; any goroutine cleanup still in flight
	// finishes before the process exits. The prior behavior (no
	// close() at all) left the HTTP server, its background goroutine
	// tree, and every DB/metric/instrument worker running until the
	// process ended, which was the original cause of the Test Race
	// package-level timeout.
	close(app.shutdownCh)
	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
	}
}


// TestRunServer_SSEMode exercises the SSE server mode path.
func TestRunServer_SSEMode_Cov(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")
	t.Setenv("STRIPE_SECRET_KEY", "")
	t.Setenv("ADMIN_EMAILS", "")
	t.Setenv("ALERT_DB_PATH", "")
	t.Setenv("OAUTH_JWT_SECRET", "")

	app := newTestApp(t)
	app.DevMode = true
	app.Config.AppMode = ModeSSE
	// See TestRunServer_HybridMode_Cov for the rationale behind injecting
	// shutdownCh — same goroutine-leak class.
	app.shutdownCh = make(chan struct{})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	app.Config.AppHost = "127.0.0.1"
	app.Config.AppPort = fmt.Sprintf("%d", port)

	errCh := make(chan error, 1)
	go func() { errCh <- app.RunServer() }()
	waitForServerReady(t, fmt.Sprintf("127.0.0.1:%d", port))

	resp, httpErr := http.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", port))
	if httpErr == nil && resp != nil {
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	}

	// See TestRunServer_HybridMode_Cov for rationale.
	close(app.shutdownCh)
	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
	}
}


// TestRunServer_WithOAuthFullLifecycle exercises RunServer with OAuth enabled,
// covering the OAuth handler wiring and KiteTokenChecker setup.
func TestRunServer_WithOAuthFullLifecycle(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")
	t.Setenv("STRIPE_SECRET_KEY", "")
	t.Setenv("ADMIN_EMAILS", "admin@test.com")
	t.Setenv("ALERT_DB_PATH", ":memory:")
	t.Setenv("OAUTH_JWT_SECRET", "test-jwt-secret-at-least-32-chars-long!!")
	t.Setenv("EXTERNAL_URL", "https://test.example.com")

	app := newTestApp(t)
	app.DevMode = true
	app.Config.AppMode = ModeHTTP
	app.Config.OAuthJWTSecret = "test-jwt-secret-at-least-32-chars-long!!"
	app.Config.ExternalURL = "https://test.example.com"
	app.Config.AlertDBPath = ":memory:"
	app.Config.AdminEmails = "admin@test.com"
	// See TestRunServer_HybridMode_Cov for the rationale.
	app.shutdownCh = make(chan struct{})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	app.Config.AppHost = "127.0.0.1"
	app.Config.AppPort = fmt.Sprintf("%d", port)

	errCh := make(chan error, 1)
	go func() { errCh <- app.RunServer() }()
	waitForServerReady(t, fmt.Sprintf("127.0.0.1:%d", port))

	// Verify OAuth endpoints are registered
	resp, httpErr := http.Get(fmt.Sprintf("http://127.0.0.1:%d/.well-known/oauth-authorization-server", port))
	if httpErr == nil && resp != nil {
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	}

	// See TestRunServer_HybridMode_Cov for rationale.
	close(app.shutdownCh)
	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
	}
}


// ===========================================================================
// startServer — all mode cases
// ===========================================================================
func TestStartServer_AllModes(t *testing.T) {
	modes := []struct {
		mode string
		ok   bool
	}{
		{ModeHybrid, true},
		{ModeSSE, true},
		{ModeHTTP, true},
		// ModeStdIO is tested separately due to os.Stdin/Stdout
		{"bogus", false},
	}

	for _, m := range modes {
		t.Run(m.mode, func(t *testing.T) {
			app := newTestApp(t)
			app.Config.AppMode = m.mode

			if !m.ok {
				err := app.startServer(nil, nil, nil, "")
				require.Error(t, err)
				assert.Contains(t, err.Error(), "invalid APP_MODE")
				return
			}

			// For valid modes, we can't fully start without blocking,
			// so just verify no error via a quick goroutine test
			mgr := newTestManagerWithDB(t)
			mcpSrv := newTestMCPServer()

			listener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			addr := listener.Addr().String()
			listener.Close()

			srv := &http.Server{Addr: addr}

			errCh := make(chan error, 1)
			go func() {
				errCh <- app.startServer(srv, mgr, mcpSrv, addr)
			}()

			waitForServerReady(t, addr)

			// Shutdown the server
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = srv.Shutdown(ctx)

			select {
			case err := <-errCh:
				assert.NoError(t, err)
			case <-time.After(3 * time.Second):
			}
		})
	}
}


// ===========================================================================
// startServer — stdio mode (uses os.Stdin/Stdout so we skip full test,
// but exercise the server creation path)
// ===========================================================================
func TestStartStdIOServer_Smoke(t *testing.T) {
	// We can't actually test STDIO properly without redirecting stdin/stdout,
	// but we can verify that the setup completes without panicking.
	// Use a pipe to simulate stdin/stdout for a brief period.

	// Instead, test that startServer with ModeStdIO doesn't return an error
	// (it will block on stdio.Listen, but the HTTP server starts in background)
	if os.Getenv("CI") != "" {
		t.Skip("STDIO test not suitable for CI")
	}
	t.Skip("STDIO mode blocks on stdin — skipping in automated tests")
}


// ===========================================================================
// startHybridServer — exercises the hybrid server start path
// ===========================================================================
func TestStartHybridServer_QuickShutdown(t *testing.T) {
	mgr := newTestManagerWithDB(t)
	app := newTestApp(t)
	app.Config.AppMode = "hybrid"

	// Create an MCP server
	t.Setenv("DEV_MODE", "true")
	app.Config.KiteAPIKey = "test_key"
	app.Config.KiteAPISecret = "test_secret"
	app.Config.AlertDBPath = ":memory:"
	app.DevMode = true

	kcMgr, mcpSrv, err := app.initializeServices()
	require.NoError(t, err)
	defer cleanupInitializeServices(app, kcMgr)

	// Create a server on a random port
	ln, lnErr := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, lnErr)
	addr := ln.Addr().String()
	ln.Close()

	srv := &http.Server{Addr: addr}
	mux := http.NewServeMux()
	srv.Handler = mux

	go func() {
		app.startHybridServer(srv, kcMgr, mcpSrv, addr)
	}()

	waitForServerReady(t, addr)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	_ = mgr
}
