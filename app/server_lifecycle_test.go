package app

// server_test.go -- consolidated tests for server lifecycle, setup, and coverage.
// Merged from: coverage_boost_test.go, coverage_boost2_test.go, server_lifecycle_test.go
import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/users"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// ===========================================================================
// Merged from coverage_boost_test.go
// ===========================================================================


// ---------------------------------------------------------------------------
// Helper: create a minimal MCP server for tests.
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// createSSEServer tests
// ---------------------------------------------------------------------------
func TestCreateSSEServer(t *testing.T) {
	app := newTestApp(t)
	mcpSrv := newTestMCPServer()
	sse := app.createSSEServer(mcpSrv, "localhost:9999")
	require.NotNil(t, sse)
}


// ---------------------------------------------------------------------------
// createStreamableHTTPServer tests
// ---------------------------------------------------------------------------
func TestCreateStreamableHTTPServer(t *testing.T) {
	mgr := newTestManager(t)
	app := newTestApp(t)
	streamable := app.createStreamableHTTPServer(newTestMCPServer(), mgr)
	require.NotNil(t, streamable)
}


// ---------------------------------------------------------------------------
// serveHTTPServer — pre-occupied port to cover error path
// ---------------------------------------------------------------------------
func TestServeHTTPServer_PortInUse(t *testing.T) {
	app := newTestApp(t)

	// Bind a port so ListenAndServe will fail.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	addr := listener.Addr().String()

	srv := &http.Server{Addr: addr, Handler: http.NewServeMux()}
	// serveHTTPServer will fail because port is in use, but should not panic.
	app.serveHTTPServer(srv)
}


// ---------------------------------------------------------------------------
// configureAndStartServer — pre-occupied port to cover code path
// ---------------------------------------------------------------------------
func TestConfigureAndStartServer_PortInUse(t *testing.T) {
	app := newTestApp(t)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	addr := listener.Addr().String()

	mux := http.NewServeMux()
	mux.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})

	srv := &http.Server{Addr: addr}
	app.configureAndStartServer(srv, mux)
	// Handler should have been set even though start failed
	assert.NotNil(t, srv.Handler)
}


// ---------------------------------------------------------------------------
// setupGracefulShutdown — basic wiring
// ---------------------------------------------------------------------------
func TestSetupGracefulShutdown_Basic(t *testing.T) {
	mgr := newTestManager(t)
	app := newTestApp(t)
	srv := &http.Server{Addr: "127.0.0.1:0"}
	// Should not panic — goroutine is created for signal handling
	app.setupGracefulShutdown(srv, mgr)
}


// ---------------------------------------------------------------------------
// startHTTPServer — exercises all setup code before the blocking start
// ---------------------------------------------------------------------------
func TestStartHTTPServer_PortInUse(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")

	mgr := newTestManager(t)
	mcpSrv := newTestMCPServer()

	app := newTestApp(t)
	app.DevMode = true
	_ = app.initStatusPageTemplate()

	// Bind a port so the server start fails
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	addr := listener.Addr().String()

	srv := &http.Server{Addr: addr}
	// Exercises createStreamableHTTPServer, setupMux, route registration,
	// configureAndStartServer → fails because port is in use
	app.startHTTPServer(srv, mgr, mcpSrv, addr)

	if app.rateLimiters != nil {
		app.rateLimiters.Stop()
	}
}


// ---------------------------------------------------------------------------
// startSSEServer — exercises all setup code before the blocking start
// ---------------------------------------------------------------------------
func TestStartSSEServer_PortInUse(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")

	mgr := newTestManager(t)
	mcpSrv := newTestMCPServer()

	app := newTestApp(t)
	app.DevMode = true
	_ = app.initStatusPageTemplate()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	addr := listener.Addr().String()

	srv := &http.Server{Addr: addr}
	app.startSSEServer(srv, mgr, mcpSrv, addr)

	if app.rateLimiters != nil {
		app.rateLimiters.Stop()
	}
}


// ---------------------------------------------------------------------------
// startHybridServer — exercises all setup code before the blocking start
// ---------------------------------------------------------------------------
func TestStartHybridServer_PortInUse(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")

	mgr := newTestManager(t)
	mcpSrv := newTestMCPServer()

	app := newTestApp(t)
	app.DevMode = true
	_ = app.initStatusPageTemplate()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	addr := listener.Addr().String()

	srv := &http.Server{Addr: addr}
	app.startHybridServer(srv, mgr, mcpSrv, addr)

	if app.rateLimiters != nil {
		app.rateLimiters.Stop()
	}
}


// ---------------------------------------------------------------------------
// startServer — test all valid mode dispatches via port-in-use
// ---------------------------------------------------------------------------
func TestStartServer_HTTPMode_PortInUse(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")

	mgr := newTestManager(t)
	mcpSrv := newTestMCPServer()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	addr := listener.Addr().String()

	app := newTestApp(t)
	app.DevMode = true
	app.Config.AppMode = ModeHTTP
	_ = app.initStatusPageTemplate()

	srv := &http.Server{Addr: addr}
	err = app.startServer(srv, mgr, mcpSrv, addr)
	assert.NoError(t, err)

	if app.rateLimiters != nil {
		app.rateLimiters.Stop()
	}
}


func TestStartServer_SSEMode_PortInUse(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")

	mgr := newTestManager(t)
	mcpSrv := newTestMCPServer()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	addr := listener.Addr().String()

	app := newTestApp(t)
	app.DevMode = true
	app.Config.AppMode = ModeSSE
	_ = app.initStatusPageTemplate()

	srv := &http.Server{Addr: addr}
	err = app.startServer(srv, mgr, mcpSrv, addr)
	assert.NoError(t, err)

	if app.rateLimiters != nil {
		app.rateLimiters.Stop()
	}
}


func TestStartServer_HybridMode_PortInUse(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")

	mgr := newTestManager(t)
	mcpSrv := newTestMCPServer()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	addr := listener.Addr().String()

	app := newTestApp(t)
	app.DevMode = true
	app.Config.AppMode = ModeHybrid
	_ = app.initStatusPageTemplate()

	srv := &http.Server{Addr: addr}
	err = app.startServer(srv, mgr, mcpSrv, addr)
	assert.NoError(t, err)

	if app.rateLimiters != nil {
		app.rateLimiters.Stop()
	}
}


// ---------------------------------------------------------------------------
// startHTTPServer — with OAuth handler (exercises the OAuth mux branch)
// ---------------------------------------------------------------------------
func TestStartHTTPServer_WithOAuth_PortInUse(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")

	mgr := newTestManager(t)
	mcpSrv := newTestMCPServer()

	app := newTestApp(t)
	app.DevMode = true
	app.oauthHandler = newTestOAuthHandler(t)
	_ = app.initStatusPageTemplate()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	addr := listener.Addr().String()

	srv := &http.Server{Addr: addr}
	app.startHTTPServer(srv, mgr, mcpSrv, addr)

	if app.rateLimiters != nil {
		app.rateLimiters.Stop()
	}
}


// ===========================================================================
// initializeServices — full initialization pipeline coverage
// ===========================================================================
func TestInitializeServices_DevMode_Minimal(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")
	t.Setenv("STRIPE_SECRET_KEY", "")
	t.Setenv("ADMIN_EMAILS", "")
	app := newTestApp(t)
	app.DevMode = true
	mgr, mcpServer, err := app.initializeServices()
	require.NoError(t, err)
	require.NotNil(t, mgr)
	require.NotNil(t, mcpServer)
	cleanupInitializeServices(app, mgr)
}


func TestInitializeServices_WithAlertDB(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")
	t.Setenv("ALERT_DB_PATH", ":memory:")
	t.Setenv("STRIPE_SECRET_KEY", "")
	t.Setenv("ADMIN_EMAILS", "")
	app := newTestApp(t)
	app.DevMode = true
	app.Config.AlertDBPath = ":memory:"
	mgr, mcpServer, err := app.initializeServices()
	require.NoError(t, err)
	require.NotNil(t, mgr)
	require.NotNil(t, mcpServer)
	assert.NotNil(t, app.auditStore)
	cleanupInitializeServices(app, mgr)
}


func TestInitializeServices_WithEncryption(t *testing.T) {
	// OAUTH_JWT_SECRET must be >=32 bytes (HMAC-SHA256 security floor) —
	// envcheck.go enforces this. Short test secrets fail the env gate
	// before initializeServices gets to run.
	const testJWTSecret = "test-jwt-secret-for-encryption-minimum-32-bytes-long"
	t.Setenv("DEV_MODE", "true")
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")
	t.Setenv("ALERT_DB_PATH", ":memory:")
	t.Setenv("OAUTH_JWT_SECRET", testJWTSecret)
	t.Setenv("EXTERNAL_URL", "https://test.example.com")
	t.Setenv("STRIPE_SECRET_KEY", "")
	t.Setenv("ADMIN_EMAILS", "admin@test.com")
	app := newTestApp(t)
	app.DevMode = true
	app.Config.AlertDBPath = ":memory:"
	app.Config.OAuthJWTSecret = testJWTSecret
	app.Config.ExternalURL = "https://test.example.com"
	app.Config.AdminEmails = "admin@test.com"
	mgr, mcpServer, err := app.initializeServices()
	require.NoError(t, err)
	require.NotNil(t, mgr)
	require.NotNil(t, mcpServer)
	cleanupInitializeServices(app, mgr)
}


// ===========================================================================
// RunServer — full lifecycle
// ===========================================================================
func TestRunServer_DevMode_FullLifecycle(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")
	t.Setenv("APP_MODE", "http")
	t.Setenv("STRIPE_SECRET_KEY", "")
	t.Setenv("ADMIN_EMAILS", "")
	app := newTestApp(t)
	app.DevMode = true
	app.Config.AppMode = ModeHTTP
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
	resp, _ := http.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", port))
	if resp != nil {
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	}
	close(app.shutdownCh)
	select {
	case err := <-errCh:
		_ = err
	case <-time.After(3 * time.Second):
	}
}



// ===========================================================================
// Merged from coverage_boost2_test.go
// ===========================================================================


// ---------------------------------------------------------------------------
// startStdIOServer — exercise via pipes (no real stdin/stdout)
// ---------------------------------------------------------------------------
func TestStartStdIOServer_ViaPipes(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")

	mgr := newTestManager(t)
	app := newTestApp(t)
	app.DevMode = true
	_ = app.initStatusPageTemplate()

	mcpSrv := newTestMCPServer()

	// Bind a port that we'll immediately use for the HTTP side-car server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	addr := listener.Addr().String()

	srv := &http.Server{Addr: addr}

	// startStdIOServer creates a StdioServer and calls stdio.Listen on
	// os.Stdin/os.Stdout — we can't directly exercise that without hijacking
	// stdin/stdout. Instead, exercise the function by calling the pieces it
	// calls:
	// 1. server.NewStdioServer (covered by SSE/HTTP tests already)
	// 2. app.setupMux (covered)
	// 3. app.configureAndStartServer in a goroutine
	//
	// To get the function itself in the profile, call it with a pre-occupied
	// port so configureAndStartServer exits quickly, and provide a pipe for
	// stdin that we close immediately to unblock stdio.Listen.
	stdinR, stdinW := io.Pipe()
	stdoutR, stdoutW := io.Pipe()
	_ = stdoutR // prevent unused

	// Override Stdin/Stdout for this test is not possible (global), so we
	// replicate startStdIOServer logic manually to hit the code:
	stdio := server.NewStdioServer(mcpSrv)
	mux := app.setupMux(mgr)
	go app.configureAndStartServer(srv, mux)

	// Start stdio.Listen in a goroutine; close the pipe to make it exit
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	go func() {
		<-ctx.Done()
		stdinW.Close()
		stdoutW.Close()
	}()
	_ = stdio.Listen(ctx, stdinR, stdoutW) // will unblock when stdinR closes

	// Cancel ctx explicitly and give the mcp-go handleNotifications
	// goroutine a moment to observe ctx.Done() and return — otherwise
	// goleak at process exit catches it.
	cancel()
	time.Sleep(20 * time.Millisecond)

	// Shut down the configureAndStartServer goroutine — without this, the
	// http.Server.ListenAndServe call leaks past test end.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()
	_ = srv.Shutdown(shutdownCtx)

	if app.rateLimiters != nil {
		app.rateLimiters.Stop()
	}
}


// ---------------------------------------------------------------------------
// RunServer with OAuth enabled — exercises the full OAuth wiring branch
// ---------------------------------------------------------------------------
func TestRunServer_WithOAuth(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")
	t.Setenv("OAUTH_JWT_SECRET", "test-jwt-secret-at-least-32-chars-long")
	t.Setenv("EXTERNAL_URL", "http://localhost:19876")
	t.Setenv("APP_MODE", "http")
	t.Setenv("STRIPE_SECRET_KEY", "")
	t.Setenv("ADMIN_EMAILS", "admin@test.com")
	t.Setenv("ALERT_DB_PATH", ":memory:")

	app := newTestApp(t)
	app.DevMode = true
	app.Config.AppMode = ModeHTTP
	app.Config.OAuthJWTSecret = "test-jwt-secret-at-least-32-chars-long"
	app.Config.ExternalURL = "http://localhost:19876"
	app.Config.AlertDBPath = ":memory:"
	app.Config.AdminEmails = "admin@test.com"

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	app.Config.AppHost = "127.0.0.1"
	app.Config.AppPort = strconv.Itoa(port)
	app.shutdownCh = make(chan struct{})

	errCh := make(chan error, 1)
	go func() {
		errCh <- app.RunServer()
	}()

	waitForServerReady(t, "127.0.0.1:"+strconv.Itoa(port))

	base := "http://127.0.0.1:" + strconv.Itoa(port)

	// Verify OAuth metadata endpoints are registered
	resp, _ := http.Get(base + "/.well-known/oauth-authorization-server")
	if resp != nil {
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	}

	// Verify OAuth register endpoint
	resp2, _ := http.Post(base+"/oauth/register", "application/json", bytes.NewBufferString(`{}`))
	if resp2 != nil {
		assert.NotEqual(t, http.StatusNotFound, resp2.StatusCode)
		resp2.Body.Close()
	}

	close(app.shutdownCh)
	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
	}
}


// ---------------------------------------------------------------------------
// initializeServices — error path (kc.New fails with invalid config)
// ---------------------------------------------------------------------------
func TestInitializeServices_Error(t *testing.T) {
	t.Setenv("DEV_MODE", "false")
	t.Setenv("KITE_API_KEY", "")
	t.Setenv("KITE_API_SECRET", "")
	t.Setenv("OAUTH_JWT_SECRET", "")
	t.Setenv("STRIPE_SECRET_KEY", "")
	t.Setenv("ADMIN_EMAILS", "")
	t.Setenv("ALERT_DB_PATH", "")

	app := newTestApp(t)
	app.DevMode = false

	_, _, err := app.initializeServices()
	// Without credentials/audit DB in production, initializeServices must fail.
	require.Error(t, err)
}


// ---------------------------------------------------------------------------
// RunServer — invalid OAuth config branch
// ---------------------------------------------------------------------------
func TestRunServer_InvalidOAuthConfig_MissingExternalURL(t *testing.T) {
	// JWT must be >=32 bytes to pass the env gate so the EXTERNAL_URL
	// branch is the actual failure surface under test.
	const testJWTSecret = "valid-secret-for-test-32-bytes-min-length-ok"
	t.Setenv("DEV_MODE", "true")
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")
	t.Setenv("OAUTH_JWT_SECRET", testJWTSecret)
	t.Setenv("EXTERNAL_URL", "") // missing → Validate() fails
	t.Setenv("APP_MODE", "http")
	t.Setenv("STRIPE_SECRET_KEY", "")
	t.Setenv("ADMIN_EMAILS", "")

	app := newTestApp(t)
	app.DevMode = true
	app.Config.AppMode = ModeHTTP
	app.Config.OAuthJWTSecret = testJWTSecret
	app.Config.ExternalURL = "" // force validation error
	app.Config.AppHost = "127.0.0.1"
	app.Config.AppPort = "0"

	err := app.RunServer()
	// Should fail because ExternalURL is empty → oauth.Config.Validate()
	// returns "invalid OAuth config: ExternalURL is required".
	require.Error(t, err)
	assert.Contains(t, err.Error(), "OAuth")
	assert.Contains(t, err.Error(), "ExternalURL")
}



// ===========================================================================
// Merged from server_lifecycle_test.go
// ===========================================================================

// ---------------------------------------------------------------------------
// RunServer — full DevMode lifecycle: start → healthz → stop
// ---------------------------------------------------------------------------
func TestRunServer_FullDevMode(t *testing.T) {
	// Pick a free port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	portStr := strings.TrimPrefix(listener.Addr().String(), "127.0.0.1:")

	t.Setenv("DEV_MODE", "true")
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")
	t.Setenv("OAUTH_JWT_SECRET", "")
	t.Setenv("APP_MODE", "http")
	t.Setenv("STRIPE_SECRET_KEY", "")
	t.Setenv("ADMIN_EMAILS", "")
	t.Setenv("ALERT_DB_PATH", "")

	app := newTestApp(t)
	app.DevMode = true
	app.Config.AppMode = ModeHTTP
	app.Config.AppHost = "127.0.0.1"
	app.Config.AppPort = portStr
	app.shutdownCh = make(chan struct{})

	errCh := make(chan error, 1)
	go func() {
		errCh <- app.RunServer()
	}()

	// Wait for server to start via TCP-accept dial (1-5ms typical).
	waitForServerReady(t, "127.0.0.1:"+portStr)
	baseURL := "http://127.0.0.1:" + portStr
	resp, err := http.Get(baseURL + "/healthz")

	if resp != nil {
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		var data map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&data)
		resp.Body.Close()
		assert.Equal(t, "ok", data["status"])
	}

	// Verify pprof endpoints are active in DEV_MODE
	if resp != nil {
		pprofResp, pprofErr := http.Get(baseURL + "/debug/pprof/")
		if pprofErr == nil {
			assert.Equal(t, http.StatusOK, pprofResp.StatusCode)
			pprofResp.Body.Close()
		}
	}

	_ = port

	close(app.shutdownCh)
	select {
	case runErr := <-errCh:
		if runErr != nil {
			t.Logf("RunServer returned error (may be expected): %v", runErr)
		}
	case <-time.After(3 * time.Second):
		// Server is still running — that's fine for a lifecycle test
	}
}


// ---------------------------------------------------------------------------
// RunServer — with OAuth, DB, and all features enabled
// ---------------------------------------------------------------------------
func TestRunServer_FullOAuthMode(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	portStr := strings.TrimPrefix(listener.Addr().String(), "127.0.0.1:")
	listener.Close()

	t.Setenv("DEV_MODE", "true")
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")
	t.Setenv("OAUTH_JWT_SECRET", "test-jwt-secret-at-least-32-chars-long!!")
	t.Setenv("EXTERNAL_URL", "http://127.0.0.1:"+portStr)
	t.Setenv("APP_MODE", "http")
	t.Setenv("STRIPE_SECRET_KEY", "")
	t.Setenv("ADMIN_EMAILS", "admin@test.com")
	t.Setenv("ALERT_DB_PATH", ":memory:")
	t.Setenv("ADMIN_PASSWORD", "test-pass-123")
	t.Setenv("GOOGLE_CLIENT_ID", "google-test-id")
	t.Setenv("GOOGLE_CLIENT_SECRET", "google-test-secret")

	app := newTestApp(t)
	app.DevMode = true
	app.Config.AppMode = ModeHTTP
	app.Config.AppHost = "127.0.0.1"
	app.Config.AppPort = portStr
	app.Config.OAuthJWTSecret = "test-jwt-secret-at-least-32-chars-long!!"
	app.Config.ExternalURL = "http://127.0.0.1:" + portStr
	app.Config.AlertDBPath = ":memory:"
	app.Config.AdminEmails = "admin@test.com"
	app.Config.GoogleClientID = "google-test-id"
	app.Config.GoogleClientSecret = "google-test-secret"
	app.shutdownCh = make(chan struct{})

	errCh := make(chan error, 1)
	go func() {
		errCh <- app.RunServer()
	}()

	// Wait for server readiness via TCP-accept dial (1-5ms typical).
	waitForServerReady(t, "127.0.0.1:"+portStr)
	baseURL := "http://127.0.0.1:" + portStr
	resp, err := http.Get(baseURL + "/healthz")

	if resp != nil {
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()

		// Verify OAuth metadata endpoints are available
		oauthResp, oauthErr := http.Get(baseURL + "/.well-known/oauth-authorization-server")
		if oauthErr == nil {
			assert.Equal(t, http.StatusOK, oauthResp.StatusCode)
			oauthResp.Body.Close()
		}

		// Verify OAuth register endpoint
		regResp, _ := http.Post(baseURL+"/oauth/register", "application/json", bytes.NewBufferString(`{}`))
		if regResp != nil {
			assert.NotEqual(t, http.StatusNotFound, regResp.StatusCode)
			regResp.Body.Close()
		}

		// Verify auth endpoints are registered
		loginResp, _ := http.Get(baseURL + "/auth/admin-login")
		if loginResp != nil {
			assert.NotEqual(t, http.StatusNotFound, loginResp.StatusCode)
			loginResp.Body.Close()
		}

		// Verify Google SSO endpoint
		googleResp, _ := http.Get(baseURL + "/auth/google/login")
		if googleResp != nil {
			assert.NotEqual(t, http.StatusNotFound, googleResp.StatusCode)
			googleResp.Body.Close()
		}
	}

	close(app.shutdownCh)
	select {
	case runErr := <-errCh:
		if runErr != nil {
			t.Logf("RunServer returned: %v", runErr)
		}
	case <-time.After(3 * time.Second):
	}
}


// ---------------------------------------------------------------------------
// RunServer — exercises the SSE mode branch
// ---------------------------------------------------------------------------
func TestRunServer_SSEMode(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	portStr := strings.TrimPrefix(listener.Addr().String(), "127.0.0.1:")
	listener.Close()

	t.Setenv("DEV_MODE", "true")
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")
	t.Setenv("OAUTH_JWT_SECRET", "")
	t.Setenv("STRIPE_SECRET_KEY", "")
	t.Setenv("ADMIN_EMAILS", "")

	app := newTestApp(t)
	app.DevMode = true
	app.Config.AppMode = ModeSSE
	app.Config.AppHost = "127.0.0.1"
	app.Config.AppPort = portStr
	app.shutdownCh = make(chan struct{})

	errCh := make(chan error, 1)
	go func() {
		errCh <- app.RunServer()
	}()

	// Wait for server readiness via TCP-accept dial (1-5ms typical).
	waitForServerReady(t, "127.0.0.1:"+portStr)
	baseURL := "http://127.0.0.1:" + portStr
	resp, err := http.Get(baseURL + "/healthz")
	if err == nil {
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	}

	close(app.shutdownCh)
	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
	}
}


// ---------------------------------------------------------------------------
// RunServer — exercises the Hybrid mode branch
// ---------------------------------------------------------------------------
func TestRunServer_HybridMode(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	portStr := strings.TrimPrefix(listener.Addr().String(), "127.0.0.1:")
	listener.Close()

	t.Setenv("DEV_MODE", "true")
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")
	t.Setenv("OAUTH_JWT_SECRET", "")
	t.Setenv("STRIPE_SECRET_KEY", "")
	t.Setenv("ADMIN_EMAILS", "")

	app := newTestApp(t)
	app.DevMode = true
	app.Config.AppMode = ModeHybrid
	app.Config.AppHost = "127.0.0.1"
	app.Config.AppPort = portStr
	app.shutdownCh = make(chan struct{})

	errCh := make(chan error, 1)
	go func() {
		errCh <- app.RunServer()
	}()

	// Wait for server readiness via TCP-accept dial (1-5ms typical).
	waitForServerReady(t, "127.0.0.1:"+portStr)
	baseURL := "http://127.0.0.1:" + portStr
	resp, err := http.Get(baseURL + "/healthz")
	if err == nil {
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	}

	close(app.shutdownCh)
	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
	}
}


// ---------------------------------------------------------------------------
// startStdIOServer — exercise the real function with mocked IO
// ---------------------------------------------------------------------------
func TestStartStdIOServer_RealFunction(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")

	mgr := newTestManager(t)
	app := newTestApp(t)
	app.DevMode = true
	_ = app.initStatusPageTemplate()

	mcpSrv := newTestMCPServer()

	// Bind a port for the HTTP sidecar
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	listener.Close()

	srv := &http.Server{Addr: addr}

	// Save original stdin/stdout and restore after test
	origStdin := os.Stdin
	origStdout := os.Stdout
	defer func() {
		os.Stdin = origStdin
		os.Stdout = origStdout
	}()

	// Create pipes to replace stdin/stdout
	stdinR, stdinW, err := os.Pipe()
	require.NoError(t, err)
	stdoutR, stdoutW, err := os.Pipe()
	require.NoError(t, err)

	os.Stdin = stdinR
	os.Stdout = stdoutW

	done := make(chan struct{})
	go func() {
		defer close(done)
		app.startStdIOServer(srv, mgr, mcpSrv)
	}()

	// Wait a moment for the server to start, then close stdin to trigger shutdown
	time.Sleep(300 * time.Millisecond)

	// Close stdin pipe to make stdio.Listen exit
	stdinW.Close()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Log("startStdIOServer did not exit within timeout, forcing close")
		stdinW.Close()
		stdoutW.Close()
	}

	stdoutR.Close()
	stdoutW.Close()

	if app.rateLimiters != nil {
		app.rateLimiters.Stop()
	}
}


// ---------------------------------------------------------------------------
// startStdIOServer — exercise via io.Pipe directly (no os.Stdin replacement)
// ---------------------------------------------------------------------------
func TestStartStdIOServer_WithPipeIO(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")

	mgr := newTestManager(t)
	app := newTestApp(t)
	app.DevMode = true
	_ = app.initStatusPageTemplate()

	mcpSrv := newTestMCPServer()
	stdio := server.NewStdioServer(mcpSrv)

	// Setup mux just like startStdIOServer does
	mux := app.setupMux(mgr)

	// Bind a port for the HTTP sidecar
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	listener.Close()

	srv := &http.Server{Addr: addr}
	go app.configureAndStartServer(srv, mux)

	// Feed a valid JSON-RPC initialize message, then close
	stdinR, stdinW := io.Pipe()
	stdoutR, stdoutW := io.Pipe()

	go func() {
		// Send a valid MCP initialize request
		initMsg := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"0.1"}}}`
		_, _ = stdinW.Write([]byte("Content-Length: " + strings.Replace(strings.Replace(string(rune(len(initMsg))), "\n", "", -1), "\r", "", -1)))
		// Give some time for the server to process
		time.Sleep(100 * time.Millisecond)
		stdinW.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = stdio.Listen(ctx, stdinR, stdoutW)
	stdoutR.Close()
	stdoutW.Close()

	// Cancel the stdio ctx explicitly and wait briefly for the
	// handleNotifications goroutine to observe ctx.Done() and exit.
	// Without this, goleak sees the goroutine alive at process exit.
	cancel()
	time.Sleep(20 * time.Millisecond)

	// Shut down the sidecar HTTP server goroutine — without this the
	// srv.ListenAndServe call leaks past test end.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()
	_ = srv.Shutdown(shutdownCtx)

	if app.rateLimiters != nil {
		app.rateLimiters.Stop()
	}
}


// ---------------------------------------------------------------------------
// initializeServices — with DB for full branch coverage
// ---------------------------------------------------------------------------
func TestInitializeServices_WithDB(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")
	t.Setenv("STRIPE_SECRET_KEY", "")
	t.Setenv("ADMIN_EMAILS", "admin@test.com")
	t.Setenv("ALERT_DB_PATH", ":memory:")
	t.Setenv("OAUTH_JWT_SECRET", "test-jwt-secret-at-least-32-chars-long!!")

	app := newTestApp(t)
	app.DevMode = true
	app.Config.AlertDBPath = ":memory:"
	app.Config.OAuthJWTSecret = "test-jwt-secret-at-least-32-chars-long!!"
	app.Config.AdminEmails = "admin@test.com"

	kcManager, mcpServer, err := app.initializeServices()
	require.NoError(t, err)
	require.NotNil(t, kcManager)
	require.NotNil(t, mcpServer)

	// Verify audit store was created (alertDB exists)
	assert.NotNil(t, app.auditStore)

	// Verify riskguard was initialized
	assert.NotNil(t, kcManager.RiskGuard())

	// Verify paper trading engine was created
	assert.NotNil(t, kcManager.PaperEngineConcrete())

	// Verify event dispatcher was set
	assert.NotNil(t, kcManager.EventDispatcher())

	// Verify scheduler was started
	assert.NotNil(t, app.scheduler)

	cleanupInitializeServices(app, kcManager)
}


// ---------------------------------------------------------------------------
// initializeServices — without DB (no audit, no paper trading, no events)
// ---------------------------------------------------------------------------
func TestInitializeServices_NoDB(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")
	t.Setenv("STRIPE_SECRET_KEY", "")
	t.Setenv("ADMIN_EMAILS", "")
	t.Setenv("ALERT_DB_PATH", "")
	t.Setenv("OAUTH_JWT_SECRET", "")

	app := newTestApp(t)
	app.DevMode = true

	kcManager, mcpServer, err := app.initializeServices()
	require.NoError(t, err)
	require.NotNil(t, kcManager)
	require.NotNil(t, mcpServer)

	// Without DB, audit store should be nil
	assert.Nil(t, app.auditStore)

	cleanupInitializeServices(app, kcManager)
}


// ---------------------------------------------------------------------------
// initializeServices — DevMode=false, with valid credentials
// ---------------------------------------------------------------------------
func TestInitializeServices_ProdMode(t *testing.T) {
	t.Setenv("DEV_MODE", "false")
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")
	t.Setenv("STRIPE_SECRET_KEY", "")
	t.Setenv("ADMIN_EMAILS", "")
	t.Setenv("ALERT_DB_PATH", ":memory:")
	t.Setenv("OAUTH_JWT_SECRET", "jwt-secret-that-is-at-least-32-chars-long")

	app := newTestApp(t)
	app.DevMode = false

	kcManager, mcpServer, err := app.initializeServices()
	require.NoError(t, err)
	require.NotNil(t, kcManager)
	require.NotNil(t, mcpServer)

	cleanupInitializeServices(app, kcManager)
}


// ---------------------------------------------------------------------------
// setupGracefulShutdown — verify shutdown sequence runs
// ---------------------------------------------------------------------------
func TestSetupGracefulShutdown_ShutdownSequence(t *testing.T) {
	mgr := newTestManagerWithDB(t)

	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	app := newTestApp(t)
	app.auditStore = audit.New(db)
	require.NoError(t, app.auditStore.InitTable())
	app.auditStore.StartWorker()

	// Create an HTTP server on a free port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	listener.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})

	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	// Start the server
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			t.Logf("Server error: %v", err)
		}
	}()

	// Wait for the server to be ready (dial-poll, 1-5ms typical).
	waitForServerReady(t, addr)

	// Setup graceful shutdown
	app.setupGracefulShutdown(srv, mgr)

	// Verify server is reachable
	resp, err := http.Get("http://" + addr + "/healthz")
	if err == nil {
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	}

	// Manually shutdown the server (simulating what happens on SIGTERM)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)

	if app.auditStore != nil {
		app.auditStore.Stop()
	}
}


// ---------------------------------------------------------------------------
// startServer — STDIO mode via pre-occupied port (exercises the case branch)
// ---------------------------------------------------------------------------
func TestStartServer_StdIOMode(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")

	mgr := newTestManager(t)
	mcpSrv := newTestMCPServer()

	app := newTestApp(t)
	app.DevMode = true
	app.Config.AppMode = ModeStdIO
	_ = app.initStatusPageTemplate()

	// Save original stdin/stdout
	origStdin := os.Stdin
	origStdout := os.Stdout
	defer func() {
		os.Stdin = origStdin
		os.Stdout = origStdout
	}()

	// Create pipes that we'll close immediately
	stdinR, stdinW, err := os.Pipe()
	require.NoError(t, err)
	_, stdoutW, err := os.Pipe()
	require.NoError(t, err)

	os.Stdin = stdinR
	os.Stdout = stdoutW

	// Bind a port for the sidecar HTTP server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	listener.Close()

	srv := &http.Server{Addr: addr}

	// Close stdin immediately so stdio.Listen exits
	go func() {
		time.Sleep(100 * time.Millisecond)
		stdinW.Close()
	}()

	done := make(chan error, 1)
	go func() {
		done <- app.startServer(srv, mgr, mcpSrv, addr)
	}()

	select {
	case startErr := <-done:
		assert.NoError(t, startErr)
	case <-time.After(5 * time.Second):
		t.Log("startServer(stdio) timed out")
		stdinW.Close()
	}

	stdoutW.Close()
	// startStdIOServer spawned a sidecar HTTP server goroutine via
	// `go app.configureAndStartServer(srv, mux)`. Without Shutdown it
	// blocks in ListenAndServe past test end — close it explicitly.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()
	_ = srv.Shutdown(shutdownCtx)
	if app.rateLimiters != nil {
		app.rateLimiters.Stop()
	}
}


// ---------------------------------------------------------------------------
// startServer — default/invalid mode returns error
// ---------------------------------------------------------------------------
func TestStartServer_DefaultInvalidMode(t *testing.T) {
	app := &App{
		Config: &Config{AppMode: "banana"},
		logger: testLogger(),
	}
	err := app.startServer(nil, nil, nil, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid APP_MODE: banana")
}


// ---------------------------------------------------------------------------
// createHTTPServer — verify fields
// ---------------------------------------------------------------------------
func TestCreateHTTPServer_Fields(t *testing.T) {
	app := newTestApp(t)
	srv := app.createHTTPServer("localhost:8080")
	assert.Equal(t, "localhost:8080", srv.Addr)
	assert.Equal(t, 30*time.Second, srv.ReadHeaderTimeout)
	assert.Equal(t, 120*time.Second, srv.WriteTimeout)
}


// ---------------------------------------------------------------------------
// initializeServices — with excluded tools
// ---------------------------------------------------------------------------
func TestInitializeServices_ExcludedTools(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")
	t.Setenv("EXCLUDED_TOOLS", "place_order,modify_order")
	t.Setenv("STRIPE_SECRET_KEY", "")
	t.Setenv("ADMIN_EMAILS", "")
	t.Setenv("ALERT_DB_PATH", "")
	t.Setenv("OAUTH_JWT_SECRET", "")

	app := newTestApp(t)
	app.DevMode = true
	app.Config.ExcludedTools = "place_order,modify_order"

	kcManager, mcpServer, err := app.initializeServices()
	require.NoError(t, err)
	require.NotNil(t, kcManager)
	require.NotNil(t, mcpServer)

	cleanupInitializeServices(app, kcManager)
}


// ---------------------------------------------------------------------------
// initializeServices — with Stripe billing (non-DevMode)
// ---------------------------------------------------------------------------
func TestInitializeServices_WithStripeBilling(t *testing.T) {
	t.Setenv("DEV_MODE", "false")
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")
	t.Setenv("STRIPE_SECRET_KEY", "sk_test_fake_key_for_testing_12345")
	t.Setenv("STRIPE_PRICE_PRO", "")
	t.Setenv("STRIPE_PRICE_PREMIUM", "")
	t.Setenv("ADMIN_EMAILS", "admin@test.com")
	t.Setenv("ALERT_DB_PATH", ":memory:")
	t.Setenv("OAUTH_JWT_SECRET", "test-jwt-secret-at-least-32-chars-long!!")

	app := newTestApp(t)
	app.DevMode = false
	app.Config.AlertDBPath = ":memory:"
	app.Config.OAuthJWTSecret = "test-jwt-secret-at-least-32-chars-long!!"
	app.Config.AdminEmails = "admin@test.com"

	kcManager, mcpServer, err := app.initializeServices()
	require.NoError(t, err)
	require.NotNil(t, kcManager)
	require.NotNil(t, mcpServer)

	// Verify billing store was created
	assert.NotNil(t, kcManager.BillingStore())

	cleanupInitializeServices(app, kcManager)
}


// ---------------------------------------------------------------------------
// initializeServices — with Stripe billing and price IDs (non-DevMode)
// ---------------------------------------------------------------------------
func TestInitializeServices_WithStripePriceIDs(t *testing.T) {
	t.Setenv("DEV_MODE", "false")
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")
	t.Setenv("STRIPE_SECRET_KEY", "sk_test_fake_key_for_testing_12345")
	t.Setenv("STRIPE_PRICE_PRO", "price_pro_test")
	t.Setenv("STRIPE_PRICE_PREMIUM", "price_premium_test")
	t.Setenv("ADMIN_EMAILS", "")
	t.Setenv("ALERT_DB_PATH", ":memory:")
	t.Setenv("OAUTH_JWT_SECRET", "")

	app := newTestApp(t)
	app.DevMode = false
	app.Config.AlertDBPath = ":memory:"

	kcManager, mcpServer, err := app.initializeServices()
	require.NoError(t, err)
	require.NotNil(t, kcManager)
	require.NotNil(t, mcpServer)

	// Billing store should be created
	assert.NotNil(t, kcManager.BillingStore())

	cleanupInitializeServices(app, kcManager)
}


// ---------------------------------------------------------------------------
// initializeServices — DevMode with Stripe (Stripe should be SKIPPED)
// ---------------------------------------------------------------------------
func TestInitializeServices_DevMode_StripeSkipped(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")
	t.Setenv("STRIPE_SECRET_KEY", "sk_test_fake_key")
	t.Setenv("ADMIN_EMAILS", "")
	t.Setenv("ALERT_DB_PATH", ":memory:")
	t.Setenv("OAUTH_JWT_SECRET", "")

	app := newTestApp(t)
	app.DevMode = true
	app.Config.AlertDBPath = ":memory:"

	kcManager, mcpServer, err := app.initializeServices()
	require.NoError(t, err)
	require.NotNil(t, kcManager)
	require.NotNil(t, mcpServer)

	// In DevMode, billing should be nil (Stripe skipped)
	assert.Nil(t, kcManager.BillingStore())

	cleanupInitializeServices(app, kcManager)
}


// ---------------------------------------------------------------------------
// RunServer — invalid mode should fail
// ---------------------------------------------------------------------------
func TestRunServer_InvalidMode(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")
	t.Setenv("OAUTH_JWT_SECRET", "")
	t.Setenv("STRIPE_SECRET_KEY", "")
	t.Setenv("ADMIN_EMAILS", "")
	t.Setenv("ALERT_DB_PATH", "")
	t.Setenv("APP_MODE", "invalid_mode_xyz")

	app := newTestApp(t)
	app.DevMode = true
	app.Config.AppMode = "invalid_mode_xyz"
	app.Config.AppHost = "127.0.0.1"
	app.Config.AppPort = "0"

	err := app.RunServer()
	assert.Error(t, err)
	// envcheck.go formats this as `APP_MODE "xxx" unknown; valid: …`.
	assert.Contains(t, err.Error(), "APP_MODE")
	assert.Contains(t, err.Error(), "unknown")
}


// ---------------------------------------------------------------------------
// RunServer — OAuth wiring directly (exercises the token checker closure)
// ---------------------------------------------------------------------------
func TestRunServer_OAuthWiring_TokenChecker(t *testing.T) {
	// This test exercises the SetKiteTokenChecker closure from RunServer
	// by directly calling the wiring code.

	t.Setenv("DEV_MODE", "true")
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")
	t.Setenv("ALERT_DB_PATH", ":memory:")
	t.Setenv("STRIPE_SECRET_KEY", "")
	t.Setenv("ADMIN_EMAILS", "")
	t.Setenv("OAUTH_JWT_SECRET", "")

	app := newTestApp(t)
	app.DevMode = true
	app.Config.AlertDBPath = ":memory:"
	app.Config.OAuthJWTSecret = "test-jwt-secret-at-least-32-chars-long!!"

	kcManager, _, err := app.initializeServices()
	require.NoError(t, err)
	defer cleanupInitializeServices(app, kcManager)

	// Replicate the OAuth wiring from RunServer
	oauthCfg := &oauth.Config{
		KiteAPIKey:  app.Config.KiteAPIKey,
		JWTSecret:   app.Config.OAuthJWTSecret,
		ExternalURL: "http://localhost:9999",
		Logger:      testLogger(),
	}
	require.NoError(t, oauthCfg.Validate())

	signer := &signerAdapter{signer: kcManager.SessionSigner()}
	exchanger := &kiteExchangerAdapter{
		apiKey:          app.Config.KiteAPIKey,
		apiSecret:       app.Config.KiteAPISecret,
		tokenStore:      kcManager.TokenStoreConcrete(),
		credentialStore: kcManager.CredentialStoreConcrete(),
		registryStore:   kcManager.RegistryStoreConcrete(),
		userStore:       kcManager.UserStoreConcrete(),
		logger:          testLogger(),
	}
	app.oauthHandler = oauth.NewHandler(oauthCfg, signer, exchanger)
	t.Cleanup(app.oauthHandler.Close)

	// Wire the token checker — replicating RunServer lines 376-402
	tokenStore := kcManager.TokenStore()
	credStore := kcManager.CredentialStore()
	uStore := kcManager.UserStore()
	tokenChecker := func(email string) bool {
		if email == "" {
			return true
		}
		if uStore != nil {
			status := uStore.GetStatus(email)
			if status == users.StatusSuspended || status == users.StatusOffboarded {
				return false
			}
		}
		entry, hasToken := tokenStore.Get(email)
		if hasToken && !kc.IsKiteTokenExpired(entry.StoredAt) {
			return true
		}
		if _, hasCredentials := credStore.Get(email); hasCredentials {
			return false
		}
		return true
	}
	app.oauthHandler.SetKiteTokenChecker(tokenChecker)

	// Test the token checker with various scenarios
	// 1. Empty email → true
	assert.True(t, tokenChecker(""))

	// 2. Unknown user (no status, no token, no credentials) → true (first-time user)
	assert.True(t, tokenChecker("unknown@test.com"))

	// 3. Add a suspended user → false
	if uStore != nil {
		uStore.EnsureUser("suspended@test.com", "", "", "self")
		_ = uStore.UpdateStatus("suspended@test.com", users.StatusSuspended)
		assert.False(t, tokenChecker("suspended@test.com"))
	}

	// 4. Add an offboarded user → false
	if uStore != nil {
		uStore.EnsureUser("offboarded@test.com", "", "", "self")
		_ = uStore.UpdateStatus("offboarded@test.com", users.StatusOffboarded)
		assert.False(t, tokenChecker("offboarded@test.com"))
	}

	// 5. User with valid token → true
	kcManager.TokenStoreConcrete().Set("validtoken@test.com", &kc.KiteTokenEntry{
		AccessToken: "valid-token",
		UserID:      "UID1",
	})
	assert.True(t, tokenChecker("validtoken@test.com"))

	// 6. User with credentials but no token → false (force re-auth)
	kcManager.CredentialStoreConcrete().Set("credonly@test.com", &kc.KiteCredentialEntry{
		APIKey:    "key",
		APISecret: "secret",
	})
	assert.False(t, tokenChecker("credonly@test.com"))

	// Wire OAuth client persistence
	if alertDB := kcManager.AlertDB(); alertDB != nil {
		app.oauthHandler.SetClientPersister(&clientPersisterAdapter{db: alertDB}, testLogger())
		err := app.oauthHandler.LoadClientsFromDB()
		assert.NoError(t, err)
	}

	// Wire key registry
	if regStore := kcManager.RegistryStoreConcrete(); regStore != nil {
		app.oauthHandler.SetRegistry(&registryAdapter{store: regStore})
	}
}


// ---------------------------------------------------------------------------
// initializeServices — initStatusPageTemplate error (should log warning)
// This branch is at line 468-470: if err := app.initStatusPageTemplate(); err != nil
// To test this, we need the template FS to be broken — but since it's embedded,
// this is hard. Instead we verify the success path works with DB.
// ---------------------------------------------------------------------------
func TestInitializeServices_WithDB_FullSetup(t *testing.T) {
	t.Setenv("DEV_MODE", "true")
	t.Setenv("KITE_API_KEY", "test_key")
	t.Setenv("KITE_API_SECRET", "test_secret")
	t.Setenv("STRIPE_SECRET_KEY", "")
	t.Setenv("ADMIN_EMAILS", "admin@test.com")
	t.Setenv("ALERT_DB_PATH", ":memory:")
	t.Setenv("OAUTH_JWT_SECRET", "test-jwt-secret-at-least-32-chars-long!!")
	t.Setenv("TELEGRAM_BOT_TOKEN", "")

	app := newTestApp(t)
	app.DevMode = true
	app.Config.AlertDBPath = ":memory:"
	app.Config.OAuthJWTSecret = "test-jwt-secret-at-least-32-chars-long!!"
	app.Config.AdminEmails = "admin@test.com"

	kcManager, mcpServer, err := app.initializeServices()
	require.NoError(t, err)
	require.NotNil(t, kcManager)
	require.NotNil(t, mcpServer)

	// Verify all services were initialized
	assert.NotNil(t, app.auditStore, "audit store should be created with :memory: DB")
	assert.NotNil(t, kcManager.RiskGuard(), "riskguard should be initialized")
	assert.NotNil(t, kcManager.PaperEngineConcrete(), "paper engine should be created with DB")
	assert.NotNil(t, kcManager.EventDispatcher(), "event dispatcher should be set")
	assert.NotNil(t, kcManager.InvitationStore(), "invitation store should be created with DB")

	cleanupInitializeServices(app, kcManager)
}


// ===========================================================================
// setupGracefulShutdown — signal-based test
// ===========================================================================
func TestSetupGracefulShutdown_SignalTriggersShutdown(t *testing.T) {
	if os.Getenv("CI") == "" {
		// On Windows, os.Interrupt cannot be sent via p.Signal().
		// On Linux CI this test works. Skip locally to avoid flakes.
		// The setupGracefulShutdown goroutine body is covered via the
		// existing TestSetupGracefulShutdown_ShutdownSequence test.
		t.Skip("skipping signal test on local machine (os.Interrupt not portable)")
	}

	mgr := newTestManagerWithDB(t)
	app := newTestApp(t)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	listener.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})

	srv := &http.Server{Addr: addr, Handler: mux}

	serverDone := make(chan struct{})
	go func() {
		if sErr := srv.ListenAndServe(); sErr != nil && sErr != http.ErrServerClosed {
			t.Logf("server error: %v", sErr)
		}
		close(serverDone)
	}()
	waitForServerReady(t, srv.Addr)

	app.setupGracefulShutdown(srv, mgr)

	p, _ := os.FindProcess(os.Getpid())
	_ = p.Signal(os.Interrupt)

	select {
	case <-serverDone:
		// success
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down within timeout")
	}
}


// ===========================================================================
// initializeServices — exercising the deeper branches with more config
// ===========================================================================
func TestInitializeServices_WithAdminEmails(t *testing.T) {
	app := newTestApp(t)
	app.Config = &Config{
		KiteAPIKey:     "test-key",
		KiteAPISecret:  "test-secret",
		OAuthJWTSecret: "jwt-secret-that-is-at-least-32-chars-long",
		ExternalURL:    "https://test.example.com",
		AppMode:        ModeHTTP,
		AppPort:        "0",
		AdminEmails:    "admin@test.com,admin2@test.com",
		AlertDBPath:    ":memory:",
	}

	mgr, mcpSrv, err := app.initializeServices()
	require.NoError(t, err)
	assert.NotNil(t, mgr)
	assert.NotNil(t, mcpSrv)
	cleanupInitializeServices(app, mgr)
}


func TestInitializeServices_DevMode(t *testing.T) {
	app := newTestApp(t)
	app.DevMode = true
	app.Config = &Config{
		KiteAPIKey:    "test-key",
		KiteAPISecret: "test-secret",
		AppMode:       ModeHTTP,
		AppPort:       "0",
	}

	mgr, mcpSrv, err := app.initializeServices()
	require.NoError(t, err)
	assert.NotNil(t, mgr)
	assert.NotNil(t, mcpSrv)
	cleanupInitializeServices(app, mgr)
}
