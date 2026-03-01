package app

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	kiteconnect "github.com/zerodha/gokiteconnect/v4"

	"github.com/mark3labs/mcp-go/server"
	"github.com/mark3labs/mcp-go/util"
	"github.com/zerodha/kite-mcp-server/app/metrics"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/ops"
	"github.com/zerodha/kite-mcp-server/kc/templates"
	"github.com/zerodha/kite-mcp-server/mcp"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// App represents the main application structure
type App struct {
	Config         *Config
	Version        string
	startTime      time.Time
	kcManager      *kc.Manager
	oauthHandler   *oauth.Handler
	statusTemplate *template.Template
	logger         *slog.Logger
	metrics        *metrics.Manager
	logBuffer      *ops.LogBuffer
}

// StatusPageData holds template data for the status page
type StatusPageData struct {
	Title   string
	Version string
	Mode    string
}

// Config holds the application configuration
type Config struct {
	KiteAPIKey      string
	KiteAPISecret   string
	KiteAccessToken string
	AppMode         string
	AppPort       string
	AppHost       string

	ExcludedTools   string
	AdminSecretPath string

	// OAuth 2.1 (opt-in: set OAUTH_JWT_SECRET to enable)
	OAuthJWTSecret string
	ExternalURL    string

	// Telegram (opt-in: set TELEGRAM_BOT_TOKEN to enable price alert notifications)
	TelegramBotToken string

	// Alert persistence (opt-in: set ALERT_DB_PATH to enable SQLite persistence)
	AlertDBPath string
}

// Server mode constants
const (
	ModeSSE    = "sse"    // Server-Sent Events mode
	ModeStdIO  = "stdio"  // Standard IO mode
	ModeHTTP   = "http"   // Streamable HTTP mode for MCP endpoint
	ModeHybrid = "hybrid" // Combined mode with both SSE and MCP endpoints

	DefaultPort    = "8080"
	DefaultHost    = "localhost"
	DefaultAppMode = "http"
)

// NewApp creates and initializes a new App instance
// NewApp creates a new application instance with logger
func NewApp(logger *slog.Logger) *App {
	return &App{
		Config: &Config{
			KiteAPIKey:      os.Getenv("KITE_API_KEY"),
			KiteAPISecret:   os.Getenv("KITE_API_SECRET"),
			KiteAccessToken: os.Getenv("KITE_ACCESS_TOKEN"),
			AppMode:         os.Getenv("APP_MODE"),
			AppPort:       os.Getenv("APP_PORT"),
			AppHost:       os.Getenv("APP_HOST"),

			ExcludedTools:   os.Getenv("EXCLUDED_TOOLS"),
			AdminSecretPath: os.Getenv("ADMIN_ENDPOINT_SECRET_PATH"),

			OAuthJWTSecret: os.Getenv("OAUTH_JWT_SECRET"),
			ExternalURL:    os.Getenv("EXTERNAL_URL"),

			TelegramBotToken: os.Getenv("TELEGRAM_BOT_TOKEN"),
			AlertDBPath:      os.Getenv("ALERT_DB_PATH"),
		},
		Version:   "v0.0.0", // Ideally injected at build time
		startTime: time.Now(),
		logger:    logger,
		metrics: metrics.New(metrics.Config{
			ServiceName:     "kite-mcp-server",
			AdminSecretPath: os.Getenv("ADMIN_ENDPOINT_SECRET_PATH"),
			AutoCleanup:     true,
		}),
	}
}

// SetVersion sets the server version
func (app *App) SetVersion(version string) {
	app.Version = version
}

// SetLogBuffer sets the log buffer for the ops dashboard SSE stream.
func (app *App) SetLogBuffer(buf *ops.LogBuffer) {
	app.logBuffer = buf
}

// LoadConfig loads and validates the application configuration
func (app *App) LoadConfig() error {
	if app.Config.AppMode == "" {
		app.Config.AppMode = DefaultAppMode
	}

	if app.Config.AppPort == "" {
		app.Config.AppPort = DefaultPort
	}

	if app.Config.AppHost == "" {
		app.Config.AppHost = DefaultHost
	}

	if app.Config.KiteAPIKey == "" || app.Config.KiteAPISecret == "" {
		if app.Config.OAuthJWTSecret == "" {
			return fmt.Errorf("KITE_API_KEY and KITE_API_SECRET are required (or enable OAuth with OAUTH_JWT_SECRET for per-user credentials)")
		}
		app.logger.Info("No global Kite credentials — per-user credentials required via MCP client config (oauth_client_id/oauth_client_secret)")
	}

	return nil
}

// RunServer initializes and starts the server based on the configured mode
func (app *App) RunServer() error {
	url := app.buildServerURL()
	app.configureHTTPClient()

	kcManager, mcpServer, err := app.initializeServices()
	if err != nil {
		return err
	}

	// Initialize OAuth handler if configured (uses Kite as identity provider)
	if app.Config.OAuthJWTSecret != "" {
		oauthCfg := &oauth.Config{
			KiteAPIKey:  app.Config.KiteAPIKey,
			JWTSecret:   app.Config.OAuthJWTSecret,
			ExternalURL: app.Config.ExternalURL,
			Logger:      app.logger,
		}
		if err := oauthCfg.Validate(); err != nil {
			return fmt.Errorf("invalid OAuth config: %w", err)
		}
		signer := &signerAdapter{signer: kcManager.SessionSigner()}
		exchanger := &kiteExchangerAdapter{
			apiKey:          app.Config.KiteAPIKey,
			apiSecret:       app.Config.KiteAPISecret,
			tokenStore:      kcManager.TokenStore(),
			credentialStore: kcManager.CredentialStore(),
			logger:          app.logger,
		}
		app.oauthHandler = oauth.NewHandler(oauthCfg, signer, exchanger)

		// Wire Kite token expiry check into OAuth middleware.
		// When a cached Kite token expires (~6 AM IST daily), RequireAuth returns 401,
		// forcing mcp-remote to re-authenticate — which includes a fresh Kite login.
		// Three states:
		//   1. Valid token cached → pass through (tools work)
		//   2. Expired/missing token BUT credentials exist → 401 (force re-auth)
		//   3. No credentials at all → pass through (first-time user, tool handler prompts)
		tokenStore := kcManager.TokenStore()
		credStore := kcManager.CredentialStore()
		app.oauthHandler.SetKiteTokenChecker(func(email string) bool {
			if email == "" {
				return true
			}
			// Check if a valid (non-expired) Kite token exists
			entry, hasToken := tokenStore.Get(email)
			if hasToken && !isKiteTokenExpired(entry.StoredAt) {
				return true // valid token, pass through
			}
			// No valid token. If user has stored credentials, they're a returning
			// user whose token expired or was cleaned up — force re-auth via 401.
			if _, hasCredentials := credStore.Get(email); hasCredentials {
				return false
			}
			// No credentials = first-time user, let tool handlers deal with onboarding
			return true
		})

		app.logger.Info("OAuth 2.1 enabled (Kite identity provider)", "external_url", app.Config.ExternalURL)
	}

	srv := app.createHTTPServer(url)
	app.setupGracefulShutdown(srv, kcManager)

	return app.startServer(srv, kcManager, mcpServer, url)
}

// buildServerURL constructs the server URL from host and port
func (app *App) buildServerURL() string {
	return app.Config.AppHost + ":" + app.Config.AppPort
}

// isKiteTokenExpired checks if a Kite token stored at the given time has likely expired.
// Kite tokens expire daily around 6 AM IST.
func isKiteTokenExpired(storedAt time.Time) bool {
	ist := time.FixedZone("IST", 5*60*60+30*60)
	now := time.Now().In(ist)
	stored := storedAt.In(ist)
	expiry := time.Date(now.Year(), now.Month(), now.Day(), 6, 0, 0, 0, ist)
	if now.Before(expiry) {
		expiry = expiry.AddDate(0, 0, -1)
	}
	return stored.Before(expiry)
}

// httpClient is a package-level HTTP client with a timeout, used instead of
// modifying the global http.DefaultClient which would affect all code.
var httpClient = &http.Client{Timeout: 30 * time.Second}

// configureHTTPClient logs that the package-level HTTP client is ready.
func (app *App) configureHTTPClient() {
	app.logger.Debug("HTTP client timeout set to 30 seconds")
}

// initializeServices creates and configures Kite Connect manager and MCP server
func (app *App) initializeServices() (*kc.Manager, *server.MCPServer, error) {
	app.logger.Info("Creating Kite Connect manager...")
	kcManager, err := kc.New(kc.Config{
		APIKey:           app.Config.KiteAPIKey,
		APISecret:        app.Config.KiteAPISecret,
		AccessToken:      app.Config.KiteAccessToken,
		Logger:           app.logger,
		Metrics:          app.metrics,
		TelegramBotToken: app.Config.TelegramBotToken,
		AlertDBPath:      app.Config.AlertDBPath,
		AppMode:          app.Config.AppMode,
		ExternalURL:      app.Config.ExternalURL,
		AdminSecretPath:  app.Config.AdminSecretPath,
		EncryptionSecret: app.Config.OAuthJWTSecret,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create Kite Connect manager: %w", err)
	}

	// Store reference for template data
	app.kcManager = kcManager

	// Initialize the status template early for the status page
	if err := app.initStatusPageTemplate(); err != nil {
		app.logger.Warn("Failed to initialize status template", "error", err)
	}

	app.logger.Debug("Kite Connect manager created successfully")

	// Create MCP server
	app.logger.Info("Creating MCP server...")
	mcpServer := server.NewMCPServer(
		"Kite MCP Server",
		app.Version,
	)
	app.logger.Debug("MCP server created successfully")

	// Register tools that will interact with MCP sessions and Kite API
	app.logger.Info("Registering MCP tools...")
	mcp.RegisterTools(mcpServer, kcManager, app.Config.ExcludedTools, app.logger)
	app.logger.Debug("MCP tools registered successfully")

	return kcManager, mcpServer, nil
}

// createHTTPServer creates and configures the HTTP server
func (app *App) createHTTPServer(url string) *http.Server {
	return &http.Server{
		Addr:              url,
		ReadHeaderTimeout: 30 * time.Second,
		WriteTimeout:      120 * time.Second,
	}
}

// setupGracefulShutdown configures graceful shutdown for the server
func (app *App) setupGracefulShutdown(srv *http.Server, kcManager *kc.Manager) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	go func() {
		defer stop()
		<-ctx.Done()
		app.logger.Info("Shutting down server...")

		// Shutdown HTTP server first (stop accepting new requests)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := srv.Shutdown(shutdownCtx); err != nil {
			app.logger.Error("Server shutdown error", "error", err)
		}

		// Then shutdown Kite manager (session cleanup and instruments scheduler)
		kcManager.Shutdown()

		app.logger.Info("Server shutdown complete")
	}()
}

// startServer selects the appropriate server mode to start
func (app *App) startServer(srv *http.Server, kcManager *kc.Manager, mcpServer *server.MCPServer, url string) error {
	switch app.Config.AppMode {
	default:
		return fmt.Errorf("invalid APP_MODE: %s", app.Config.AppMode)

	case ModeHybrid:
		app.startHybridServer(srv, kcManager, mcpServer, url)

	case ModeStdIO:
		app.startStdIOServer(srv, kcManager, mcpServer)

	case ModeSSE:
		app.startSSEServer(srv, kcManager, mcpServer, url)

	case ModeHTTP:
		app.startHTTPServer(srv, kcManager, mcpServer, url)
	}

	return nil
}

// setupMux creates and configures a new HTTP mux with common handlers
func (app *App) setupMux(kcManager *kc.Manager) *http.ServeMux {
	mux := http.NewServeMux()

	// Unified /callback handler: dispatches by flow param
	// - flow=oauth → MCP OAuth callback (Kite → JWT → MCP auth code)
	// - flow=browser → Browser auth callback (Kite → JWT cookie for ops dashboard)
	// - default      → Login tool re-auth (existing session_id flow)
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		requestToken := r.URL.Query().Get("request_token")
		flow := r.URL.Query().Get("flow")
		switch flow {
		case "oauth":
			if app.oauthHandler != nil {
				app.oauthHandler.HandleKiteOAuthCallback(w, r, requestToken)
			} else {
				http.Error(w, "OAuth not configured", http.StatusInternalServerError)
			}
		case "browser":
			if app.oauthHandler != nil {
				app.oauthHandler.HandleBrowserAuthCallback(w, r, requestToken)
			} else {
				http.Error(w, "OAuth not configured", http.StatusInternalServerError)
			}
		default:
			kcManager.HandleKiteCallback()(w, r)
		}
	})

	if app.Config.AdminSecretPath != "" {
		mux.HandleFunc("/admin/", app.metrics.AdminHTTPHandler())
	}
	// Ops dashboard: protected by OAuth if available, otherwise by secret path
	opsHandler := ops.New(kcManager, app.metrics, app.logBuffer, app.logger, app.Version, app.startTime)
	if app.oauthHandler != nil {
		opsHandler.RegisterRoutes(mux, app.oauthHandler.RequireAuthBrowser)
	} else if app.Config.AdminSecretPath != "" {
		// Fallback for local dev: use identity middleware (no auth)
		opsHandler.RegisterRoutes(mux, func(next http.Handler) http.Handler { return next })
	}
	// Register OAuth 2.1 endpoints if enabled
	if app.oauthHandler != nil {
		mux.HandleFunc("/.well-known/oauth-protected-resource", app.oauthHandler.ResourceMetadata)
		mux.HandleFunc("/.well-known/oauth-authorization-server", app.oauthHandler.AuthServerMetadata)
		mux.HandleFunc("/oauth/register", app.oauthHandler.Register)
		mux.HandleFunc("/oauth/authorize", app.oauthHandler.Authorize)
		mux.HandleFunc("/oauth/token", app.oauthHandler.Token)
	}
	// Register browser login route for ops dashboard auth (requires OAuth)
	if app.oauthHandler != nil {
		mux.HandleFunc("/auth/browser-login", app.oauthHandler.HandleBrowserLogin)
	}

	app.serveStatusPage(mux)
	return mux
}

// serveHTTPServer starts the HTTP server with error handling
func (app *App) serveHTTPServer(srv *http.Server) {
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		app.logger.Error("HTTP server error", "error", err)
	}
}

// createSSEServer creates and configures an SSE server
func (app *App) createSSEServer(mcpServer *server.MCPServer, url string) *server.SSEServer {
	return server.NewSSEServer(mcpServer,
		server.WithBaseURL(url),
		server.WithKeepAlive(true),
	)
}

// createStreamableHTTPServer creates and configures a streamable HTTP server
func (app *App) createStreamableHTTPServer(mcpServer *server.MCPServer, kcManager *kc.Manager) *server.StreamableHTTPServer {
	return server.NewStreamableHTTPServer(mcpServer,
		server.WithSessionIdManager(kcManager.SessionManager()),
		server.WithLogger(util.DefaultLogger()),
	)
}

// withSessionType adds session type to context based on URL path
func withSessionType(sessionType string, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := mcp.WithSessionType(r.Context(), sessionType)
		r = r.WithContext(ctx)
		handler(w, r)
	}
}

// registerSSEEndpoints registers SSE-specific endpoints on the mux
func (app *App) registerSSEEndpoints(mux *http.ServeMux, sse *server.SSEServer) {
	sseHandler := withSessionType(mcp.SessionTypeSSE, sse.ServeHTTP)
	messageHandler := withSessionType(mcp.SessionTypeSSE, sse.ServeHTTP)

	if app.oauthHandler != nil {
		mux.Handle("/sse", app.oauthHandler.RequireAuth(http.HandlerFunc(sseHandler)))
		mux.Handle("/message", app.oauthHandler.RequireAuth(http.HandlerFunc(messageHandler)))
	} else {
		mux.HandleFunc("/sse", sseHandler)
		mux.HandleFunc("/message", messageHandler)
	}
}

// configureAndStartServer sets up server handler and starts it
func (app *App) configureAndStartServer(srv *http.Server, mux *http.ServeMux) {
	srv.Handler = mux
	app.serveHTTPServer(srv)
}

// startHybridServer starts a server with both SSE and MCP endpoints
func (app *App) startHybridServer(srv *http.Server, kcManager *kc.Manager, mcpServer *server.MCPServer, url string) {
	app.logger.Info("Starting Hybrid MCP server with both SSE and MCP endpoints", "url", "http://"+url)

	// Initialize both server types
	sse := app.createSSEServer(mcpServer, url)
	streamable := app.createStreamableHTTPServer(mcpServer, kcManager)

	// Setup mux with common handlers
	mux := app.setupMux(kcManager)

	// Register endpoints
	app.registerSSEEndpoints(mux, sse)
	mcpHandler := withSessionType(mcp.SessionTypeMCP, streamable.ServeHTTP)
	if app.oauthHandler != nil {
		mux.Handle("/mcp", app.oauthHandler.RequireAuth(http.HandlerFunc(mcpHandler)))
	} else {
		mux.HandleFunc("/mcp", mcpHandler)
	}

	app.logger.Info("Hybrid mode enabled with both SSE and MCP endpoints on the same server")
	app.logger.Info("SSE endpoints available", "url", fmt.Sprintf("http://%s/sse and http://%s/message", url, url))
	app.logger.Info("MCP endpoint available", "url", fmt.Sprintf("http://%s/mcp", url))

	app.configureAndStartServer(srv, mux)
}

// startStdIOServer starts a server in STDIO mode
func (app *App) startStdIOServer(srv *http.Server, kcManager *kc.Manager, mcpServer *server.MCPServer) {
	app.logger.Info("Starting STDIO MCP server...")
	stdio := server.NewStdioServer(mcpServer)

	// Setup mux with common handlers
	mux := app.setupMux(kcManager)

	go app.configureAndStartServer(srv, mux)

	ctx := context.Background()
	if err := stdio.Listen(ctx, os.Stdin, os.Stdout); err != nil {
		app.logger.Error("STDIO server error", "error", err)
	}
}

// startSSEServer starts a server in SSE mode
func (app *App) startSSEServer(srv *http.Server, kcManager *kc.Manager, mcpServer *server.MCPServer, url string) {
	app.logger.Info("Starting SSE MCP server", "url", "http://"+url)
	sse := app.createSSEServer(mcpServer, url)

	// Setup mux with common handlers
	mux := app.setupMux(kcManager)
	app.registerSSEEndpoints(mux, sse)

	app.logger.Info("Active MCP and Kite sessions will be monitored and cleaned up automatically")
	app.configureAndStartServer(srv, mux)
}

// startHTTPServer starts a server in HTTP mode
func (app *App) startHTTPServer(srv *http.Server, kcManager *kc.Manager, mcpServer *server.MCPServer, url string) {
	app.logger.Info("Starting Streamable HTTP MCP server", "url", "http://"+url)
	streamable := app.createStreamableHTTPServer(mcpServer, kcManager)

	// Setup mux with common handlers
	mux := app.setupMux(kcManager)

	// Register /mcp with optional OAuth middleware
	mcpHandler := withSessionType(mcp.SessionTypeMCP, streamable.ServeHTTP)
	if app.oauthHandler != nil {
		mux.Handle("/mcp", app.oauthHandler.RequireAuth(http.HandlerFunc(mcpHandler)))
		app.logger.Info("OAuth middleware enabled for /mcp endpoint")
	} else {
		mux.HandleFunc("/mcp", mcpHandler)
	}

	app.logger.Info("MCP session manager configured with automatic cleanup for both MCP and Kite sessions")
	app.logger.Info("MCP Session manager configured", "session_expiry", kc.DefaultSessionDuration)
	app.logger.Info("Serving documentation at root URL")

	app.configureAndStartServer(srv, mux)
}

// initStatusPageTemplate initializes the status template
func (app *App) initStatusPageTemplate() error {
	tmpl, err := template.ParseFS(templates.FS, "base.html", "status.html")
	if err != nil {
		return fmt.Errorf("failed to parse status template: %w", err)
	}
	app.statusTemplate = tmpl
	app.logger.Info("Status template initialized successfully")
	return nil
}

// getStatusData returns template data for the status page
func (app *App) getStatusData() StatusPageData {
	return StatusPageData{
		Title:   "Status",
		Version: app.Version,
		Mode:    app.Config.AppMode,
	}
}

// serveStatusPage configures the HTTP mux to serve status page using templates
func (app *App) serveStatusPage(mux *http.ServeMux) {
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Only serve status page at root path
		if path != "/" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("Not Found"))
			return
		}

		// Serve status page with template data
		if app.statusTemplate == nil {
			// Fallback to simple text if template failed to load
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Kite MCP Server - Status template not available"))
			return
		}

		data := app.getStatusData()
		var buf bytes.Buffer
		if err := app.statusTemplate.ExecuteTemplate(&buf, "base", data); err != nil {
			app.logger.Error("Failed to execute status template", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if _, err := buf.WriteTo(w); err != nil {
			app.logger.Error("Failed to write status page", "error", err)
		}
	})

	app.logger.Info("Template-based status page configured to be served at root URL")
}

// --- OAuth adapter types ---

// signerAdapter wraps kc.SessionSigner to implement oauth.Signer.
type signerAdapter struct {
	signer *kc.SessionSigner
}

func (s *signerAdapter) Sign(data string) string {
	return s.signer.SignSessionID(data)
}

func (s *signerAdapter) Verify(signed string) (string, error) {
	return s.signer.VerifySessionID(signed)
}

// kiteExchangerAdapter exchanges a Kite request_token for user identity.
type kiteExchangerAdapter struct {
	apiKey          string
	apiSecret       string
	tokenStore      *kc.KiteTokenStore
	credentialStore *kc.KiteCredentialStore
	logger          *slog.Logger
}

func (a *kiteExchangerAdapter) ExchangeRequestToken(requestToken string) (string, error) {
	client := kiteconnect.New(a.apiKey)
	userSess, err := client.GenerateSession(requestToken, a.apiSecret)
	if err != nil {
		return "", fmt.Errorf("kite generate session: %w", err)
	}

	// UserSession embeds UserProfile — Email available directly
	email := userSess.Email
	if email == "" {
		email = userSess.UserID
	}

	a.logger.Debug("Kite token exchange successful", "email", email, "user_id", userSess.UserID)

	// Cache the access token keyed by email
	a.tokenStore.Set(strings.ToLower(email), &kc.KiteTokenEntry{
		AccessToken: userSess.AccessToken,
		UserID:      userSess.UserID,
		UserName:    userSess.UserName,
	})

	return email, nil
}

func (a *kiteExchangerAdapter) ExchangeWithCredentials(requestToken, apiKey, apiSecret string) (string, error) {
	client := kiteconnect.New(apiKey)
	userSess, err := client.GenerateSession(requestToken, apiSecret)
	if err != nil {
		return "", fmt.Errorf("kite generate session with per-user credentials: %w", err)
	}

	email := userSess.Email
	if email == "" {
		email = userSess.UserID
	}

	a.logger.Debug("Kite token exchange (per-user credentials) successful", "email", email, "user_id", userSess.UserID)

	// Cache the access token keyed by email
	a.tokenStore.Set(strings.ToLower(email), &kc.KiteTokenEntry{
		AccessToken: userSess.AccessToken,
		UserID:      userSess.UserID,
		UserName:    userSess.UserName,
	})

	// Store per-user credentials so all future operations use them
	a.credentialStore.Set(strings.ToLower(email), &kc.KiteCredentialEntry{
		APIKey:    apiKey,
		APISecret: apiSecret,
	})

	return email, nil
}

func (a *kiteExchangerAdapter) GetCredentials(email string) (string, string, bool) {
	email = strings.ToLower(email)
	entry, ok := a.credentialStore.Get(email)
	if !ok {
		// Fall back to global credentials if available
		if a.apiKey != "" && a.apiSecret != "" {
			return a.apiKey, a.apiSecret, true
		}
		return "", "", false
	}
	return entry.APIKey, entry.APISecret, true
}

func (a *kiteExchangerAdapter) GetSecretByAPIKey(apiKey string) (string, bool) {
	return a.credentialStore.GetSecretByAPIKey(apiKey)
}
