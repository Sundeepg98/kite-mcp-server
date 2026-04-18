package oauth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"log/slog"
	"net"
	"net/http"

	"github.com/zerodha/kite-mcp-server/kc/templates"
)

// Signer signs and verifies arbitrary strings (implemented by kc.SessionSigner via adapter).
type Signer interface {
	Sign(data string) string
	Verify(signed string) (string, error)
}

// KiteExchanger exchanges a Kite request_token for user identity and caches the access token.
type KiteExchanger interface {
	ExchangeRequestToken(requestToken string) (email string, err error)
	ExchangeWithCredentials(requestToken, apiKey, apiSecret string) (email string, err error)
	GetCredentials(email string) (apiKey, apiSecret string, ok bool)
	GetSecretByAPIKey(apiKey string) (apiSecret string, ok bool)
}

// KiteTokenChecker checks whether the Kite trading token for a given email is still valid.
// Returns true if the token is valid (or no token cached yet), false if expired.
type KiteTokenChecker func(email string) bool

// ConsentRecorder captures the DPDP Act 2023 consent-grant event that occurs
// when a user completes the Kite OAuth flow — at callback time we know the
// email (via Kite token exchange) plus the IP/UA/timestamp, which is the
// minimum record the Data Protection Board may request in an audit.
//
// Implementations must be non-blocking and best-effort: the OAuth callback
// should not fail just because consent logging is unavailable. Implementations
// are expected to swallow or log their own errors — the callback ignores the
// return value.
type ConsentRecorder func(email, ipAddress, userAgent string)

// AdminUserStore provides user lookup, password verification, and auto-provisioning for login.
// Implemented by users.Store to avoid direct import of the users package.
type AdminUserStore interface {
	GetRole(email string) string
	GetStatus(email string) string
	VerifyPassword(email, password string) (bool, error)
	// EnsureGoogleUser auto-creates a trader account on first Google SSO login.
	// Existing users are left unchanged (admins keep admin role).
	EnsureGoogleUser(email string)
}

// RegistryEntry is a thin projection of a pre-registered Kite app, used inside
// the oauth package to avoid importing the registry package directly.
type RegistryEntry struct {
	APIKey       string
	APISecret    string
	RegisteredBy string // admin email who registered the app
}

// KeyRegistry provides access to the pre-registered Kite app credentials.
// Implemented by registry.Store to avoid direct import.
type KeyRegistry interface {
	HasEntries() bool
	GetByEmail(email string) (*RegistryEntry, bool)
	GetSecretByAPIKey(apiKey string) (apiSecret string, ok bool)
}

// Handler implements all OAuth 2.1 HTTP endpoints.
//
// Endpoint handlers are grouped by flow across sibling files:
//   - handlers.go           core wiring (Handler struct, NewHandler, setters, metadata, Register, helpers)
//   - handlers_oauth.go     OAuth 2.1 Authorize / email prompt / Token
//   - handlers_callback.go  Kite OAuth callback (HandleKiteOAuthCallback)
//   - handlers_browser.go   browser login flow (HandleBrowserLogin / HandleBrowserAuthCallback / HandleLoginChoice)
//   - handlers_admin.go     admin password login (HandleAdminLogin)
type Handler struct {
	config           *Config
	jwt              *JWTManager
	authCodes        *AuthCodeStore
	clients          *ClientStore
	signer           Signer
	exchanger        KiteExchanger
	logger           *slog.Logger
	kiteTokenChecker KiteTokenChecker
	consentRecorder  ConsentRecorder
	userStore        AdminUserStore
	registry         KeyRegistry
	googleSSO        *GoogleSSOConfig
	httpClient       *http.Client // nil = default; injectable for testing Google OAuth

	// Cached templates (parsed once at startup)
	loginSuccessTmpl *template.Template
	browserLoginTmpl *template.Template
	adminLoginTmpl   *template.Template
	emailPromptTmpl  *template.Template
	loginChoiceTmpl  *template.Template
}

// NewHandler creates a new OAuth handler. Config must be validated first.
func NewHandler(cfg *Config, signer Signer, exchanger KiteExchanger) *Handler {
	h := &Handler{
		config:    cfg,
		jwt:       NewJWTManager(cfg.JWTSecret, cfg.TokenExpiry),
		authCodes: NewAuthCodeStore(),
		clients:   NewClientStore(),
		signer:    signer,
		exchanger: exchanger,
		logger:    cfg.Logger,
	}

	// Pre-parse templates from embedded FS.
	// COVERAGE: The error branches below are unreachable because templates are
	// compiled into the binary via embed.FS and are validated at build time.
	// They are retained as defensive guards against future embed corruption.
	var err error
	h.loginSuccessTmpl, err = template.ParseFS(templates.FS, "base.html", "login_success.html")
	if err != nil {
		cfg.Logger.Error("Failed to parse login_success template", "error", err)
	}
	h.browserLoginTmpl, err = template.ParseFS(templates.FS, "base.html", "browser_login.html")
	if err != nil {
		cfg.Logger.Error("Failed to parse browser_login template", "error", err)
	}
	h.adminLoginTmpl, err = template.ParseFS(templates.FS, "base.html", "admin_login.html")
	if err != nil {
		cfg.Logger.Error("Failed to parse admin_login template", "error", err)
	}
	h.emailPromptTmpl, err = template.ParseFS(templates.FS, "base.html", "email_prompt.html")
	if err != nil {
		cfg.Logger.Error("Failed to parse email_prompt template", "error", err)
	}
	h.loginChoiceTmpl, err = template.ParseFS(templates.FS, "base.html", "login_choice.html")
	if err != nil {
		cfg.Logger.Error("Failed to parse login_choice template", "error", err)
	}

	return h
}

// Close releases resources held by the handler (e.g., background goroutines).
func (h *Handler) Close() {
	h.authCodes.Close()
}

// SetClientPersister enables persistence for the OAuth client store.
func (h *Handler) SetClientPersister(p ClientPersister, logger *slog.Logger) {
	h.clients.SetPersister(p)
	h.clients.SetLogger(logger)
}

// LoadClientsFromDB loads persisted OAuth clients into the in-memory store.
func (h *Handler) LoadClientsFromDB() error {
	return h.clients.LoadFromDB()
}

// SetKiteTokenChecker registers a callback that checks Kite token validity.
// When set, RequireAuth returns 401 if the Kite token has expired, forcing
// mcp-remote to re-authenticate (which includes a fresh Kite login).
func (h *Handler) SetKiteTokenChecker(checker KiteTokenChecker) {
	h.kiteTokenChecker = checker
}

// SetConsentRecorder registers a callback that persists a DPDP Act 2023
// consent-grant event. The Handler invokes it once per successful OAuth
// callback, after the email is known. When nil (default), consent recording
// is disabled — appropriate for DevMode or clients that don't need the audit
// trail. Production deployments must wire this to a durable store.
func (h *Handler) SetConsentRecorder(rec ConsentRecorder) {
	h.consentRecorder = rec
}

// SetRegistry sets the key registry for zero-config onboarding.
// When set, generic OAuth clients can be matched to Kite apps by email.
func (h *Handler) SetRegistry(r KeyRegistry) {
	h.registry = r
}

// SetUserStore sets the user store for admin password-based login.
func (h *Handler) SetUserStore(store AdminUserStore) {
	h.userStore = store
}

// SetGoogleSSO enables Google SSO for admin login.
func (h *Handler) SetGoogleSSO(cfg *GoogleSSOConfig) {
	h.googleSSO = cfg
}

// SetHTTPClient sets a custom HTTP client for Google OAuth operations (token exchange + userinfo).
// When nil (default), the standard library clients are used.
func (h *Handler) SetHTTPClient(c *http.Client) {
	h.httpClient = c
}

// GoogleSSOEnabled returns true if Google SSO is configured.
func (h *Handler) GoogleSSOEnabled() bool {
	return h.googleSSO != nil
}

// oauthState is packed into Kite's redirect_params to round-trip MCP client data.
type oauthState struct {
	ClientID      string `json:"c"`
	RedirectURI   string `json:"r"`
	CodeChallenge string `json:"k"`
	State         string `json:"s"`
	RegistryKey   string `json:"g,omitempty"` // Kite API key from registry (zero-config flow)
}

// --- Well-Known Metadata Endpoints ---

// ResourceMetadata serves RFC 9728 OAuth Protected Resource Metadata.
func (h *Handler) ResourceMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{
		"resource":              h.config.ExternalURL + "/mcp",
		"authorization_servers": []string{h.config.ExternalURL},
	})
}

// AuthServerMetadata serves RFC 8414 OAuth Authorization Server Metadata.
func (h *Handler) AuthServerMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                 h.config.ExternalURL,
		"authorization_endpoint":                 h.config.ExternalURL + "/oauth/authorize",
		"token_endpoint":                         h.config.ExternalURL + "/oauth/token",
		"registration_endpoint":                  h.config.ExternalURL + "/oauth/register",
		"response_types_supported":               []string{"code"},
		"grant_types_supported":                  []string{"authorization_code"},
		"code_challenge_methods_supported":       []string{"S256"},
		"token_endpoint_auth_methods_supported":  []string{"client_secret_post"},
	})
}

// --- Dynamic Client Registration (RFC 7591) ---

// Register handles POST /oauth/register.
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB limit

	var req struct {
		RedirectURIs []string `json:"redirect_uris"`
		ClientName   string   `json:"client_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "invalid JSON body"})
		return
	}
	if len(req.RedirectURIs) == 0 {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "redirect_uris required"})
		return
	}
	if len(req.RedirectURIs) > 10 {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "too many redirect_uris (max 10)"})
		return
	}

	clientID, clientSecret, err := h.clients.Register(req.RedirectURIs, req.ClientName)
	if err != nil {
		h.logger.Error("Failed to register client", "error", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}

	h.logger.Debug("Registered OAuth client", "client_id", clientID, "client_name", req.ClientName)

	h.writeJSON(w, http.StatusCreated, map[string]any{
		"client_id":                  clientID,
		"client_secret":              clientSecret,
		"redirect_uris":              req.RedirectURIs,
		"client_name":                req.ClientName,
		"grant_types":                []string{"authorization_code"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "client_secret_post",
	})
}

// --- Internal helpers ---

// generateCSRFToken generates a random CSRF token using crypto/rand.
// COVERAGE: The rand.Read error branch is unreachable in Go 1.24+
// (crypto/rand.Read is guaranteed to succeed or panic).
func generateCSRFToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err // COVERAGE: unreachable — crypto/rand.Read is fatal in Go 1.24+
	}
	return hex.EncodeToString(b), nil
}

// writeJSON writes a JSON response with the given status code.
func (h *Handler) writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to write JSON response", "error", err)
	}
}

// clientIP extracts the best-effort client IP for audit records. Fly.io sets
// Fly-Client-IP to the real client IP — prefer it when present. Otherwise
// strip the port from r.RemoteAddr (e.g. "127.0.0.1:12345" → "127.0.0.1") so
// logs don't carry ephemeral source ports.
//
// Returns "" when both sources are empty — callers should still record the
// consent event (the other fields carry sufficient weight).
func clientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	if flyIP := r.Header.Get("Fly-Client-IP"); flyIP != "" {
		return flyIP
	}
	ip := r.RemoteAddr
	if host, _, err := net.SplitHostPort(ip); err == nil {
		return host
	}
	return ip
}
