package oauth

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

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

// Handler implements all OAuth 2.1 HTTP endpoints.
type Handler struct {
	config           *Config
	jwt              *JWTManager
	authCodes        *AuthCodeStore
	clients          *ClientStore
	signer           Signer
	exchanger        KiteExchanger
	logger           *slog.Logger
	kiteTokenChecker KiteTokenChecker

	// Cached templates (parsed once at startup)
	loginSuccessTmpl  *template.Template
	browserLoginTmpl  *template.Template
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

	// Pre-parse templates from embedded FS
	var err error
	h.loginSuccessTmpl, err = template.ParseFS(templates.FS, "base.html", "login_success.html")
	if err != nil {
		cfg.Logger.Error("Failed to parse login_success template", "error", err)
	}
	h.browserLoginTmpl, err = template.ParseFS(templates.FS, "base.html", "browser_login.html")
	if err != nil {
		cfg.Logger.Error("Failed to parse browser_login template", "error", err)
	}

	return h
}

// SetKiteTokenChecker registers a callback that checks Kite token validity.
// When set, RequireAuth returns 401 if the Kite token has expired, forcing
// mcp-remote to re-authenticate (which includes a fresh Kite login).
func (h *Handler) SetKiteTokenChecker(checker KiteTokenChecker) {
	h.kiteTokenChecker = checker
}

// oauthState is packed into Kite's redirect_params to round-trip MCP client data.
type oauthState struct {
	ClientID      string `json:"c"`
	RedirectURI   string `json:"r"`
	CodeChallenge string `json:"k"`
	State         string `json:"s"`
}

// --- Well-Known Metadata Endpoints ---

// ResourceMetadata serves RFC 9728 OAuth Protected Resource Metadata.
func (h *Handler) ResourceMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]interface{}{
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
	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"issuer":                                h.config.ExternalURL,
		"authorization_endpoint":                h.config.ExternalURL + "/oauth/authorize",
		"token_endpoint":                        h.config.ExternalURL + "/oauth/token",
		"registration_endpoint":                 h.config.ExternalURL + "/oauth/register",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"code_challenge_methods_supported":       []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post"},
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

	h.writeJSON(w, http.StatusCreated, map[string]interface{}{
		"client_id":                  clientID,
		"client_secret":              clientSecret,
		"redirect_uris":              req.RedirectURIs,
		"client_name":                req.ClientName,
		"grant_types":                []string{"authorization_code"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "client_secret_post",
	})
}

// --- Authorization Endpoint ---

// Authorize handles GET /oauth/authorize — validates params and redirects to Kite login.
func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")
	state := q.Get("state")
	responseType := q.Get("response_type")

	// Validate required params
	if responseType != "code" {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_response_type"})
		return
	}
	if clientID == "" || redirectURI == "" {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "client_id and redirect_uri required"})
		return
	}
	if codeChallengeMethod != "S256" {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "code_challenge_method must be S256"})
		return
	}
	if codeChallenge == "" {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "code_challenge required"})
		return
	}

	// Validate redirect_uri scheme (only http/https allowed)
	parsed, err := url.Parse(redirectURI)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "redirect_uri must use http or https scheme"})
		return
	}

	// Validate client — if unknown, auto-register as a Kite API key client
	if _, ok := h.clients.Get(clientID); !ok {
		h.clients.RegisterKiteClient(clientID, []string{redirectURI})
		h.logger.Info("Auto-registered Kite API key client", "client_id", clientID)
	} else if h.clients.IsKiteClient(clientID) {
		// Ensure this redirect_uri is registered for existing Kite clients
		h.clients.AddRedirectURI(clientID, redirectURI)
	}

	if !h.clients.ValidateRedirectURI(clientID, redirectURI) {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "redirect_uri mismatch for client"})
		return
	}

	// Pack MCP client state into signed redirect_params
	stateData := oauthState{
		ClientID:      clientID,
		RedirectURI:   redirectURI,
		CodeChallenge: codeChallenge,
		State:         state,
	}
	stateJSON, err := json.Marshal(stateData)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	encodedState := base64.URLEncoding.EncodeToString(stateJSON)
	signedState := h.signer.Sign(encodedState)

	// Build redirect_params: flow=oauth&data=<signed>
	redirectParams := "flow=oauth&data=" + url.QueryEscape(signedState)

	// Use per-user API key for Kite login if this is a Kite API key client
	kiteAPIKey := h.config.KiteAPIKey
	if h.clients.IsKiteClient(clientID) {
		kiteAPIKey = clientID
	}

	if kiteAPIKey == "" {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "No Kite API credentials configured. Set oauth_client_id and oauth_client_secret in your MCP client config."})
		return
	}

	// Redirect to Kite login
	kiteURL := fmt.Sprintf("https://kite.zerodha.com/connect/login?api_key=%s&v=3&redirect_params=%s",
		kiteAPIKey, url.QueryEscape(redirectParams))
	h.logger.Info("Redirecting to Kite login", "client_id", clientID, "is_kite_key", h.clients.IsKiteClient(clientID))
	http.Redirect(w, r, kiteURL, http.StatusFound)
}

// --- Kite OAuth Callback ---

// HandleKiteOAuthCallback handles the Kite callback for MCP OAuth flow.
// Called when flow=oauth in the callback query params.
func (h *Handler) HandleKiteOAuthCallback(w http.ResponseWriter, r *http.Request, requestToken string) {
	if requestToken == "" {
		http.Error(w, "missing request_token", http.StatusBadRequest)
		return
	}

	// Read and verify signed state data
	signedData := r.URL.Query().Get("data")
	if signedData == "" {
		http.Error(w, "missing data parameter", http.StatusBadRequest)
		return
	}

	encodedState, err := h.signer.Verify(signedData)
	if err != nil {
		h.logger.Warn("Invalid OAuth callback signature", "error", err)
		http.Error(w, "invalid or expired callback data", http.StatusBadRequest)
		return
	}

	// Decode state
	stateJSON, err := base64.URLEncoding.DecodeString(encodedState)
	if err != nil {
		http.Error(w, "invalid state encoding", http.StatusBadRequest)
		return
	}
	var st oauthState
	if err := json.Unmarshal(stateJSON, &st); err != nil {
		http.Error(w, "invalid state data", http.StatusBadRequest)
		return
	}

	var mcpCode string
	if h.clients.IsKiteClient(st.ClientID) {
		// Per-user Kite API key: defer exchange to /oauth/token (we need client_secret)
		var err error
		mcpCode, err = h.authCodes.Generate(&AuthCodeEntry{
			ClientID:      st.ClientID,
			CodeChallenge: st.CodeChallenge,
			RedirectURI:   st.RedirectURI,
			RequestToken:  requestToken,
		})
		if err != nil {
			h.logger.Error("Failed to generate auth code (deferred)", "error", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		h.logger.Info("Kite OAuth callback (deferred exchange)", "client_id", st.ClientID)
	} else {
		// Normal flow: exchange immediately with global credentials
		email, err := h.exchanger.ExchangeRequestToken(requestToken)
		if err != nil {
			h.logger.Error("Kite token exchange failed", "error", err)
			http.Error(w, "failed to authenticate with Kite", http.StatusInternalServerError)
			return
		}
		mcpCode, err = h.authCodes.Generate(&AuthCodeEntry{
			ClientID:      st.ClientID,
			CodeChallenge: st.CodeChallenge,
			RedirectURI:   st.RedirectURI,
			Email:         email,
		})
		if err != nil {
			h.logger.Error("Failed to generate auth code", "error", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		h.logger.Debug("Kite OAuth complete, issuing MCP auth code", "email", email, "client_id", st.ClientID)
	}

	// Build redirect URL back to MCP client using proper url.URL construction
	parsed, parseErr := url.Parse(st.RedirectURI)
	if parseErr != nil {
		h.logger.Error("Invalid redirect URI in state", "redirect_uri", st.RedirectURI, "error", parseErr)
		http.Error(w, "invalid redirect URI", http.StatusBadRequest)
		return
	}
	params := parsed.Query()
	params.Set("code", mcpCode)
	if st.State != "" {
		params.Set("state", st.State)
	}
	redirectURL := (&url.URL{
		Scheme:   parsed.Scheme,
		Host:     parsed.Host,
		Path:     parsed.Path,
		RawQuery: params.Encode(),
	}).String()

	// Serve the same success page as the non-OAuth callback, with auto-redirect
	if h.loginSuccessTmpl == nil {
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := struct {
		Title       string
		RedirectURL string
	}{
		Title:       "Login Successful",
		RedirectURL: redirectURL,
	}
	if err := h.loginSuccessTmpl.ExecuteTemplate(w, "base", data); err != nil {
		h.logger.Error("Failed to render success template", "error", err)
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}
}

// --- Browser Auth Callback ---

// HandleBrowserAuthCallback handles the Kite callback for browser login flow.
// Called when flow=browser in the callback query params.
// Sets a JWT cookie and redirects to the target page (e.g. /admin/ops).
func (h *Handler) HandleBrowserAuthCallback(w http.ResponseWriter, r *http.Request, requestToken string) {
	if requestToken == "" {
		http.Error(w, "missing request_token", http.StatusBadRequest)
		return
	}

	// Read and verify signed target (base64-encoded "email::redirect")
	signedTarget := r.URL.Query().Get("target")
	redirect := "/admin/ops" // default
	var dashEmail string
	if signedTarget != "" {
		decoded, err := h.signer.Verify(signedTarget)
		if err != nil {
			h.logger.Warn("Invalid browser auth callback signature", "error", err)
		} else if rawBytes, b64err := base64.RawURLEncoding.DecodeString(decoded); b64err == nil {
			if parts := strings.SplitN(string(rawBytes), "::", 2); len(parts) == 2 {
				dashEmail = parts[0]
				redirect = parts[1]
			}
		} else {
			// Legacy: plain redirect without email
			redirect = decoded
		}
	}

	// Prevent open redirect: only allow relative paths
	if !strings.HasPrefix(redirect, "/") || strings.HasPrefix(redirect, "//") {
		redirect = "/admin/ops"
	}

	// Exchange Kite request_token for user identity using per-user or global credentials
	var email string
	var err error
	if dashEmail != "" {
		// Per-user: look up stored API key/secret for this email
		apiKey, apiSecret, ok := h.exchanger.GetCredentials(dashEmail)
		if !ok {
			h.logger.Error("No stored credentials for browser auth user", "email", dashEmail)
			http.Error(w, "Authentication failed: no credentials found", http.StatusUnauthorized)
			return
		}
		email, err = h.exchanger.ExchangeWithCredentials(requestToken, apiKey, apiSecret)
	} else {
		// Global fallback
		email, err = h.exchanger.ExchangeRequestToken(requestToken)
	}
	if err != nil {
		h.logger.Error("Kite browser auth token exchange failed", "error", err)
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	// Set JWT cookie for browser auth
	if err := h.SetAuthCookie(w, email); err != nil {
		h.logger.Error("Failed to set auth cookie", "error", err)
		http.Error(w, "Failed to set auth cookie", http.StatusInternalServerError)
		return
	}

	h.logger.Info("Browser auth login successful", "email", email)
	http.Redirect(w, r, redirect, http.StatusFound)
}

// --- Browser Login URL ---

// GenerateBrowserLoginURL generates a Kite login URL for browser-based auth.
// The email and redirect path are signed together and passed through as redirect_params,
// so the callback can look up per-user credentials for the token exchange.
func (h *Handler) GenerateBrowserLoginURL(apiKey, email, redirect string) string {
	if apiKey == "" {
		apiKey = h.config.KiteAPIKey
	}
	// Base64-encode email::redirect before signing, because the signer uses
	// | and . as internal separators which conflict with email addresses
	raw := base64.RawURLEncoding.EncodeToString([]byte(email + "::" + redirect))
	signedTarget := h.signer.Sign(raw)
	redirectParams := "flow=browser&target=" + url.QueryEscape(signedTarget)
	return fmt.Sprintf("https://kite.zerodha.com/connect/login?api_key=%s&v=3&redirect_params=%s",
		apiKey, url.QueryEscape(redirectParams))
}

// --- Browser Login Page ---

// generateCSRFToken generates a random CSRF token using crypto/rand.
func generateCSRFToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// HandleBrowserLogin serves a login form or redirects to Kite login for browser-based auth.
// If an email query param is provided, looks up stored credentials and redirects to Kite.
// Otherwise, serves a login form where the user enters their email.
// CSRF protection: GET sets a random token as an HttpOnly cookie and hidden form field;
// POST verifies the cookie matches the form value.
func (h *Handler) HandleBrowserLogin(w http.ResponseWriter, r *http.Request) {
	redirect := r.URL.Query().Get("redirect")
	if redirect == "" {
		redirect = "/admin/ops"
	}

	if r.Method == http.MethodPost {
		r.ParseForm()
		email := r.FormValue("email")
		redirect = r.FormValue("redirect")
		if redirect == "" {
			redirect = "/admin/ops"
		}

		// Verify CSRF token: cookie must match form value
		csrfCookie, err := r.Cookie("csrf_token")
		csrfForm := r.FormValue("csrf_token")
		if err != nil || csrfCookie.Value == "" || csrfCookie.Value != csrfForm {
			csrfToken, tokenErr := generateCSRFToken()
			if tokenErr != nil {
				h.logger.Error("Failed to generate CSRF token", "error", tokenErr)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			h.serveBrowserLoginForm(w, redirect, "Invalid or missing CSRF token. Please try again.", csrfToken)
			return
		}

		if email == "" {
			csrfToken, tokenErr := generateCSRFToken()
			if tokenErr != nil {
				h.logger.Error("Failed to generate CSRF token", "error", tokenErr)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			h.serveBrowserLoginForm(w, redirect, "", csrfToken)
			return
		}

		apiKey, _, ok := h.exchanger.GetCredentials(email)
		if !ok {
			csrfToken, tokenErr := generateCSRFToken()
			if tokenErr != nil {
				h.logger.Error("Failed to generate CSRF token", "error", tokenErr)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			h.serveBrowserLoginForm(w, redirect, "No credentials found for this email. Please authenticate via your MCP client first.", csrfToken)
			return
		}

		kiteURL := h.GenerateBrowserLoginURL(apiKey, email, redirect)
		http.Redirect(w, r, kiteURL, http.StatusFound)
		return
	}

	// GET request: check for email query param
	email := r.URL.Query().Get("email")
	if email != "" {
		apiKey, _, ok := h.exchanger.GetCredentials(email)
		if ok {
			kiteURL := h.GenerateBrowserLoginURL(apiKey, email, redirect)
			http.Redirect(w, r, kiteURL, http.StatusFound)
			return
		}
	}

	// Serve form with a fresh CSRF token
	csrfToken, err := generateCSRFToken()
	if err != nil {
		h.logger.Error("Failed to generate CSRF token", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	errorMsg := ""
	if email != "" {
		errorMsg = "No credentials found for this email. Please authenticate via your MCP client first."
	}
	h.serveBrowserLoginForm(w, redirect, errorMsg, csrfToken)
}

// serveBrowserLoginForm renders the browser login form template.
func (h *Handler) serveBrowserLoginForm(w http.ResponseWriter, redirect string, errorMsg string, csrfToken string) {
	if h.browserLoginTmpl == nil {
		http.Error(w, "Failed to load login page", http.StatusInternalServerError)
		return
	}

	// Set CSRF token as HttpOnly cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Path:     "/auth/browser-login",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   true,
	})

	data := struct {
		Title     string
		Redirect  string
		Error     string
		CSRFToken string
	}{
		Title:     "Login",
		Redirect:  redirect,
		Error:     errorMsg,
		CSRFToken: csrfToken,
	}

	// Buffer template output to avoid partial writes on error
	var buf bytes.Buffer
	if err := h.browserLoginTmpl.ExecuteTemplate(&buf, "base", data); err != nil {
		h.logger.Error("Failed to render browser login template", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	buf.WriteTo(w)
}

// --- Token Endpoint ---

// Token handles POST /oauth/token — exchanges auth code + PKCE verifier for JWT.
func (h *Handler) Token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 64*1024) // 64 KB limit

	if err := r.ParseForm(); err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}

	grantType := r.FormValue("grant_type")
	code := r.FormValue("code")
	codeVerifier := r.FormValue("code_verifier")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	if grantType != "authorization_code" {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
		return
	}
	if code == "" || codeVerifier == "" || clientID == "" {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "code, code_verifier, and client_id required"})
		return
	}

	// Validate client credentials
	client, ok := h.clients.Get(clientID)
	if !ok {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	// For Kite API key clients, skip secret comparison — validated by Kite's GenerateSession instead
	if !client.IsKiteAPIKey && client.ClientSecret != clientSecret {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}

	// Consume auth code
	entry, ok := h.authCodes.Consume(code)
	if !ok {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "code expired or already used"})
		return
	}

	// Verify client_id matches
	if entry.ClientID != clientID {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "client_id mismatch"})
		return
	}

	// PKCE S256 verification: SHA256(code_verifier) must equal stored code_challenge
	hash := sha256.Sum256([]byte(codeVerifier))
	computed := base64.RawURLEncoding.EncodeToString(hash[:])
	if computed != entry.CodeChallenge {
		h.logger.Warn("PKCE verification failed", "client_id", clientID)
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "PKCE verification failed"})
		return
	}

	// Resolve email — either already known (normal flow) or needs deferred exchange
	email := entry.Email
	if email == "" && entry.RequestToken != "" {
		// Deferred exchange: client_id = Kite API key, client_secret = Kite API secret
		// If client_secret not in request (public OAuth clients like Claude Code native),
		// fall back to the credential store which persists secrets from previous sessions.
		secret := clientSecret
		if secret == "" {
			if storedSecret, ok := h.exchanger.GetSecretByAPIKey(clientID); ok {
				secret = storedSecret
				h.logger.Debug("Using stored API secret for deferred exchange", "client_id", clientID)
			} else {
				h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "client_secret (Kite API secret) required for per-user authentication"})
				return
			}
		}
		var err error
		email, err = h.exchanger.ExchangeWithCredentials(entry.RequestToken, clientID, secret)
		if err != nil {
			h.logger.Error("Deferred Kite token exchange failed", "client_id", clientID, "error", err)
			h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "Kite authentication failed — check your API key and secret"})
			return
		}
		h.logger.Debug("Deferred Kite exchange successful", "email", email, "client_id", clientID)
	}

	if email == "" {
		h.logger.Error("No email resolved for token", "client_id", clientID)
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error", "error_description": "failed to determine user identity"})
		return
	}

	// Generate JWT
	accessToken, err := h.jwt.GenerateToken(email, clientID)
	if err != nil {
		h.logger.Error("Failed to generate JWT", "error", err)
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}

	h.logger.Debug("Issued JWT access token", "email", email, "client_id", clientID)

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   int(h.config.TokenExpiry.Seconds()),
	})
}

// --- Internal helpers ---

// generateKiteLoginURL builds a Kite Connect login URL with the given redirect_params.
func (h *Handler) generateKiteLoginURL(redirectParams string) string {
	return fmt.Sprintf("https://kite.zerodha.com/connect/login?api_key=%s&v=3&redirect_params=%s",
		h.config.KiteAPIKey, url.QueryEscape(redirectParams))
}

// writeJSON writes a JSON response with the given status code.
func (h *Handler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to write JSON response", "error", err)
	}
}
