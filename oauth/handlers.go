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

// AdminUserStore provides user lookup and password verification for admin login.
// Implemented by users.Store to avoid direct import of the users package.
type AdminUserStore interface {
	GetRole(email string) string
	GetStatus(email string) string
	VerifyPassword(email, password string) (bool, error)
}

// KeyRegistry provides access to the pre-registered Kite app credentials.
// Implemented by registry.Store to avoid direct import.
type KeyRegistry interface {
	HasEntries() bool
	GetByEmail(email string) (apiKey, apiSecret string, ok bool)
	GetSecretByAPIKey(apiKey string) (apiSecret string, ok bool)
}

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
	userStore        AdminUserStore
	registry         KeyRegistry
	googleSSO        *GoogleSSOConfig

	// Cached templates (parsed once at startup)
	loginSuccessTmpl   *template.Template
	browserLoginTmpl   *template.Template
	adminLoginTmpl     *template.Template
	emailPromptTmpl    *template.Template
	loginChoiceTmpl    *template.Template
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

// SetRegistry sets the key registry for zero-config onboarding.
// When set, generic OAuth clients can be matched to Kite apps by email.
func (h *Handler) SetRegistry(r KeyRegistry) {
	h.registry = r
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

	// Pack MCP client state — redirectToKiteLogin/serveEmailPrompt will sign and encode it
	stateData := oauthState{
		ClientID:      clientID,
		RedirectURI:   redirectURI,
		CodeChallenge: codeChallenge,
		State:         state,
	}

	// Determine Kite API key for login redirect
	if h.clients.IsKiteClient(clientID) {
		// Per-user Kite API key client: redirect directly to Kite login
		h.redirectToKiteLogin(w, r, clientID, stateData)
		return
	}

	// Generic (dynamically registered) client
	// If the key registry has entries, show the email prompt instead of going to Kite directly.
	// This enables zero-config onboarding: user enters email, server looks up registry for their app.
	if h.registry != nil && h.registry.HasEntries() {
		h.serveEmailPrompt(w, stateData, "")
		return
	}

	// Fallback: use global Kite API key if available
	kiteAPIKey := h.config.KiteAPIKey
	if kiteAPIKey == "" {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "No Kite API credentials configured. Set oauth_client_id and oauth_client_secret in your MCP client config."})
		return
	}

	h.redirectToKiteLogin(w, r, kiteAPIKey, stateData)
}

// redirectToKiteLogin packs the OAuth state and redirects to Kite's login page.
func (h *Handler) redirectToKiteLogin(w http.ResponseWriter, r *http.Request, kiteAPIKey string, stateData oauthState) {
	stateJSON, err := json.Marshal(stateData)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	encodedState := base64.URLEncoding.EncodeToString(stateJSON)
	signedState := h.signer.Sign(encodedState)

	redirectParams := "flow=oauth&data=" + url.QueryEscape(signedState)
	kiteURL := fmt.Sprintf("https://kite.zerodha.com/connect/login?api_key=%s&v=3&redirect_params=%s",
		kiteAPIKey, url.QueryEscape(redirectParams))
	h.logger.Info("Redirecting to Kite login", "client_id", stateData.ClientID, "api_key", kiteAPIKey[:8]+"...", "registry_flow", stateData.RegistryKey != "")
	http.Redirect(w, r, kiteURL, http.StatusFound)
}

// serveEmailPrompt renders the email prompt page for zero-config onboarding.
func (h *Handler) serveEmailPrompt(w http.ResponseWriter, stateData oauthState, errorMsg string) {
	if h.emailPromptTmpl == nil {
		http.Error(w, "email prompt page unavailable", http.StatusInternalServerError)
		return
	}

	// Pack the OAuth state into a signed string so it survives the email form POST
	stateJSON, err := json.Marshal(stateData)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	encodedState := base64.URLEncoding.EncodeToString(stateJSON)
	signedOAuthState := h.signer.Sign(encodedState)

	// Generate CSRF token
	csrfToken, err := generateCSRFToken()
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Path:     "/oauth/email-lookup",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   true,
	})

	data := struct {
		Title      string
		Error      string
		CSRFToken  string
		OAuthState string
	}{
		Title:      "Connect to Kite",
		Error:      errorMsg,
		CSRFToken:  csrfToken,
		OAuthState: signedOAuthState,
	}

	var buf bytes.Buffer
	if err := h.emailPromptTmpl.ExecuteTemplate(&buf, "base", data); err != nil {
		h.logger.Error("Failed to render email prompt template", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if _, err := buf.WriteTo(w); err != nil {
		h.logger.Debug("Failed to write email prompt response", "error", err)
	}
}

// HandleEmailLookup handles POST /oauth/email-lookup — looks up registry for user's email,
// then redirects to Kite login with the registered app's API key.
func (h *Handler) HandleEmailLookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form data", http.StatusBadRequest)
		return
	}

	email := strings.TrimSpace(r.FormValue("email"))
	signedOAuthState := r.FormValue("oauth_state")

	// Verify CSRF token
	csrfCookie, err := r.Cookie("csrf_token")
	csrfForm := r.FormValue("csrf_token")
	if err != nil || csrfCookie.Value == "" || csrfCookie.Value != csrfForm {
		h.logger.Warn("CSRF verification failed on email-lookup")
		// Re-render with error — need to recover oauthState from signed form field
		if st, ok := h.recoverOAuthState(signedOAuthState); ok {
			h.serveEmailPrompt(w, st, "Invalid or expired form. Please try again.")
		} else {
			http.Error(w, "invalid or expired session", http.StatusBadRequest)
		}
		return
	}

	// Recover the OAuth state from the signed form field
	st, ok := h.recoverOAuthState(signedOAuthState)
	if !ok {
		http.Error(w, "invalid or expired OAuth state", http.StatusBadRequest)
		return
	}

	if email == "" {
		h.serveEmailPrompt(w, st, "Please enter your email address.")
		return
	}

	// Look up registry for this email
	if h.registry == nil || !h.registry.HasEntries() {
		http.Error(w, "key registry not configured", http.StatusInternalServerError)
		return
	}

	apiKey, _, ok := h.registry.GetByEmail(email)
	if !ok {
		h.logger.Info("Email not found in key registry", "email", email)
		h.serveEmailPrompt(w, st, "No app registered for this email. Contact your admin.")
		return
	}

	// Set the RegistryKey in the state so callback knows to use registry credentials
	st.RegistryKey = apiKey
	h.logger.Info("Registry lookup successful, redirecting to Kite login", "email", email, "api_key", apiKey[:8]+"...")

	// Redirect to Kite login with the registry-provided API key
	h.redirectToKiteLogin(w, r, apiKey, st)
}

// recoverOAuthState decodes and verifies a signed OAuth state string.
func (h *Handler) recoverOAuthState(signed string) (oauthState, bool) {
	if signed == "" {
		return oauthState{}, false
	}
	encodedState, err := h.signer.Verify(signed)
	if err != nil {
		return oauthState{}, false
	}
	stateJSON, err := base64.URLEncoding.DecodeString(encodedState)
	if err != nil {
		return oauthState{}, false
	}
	var st oauthState
	if err := json.Unmarshal(stateJSON, &st); err != nil {
		return oauthState{}, false
	}
	return st, true
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
	var ssoEmail string // set when email is known at callback time (for dashboard SSO)
	if h.clients.IsKiteClient(st.ClientID) {
		// Per-user Kite API key: try immediate exchange for returning users (SSO),
		// fall back to deferred exchange for first-time users.
		var immediateOK bool
		if apiSecret, ok := h.exchanger.GetSecretByAPIKey(st.ClientID); ok {
			// Returning user: stored credentials found. Try immediate exchange.
			email, err := h.exchanger.ExchangeWithCredentials(requestToken, st.ClientID, apiSecret)
			if err != nil {
				// Credentials may be stale (user changed secret at Kite).
				// Fall through to deferred exchange — fresh secret from client will fix it.
				h.logger.Warn("Immediate exchange failed, falling back to deferred",
					"client_id", st.ClientID, "error", err)
			} else {
				immediateOK = true
				ssoEmail = email
				var genErr error
				mcpCode, genErr = h.authCodes.Generate(&AuthCodeEntry{
					ClientID:      st.ClientID,
					CodeChallenge: st.CodeChallenge,
					RedirectURI:   st.RedirectURI,
					Email:         email,
				})
				if genErr != nil {
					h.logger.Error("Failed to generate auth code (immediate)", "error", genErr)
					http.Error(w, "server error", http.StatusInternalServerError)
					return
				}
				h.logger.Info("Kite OAuth callback (immediate exchange, SSO)", "email", email, "client_id", st.ClientID)
			}
		}
		if !immediateOK {
			// First-time user or stale credentials: defer exchange to /oauth/token
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
		}
	} else if st.RegistryKey != "" {
		// Registry flow: user came through the email prompt, RegistryKey is the Kite API key
		// Look up the registry's stored API secret for this key
		apiSecret := ""
		if h.registry != nil {
			if secret, ok := h.registry.GetSecretByAPIKey(st.RegistryKey); ok {
				apiSecret = secret
			}
		}
		if apiSecret == "" {
			h.logger.Error("Registry key not found in registry", "registry_key", st.RegistryKey)
			http.Error(w, "failed to authenticate: registry credentials not found", http.StatusInternalServerError)
			return
		}
		email, err := h.exchanger.ExchangeWithCredentials(requestToken, st.RegistryKey, apiSecret)
		if err != nil {
			h.logger.Error("Registry flow Kite token exchange failed", "registry_key", st.RegistryKey, "error", err)
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
			h.logger.Error("Failed to generate auth code (registry)", "error", err)
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		ssoEmail = email
		h.logger.Info("Registry flow Kite OAuth complete", "email", email, "registry_key", st.RegistryKey[:8]+"...", "client_id", st.ClientID)
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
		ssoEmail = email
		h.logger.Debug("Kite OAuth complete, issuing MCP auth code", "email", email, "client_id", st.ClientID)
	}

	// SSO: set dashboard cookie if email is known (Callback Session Establishment pattern)
	if ssoEmail != "" {
		if err := h.SetAuthCookie(w, ssoEmail); err != nil {
			h.logger.Warn("Failed to set SSO dashboard cookie", "email", ssoEmail, "error", err)
		} else {
			h.logger.Debug("SSO dashboard cookie set", "email", ssoEmail)
		}
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

	if dashEmail != "" && email != dashEmail {
		h.logger.Warn("Browser auth email mismatch", "signed_email", dashEmail, "kite_email", email)
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

// HandleLoginChoice serves a unified login page offering Kite login and admin login.
// If the user already has a valid dashboard cookie, redirects to the dashboard.
func (h *Handler) HandleLoginChoice(w http.ResponseWriter, r *http.Request) {
	redirect := r.URL.Query().Get("redirect")
	if redirect == "" {
		redirect = "/dashboard"
	}

	// If the user already has a valid cookie, skip the login page.
	if cookie, err := r.Cookie(cookieName); err == nil && cookie.Value != "" {
		if _, err := h.jwt.ValidateToken(cookie.Value, "dashboard"); err == nil {
			http.Redirect(w, r, redirect, http.StatusFound)
			return
		}
	}

	if h.loginChoiceTmpl == nil {
		http.Error(w, "Failed to load login page", http.StatusInternalServerError)
		return
	}

	data := struct {
		Title            string
		Redirect         string
		GoogleSSOEnabled bool
		ShowAdminLogin   bool
	}{
		Title:            "Sign In",
		Redirect:         redirect,
		ShowAdminLogin:   r.URL.Query().Get("admin") == "1",
		GoogleSSOEnabled: r.URL.Query().Get("admin") == "1" && h.GoogleSSOEnabled(),
	}

	var buf bytes.Buffer
	if err := h.loginChoiceTmpl.ExecuteTemplate(&buf, "base", data); err != nil {
		h.logger.Error("Failed to render login choice template", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if _, err := buf.WriteTo(w); err != nil {
		h.logger.Error("Failed to write login choice page", "error", err)
	}
}

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
		redirect = "/dashboard"
	}

	if r.Method == http.MethodPost {
		_ = r.ParseForm() // #nosec G104 -- form parse error is non-fatal; FormValue returns empty string
		email := r.FormValue("email")
		redirect = r.FormValue("redirect")
		if redirect == "" {
			redirect = "/dashboard"
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
		if !ok && h.registry != nil {
			// Fallback: check the key registry for pre-registered credentials
			if regKey, _, regOK := h.registry.GetByEmail(email); regOK {
				apiKey = regKey
				ok = true
				h.logger.Info("Browser login: found credentials via key registry", "email", email)
			}
		}
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
		if !ok && h.registry != nil {
			// Fallback: check the key registry for pre-registered credentials
			if regKey, _, regOK := h.registry.GetByEmail(email); regOK {
				apiKey = regKey
				ok = true
				h.logger.Info("Browser login: found credentials via key registry (GET)", "email", email)
			}
		}
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
	if _, err := buf.WriteTo(w); err != nil {
		h.logger.Debug("Failed to write browser login response", "error", err)
	}
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
			// Fallback for public OAuth clients (e.g., Claude Code native) that don't send
			// client_secret on token exchange. Safe because: (1) this branch is only reachable
			// for Kite API key clients (entry.RequestToken is only set in HandleKiteOAuthCallback
			// for IsKiteAPIKey clients), and (2) Kite API keys are globally unique per app.
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

// --- Admin Login ---

// SetUserStore sets the user store for admin password-based login.
func (h *Handler) SetUserStore(store AdminUserStore) {
	h.userStore = store
}

// SetGoogleSSO enables Google SSO for admin login.
func (h *Handler) SetGoogleSSO(cfg *GoogleSSOConfig) {
	h.googleSSO = cfg
}

// GoogleSSOEnabled returns true if Google SSO is configured.
func (h *Handler) GoogleSSOEnabled() bool {
	return h.googleSSO != nil
}

// HandleAdminLogin serves and processes the admin password login form.
// GET: renders admin_login.html with CSRF token.
// POST: validates CSRF, checks admin role + active status + bcrypt password.
// On success: sets auth cookie and redirects to /admin/ops.
func (h *Handler) HandleAdminLogin(w http.ResponseWriter, r *http.Request) {
	redirect := r.URL.Query().Get("redirect")
	if redirect == "" {
		redirect = "/admin/ops"
	}

	if r.Method == http.MethodPost {
		_ = r.ParseForm() // #nosec G104 -- form parse error is non-fatal; FormValue returns empty string
		email := strings.TrimSpace(strings.ToLower(r.FormValue("email")))
		password := r.FormValue("password")
		redirect = r.FormValue("redirect")
		if redirect == "" {
			redirect = "/admin/ops"
		}
		// Prevent open redirect
		if !strings.HasPrefix(redirect, "/") || strings.HasPrefix(redirect, "//") {
			redirect = "/admin/ops"
		}

		// Verify CSRF token: cookie must match form value
		csrfCookie, err := r.Cookie("csrf_token_admin")
		csrfForm := r.FormValue("csrf_token")
		if err != nil || csrfCookie.Value == "" || csrfCookie.Value != csrfForm {
			csrfToken, tokenErr := generateCSRFToken()
			if tokenErr != nil {
				h.logger.Error("Failed to generate CSRF token", "error", tokenErr)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			h.serveAdminLoginForm(w, redirect, "Invalid or missing CSRF token. Please try again.", csrfToken)
			return
		}

		// Validate user store is available
		if h.userStore == nil {
			h.serveAdminLoginForm(w, redirect, "Admin login not configured.", "")
			return
		}

		// Check role and status, then verify password.
		// Always run bcrypt even for invalid users (timing safety handled by VerifyPassword).
		role := h.userStore.GetRole(email)
		status := h.userStore.GetStatus(email)
		match, verifyErr := h.userStore.VerifyPassword(email, password)

		if verifyErr != nil {
			h.logger.Error("Password verification error", "email", email, "error", verifyErr)
		}

		if !match || role != "admin" || status != "active" {
			h.logger.Warn("Admin login failed", "email", email, "role", role, "status", status, "match", match)
			csrfToken, tokenErr := generateCSRFToken()
			if tokenErr != nil {
				h.logger.Error("Failed to generate CSRF token", "error", tokenErr)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			h.serveAdminLoginForm(w, redirect, "Invalid email or password.", csrfToken)
			return
		}

		// Success: set auth cookie and redirect
		if err := h.SetAuthCookie(w, email); err != nil {
			h.logger.Error("Failed to set auth cookie on admin login", "email", email, "error", err)
			http.Error(w, "Failed to set auth cookie", http.StatusInternalServerError)
			return
		}

		h.logger.Info("Admin password login successful", "email", email)
		http.Redirect(w, r, redirect, http.StatusFound)
		return
	}

	// GET: serve form with fresh CSRF token
	csrfToken, err := generateCSRFToken()
	if err != nil {
		h.logger.Error("Failed to generate CSRF token", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	h.serveAdminLoginForm(w, redirect, "", csrfToken)
}

// serveAdminLoginForm renders the admin login form template.
func (h *Handler) serveAdminLoginForm(w http.ResponseWriter, redirect string, errorMsg string, csrfToken string) {
	if h.adminLoginTmpl == nil {
		http.Error(w, "Failed to load admin login page", http.StatusInternalServerError)
		return
	}

	// Set CSRF token as HttpOnly cookie (different name from browser login)
	if csrfToken != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     "csrf_token_admin",
			Value:    csrfToken,
			Path:     "/auth/admin-login",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
			Secure:   true,
		})
	}

	data := struct {
		Title            string
		Redirect         string
		Error            string
		CSRFToken        string
		GoogleSSOEnabled bool
	}{
		Title:            "Admin Login",
		Redirect:         redirect,
		Error:            errorMsg,
		CSRFToken:        csrfToken,
		GoogleSSOEnabled: h.GoogleSSOEnabled(),
	}

	var buf bytes.Buffer
	if err := h.adminLoginTmpl.ExecuteTemplate(&buf, "base", data); err != nil {
		h.logger.Error("Failed to render admin login template", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if _, err := buf.WriteTo(w); err != nil {
		h.logger.Debug("Failed to write admin login response", "error", err)
	}
}

// --- Internal helpers ---

// writeJSON writes a JSON response with the given status code.
func (h *Handler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to write JSON response", "error", err)
	}
}
