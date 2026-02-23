package oauth

import (
	"crypto/sha256"
	"encoding/base64"
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
}

// Handler implements all OAuth 2.1 HTTP endpoints.
type Handler struct {
	config    *Config
	jwt       *JWTManager
	authCodes *AuthCodeStore
	clients   *ClientStore
	signer    Signer
	exchanger KiteExchanger
	logger    *slog.Logger
}

// NewHandler creates a new OAuth handler. Config must be validated first.
func NewHandler(cfg *Config, signer Signer, exchanger KiteExchanger) *Handler {
	return &Handler{
		config:    cfg,
		jwt:       NewJWTManager(cfg.JWTSecret, cfg.TokenExpiry),
		authCodes: NewAuthCodeStore(),
		clients:   NewClientStore(),
		signer:    signer,
		exchanger: exchanger,
		logger:    cfg.Logger,
	}
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
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"resource":              h.config.ExternalURL + "/mcp",
		"authorization_servers": []string{h.config.ExternalURL},
	})
}

// AuthServerMetadata serves RFC 8414 OAuth Authorization Server Metadata.
func (h *Handler) AuthServerMetadata(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
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

	var req struct {
		RedirectURIs []string `json:"redirect_uris"`
		ClientName   string   `json:"client_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "invalid JSON body"})
		return
	}
	if len(req.RedirectURIs) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "redirect_uris required"})
		return
	}

	clientID, clientSecret, err := h.clients.Register(req.RedirectURIs, req.ClientName)
	if err != nil {
		h.logger.Error("Failed to register client", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}

	h.logger.Info("Registered OAuth client", "client_id", clientID, "client_name", req.ClientName)

	writeJSON(w, http.StatusCreated, map[string]interface{}{
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
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")
	state := q.Get("state")
	responseType := q.Get("response_type")

	// Validate required params
	if responseType != "code" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_response_type"})
		return
	}
	if clientID == "" || redirectURI == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "client_id and redirect_uri required"})
		return
	}
	if codeChallengeMethod != "S256" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "code_challenge_method must be S256"})
		return
	}
	if codeChallenge == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "code_challenge required"})
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
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "redirect_uri mismatch for client"})
		return
	}

	// Pack MCP client state into signed redirect_params
	stateData := oauthState{
		ClientID:      clientID,
		RedirectURI:   redirectURI,
		CodeChallenge: codeChallenge,
		State:         state,
	}
	stateJSON, _ := json.Marshal(stateData)
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
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "No Kite API credentials configured. Set oauth_client_id and oauth_client_secret in your MCP client config."})
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
		h.logger.Info("Kite OAuth complete, issuing MCP auth code", "email", email, "client_id", st.ClientID)
	}

	// Build redirect URL back to MCP client
	sep := "?"
	if strings.Contains(st.RedirectURI, "?") {
		sep = "&"
	}
	redirectURL := st.RedirectURI + sep + "code=" + mcpCode
	if st.State != "" {
		redirectURL += "&state=" + st.State
	}

	// Serve the same success page as the non-OAuth callback, with auto-redirect
	tmpl, err := template.ParseFS(templates.FS, "base.html", "login_success.html")
	if err != nil {
		h.logger.Error("Failed to parse success template, falling back to redirect", "error", err)
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
	if err := tmpl.ExecuteTemplate(w, "base", data); err != nil {
		h.logger.Error("Failed to render success template", "error", err)
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}
}

// --- Kite Dashboard Callback ---

// HandleKiteDashCallback handles the Kite callback for dashboard login flow.
// Called when flow=dash in the callback query params.
func (h *Handler) HandleKiteDashCallback(w http.ResponseWriter, r *http.Request, requestToken string) {
	if requestToken == "" {
		http.Error(w, "missing request_token", http.StatusBadRequest)
		return
	}

	// Read and verify signed redirect target
	signedTarget := r.URL.Query().Get("target")
	redirect := "/admin/ops" // default
	if signedTarget != "" {
		decoded, err := h.signer.Verify(signedTarget)
		if err != nil {
			h.logger.Warn("Invalid dashboard callback signature", "error", err)
			// Fall through to default redirect rather than erroring
		} else {
			redirect = decoded
		}
	}

	// Exchange Kite request_token for user identity
	email, err := h.exchanger.ExchangeRequestToken(requestToken)
	if err != nil {
		h.logger.Error("Kite dashboard token exchange failed", "error", err)
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	// Set JWT cookie for browser auth
	if err := h.SetAuthCookie(w, email); err != nil {
		h.logger.Error("Failed to set auth cookie", "error", err)
		http.Error(w, "Failed to set auth cookie", http.StatusInternalServerError)
		return
	}

	h.logger.Info("Dashboard login successful", "email", email)
	http.Redirect(w, r, redirect, http.StatusFound)
}

// --- Dashboard Login URL ---

// GenerateDashboardLoginURL generates a Kite login URL for dashboard browser auth.
// The redirect path is signed and passed through as redirect_params.
func (h *Handler) GenerateDashboardLoginURL(redirect string) string {
	signedTarget := h.signer.Sign(redirect)
	redirectParams := "flow=dash&target=" + url.QueryEscape(signedTarget)
	return h.generateKiteLoginURL(redirectParams)
}

// --- Token Endpoint ---

// Token handles POST /oauth/token — exchanges auth code + PKCE verifier for JWT.
func (h *Handler) Token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}

	grantType := r.FormValue("grant_type")
	code := r.FormValue("code")
	codeVerifier := r.FormValue("code_verifier")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	if grantType != "authorization_code" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
		return
	}
	if code == "" || codeVerifier == "" || clientID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "code, code_verifier, and client_id required"})
		return
	}

	// Validate client credentials
	client, ok := h.clients.Get(clientID)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	// For Kite API key clients, skip secret comparison — validated by Kite's GenerateSession instead
	if !client.IsKiteAPIKey && client.ClientSecret != clientSecret {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}

	// Consume auth code
	entry, ok := h.authCodes.Consume(code)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "code expired or already used"})
		return
	}

	// Verify client_id matches
	if entry.ClientID != clientID {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "client_id mismatch"})
		return
	}

	// PKCE S256 verification: SHA256(code_verifier) must equal stored code_challenge
	hash := sha256.Sum256([]byte(codeVerifier))
	computed := base64.RawURLEncoding.EncodeToString(hash[:])
	if computed != entry.CodeChallenge {
		h.logger.Warn("PKCE verification failed", "client_id", clientID)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "PKCE verification failed"})
		return
	}

	// Resolve email — either already known (normal flow) or needs deferred exchange
	email := entry.Email
	if email == "" && entry.RequestToken != "" {
		// Deferred exchange: client_id = Kite API key, client_secret = Kite API secret
		if clientSecret == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "client_secret (Kite API secret) required for per-user authentication"})
			return
		}
		var err error
		email, err = h.exchanger.ExchangeWithCredentials(entry.RequestToken, clientID, clientSecret)
		if err != nil {
			h.logger.Error("Deferred Kite token exchange failed", "client_id", clientID, "error", err)
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "Kite authentication failed — check your API key and secret"})
			return
		}
		h.logger.Info("Deferred Kite exchange successful", "email", email, "client_id", clientID)
	}

	if email == "" {
		h.logger.Error("No email resolved for token", "client_id", clientID)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error", "error_description": "failed to determine user identity"})
		return
	}

	// Generate JWT
	accessToken, err := h.jwt.GenerateToken(email, clientID)
	if err != nil {
		h.logger.Error("Failed to generate JWT", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}

	h.logger.Info("Issued JWT access token", "email", email, "client_id", clientID)

	writeJSON(w, http.StatusOK, map[string]interface{}{
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
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}
