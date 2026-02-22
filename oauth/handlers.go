package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// Handler implements all OAuth 2.1 HTTP endpoints.
type Handler struct {
	config      *Config
	jwt         *JWTManager
	authCodes   *AuthCodeStore
	clients     *ClientStore
	googleOAuth *oauth2.Config
	logger      *slog.Logger
}

// NewHandler creates a new OAuth handler. Config must be validated first.
func NewHandler(cfg *Config) *Handler {
	return &Handler{
		config:    cfg,
		jwt:       NewJWTManager(cfg.JWTSecret, cfg.TokenExpiry),
		authCodes: NewAuthCodeStore(),
		clients:   NewClientStore(),
		googleOAuth: &oauth2.Config{
			ClientID:     cfg.GoogleClientID,
			ClientSecret: cfg.GoogleClientSecret,
			RedirectURL:  cfg.ExternalURL + "/oauth/google/callback",
			Scopes:       []string{"openid", "email"},
			Endpoint:     google.Endpoint,
		},
		logger: cfg.Logger,
	}
}

// oauthState is packed into Google's state parameter to round-trip MCP client data.
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
		"issuer":                             h.config.ExternalURL,
		"authorization_endpoint":             h.config.ExternalURL + "/oauth/authorize",
		"token_endpoint":                     h.config.ExternalURL + "/oauth/token",
		"registration_endpoint":              h.config.ExternalURL + "/oauth/register",
		"response_types_supported":           []string{"code"},
		"grant_types_supported":              []string{"authorization_code"},
		"code_challenge_methods_supported":   []string{"S256"},
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
		"client_id":                clientID,
		"client_secret":            clientSecret,
		"redirect_uris":            req.RedirectURIs,
		"client_name":              req.ClientName,
		"grant_types":              []string{"authorization_code"},
		"response_types":           []string{"code"},
		"token_endpoint_auth_method": "client_secret_post",
	})
}

// --- Authorization Endpoint ---

// Authorize handles GET /oauth/authorize — validates params and redirects to Google.
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

	// Validate client
	if !h.clients.ValidateRedirectURI(clientID, redirectURI) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "unknown client_id or redirect_uri mismatch"})
		return
	}

	// Pack MCP client state into Google's state param
	stateData := oauthState{
		ClientID:      clientID,
		RedirectURI:   redirectURI,
		CodeChallenge: codeChallenge,
		State:         state,
	}
	stateJSON, _ := json.Marshal(stateData)
	encodedState := base64.URLEncoding.EncodeToString(stateJSON)

	// Redirect to Google
	googleURL := h.googleOAuth.AuthCodeURL(encodedState, oauth2.AccessTypeOffline)
	h.logger.Info("Redirecting to Google OAuth", "client_id", clientID)
	http.Redirect(w, r, googleURL, http.StatusFound)
}

// --- Google Callback ---

// GoogleCallback handles GET /oauth/google/callback — exchanges Google code, issues MCP auth code.
func (h *Handler) GoogleCallback(w http.ResponseWriter, r *http.Request) {
	// Check for Google errors
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		h.logger.Warn("Google OAuth error", "error", errParam)
		http.Error(w, "Google OAuth error: "+errParam, http.StatusBadRequest)
		return
	}

	googleCode := r.URL.Query().Get("code")
	encodedState := r.URL.Query().Get("state")
	if googleCode == "" || encodedState == "" {
		http.Error(w, "missing code or state", http.StatusBadRequest)
		return
	}

	// Decode our packed state
	stateJSON, err := base64.URLEncoding.DecodeString(encodedState)
	if err != nil {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}
	var st oauthState
	if err := json.Unmarshal(stateJSON, &st); err != nil {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}

	// Exchange Google code for token
	token, err := h.googleOAuth.Exchange(r.Context(), googleCode)
	if err != nil {
		h.logger.Error("Google token exchange failed", "error", err)
		http.Error(w, "failed to exchange Google token", http.StatusInternalServerError)
		return
	}

	// Get user email from Google userinfo
	email, err := h.getGoogleEmail(token)
	if err != nil {
		h.logger.Error("Failed to get Google email", "error", err)
		http.Error(w, "failed to get user info", http.StatusInternalServerError)
		return
	}

	// Check allowlist
	if !h.config.IsEmailAllowed(email) {
		h.logger.Warn("Email not allowed", "email", email)
		http.Error(w, "access denied: email not allowed", http.StatusForbidden)
		return
	}

	// Generate MCP authorization code
	mcpCode, err := h.authCodes.Generate(&AuthCodeEntry{
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

	h.logger.Info("Google OAuth complete, issuing MCP auth code", "email", email, "client_id", st.ClientID)

	// Redirect back to MCP client
	sep := "?"
	if strings.Contains(st.RedirectURI, "?") {
		sep = "&"
	}
	redirectURL := st.RedirectURI + sep + "code=" + mcpCode
	if st.State != "" {
		redirectURL += "&state=" + st.State
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// getGoogleEmail fetches the user's email from Google userinfo API.
func (h *Handler) getGoogleEmail(token *oauth2.Token) (string, error) {
	client := h.googleOAuth.Client(nil, token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var info struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return "", err
	}
	if info.Email == "" {
		return "", fmt.Errorf("no email in Google response")
	}
	return info.Email, nil
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
	if client.ClientSecret != clientSecret {
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

	// Generate JWT
	accessToken, err := h.jwt.GenerateToken(entry.Email, clientID)
	if err != nil {
		h.logger.Error("Failed to generate JWT", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}

	h.logger.Info("Issued JWT access token", "email", entry.Email, "client_id", clientID)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   int(h.config.TokenExpiry.Seconds()),
	})
}

// GetGoogleAuthURL generates a Google OAuth URL for browser-based dashboard login.
// The state parameter is passed through and returned in the callback.
func (h *Handler) GetGoogleAuthURL(state string) string {
	// Use a separate config with dashboard callback URL
	dashboardOAuth := *h.googleOAuth
	dashboardOAuth.RedirectURL = h.config.ExternalURL + "/dashboard/callback"
	return dashboardOAuth.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

// ExchangeCodeForEmail exchanges a Google OAuth code (from dashboard callback) for the user's email.
func (h *Handler) ExchangeCodeForEmail(ctx context.Context, code string) (string, error) {
	dashboardOAuth := *h.googleOAuth
	dashboardOAuth.RedirectURL = h.config.ExternalURL + "/dashboard/callback"

	token, err := dashboardOAuth.Exchange(ctx, code)
	if err != nil {
		return "", fmt.Errorf("google token exchange: %w", err)
	}

	email, err := h.getGoogleEmail(token)
	if err != nil {
		return "", fmt.Errorf("get google email: %w", err)
	}

	if !h.config.IsEmailAllowed(email) {
		return "", fmt.Errorf("email not allowed: %s", email)
	}

	return email, nil
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}
