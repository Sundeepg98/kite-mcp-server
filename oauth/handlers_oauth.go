package oauth

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

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
		h.clients.AddRedirectURI(clientID, redirectURI)
	}

	if !h.clients.ValidateRedirectURI(clientID, redirectURI) {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "redirect_uri mismatch for client"})
		return
	}

	stateData := oauthState{
		ClientID:      clientID,
		RedirectURI:   redirectURI,
		CodeChallenge: codeChallenge,
		State:         state,
	}

	if h.clients.IsKiteClient(clientID) {
		h.redirectToKiteLogin(w, r, clientID, stateData)
		return
	}

	if h.registry != nil && h.registry.HasEntries() {
		h.serveEmailPrompt(w, stateData, "")
		return
	}

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
	kiteURL := "https://kite.zerodha.com/connect/login?api_key=" + kiteAPIKey + "&v=3&redirect_params=" + url.QueryEscape(redirectParams)
	h.logger.Info("Redirecting to Kite login", "client_id", stateData.ClientID, "api_key", kiteAPIKey[:8]+"...", "registry_flow", stateData.RegistryKey != "")
	http.Redirect(w, r, kiteURL, http.StatusFound)
}

// serveEmailPrompt renders the email prompt page for zero-config onboarding.
func (h *Handler) serveEmailPrompt(w http.ResponseWriter, stateData oauthState, errorMsg string) {
	if h.emailPromptTmpl == nil {
		http.Error(w, "email prompt page unavailable", http.StatusInternalServerError)
		return
	}

	stateJSON, err := json.Marshal(stateData)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	encodedState := base64.URLEncoding.EncodeToString(stateJSON)
	signedOAuthState := h.signer.Sign(encodedState)

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

	csrfCookie, err := r.Cookie("csrf_token")
	csrfForm := r.FormValue("csrf_token")
	if err != nil || csrfCookie.Value == "" || csrfCookie.Value != csrfForm {
		h.logger.Warn("CSRF verification failed on email-lookup")
		if st, ok := h.recoverOAuthState(signedOAuthState); ok {
			h.serveEmailPrompt(w, st, "Invalid or expired form. Please try again.")
		} else {
			http.Error(w, "invalid or expired session", http.StatusBadRequest)
		}
		return
	}

	st, ok := h.recoverOAuthState(signedOAuthState)
	if !ok {
		http.Error(w, "invalid or expired OAuth state", http.StatusBadRequest)
		return
	}

	if email == "" {
		h.serveEmailPrompt(w, st, "Please enter your email address.")
		return
	}

	if h.registry == nil || !h.registry.HasEntries() {
		http.Error(w, "key registry not configured", http.StatusInternalServerError)
		return
	}

	reg, ok := h.registry.GetByEmail(email)
	if !ok {
		h.logger.Info("Email not found in key registry", "email", email)
		h.serveEmailPrompt(w, st, "No app registered for this email. Contact your admin.")
		return
	}

	st.RegistryKey = reg.APIKey
	h.logger.Info("Registry lookup successful, redirecting to Kite login", "email", email, "api_key", reg.APIKey[:8]+"...")

	h.redirectToKiteLogin(w, r, reg.APIKey, st)
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

// --- Token Endpoint ---

// Token handles POST /oauth/token — exchanges auth code + PKCE verifier for JWT.
func (h *Handler) Token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)

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

	client, ok := h.clients.Get(clientID)
	if !ok {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	if !client.IsKiteAPIKey && client.ClientSecret != clientSecret {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}

	entry, ok := h.authCodes.Consume(code)
	if !ok {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "code expired or already used"})
		return
	}

	if entry.ClientID != clientID {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "client_id mismatch"})
		return
	}

	hash := sha256.Sum256([]byte(codeVerifier))
	computed := base64.RawURLEncoding.EncodeToString(hash[:])
	if computed != entry.CodeChallenge {
		h.logger.Warn("PKCE verification failed", "client_id", clientID)
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "PKCE verification failed"})
		return
	}

	email := entry.Email
	if email == "" && entry.RequestToken != "" {
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
