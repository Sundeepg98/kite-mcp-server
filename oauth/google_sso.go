package oauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// GoogleSSOConfig holds configuration for Google OAuth SSO.
type GoogleSSOConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

// oauthConfig returns the golang.org/x/oauth2 config for Google.
func (g *GoogleSSOConfig) oauthConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     g.ClientID,
		ClientSecret: g.ClientSecret,
		RedirectURL:  g.RedirectURL,
		Scopes:       []string{"openid", "email", "profile"},
		Endpoint:     google.Endpoint,
	}
}

// googleStateCookieName is the short-lived cookie for CSRF state verification.
const googleStateCookieName = "google_oauth_state"

// HandleGoogleLogin redirects the user to the Google consent screen.
func (h *Handler) HandleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	if h.googleSSO == nil {
		http.Error(w, "Google SSO not configured", http.StatusNotFound)
		return
	}

	// Generate a random state parameter for CSRF protection.
	stateBytes := make([]byte, 32)
	if _, err := rand.Read(stateBytes); err != nil {
		h.logger.Error("Failed to generate Google SSO state", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	state := base64.URLEncoding.EncodeToString(stateBytes)

	// Encode the redirect URL into the state cookie so we can restore it after callback.
	redirect := r.URL.Query().Get("redirect")
	if redirect == "" {
		redirect = "/dashboard"
	}
	if !strings.HasPrefix(redirect, "/") || strings.HasPrefix(redirect, "//") {
		redirect = "/dashboard"
	}

	// Store state + redirect in a short-lived cookie.
	cookieValue := state + "|" + redirect
	http.SetCookie(w, &http.Cookie{
		Name:     googleStateCookieName,
		Value:    cookieValue,
		Path:     "/auth/google/callback",
		MaxAge:   300, // 5 minutes
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	authURL := h.googleSSO.oauthConfig().AuthCodeURL(state, oauth2.AccessTypeOffline)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// HandleGoogleCallback handles the OAuth callback from Google.
func (h *Handler) HandleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	if h.googleSSO == nil {
		http.Error(w, "Google SSO not configured", http.StatusNotFound)
		return
	}

	// Verify state parameter against cookie (CSRF protection).
	stateCookie, err := r.Cookie(googleStateCookieName)
	if err != nil || stateCookie.Value == "" {
		h.logger.Warn("Google SSO callback: missing state cookie")
		http.Error(w, "Invalid state: missing cookie", http.StatusBadRequest)
		return
	}

	// Parse state and redirect from cookie value.
	parts := strings.SplitN(stateCookie.Value, "|", 2)
	if len(parts) != 2 {
		h.logger.Warn("Google SSO callback: malformed state cookie")
		http.Error(w, "Invalid state: malformed cookie", http.StatusBadRequest)
		return
	}
	expectedState := parts[0]
	redirect := parts[1]

	// Clear the state cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     googleStateCookieName,
		Value:    "",
		Path:     "/auth/google/callback",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	// Check for OAuth error response.
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		h.logger.Warn("Google SSO callback error", "error", errParam)
		http.Redirect(w, r, "/auth/admin-login?redirect="+url.QueryEscape(redirect), http.StatusFound)
		return
	}

	// Verify state matches.
	queryState := r.URL.Query().Get("state")
	if queryState != expectedState {
		h.logger.Warn("Google SSO callback: state mismatch")
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	// Exchange authorization code for token.
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	token, err := h.googleSSO.oauthConfig().Exchange(ctx, code)
	if err != nil {
		h.logger.Error("Google SSO token exchange failed", "error", err)
		http.Error(w, "Failed to exchange authorization code", http.StatusInternalServerError)
		return
	}

	// Fetch user info from Google.
	email, err := fetchGoogleUserInfo(ctx, token.AccessToken)
	if err != nil {
		h.logger.Error("Google SSO userinfo fetch failed", "error", err)
		http.Error(w, "Failed to fetch user info", http.StatusInternalServerError)
		return
	}

	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" {
		http.Error(w, "No email returned from Google", http.StatusBadRequest)
		return
	}

	if h.userStore == nil {
		h.logger.Error("Google SSO: user store not configured")
		http.Error(w, "Login not configured", http.StatusInternalServerError)
		return
	}

	// Auto-create user on first Google login (role=trader).
	// Existing admins keep their admin role (EnsureGoogleUser only creates if missing).
	h.userStore.EnsureGoogleUser(email)

	// Link user to admin if a pre-registered app exists for this email.
	if h.registry != nil {
		if reg, found := h.registry.GetByEmail(email); found && reg != nil && reg.RegisteredBy != "" {
			if setter, ok := h.userStore.(interface{ SetAdminEmail(string, string) error }); ok {
				if err := setter.SetAdminEmail(email, reg.RegisteredBy); err != nil {
					h.logger.Error("Failed to link user to admin", "email", email, "admin", reg.RegisteredBy, "error", err)
				} else {
					h.logger.Info("Linked Google SSO user to admin", "email", email, "admin", reg.RegisteredBy)
				}
			}
		}
	}

	status := h.userStore.GetStatus(email)
	if status != "active" {
		h.logger.Warn("Google SSO login denied: account not active", "email", email, "status", status)
		http.Error(w, "Account is suspended or inactive.", http.StatusForbidden)
		return
	}

	// Set auth cookie and redirect.
	if err := h.SetAuthCookie(w, email); err != nil {
		h.logger.Error("Failed to set auth cookie on Google SSO login", "email", email, "error", err)
		http.Error(w, "Failed to set auth cookie", http.StatusInternalServerError)
		return
	}

	role := h.userStore.GetRole(email)
	h.logger.Info("Google SSO login successful", "email", email, "role", role)
	if !strings.HasPrefix(redirect, "/") || strings.HasPrefix(redirect, "//") {
		if role == "admin" {
			redirect = "/admin/ops"
		} else {
			redirect = "/dashboard"
		}
	}
	http.Redirect(w, r, redirect, http.StatusFound)
}

// fetchGoogleUserInfo calls the Google userinfo endpoint and returns the email.
func fetchGoogleUserInfo(ctx context.Context, accessToken string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.googleapis.com/oauth2/v2/userinfo", nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch userinfo: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("userinfo returned %d: %s", resp.StatusCode, string(body))
	}

	var info struct {
		Email         string `json:"email"`
		VerifiedEmail bool   `json:"verified_email"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return "", fmt.Errorf("decode userinfo: %w", err)
	}

	if !info.VerifiedEmail {
		return "", fmt.Errorf("email not verified: %s", info.Email)
	}

	return info.Email, nil
}
