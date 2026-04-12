package oauth

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

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
	redirect := "/admin/ops"
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

	var email string
	var err error
	if dashEmail != "" {
		apiKey, apiSecret, ok := h.exchanger.GetCredentials(dashEmail)
		if !ok {
			h.logger.Error("No stored credentials for browser auth user", "email", dashEmail)
			http.Error(w, "Authentication failed: no credentials found", http.StatusUnauthorized)
			return
		}
		email, err = h.exchanger.ExchangeWithCredentials(requestToken, apiKey, apiSecret)
	} else {
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
		ShowAdminLogin:   false,
		GoogleSSOEnabled: h.GoogleSSOEnabled(),
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
			if reg, regOK := h.registry.GetByEmail(email); regOK {
				apiKey = reg.APIKey
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
			if reg, regOK := h.registry.GetByEmail(email); regOK {
				apiKey = reg.APIKey
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
