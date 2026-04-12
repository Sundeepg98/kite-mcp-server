package oauth

import (
	"bytes"
	"net/http"
	"strings"
)

// --- Admin Login ---

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

		if err := h.SetAuthCookie(w, email); err != nil { // COVERAGE: unreachable — HS256 signing never fails
			h.logger.Error("Failed to set auth cookie on admin login", "email", email, "error", err)
			http.Error(w, "Failed to set auth cookie", http.StatusInternalServerError)
			return
		}

		h.logger.Info("Admin password login successful", "email", email)
		http.Redirect(w, r, redirect, http.StatusFound)
		return
	}

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
