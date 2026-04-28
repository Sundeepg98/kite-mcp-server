package oauth

import (
	"bytes"
	"net/http"
	"strings"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/users"
)

// --- Admin MFA (TOTP) — enrollment + verification + cookie middleware ---
//
// This file ships Slice 2 of the MFA-on-admin-actions deliverable
// (closes docs/SECURITY_POSTURE.md §4.3 / docs/access-control.md §8).
//
// Flow:
//   1. Admin authenticates via password / Google SSO (existing path).
//   2. The dashboard auth middleware sets `kite_jwt` cookie + email-in-ctx.
//   3. RequireAdminMFA wraps the admin gate. It checks:
//      a. email-in-ctx present (else 401)
//      b. user has TOTP enrolled (else redirect to /auth/admin-mfa/enroll)
//      c. valid kite_admin_mfa cookie present (else redirect to /verify)
//      Only when all three hold does the request reach the inner handler.
//   4. Enrollment / verification endpoints set the MFA-verified cookie
//      with a SHORT expiry (15 min). After that the user is asked again.
//
// The MFA cookie uses the existing JWT manager with a distinct audience
// ("admin-mfa") so a stolen MFA token cannot be replayed against any
// other endpoint that takes a JWT with a different audience.

// adminMFACookieName is the cookie holding the short-lived MFA-verified JWT.
const adminMFACookieName = "kite_admin_mfa"

// adminMFAAudience scopes the MFA cookie's JWT — every gated endpoint
// validates against this audience so leaked MFA tokens cannot be replayed
// against the dashboard or MCP scopes.
const adminMFAAudience = "admin-mfa"

// adminMFATokenExpiry is the lifetime of an MFA-verified session.
// 15 minutes is the conventional sudo / MFA-elevation window — long
// enough for routine admin work, short enough to bound stolen-cookie
// replay risk.
const adminMFATokenExpiry = 15 * time.Minute

// MintAdminMFAToken issues a short-lived JWT marking the user's MFA
// gate as passed. Used by both enroll and verify success paths and by
// tests. Exposed (not unexported) because the dashboard middleware
// occasionally needs to mint via a different code path.
func (h *Handler) MintAdminMFAToken(email string) (string, error) {
	return h.jwt.GenerateTokenWithExpiry(email, adminMFAAudience, adminMFATokenExpiry)
}

// setAdminMFACookie writes the MFA-verified cookie. HttpOnly + Secure +
// SameSite=Lax — same hardening as the dashboard cookie, just shorter
// MaxAge.
func (h *Handler) setAdminMFACookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     adminMFACookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(adminMFATokenExpiry.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// HandleAdminMFAEnroll handles enrollment.
//
// GET — fresh flow: generate a new TOTP secret, render the enrollment
// form (manual-entry secret + otpauth:// link). POST — verify the
// supplied code matches the freshly-generated secret; if so, persist
// the secret on the user store and mint the MFA cookie.
//
// The secret is round-tripped through a hidden form field rather than
// stored server-side at GET time. Only the SUCCESSFUL POST persists.
// This avoids retaining a half-enrolled secret if the user abandons the
// flow.
func (h *Handler) HandleAdminMFAEnroll(w http.ResponseWriter, r *http.Request) {
	email := EmailFromContext(r.Context())
	if email == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	redirect := safeRedirect(r.URL.Query().Get("redirect"), "/admin/ops")

	if r.Method == http.MethodPost {
		_ = r.ParseForm() //nolint:errcheck // form parse error -> FormValue returns empty
		secret := r.FormValue("secret")
		code := r.FormValue("code")
		formRedirect := safeRedirect(r.FormValue("redirect"), "/admin/ops")

		// CSRF: cookie token must match form token.
		if !h.checkAdminMFACSRF(r) {
			h.serveAdminMFAEnrollForm(w, email, secret, formRedirect, "Invalid or expired CSRF token. Please try again.")
			return
		}
		// Verify the code matches the supplied secret. This is the
		// "you typed the right code from your app" check — no DB
		// touch happens until verification succeeds.
		if !users.VerifyTOTPCode(secret, code, time.Now(), users.TOTPSkewSteps) {
			h.serveAdminMFAEnrollForm(w, email, secret, formRedirect, "Code did not match. Try again with the latest code from your authenticator.")
			return
		}
		// Persist. The store-layer enforces "admin role" defence in depth.
		if err := h.userStore.SetTOTPSecret(email, secret); err != nil {
			h.logger.Error("Failed to persist TOTP secret", "email", email, "error", err)
			h.serveAdminMFAEnrollForm(w, email, secret, formRedirect, "Could not save enrollment: "+err.Error())
			return
		}
		// Mint the MFA cookie so the very next admin request passes.
		token, err := h.MintAdminMFAToken(email)
		if err != nil { // COVERAGE: unreachable — HS256 SignedString never fails.
			h.logger.Error("Failed to mint MFA token after enroll", "email", email, "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		h.setAdminMFACookie(w, token)
		h.logger.Info("Admin MFA enrolled", "email", email)
		http.Redirect(w, r, formRedirect, http.StatusFound)
		return
	}

	// GET: fresh secret + render form.
	secret, err := users.GenerateTOTPSecret()
	if err != nil { // COVERAGE: unreachable — Go 1.25 crypto/rand.Read is fatal on failure.
		h.logger.Error("Failed to generate TOTP secret", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.serveAdminMFAEnrollForm(w, email, secret, redirect, "")
}

// HandleAdminMFAVerify handles ongoing verification (after enrollment).
//
// GET — render the 6-digit code form. If the user hasn't enrolled yet,
// redirect to /enroll. POST — verify the code against the stored
// secret. On success, mint the MFA cookie.
func (h *Handler) HandleAdminMFAVerify(w http.ResponseWriter, r *http.Request) {
	email := EmailFromContext(r.Context())
	if email == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	redirect := safeRedirect(r.URL.Query().Get("redirect"), "/admin/ops")

	// If not enrolled, route to enrollment first — avoids a confusing
	// "verify failed" loop for an unenrolled admin.
	if h.userStore == nil || !h.userStore.HasTOTP(email) {
		http.Redirect(w, r, "/auth/admin-mfa/enroll?redirect="+redirect, http.StatusFound)
		return
	}

	if r.Method == http.MethodPost {
		_ = r.ParseForm() //nolint:errcheck // FormValue handles missing values.
		code := r.FormValue("code")
		formRedirect := safeRedirect(r.FormValue("redirect"), "/admin/ops")

		if !h.checkAdminMFACSRF(r) {
			h.serveAdminMFAVerifyForm(w, formRedirect, "Invalid or expired CSRF token. Please try again.")
			return
		}
		ok, err := h.userStore.VerifyTOTP(email, code)
		if err != nil { // COVERAGE: error path requires infrastructure failure (e.g. encryption key missing).
			h.logger.Error("MFA verify infrastructure error", "email", email, "error", err)
			h.serveAdminMFAVerifyForm(w, formRedirect, "Verification temporarily unavailable. Try again.")
			return
		}
		if !ok {
			h.logger.Warn("Admin MFA verification failed", "email", email)
			h.serveAdminMFAVerifyForm(w, formRedirect, "Code did not match. Try again with the latest code from your authenticator.")
			return
		}
		token, err := h.MintAdminMFAToken(email)
		if err != nil { // COVERAGE: unreachable — HS256 SignedString never fails.
			h.logger.Error("Failed to mint MFA token after verify", "email", email, "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		h.setAdminMFACookie(w, token)
		h.logger.Info("Admin MFA verified", "email", email)
		http.Redirect(w, r, formRedirect, http.StatusFound)
		return
	}

	h.serveAdminMFAVerifyForm(w, redirect, "")
}

// RequireAdminMFA is the middleware that gates admin paths.
// Preconditions: the upstream admin auth middleware has already set
// email-in-ctx (via ContextWithEmail). RequireAdminMFA checks:
//   - email present (else 401 — defensive; should never trip in prod)
//   - kite_admin_mfa cookie present and valid for THIS email
//
// If the cookie is missing/invalid, the user is redirected to
// /auth/admin-mfa/enroll (un-enrolled) or /verify (enrolled). The
// original path is preserved as the redirect target so they land back
// where they were after the gate clears.
func (h *Handler) RequireAdminMFA(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		email := EmailFromContext(r.Context())
		if email == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Cookie + audience match means MFA was passed within the last
		// adminMFATokenExpiry window. Subject must match the current
		// request's email — defends against a stolen cookie minted for
		// a different account.
		if cookie, err := r.Cookie(adminMFACookieName); err == nil && cookie.Value != "" {
			if claims, err := h.jwt.ValidateToken(cookie.Value, adminMFAAudience); err == nil {
				if strings.EqualFold(claims.Subject, email) {
					next.ServeHTTP(w, r)
					return
				}
			}
		}

		// Route to verify or enroll, preserving the original path so
		// the user lands back where they were.
		dest := "/auth/admin-mfa/verify"
		if h.userStore == nil || !h.userStore.HasTOTP(email) {
			dest = "/auth/admin-mfa/enroll"
		}
		http.Redirect(w, r, dest+"?redirect="+r.URL.Path, http.StatusFound)
	})
}

// --- helpers ---

// checkAdminMFACSRF compares the CSRF token in the cookie against the
// form value. Returns true on match, false otherwise. The CSRF cookie
// is set by serveAdminMFAEnrollForm / serveAdminMFAVerifyForm on every
// GET render, with a Path of /auth/admin-mfa so the same cookie covers
// both endpoints.
func (h *Handler) checkAdminMFACSRF(r *http.Request) bool {
	cookie, err := r.Cookie("csrf_token_admin_mfa")
	if err != nil || cookie.Value == "" {
		return false
	}
	form := r.FormValue("csrf_token")
	if form == "" {
		return false
	}
	return cookie.Value == form
}

// serveAdminMFAEnrollForm renders the enrollment template.
func (h *Handler) serveAdminMFAEnrollForm(w http.ResponseWriter, email, secret, redirect, errMsg string) {
	if h.adminMfaEnrollTmpl == nil {
		http.Error(w, "MFA enrollment template missing", http.StatusInternalServerError)
		return
	}

	csrf, err := generateCSRFToken()
	if err != nil { // COVERAGE: unreachable — generateCSRFToken uses crypto/rand which is fatal on failure.
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token_admin_mfa",
		Value:    csrf,
		Path:     "/auth/admin-mfa",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	issuer := "kite-mcp-server"
	otpURI := users.ProvisioningURI(secret, issuer, email)

	data := struct {
		Title      string
		Issuer     string
		Account    string
		Secret     string
		OtpAuthURI string
		Redirect   string
		CSRFToken  string
		Error      string
	}{
		Title:      "Set up MFA",
		Issuer:     issuer,
		Account:    email,
		Secret:     secret,
		OtpAuthURI: otpURI,
		Redirect:   redirect,
		CSRFToken:  csrf,
		Error:      errMsg,
	}

	var buf bytes.Buffer
	if err := h.adminMfaEnrollTmpl.ExecuteTemplate(&buf, "base", data); err != nil {
		h.logger.Error("Failed to render MFA enroll template", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if _, err := buf.WriteTo(w); err != nil { // COVERAGE: response write errors only on client disconnect.
		h.logger.Debug("Failed to write MFA enroll response", "error", err)
	}
}

// serveAdminMFAVerifyForm renders the verify template.
func (h *Handler) serveAdminMFAVerifyForm(w http.ResponseWriter, redirect, errMsg string) {
	if h.adminMfaVerifyTmpl == nil {
		http.Error(w, "MFA verify template missing", http.StatusInternalServerError)
		return
	}
	csrf, err := generateCSRFToken()
	if err != nil { // COVERAGE: unreachable — generateCSRFToken uses crypto/rand which is fatal on failure.
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token_admin_mfa",
		Value:    csrf,
		Path:     "/auth/admin-mfa",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	data := struct {
		Title     string
		Redirect  string
		CSRFToken string
		Error     string
	}{
		Title:     "Two-factor verification",
		Redirect:  redirect,
		CSRFToken: csrf,
		Error:     errMsg,
	}
	var buf bytes.Buffer
	if err := h.adminMfaVerifyTmpl.ExecuteTemplate(&buf, "base", data); err != nil {
		h.logger.Error("Failed to render MFA verify template", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if _, err := buf.WriteTo(w); err != nil { // COVERAGE: response write errors only on client disconnect.
		h.logger.Debug("Failed to write MFA verify response", "error", err)
	}
}

// safeRedirect returns the candidate path if it is a safe relative path,
// otherwise the fallback. Prevents open-redirect attacks via the
// `redirect` query/form parameter.
func safeRedirect(candidate, fallback string) string {
	if candidate == "" {
		return fallback
	}
	if !strings.HasPrefix(candidate, "/") || strings.HasPrefix(candidate, "//") {
		return fallback
	}
	return candidate
}
