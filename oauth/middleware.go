package oauth

import (
	"context"
	"net/http"
	"strings"
)

type emailContextKey struct{}

// EmailFromContext extracts the authenticated email from the request context.
func EmailFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(emailContextKey{}).(string); ok {
		return v
	}
	return ""
}

// RequireAuth returns middleware that validates Bearer JWT tokens on requests.
// Unauthenticated requests get a 401 with WWW-Authenticate pointing to the resource metadata.
func (h *Handler) RequireAuth(next http.Handler) http.Handler {
	resourceMetadataURL := h.config.ExternalURL + "/.well-known/oauth-protected-resource"

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+resourceMetadataURL+`"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		tokenStr := strings.TrimPrefix(auth, "Bearer ")
		claims, err := h.jwt.ValidateToken(tokenStr)
		if err != nil {
			h.logger.Debug("Invalid JWT", "error", err)
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", resource_metadata="`+resourceMetadataURL+`"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Add email to context for downstream handlers
		ctx := context.WithValue(r.Context(), emailContextKey{}, claims.Subject)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// cookieName is the JWT cookie used for browser-based auth (ops dashboard, etc).
const cookieName = "kite_jwt"

// RequireAuthBrowser returns middleware for browser-based auth.
// Tries Bearer token first, then falls back to a JWT cookie.
// If neither is valid, redirects to the Kite login flow.
func (h *Handler) RequireAuthBrowser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try Bearer token first
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			tokenStr := strings.TrimPrefix(auth, "Bearer ")
			if claims, err := h.jwt.ValidateToken(tokenStr); err == nil {
				ctx := context.WithValue(r.Context(), emailContextKey{}, claims.Subject)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}

		// Try cookie
		cookie, err := r.Cookie(cookieName)
		if err == nil && cookie.Value != "" {
			claims, err := h.jwt.ValidateToken(cookie.Value)
			if err == nil {
				ctx := context.WithValue(r.Context(), emailContextKey{}, claims.Subject)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
			h.logger.Debug("Invalid dashboard cookie", "error", err)
		}

		// Redirect to browser login with redirect back to original URL
		redirectURL := h.config.ExternalURL + "/auth/browser-login?redirect=" + r.URL.Path
		http.Redirect(w, r, redirectURL, http.StatusFound)
	})
}

// SetAuthCookie sets a JWT cookie for browser-based dashboard auth.
func (h *Handler) SetAuthCookie(w http.ResponseWriter, email string) error {
	token, err := h.jwt.GenerateToken(email, "dashboard")
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   86400, // 24 hours
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

// JWTManager returns the JWT manager for external use.
func (h *Handler) JWTManager() *JWTManager {
	return h.jwt
}
