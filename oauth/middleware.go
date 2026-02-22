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
