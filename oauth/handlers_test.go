package oauth

import (
	"net/http"
	"net/http/httptest"
	"testing"

)

// --- Well-Known Metadata ---


func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}


// ===========================================================================
// Consent cookie ordering (MCP §security-best-practices confused-deputy)
//
// The dashboard/session auth cookie (cookieName = "kite_jwt") is the CONSENT
// cookie. MCP spec warns that if a server sets it BEFORE user approval, an
// attacker can induce the server to issue the cookie without explicit consent
// ("confused deputy"). These tests lock in the ordering: cookie is set ONLY
// after a successful approval decision, never before.
//
// Note: short-lived CSRF tokens (csrf_token*, google_oauth_state) are NOT
// consent cookies — they are nonces required to be set pre-approval. We only
// guard the kite_jwt dashboard cookie here.
// ===========================================================================

// findAuthCookie extracts the kite_jwt Set-Cookie value (if any) from the recorder.
// Returns "" when absent; ignores the clearing cookie (MaxAge<0).
func findAuthCookie(t *testing.T, rr *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rr.Result().Cookies() {
		if c.Name == cookieName && c.Value != "" && c.MaxAge >= 0 {
			return c
		}
	}
	return nil
}
