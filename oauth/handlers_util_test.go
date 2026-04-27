package oauth

import (
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
)

// --- Well-Known Metadata ---

// ===========================================================================
// writeJSON — unmarshalable type (error path)
// ===========================================================================
func TestWriteJSON_UnmarshalableType(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	rr := httptest.NewRecorder()
	h.writeJSON(rr, http.StatusOK, map[string]interface{}{
		"bad": math.Inf(1),
	})

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (status already written before encode fails)", rr.Code)
	}
}

// ===========================================================================
// clientIP — pure-function priority: Fly-Client-IP header > RemoteAddr
// ===========================================================================
//
// Coverage gap fix: clientIP feeds the consent-record audit trail
// (DPDP Act compliance). Each branch path needs explicit coverage.

// TestClientIP_FlyHeaderPreferred verifies the Fly.io trusted-proxy
// header takes precedence over RemoteAddr. Production traffic on
// Fly.io always carries Fly-Client-IP; preferring it stops the
// audit log from recording the proxy IP instead of the user IP.
func TestClientIP_FlyHeaderPreferred(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Fly-Client-IP", "203.0.113.42")
	r.RemoteAddr = "10.0.0.1:54321" // proxy address — must not win
	if got := clientIP(r); got != "203.0.113.42" {
		t.Errorf("clientIP = %q, want 203.0.113.42 (Fly header wins)", got)
	}
}

// TestClientIP_NoFlyHeaderStripsPort verifies the local-dev path:
// no Fly header, so we strip the ephemeral source port from RemoteAddr
// (logs would otherwise carry "127.0.0.1:54321" which is useless for
// per-IP rate-limit / abuse review).
func TestClientIP_NoFlyHeaderStripsPort(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "192.168.1.10:54321"
	if got := clientIP(r); got != "192.168.1.10" {
		t.Errorf("clientIP = %q, want 192.168.1.10 (port stripped)", got)
	}
}

// TestClientIP_RemoteAddrWithoutPort covers the path where RemoteAddr
// has no port (rare but valid — net.SplitHostPort fails and we return
// the raw value). Defensive: don't lose the IP if port-stripping fails.
func TestClientIP_RemoteAddrWithoutPort(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "192.168.1.10" // no port
	if got := clientIP(r); got != "192.168.1.10" {
		t.Errorf("clientIP = %q, want 192.168.1.10 (no-port fallback)", got)
	}
}

// TestClientIP_NilRequest pins the nil-guard contract: defensive
// check returns empty string rather than panicking on a malformed
// caller path.
func TestClientIP_NilRequest(t *testing.T) {
	t.Parallel()
	if got := clientIP(nil); got != "" {
		t.Errorf("clientIP(nil) = %q, want empty string", got)
	}
}

// TestClientIP_IPv6 covers an IPv6 RemoteAddr — net.SplitHostPort
// handles bracket notation; verify the stripped host doesn't carry
// the brackets back to the audit log.
func TestClientIP_IPv6(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "[2001:db8::1]:54321"
	if got := clientIP(r); got != "2001:db8::1" {
		t.Errorf("clientIP IPv6 = %q, want 2001:db8::1 (no brackets)", got)
	}
}

// ===========================================================================
// SetConsentRecorder — wiring helper, must replace the field
// ===========================================================================
//
// SetConsentRecorder is the production wire-in for the DPDP-consent
// audit trail. Trivial setter; coverage gap was 0% because no test
// previously exercised it.

// TestSetConsentRecorder_OverwritesField verifies the setter
// replaces the field. Pairs with the nil-recorder default for
// dev-mode (no audit recording).
func TestSetConsentRecorder_OverwritesField(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	// Default: no recorder wired.
	if h.consentRecorder != nil {
		t.Fatal("default handler should have nil consentRecorder")
	}

	// Wire a recorder (ConsentRecorder is a func type — no wrapper needed).
	called := false
	var rec ConsentRecorder = func(email, ip, userAgent string) {
		called = true
		if email != "u@t.com" {
			t.Errorf("email = %q, want u@t.com", email)
		}
	}
	h.SetConsentRecorder(rec)

	if h.consentRecorder == nil {
		t.Fatal("SetConsentRecorder should wire the field")
	}
	// Invoke through the field to confirm round-trip.
	h.consentRecorder("u@t.com", "203.0.113.1", "Mozilla")
	if !called {
		t.Error("the wired recorder should have been invoked")
	}
}
