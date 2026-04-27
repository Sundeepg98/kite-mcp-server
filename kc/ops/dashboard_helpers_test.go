package ops

// dashboard_helpers_test.go — coverage close-out for the dashboard
// helper layer: pure formatters (truncateConnectionID, relativeTime,
// intParam), error response helper (writeJSONError), and the
// authentication / method-validation surfaces of the connections
// handler (the rest needs a full session-registry fixture which
// existing kc/ops/admin_*_test.go tests already exercise).
//
// Sub-commit B of Wave B option 1 (app/ HTTP integration tests). The
// brief named "app/dashboard_handlers_test.go" but the dashboard
// handlers live in kc/ops/, not app/ — so the tests live here too.
// app/ owns only the static landing/healthz routes; the dashboard
// is bolted on via kc/ops/DashboardHandler.RegisterRoutes.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ===========================================================================
// truncateConnectionID — short / boundary / long / empty
// ===========================================================================

// TestTruncateConnectionID covers the three branches: shorter-than-cap
// returns unchanged; equal-to-cap returns unchanged; longer takes the
// "<head 12>…<tail 4>" shortened form.
func TestTruncateConnectionID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty unchanged", "", ""},
		{"short unchanged (1 char)", "a", "a"},
		{
			name: "exactly cap (16 chars) unchanged — boundary",
			in:   "abcdefghijklmnop", // 12+4 = 16
			want: "abcdefghijklmnop",
		},
		{
			name: "long takes head…tail form",
			in:   "abcdefghijklmnop1234567890",
			want: "abcdefghijkl…7890",
		},
		{
			name: "very long still head…tail",
			in:   "0123456789abcdefghijklmnopqrstuvwxyz",
			want: "0123456789ab…wxyz",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := truncateConnectionID(tc.in)
			assert.Equal(t, tc.want, got)
		})
	}
}

// ===========================================================================
// relativeTime — every duration bucket + zero/future
// ===========================================================================

// TestRelativeTime covers the five duration buckets the helper
// distinguishes plus the zero-time and future-time edge cases.
func TestRelativeTime(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name string
		t    time.Time
		want string
	}{
		{
			name: "zero time returns empty",
			t:    time.Time{},
			want: "",
		},
		{
			name: "future time clamps to 'just now' (negative duration handled)",
			t:    now.Add(time.Hour), // future: d=-1h, max(d,0)=0 → < minute → secs<=1 → just now
			want: "just now",
		},
		{
			name: "0 seconds ago is 'just now'",
			t:    now,
			want: "just now",
		},
		{
			name: "1 second ago is 'just now' (boundary)",
			t:    now.Add(-1 * time.Second),
			want: "just now",
		},
		{
			name: "30 seconds ago is '30 sec ago'",
			t:    now.Add(-30 * time.Second),
			want: "30 sec ago",
		},
		{
			name: "1 minute ago is '1 min ago' (singular)",
			t:    now.Add(-1 * time.Minute),
			want: "1 min ago",
		},
		{
			name: "5 minutes ago is '5 min ago'",
			t:    now.Add(-5 * time.Minute),
			want: "5 min ago",
		},
		{
			name: "1 hour ago is '1 hour ago' (singular)",
			t:    now.Add(-1 * time.Hour),
			want: "1 hour ago",
		},
		{
			name: "3 hours ago is '3 hours ago'",
			t:    now.Add(-3 * time.Hour),
			want: "3 hours ago",
		},
		{
			name: "1 day ago is '1 day ago' (singular)",
			t:    now.Add(-24 * time.Hour),
			want: "1 day ago",
		},
		{
			name: "5 days ago is '5 days ago'",
			t:    now.Add(-5 * 24 * time.Hour),
			want: "5 days ago",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := relativeTime(tc.t, now)
			assert.Equal(t, tc.want, got)
		})
	}
}

// ===========================================================================
// intParam — default / valid / invalid / negative
// ===========================================================================

// TestIntParam covers the four branches: missing query param returns
// default; valid integer returns the parsed value; non-numeric input
// returns default; negative input returns default (pin the "no
// negative" contract — the helper never returns < 0).
func TestIntParam(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		query      string
		key        string
		defaultVal int
		want       int
	}{
		{"missing key returns default", "", "limit", 20, 20},
		{"valid integer returns parsed", "limit=50", "limit", 20, 50},
		{"zero is valid (returned as-is)", "limit=0", "limit", 20, 0},
		{"non-numeric returns default", "limit=abc", "limit", 20, 20},
		{"negative returns default", "limit=-5", "limit", 20, 20},
		{"different key not present returns default", "other=10", "limit", 7, 7},
		{"empty value returns default (string is empty)", "limit=", "limit", 20, 20},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/?"+tc.query, nil)
			got := intParam(req, tc.key, tc.defaultVal)
			assert.Equal(t, tc.want, got)
		})
	}
}

// ===========================================================================
// writeJSONError — JSON shape + status code + content-type
// ===========================================================================

// TestWriteJSONError covers the helper's three contracts: writes the
// JSON Content-Type header, writes the requested HTTP status, and
// emits a {error, message} body. Pin the wire shape so dashboard JS
// callers can rely on it.
func TestWriteJSONError(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)

	tests := []struct {
		name    string
		status  int
		errCode string
		message string
	}{
		{"401 unauthenticated", http.StatusUnauthorized, "not_authenticated", "Not authenticated."},
		{"403 forbidden", http.StatusForbidden, "forbidden", "Admin access required."},
		{"404 not found", http.StatusNotFound, "not_found", "Resource missing."},
		{"500 internal", http.StatusInternalServerError, "internal", "Server error."},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			d.writeJSONError(rec, tc.status, tc.errCode, tc.message)

			assert.Equal(t, tc.status, rec.Code)
			assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

			var got map[string]string
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
			assert.Equal(t, tc.errCode, got["error"])
			assert.Equal(t, tc.message, got["message"])
		})
	}
}

// ===========================================================================
// connections handler — auth + method validation surfaces
// ===========================================================================

// TestConnections_MethodNotAllowed covers the non-GET branch: only
// GET is supported; POST/PUT/DELETE return 405.
func TestConnections_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			req := requestWithEmail(method, "/dashboard/api/connections", "user@test.com", nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusMethodNotAllowed, rec.Code,
				"%s on /connections must return 405", method)
		})
	}
}

// TestConnections_NoAuth covers the missing-email branch: a request
// without an email in the context returns 401 with the typed
// not_authenticated error code.
func TestConnections_NoAuth(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	// requestWithEmail("") leaves the context empty.
	req := requestWithEmail(http.MethodGet, "/dashboard/api/connections", "", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "not_authenticated", body["error"])
}

// TestConnections_AuthenticatedReturnsJSON covers the happy path
// shape: authenticated user gets a 200 + JSON response, even when
// they have no active sessions or audit entries (the merge logic
// produces an empty list, not an error).
func TestConnections_AuthenticatedReturnsJSON(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/connections", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	// Body should be valid JSON (object or array). Don't pin the schema
	// hard — the merge logic is exercised in admin_edge_*_test.go.
	body := rec.Body.Bytes()
	require.NotEmpty(t, body, "authenticated GET should return non-empty JSON")
	var raw any
	require.NoError(t, json.Unmarshal(body, &raw),
		"response must be valid JSON, got: %s", string(body))
}
