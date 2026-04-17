package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWithRequestID_GeneratesIDWhenAbsent verifies that a fresh UUIDv7
// is generated and echoed back when the client does not provide a header.
func TestWithRequestID_GeneratesIDWhenAbsent(t *testing.T) {
	var seenID string
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seenID = RequestIDFromCtx(r.Context())
	})

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	withRequestID(next).ServeHTTP(rec, req)

	// Handler received a non-empty ID.
	require.NotEmpty(t, seenID, "handler should see a generated request ID")

	// Response echoes the ID back.
	echoed := rec.Header().Get("X-Request-ID")
	assert.Equal(t, seenID, echoed, "response header should echo the same ID")

	// ID is a valid UUID format (36 chars with dashes at 8-4-4-4-12).
	assert.Len(t, seenID, 36, "UUID string must be 36 characters")
	assert.Equal(t, 4, strings.Count(seenID, "-"), "UUID must contain 4 dashes")
}

// TestWithRequestID_AcceptsValidClientHeader verifies that a valid
// X-Request-ID sent by the client is preserved end-to-end.
func TestWithRequestID_AcceptsValidClientHeader(t *testing.T) {
	clientID := "018f1e8c-7b8a-7c2f-ab12-3456789abcde" // valid UUID format
	var seenID string
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seenID = RequestIDFromCtx(r.Context())
	})

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("X-Request-ID", clientID)
	rec := httptest.NewRecorder()

	withRequestID(next).ServeHTTP(rec, req)

	assert.Equal(t, clientID, seenID, "handler should see the client-supplied ID")
	assert.Equal(t, clientID, rec.Header().Get("X-Request-ID"), "response should echo the client ID")
}

// TestWithRequestID_RejectsHeaderInjection verifies that CRLF-bearing
// headers (attempted response-splitting) are replaced with a generated ID.
func TestWithRequestID_RejectsHeaderInjection(t *testing.T) {
	malicious := "legit-id\r\nInjected-Header: evil"
	var seenID string
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seenID = RequestIDFromCtx(r.Context())
	})

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("X-Request-ID", malicious)
	rec := httptest.NewRecorder()

	withRequestID(next).ServeHTTP(rec, req)

	// Malicious value must be dropped — expect a freshly generated UUID.
	assert.NotEqual(t, malicious, seenID, "CRLF header must be rejected")
	assert.NotContains(t, seenID, "\r", "request ID must not contain CR")
	assert.NotContains(t, seenID, "\n", "request ID must not contain LF")
	assert.Len(t, seenID, 36, "fallback ID should be a UUID")

	// Response header must not contain smuggled content either.
	echoed := rec.Header().Get("X-Request-ID")
	assert.NotContains(t, echoed, "\r")
	assert.NotContains(t, echoed, "\n")
	assert.NotContains(t, echoed, "Injected-Header")
}

// TestWithRequestID_RejectsOverlongHeader verifies that a request ID
// beyond a sane upper bound is discarded.
func TestWithRequestID_RejectsOverlongHeader(t *testing.T) {
	overlong := strings.Repeat("a", 513)
	var seenID string
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seenID = RequestIDFromCtx(r.Context())
	})

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("X-Request-ID", overlong)
	rec := httptest.NewRecorder()

	withRequestID(next).ServeHTTP(rec, req)

	assert.NotEqual(t, overlong, seenID, "overlong header must be rejected")
	assert.Len(t, seenID, 36, "fallback ID should be a UUID")
}

// TestWithRequestID_AcceptsPermissiveFreeformID verifies that callers using
// short opaque request IDs (common in trace systems) are accepted without
// forcing UUID format.
func TestWithRequestID_AcceptsPermissiveFreeformID(t *testing.T) {
	clientID := "trace-123_abcDEF"
	var seenID string
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seenID = RequestIDFromCtx(r.Context())
	})

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("X-Request-ID", clientID)
	rec := httptest.NewRecorder()

	withRequestID(next).ServeHTTP(rec, req)

	assert.Equal(t, clientID, seenID, "freeform non-UUID IDs should be accepted")
}

// TestRequestIDFromCtx_Empty returns empty string when no ID is set.
func TestRequestIDFromCtx_Empty(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	id := RequestIDFromCtx(req.Context())
	assert.Empty(t, id)
}

// TestIsValidRequestID table-drives the validator.
func TestIsValidRequestID(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{"empty", "", false},
		{"uuid", "018f1e8c-7b8a-7c2f-ab12-3456789abcde", true},
		{"freeform_alphanum", "abc123", true},
		{"with_underscore_dash", "trace-id_123", true},
		{"newline", "abc\nxyz", false},
		{"carriage_return", "abc\rxyz", false},
		{"crlf", "abc\r\nxyz", false},
		{"too_long", strings.Repeat("a", 513), false},
		{"space_rejected", "abc xyz", false},
		{"control_char", "abc\x00xyz", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidRequestID(tt.value)
			assert.Equal(t, tt.want, got, "value=%q", tt.value)
		})
	}
}

// TestNewRequestID_IsUnique smoke-tests that generated IDs differ.
func TestNewRequestID_IsUnique(t *testing.T) {
	seen := make(map[string]struct{}, 100)
	for i := 0; i < 100; i++ {
		id := newRequestID()
		require.NotEmpty(t, id)
		require.Len(t, id, 36)
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate request ID generated: %s", id)
		}
		seen[id] = struct{}{}
	}
}
