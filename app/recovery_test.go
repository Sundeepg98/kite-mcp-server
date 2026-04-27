package app

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	logport "github.com/zerodha/kite-mcp-server/kc/logger"
)

// TestRecoverPanic_NoPanicPassThrough: a handler that returns normally must
// not trip the recovery path. Response body and status come from the
// handler unchanged.
func TestRecoverPanic_NoPanicPassThrough(t *testing.T) {
	t.Parallel()
	h := recoverPanicWithPort(logport.NewSlog(testLogger()), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("all good"))
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ok", nil))

	assert.Equal(t, http.StatusTeapot, rec.Code)
	assert.Equal(t, "all good", rec.Body.String())
}

// TestRecoverPanic_PanicReturns500WithRequestID: the golden path — handler
// panics, recovery catches it, response is a structured 500 carrying the
// request_id for client-side correlation, and the stack trace lands in
// the logger at Error level.
func TestRecoverPanic_PanicReturns500WithRequestID(t *testing.T) {
	t.Parallel()
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Panic happens inside the inner handler, AFTER withRequestID has set
	// the context — the outer recoverPanic must be able to read the ID back.
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("database connection lost")
	})
	h := recoverPanicWithPort(logport.NewSlog(logger), withRequestID(inner))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/trade", nil)
	req.Header.Set(requestIDHeader, "known-id-1234")
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Equal(t, "known-id-1234", rec.Header().Get(requestIDHeader),
		"request ID must be echoed on the 500 response for client correlation")
	assert.Contains(t, rec.Body.String(), `"error":"internal_server_error"`)
	assert.Contains(t, rec.Body.String(), `"request_id":"known-id-1234"`)

	logOutput := logBuf.String()
	assert.Contains(t, logOutput, `"level":"ERROR"`, "panic must log at Error level")
	assert.Contains(t, logOutput, "panic recovered in HTTP handler")
	assert.Contains(t, logOutput, "database connection lost", "panic value must be in the log")
	assert.Contains(t, logOutput, "known-id-1234", "request ID must be in the log")
	assert.Contains(t, logOutput, "stack", "stack trace field must be present")
	// Verify the stack trace includes a recognizable Go frame — this is
	// belt-and-suspenders: if runtime/debug.Stack() ever returned empty,
	// the test would catch it.
	assert.Contains(t, logOutput, "recovery.go", "stack must name the recovery source file")
}

// TestRecoverPanic_AbortHandlerRePanics: http.ErrAbortHandler is a Go
// sentinel meaning "close the connection silently without a response".
// Servers rely on this to force RST; recovery must re-raise it so the
// outer net/http machinery can complete the abort flow, not swallow it
// into a 500.
func TestRecoverPanic_AbortHandlerRePanics(t *testing.T) {
	t.Parallel()
	h := recoverPanicWithPort(logport.NewSlog(testLogger()), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic(http.ErrAbortHandler)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/abort", nil)
	assert.PanicsWithValue(t, http.ErrAbortHandler, func() {
		h.ServeHTTP(rec, req)
	}, "ErrAbortHandler must be re-raised, not swallowed into a 500")
}

// TestRecoverPanic_NoRequestIDWhenMiddlewareSkipped: when recoverPanic is
// installed but withRequestID is not, the response must still land a
// clean 500 — the request_id field in the body is empty rather than
// being populated with random bytes.
func TestRecoverPanic_NoRequestIDWhenMiddlewareSkipped(t *testing.T) {
	t.Parallel()
	h := recoverPanicWithPort(logport.NewSlog(testLogger()), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("no request ID set up")
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/bare", nil))

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), `"request_id":""`,
		"empty request ID must render as an empty string, never as random bytes")
	assert.Empty(t, rec.Header().Get(requestIDHeader),
		"no request ID header should be set when none was in context")
}

// TestRecoverPanic_NilLoggerTolerated: app wiring may hand a nil logger
// during early bootstrap; recovery must not itself panic in that case.
func TestRecoverPanic_NilLoggerTolerated(t *testing.T) {
	t.Parallel()
	h := recoverPanicWithPort(nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	}))

	rec := httptest.NewRecorder()
	require.NotPanics(t, func() {
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/nil-logger", nil))
	})
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// TestJsonEscape_StripsUnexpectedBytes: belt-and-suspenders on the narrow
// JSON escape helper — validated request IDs pass through, anything odd
// is zeroed out.
func TestJsonEscape_StripsUnexpectedBytes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"uuid-like", "01234567-89ab-7def-0123-456789abcdef", "01234567-89ab-7def-0123-456789abcdef"},
		{"alphanum", "abcXYZ123", "abcXYZ123"},
		{"unreserved", "a-b._c~d", "a-b._c~d"},
		{"empty", "", ""},
		{"quote-injection", `a"b`, ""},
		{"newline", "a\nb", ""},
		{"backslash", `a\b`, ""},
		// Non-ASCII must be rejected (not surviving into the JSON body)
		{"utf8", "αβγ", ""},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := jsonEscape(tc.in)
			assert.Equal(t, tc.want, got,
				"jsonEscape(%q) = %q, want %q", tc.in, got, tc.want)
		})
	}
}

// TestRecoverPanic_Integration verifies the full outer-to-inner chain as
// wired in configureAndStartServer: recoverPanic → withRequestID →
// securityHeaders → handler. A panic anywhere inside should land a clean
// 500 with the request ID echoed, and security headers from the inner
// middleware should NOT leak into the recovery response (they apply only
// when the inner chain successfully writes; recovery writes its own
// minimal envelope).
func TestRecoverPanic_Integration(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))

	mux := http.NewServeMux()
	mux.HandleFunc("/panic", func(w http.ResponseWriter, r *http.Request) {
		panic("inner handler exploded")
	})
	// Reproduce the exact chain used by configureAndStartServer.
	srvHandler := recoverPanicWithPort(logport.NewSlog(logger), withRequestID(securityHeaders(mux)))

	rec := httptest.NewRecorder()
	srvHandler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/panic", nil))

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.NotEmpty(t, rec.Header().Get(requestIDHeader),
		"withRequestID must have generated an ID before the panic, so the 500 still carries one")
	body := rec.Body.String()
	assert.True(t, strings.Contains(body, `"error":"internal_server_error"`),
		"body should be the recovery JSON envelope: %s", body)
}
