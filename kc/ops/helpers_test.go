package ops

// helpers_test.go — shared test infrastructure for the kc/ops package.
// Consolidates helpers that were previously defined in handler_test.go but
// used across the whole package (devNull, noopAuth, requestWithEmail) and
// adds a shared discard logger backed by testutil.DiscardLogger so every
// ops test uses the same fixture.

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/zerodha/kite-mcp-server/oauth"
	"github.com/zerodha/kite-mcp-server/testutil"
)

// testLogger returns a discard logger shared across the ops test suite. It
// delegates to testutil.DiscardLogger so every package converges on the same
// no-op logger fixture.
func testLogger() *slog.Logger {
	return testutil.DiscardLogger()
}

// devNull implements io.Writer and discards all bytes. It is used by factories
// that build a slog.Logger directly (the handler constructor stores the
// *slog.Logger, so some tests need a writer rather than a logger).
type devNull struct{}

func (devNull) Write(p []byte) (int, error) { return len(p), nil }

// Compile-time assertion that devNull satisfies io.Writer.
var _ io.Writer = devNull{}

// noopAuth is a pass-through middleware that does NOT enforce authentication.
// Tests wire it into RegisterRoutes when they want to exercise handlers
// without an email context, or supply one themselves via requestWithEmail.
func noopAuth(next http.Handler) http.Handler { return next }

// requestWithEmail returns a request whose context carries the given email,
// matching what oauth.RequireAuthBrowser would inject in production. Pass an
// empty email to build a request with no auth context.
func requestWithEmail(method, target, email string, body *strings.Reader) *http.Request {
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, target, body)
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	if email != "" {
		ctx := oauth.ContextWithEmail(req.Context(), email)
		req = req.WithContext(ctx)
	}
	return req
}
