package billing

import (
	"net/http"
	"os"
	"testing"
	"time"

	stripe "github.com/stripe/stripe-go/v82"
)

// main_test.go — package-level test setup.
//
// Overrides the Stripe SDK's default HTTP client with one that disables
// connection keep-alives and uses a short idle timeout. This forces the
// HTTP/2 readLoop goroutine (net/http.(*http2ClientConn).readLoop) to
// exit promptly when a Stripe request completes, instead of the SDK
// default of ~90s idle hold. Without this, the billing package's
// goleak sentinel had to IgnoreTopFunction("net/http.(*http2ClientConn).readLoop")
// because earlier tests in the package left readLoop goroutines alive
// into the sentinel's VerifyNone window.
//
// Scope: test-only. Production still uses the Stripe SDK's default
// HTTP client (with keep-alives for connection reuse), which is the
// right choice for a long-running server.

func TestMain(m *testing.M) {
	// Short-lived HTTP transport for tests. DisableKeepAlives=true
	// means every Stripe API call closes its connection on response,
	// so no readLoop goroutine lingers. IdleConnTimeout=1s is a
	// belt-and-braces follow-up in case a connection somehow survives
	// despite DisableKeepAlives (shouldn't happen, but cheap insurance).
	transport := &http.Transport{
		DisableKeepAlives: true,
		IdleConnTimeout:   time.Second,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}
	stripe.SetHTTPClient(client)

	os.Exit(m.Run())
}
