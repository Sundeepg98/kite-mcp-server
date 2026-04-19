package billing

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"go.uber.org/goleak"
)

// leak_sentinel_test.go — forward-looking goroutine-leak sentinel for
// the billing package. Today NewStore is a pure constructor: allocates
// an in-memory map + stores the *alerts.DB handle. No background
// goroutines, no webhook processors, no polling loops.
//
// Billing is a natural place for future background work:
//   - Stripe webhook replay retries
//   - Subscription expiry batch jobs (grace-period reminders, tier
//     downgrade enforcement)
//   - Cache refresh from Stripe after out-of-band portal changes
//
// Whichever lands first, this sentinel catches a missing Shutdown
// hook immediately. goleak's stack trace identifies the exact
// goroutine function, making the fix one-line.
//
// Pattern mirrors kc/alerts/leak_sentinel_test.go and the three
// earlier sentinels in kc/{scheduler,audit,ticker}.

// TestGoroutineLeakSentinel_Billing verifies that construction and
// basic operation of the billing Store do not leak goroutines.
func TestGoroutineLeakSentinel_Billing(t *testing.T) {
	defer goleak.VerifyNone(t,
		// modernc.org/sqlite driver owns a pool of connection-manager
		// goroutines per *sql.DB; legitimately alive for the test
		// cleanup window.
		goleak.IgnoreTopFunction("database/sql.(*DB).connectionOpener"),
		goleak.IgnoreTopFunction("database/sql.(*DB).connectionResetter"),
		// The HTTP/2 readLoop ignore that was here previously is now
		// unnecessary: main_test.go installs a Stripe HTTP client with
		// DisableKeepAlives=true + IdleConnTimeout=1s, so readLoop
		// goroutines exit promptly after each Stripe call instead of
		// the SDK default ~90s idle hold. If a real leak in billing's
		// own code appears in future, VerifyNone will surface it
		// immediately — no stdlib-function noise to filter through.
	)

	// Build 5 stores with in-memory DBs. Each gets the full
	// init-table round trip so we also catch leaks that might only
	// surface after DDL execution.
	for i := 0; i < 5; i++ {
		db, err := alerts.OpenDB(":memory:")
		require.NoError(t, err)
		t.Cleanup(func() { db.Close() })

		store := NewStore(db, nil)
		require.NoError(t, store.InitTable())
		// Touch the read path — GetSubscription must not spawn a
		// goroutine (e.g. a lazy background refresh) as a side effect.
		_ = store.GetSubscription("no-such-user@example.com")
	}
}
