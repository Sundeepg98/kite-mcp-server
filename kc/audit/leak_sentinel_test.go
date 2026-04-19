package audit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"go.uber.org/goleak"
)

// leak_sentinel_test.go — goroutine-leak sentinel for the audit
// Store.StartWorker/Stop lifecycle. StartWorker spawns a drain
// goroutine that ranges over writeCh until Stop closes it; the
// goroutine signals exit by closing s.done, which Stop waits on.
// A refactor that drops either side of that handshake would leak
// one goroutine per worker start.
//
// Uses go.uber.org/goleak VerifyNone at test end — precise stack
// traces on any leak; replaces the earlier runtime.NumGoroutine
// tolerance pattern.

// newShortLivedStore opens an in-memory DB, inits the audit table,
// and returns the Store plus a close function the caller must invoke
// before the next cycle. Closing within the loop prevents SQLite
// connection-pool goroutines from accumulating.
func newShortLivedStore(t *testing.T) (*Store, func()) {
	t.Helper()
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	s := New(db)
	require.NoError(t, s.InitTable())
	return s, func() { db.Close() }
}

// TestGoroutineLeakSentinel_StoreWorker verifies that 10
// StartWorker+Stop cycles leave no goroutines behind.
func TestGoroutineLeakSentinel_StoreWorker(t *testing.T) {
	defer goleak.VerifyNone(t,
		goleak.IgnoreTopFunction("testing.(*T).Parallel"),
		// modernc.org/sqlite spawns internal goroutines that outlive
		// the DB close on some platforms; tolerate them.
		goleak.IgnoreAnyFunction("modernc.org/sqlite.(*conn).run"),
	)

	const cycles = 10
	for i := 0; i < cycles; i++ {
		s, closeDB := newShortLivedStore(t)
		s.StartWorker()
		// Enqueue one entry so the worker exercises its read-and-hash
		// path at least once — catches leaks that only surface after
		// the first channel receive.
		s.Enqueue(&ToolCall{
			CallID:      "leak-sentinel",
			Email:       "",
			ToolName:    "noop",
			StartedAt:   time.Now(),
			CompletedAt: time.Now(),
		})
		s.Stop() // Stop drains and waits for worker goroutine to exit
		closeDB()
	}
}

// TestStoreStopIdempotent locks in the sync.Once + nil-guard pair in
// Store.Stop(). A refactor that removed either guard would either panic
// on the second close(writeCh) or NPE on the nil-channel receive.
func TestStoreStopIdempotent(t *testing.T) {
	s := openTestStore(t)
	s.StartWorker()
	// Triple Stop — must not panic.
	s.Stop()
	s.Stop()
	s.Stop()

	// Stop without StartWorker must also be a no-op.
	s2 := openTestStore(t)
	s2.Stop()
	s2.Stop()
}
