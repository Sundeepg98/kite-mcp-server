package papertrading

import (
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
)

// TestPaperOrders_FK_RejectsOrphan pins the DDD aggregate-boundary invariant:
// inserting a paper_orders row whose email has no matching paper_accounts row
// MUST fail with a FOREIGN KEY constraint violation. Together with the per-
// connection foreign_keys=ON PRAGMA (kc/alerts/db.go:dsnWithFKPragma), this
// guarantees no orphan order rows can exist in the schema.
func TestPaperOrders_FK_RejectsOrphan(t *testing.T) {
	t.Parallel()
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	store := NewStore(db, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	require.NoError(t, store.InitTables())

	// No paper_accounts row → InsertOrder must fail FK check.
	err = store.InsertOrder(&Order{
		OrderID: "ORPHAN1", Email: "ghost@nowhere.com",
		Exchange: "NSE", Tradingsymbol: "SBIN",
		TransactionType: "BUY", OrderType: "MARKET", Product: "CNC",
		Variety: "regular", Quantity: 1, Status: "COMPLETE",
		PlacedAt: time.Now().UTC(),
	})
	require.Error(t, err, "orphan paper_orders row must be rejected by FOREIGN KEY constraint")
	assert.Contains(t, err.Error(), "FOREIGN KEY", "error must surface the FK violation cause")
}

// TestPaperPositions_FK_RejectsOrphan pins the same invariant for paper_positions.
func TestPaperPositions_FK_RejectsOrphan(t *testing.T) {
	t.Parallel()
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	store := NewStore(db, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	require.NoError(t, store.InitTables())

	err = store.UpsertPosition(&Position{
		Email: "ghost@nowhere.com", Exchange: "NSE", Tradingsymbol: "SBIN",
		Product: "CNC", Quantity: 1, AveragePrice: 500,
	})
	require.Error(t, err, "orphan paper_positions row must be rejected by FOREIGN KEY constraint")
	assert.Contains(t, err.Error(), "FOREIGN KEY")
}

// TestPaperHoldings_FK_RejectsOrphan pins the same invariant for paper_holdings.
func TestPaperHoldings_FK_RejectsOrphan(t *testing.T) {
	t.Parallel()
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	store := NewStore(db, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	require.NoError(t, store.InitTables())

	err = store.UpsertHolding(&Holding{
		Email: "ghost@nowhere.com", Exchange: "NSE", Tradingsymbol: "SBIN",
		Quantity: 1, AveragePrice: 500,
	})
	require.Error(t, err, "orphan paper_holdings row must be rejected by FOREIGN KEY constraint")
	assert.Contains(t, err.Error(), "FOREIGN KEY")
}

// TestPaperOrders_FK_AcceptsAfterParent verifies that once a paper_accounts
// parent row exists, child inserts succeed. This complements the orphan-
// rejection tests by proving the FK clause does not over-restrict.
func TestPaperOrders_FK_AcceptsAfterParent(t *testing.T) {
	t.Parallel()
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	store := NewStore(db, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	require.NoError(t, store.InitTables())

	const email = "parent@present.com"
	require.NoError(t, store.EnableAccount(email, 1_000_000))

	// Now FK is satisfied — child insert succeeds.
	require.NoError(t, store.InsertOrder(&Order{
		OrderID: "OK1", Email: email,
		Exchange: "NSE", Tradingsymbol: "SBIN",
		TransactionType: "BUY", OrderType: "MARKET", Product: "CNC",
		Variety: "regular", Quantity: 1, Status: "COMPLETE",
		PlacedAt: time.Now().UTC(),
	}))

	require.NoError(t, store.UpsertPosition(&Position{
		Email: email, Exchange: "NSE", Tradingsymbol: "SBIN",
		Product: "CNC", Quantity: 1, AveragePrice: 500,
	}))

	require.NoError(t, store.UpsertHolding(&Holding{
		Email: email, Exchange: "NSE", Tradingsymbol: "SBIN",
		Quantity: 1, AveragePrice: 500,
	}))
}
