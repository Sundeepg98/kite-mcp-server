package billing

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestStore creates a billing Store backed only by the in-memory map
// (no SQLite). This is sufficient for testing business logic since the
// Store gracefully handles a nil DB.


// ---------------------------------------------------------------------------
// Store tests
// ---------------------------------------------------------------------------
func TestSetSubscription_Create(t *testing.T) {
	s := newTestStore()

	sub := &Subscription{
		AdminEmail: "alice@example.com",
		Tier:       TierPro,
		Status:     StatusActive,
	}
	err := s.SetSubscription(sub)
	require.NoError(t, err)

	got := s.GetSubscription("alice@example.com")
	require.NotNil(t, got)
	assert.Equal(t, "alice@example.com", got.AdminEmail)
	assert.Equal(t, TierPro, got.Tier)
	assert.Equal(t, StatusActive, got.Status)
	assert.WithinDuration(t, time.Now(), got.UpdatedAt, 2*time.Second)
}


func TestSetSubscription_Update(t *testing.T) {
	s := newTestStore()

	// Create initial subscription.
	err := s.SetSubscription(&Subscription{
		AdminEmail: "bob@example.com",
		Tier:       TierPro,
		Status:     StatusActive,
	})
	require.NoError(t, err)

	// Update to Premium.
	err = s.SetSubscription(&Subscription{
		AdminEmail: "bob@example.com",
		Tier:       TierPremium,
		Status:     StatusActive,
	})
	require.NoError(t, err)

	got := s.GetSubscription("bob@example.com")
	require.NotNil(t, got)
	assert.Equal(t, TierPremium, got.Tier)
}


func TestSetSubscription_EmailNormalization(t *testing.T) {
	s := newTestStore()

	err := s.SetSubscription(&Subscription{
		AdminEmail: "Alice@Example.COM",
		Tier:       TierPro,
		Status:     StatusActive,
	})
	require.NoError(t, err)

	// Retrieve with different casing — should find the same subscription.
	got := s.GetSubscription("alice@example.com")
	require.NotNil(t, got, "lookup with lowercase should find subscription set with mixed case")
	assert.Equal(t, TierPro, got.Tier)

	got2 := s.GetSubscription("ALICE@EXAMPLE.COM")
	require.NotNil(t, got2, "lookup with uppercase should find subscription set with mixed case")
	assert.Equal(t, TierPro, got2.Tier)
}


func TestSetSubscription_EmptyEmail(t *testing.T) {
	s := newTestStore()
	err := s.SetSubscription(&Subscription{
		AdminEmail: "",
		Tier:       TierPro,
		Status:     StatusActive,
	})
	assert.Error(t, err, "empty email should be rejected")
}


// ---------------------------------------------------------------------------
// Additional coverage tests: LoadFromDB, InitTable, nil-DB edges
// ---------------------------------------------------------------------------
func TestLoadFromDB_EmptyDB(t *testing.T) {
	db := openTestDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := NewStore(db, logger)
	require.NoError(t, s.InitTable())

	// LoadFromDB on a freshly created (empty) table should return no error.
	err := s.LoadFromDB()
	require.NoError(t, err)

	// No subscriptions should be loaded.
	assert.Nil(t, s.GetSubscription("nobody@example.com"))
	assert.Equal(t, TierFree, s.GetTier("nobody@example.com"))
}


func TestLoadFromDB_NilDB(t *testing.T) {
	// Store with nil DB — LoadFromDB should be a no-op.
	s := newTestStore()
	err := s.LoadFromDB()
	require.NoError(t, err)
}


func TestInitTable_NilDB(t *testing.T) {
	s := newTestStore()
	// InitTable with nil DB should return nil (no-op).
	err := s.InitTable()
	require.NoError(t, err)
}


func TestInitTable_Idempotent(t *testing.T) {
	db := openTestDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := NewStore(db, logger)

	// Call InitTable twice — second call should succeed (migration is idempotent).
	require.NoError(t, s.InitTable())
	require.NoError(t, s.InitTable())

	// Should still be able to write/read data.
	require.NoError(t, s.SetSubscription(&Subscription{
		AdminEmail: "idempotent@example.com",
		Tier:       TierPro,
		Status:     StatusActive,
	}))
	got := s.GetSubscription("idempotent@example.com")
	require.NotNil(t, got)
	assert.Equal(t, TierPro, got.Tier)
}


func TestGetSubscription_NonExistent(t *testing.T) {
	s := newTestStore()
	got := s.GetSubscription("nonexistent@example.com")
	assert.Nil(t, got)
}


func TestSetSubscription_PersistsToDB(t *testing.T) {
	db := openTestDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := NewStore(db, logger)
	require.NoError(t, s.InitTable())

	sub := &Subscription{
		AdminEmail:       "persist@example.com",
		Tier:             TierPremium,
		StripeCustomerID: "cus_persist",
		StripeSubID:      "sub_persist",
		Status:           StatusActive,
		MaxUsers:         10,
	}
	require.NoError(t, s.SetSubscription(sub))

	// Create a new store from the same DB and load — should see the subscription.
	s2 := NewStore(db, logger)
	require.NoError(t, s2.InitTable())
	require.NoError(t, s2.LoadFromDB())

	got := s2.GetSubscription("persist@example.com")
	require.NotNil(t, got)
	assert.Equal(t, TierPremium, got.Tier)
	assert.Equal(t, "cus_persist", got.StripeCustomerID)
	assert.Equal(t, "sub_persist", got.StripeSubID)
	assert.Equal(t, StatusActive, got.Status)
	assert.Equal(t, 10, got.MaxUsers)
}


func TestSetSubscription_WithExpiresAt(t *testing.T) {
	db := openTestDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := NewStore(db, logger)
	require.NoError(t, s.InitTable())

	exp := time.Now().Add(30 * 24 * time.Hour) // 30 days from now
	require.NoError(t, s.SetSubscription(&Subscription{
		AdminEmail: "expiry@example.com",
		Tier:       TierPro,
		Status:     StatusActive,
		ExpiresAt:  exp,
	}))

	// Reload and verify ExpiresAt round-trips.
	s2 := NewStore(db, logger)
	require.NoError(t, s2.InitTable())
	require.NoError(t, s2.LoadFromDB())

	got := s2.GetSubscription("expiry@example.com")
	require.NotNil(t, got)
	// Compare within 1 second due to RFC3339 truncation.
	assert.WithinDuration(t, exp, got.ExpiresAt, 2*time.Second)
}


func TestIsEventProcessed_NilDB(t *testing.T) {
	s := newTestStore()
	// IsEventProcessed with nil DB should always return false.
	assert.False(t, s.IsEventProcessed("evt_any"))
}


func TestMarkEventProcessed_NilDB(t *testing.T) {
	s := newTestStore()
	// MarkEventProcessed with nil DB should return nil (no-op).
	err := s.MarkEventProcessed("evt_any", "test.event")
	require.NoError(t, err)
}


func TestLoadFromDB_MultipleSubscriptions(t *testing.T) {
	db := openTestDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := NewStore(db, logger)
	require.NoError(t, s.InitTable())

	// Insert multiple subscriptions
	require.NoError(t, s.SetSubscription(&Subscription{
		AdminEmail: "a@example.com",
		Tier:       TierPro,
		Status:     StatusActive,
		MaxUsers:   5,
	}))
	require.NoError(t, s.SetSubscription(&Subscription{
		AdminEmail: "b@example.com",
		Tier:       TierPremium,
		Status:     StatusTrialing,
		MaxUsers:   20,
	}))
	require.NoError(t, s.SetSubscription(&Subscription{
		AdminEmail: "c@example.com",
		Tier:       TierSoloPro,
		Status:     StatusActive,
		MaxUsers:   1,
	}))

	// Reload into a fresh store
	s2 := NewStore(db, logger)
	require.NoError(t, s2.InitTable())
	require.NoError(t, s2.LoadFromDB())

	subA := s2.GetSubscription("a@example.com")
	require.NotNil(t, subA)
	assert.Equal(t, TierPro, subA.Tier)
	assert.Equal(t, 5, subA.MaxUsers)

	subB := s2.GetSubscription("b@example.com")
	require.NotNil(t, subB)
	assert.Equal(t, TierPremium, subB.Tier)
	assert.Equal(t, StatusTrialing, subB.Status)

	subC := s2.GetSubscription("c@example.com")
	require.NotNil(t, subC)
	assert.Equal(t, TierSoloPro, subC.Tier)
	assert.Equal(t, 1, subC.MaxUsers)
}


// TestSetSubscription_WhitespaceEmail tests that whitespace-only email is rejected.
func TestSetSubscription_WhitespaceEmail(t *testing.T) {
	s := newTestStore()
	err := s.SetSubscription(&Subscription{
		AdminEmail: "   ",
		Tier:       TierPro,
		Status:     StatusActive,
	})
	assert.Error(t, err, "whitespace-only email should be rejected")
}


// TestInitTable_Migration tests the InitTable migration path where the old
// "email" column needs to be renamed to "admin_email".
func TestInitTable_Migration(t *testing.T) {
	db := openTestDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create old-schema table with "email" PK instead of "admin_email".
	err := db.ExecDDL(`CREATE TABLE billing (
		email              TEXT PRIMARY KEY,
		tier               INTEGER NOT NULL DEFAULT 0,
		stripe_customer_id TEXT DEFAULT '',
		stripe_sub_id      TEXT DEFAULT '',
		status             TEXT NOT NULL DEFAULT 'active',
		expires_at         TEXT DEFAULT '',
		updated_at         TEXT NOT NULL
	)`)
	require.NoError(t, err)

	// Insert a row with old schema.
	err = db.ExecInsert(
		`INSERT INTO billing (email, tier, stripe_customer_id, stripe_sub_id, status, updated_at)
		 VALUES (?, ?, '', '', 'active', ?)`,
		"old@example.com", 1, time.Now().Format(time.RFC3339),
	)
	require.NoError(t, err)

	// Now call InitTable which should migrate the table.
	s := NewStore(db, logger)
	require.NoError(t, s.InitTable())

	// Load from DB — should see the migrated data.
	require.NoError(t, s.LoadFromDB())
	sub := s.GetSubscription("old@example.com")
	require.NotNil(t, sub, "migrated subscription should be loadable")
	assert.Equal(t, TierPro, sub.Tier)
	assert.Equal(t, StatusActive, sub.Status)
}


// ===========================================================================
// DB error-path tests to push coverage above 95%
// ===========================================================================
func TestSetSubscription_DBWriteError(t *testing.T) {
	db := openTestDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := NewStore(db, logger)
	require.NoError(t, s.InitTable())

	// Close the DB to force a write error.
	db.Close()

	err := s.SetSubscription(&Subscription{
		AdminEmail: "err@example.com",
		Tier:       TierPro,
		Status:     StatusActive,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "persist subscription")
}


func TestSetSubscription_WithExpiresAtDBRoundTrip(t *testing.T) {
	db := openTestDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := NewStore(db, logger)
	require.NoError(t, s.InitTable())

	// Empty ExpiresAt should persist as empty string.
	require.NoError(t, s.SetSubscription(&Subscription{
		AdminEmail: "noexpiry@example.com",
		Tier:       TierPro,
		Status:     StatusActive,
	}))

	s2 := NewStore(db, logger)
	require.NoError(t, s2.LoadFromDB())
	got := s2.GetSubscription("noexpiry@example.com")
	require.NotNil(t, got)
	assert.True(t, got.ExpiresAt.IsZero())
}


func TestLoadFromDB_ClosedDB(t *testing.T) {
	db := openTestDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := NewStore(db, logger)
	require.NoError(t, s.InitTable())
	db.Close()

	err := s.LoadFromDB()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "query billing")
}


func TestIsEventProcessed_ClosedDB(t *testing.T) {
	db := openTestDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := NewStore(db, logger)
	require.NoError(t, s.InitEventLogTable())
	db.Close()

	// Scan error falls through to return false.
	assert.False(t, s.IsEventProcessed("evt_test"))
}


func TestInitTable_ClosedDB(t *testing.T) {
	db := openTestDB(t)
	s := NewStore(db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	db.Close()

	err := s.InitTable()
	require.Error(t, err)
}
