package billing

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
)

// newTestStore creates a billing Store backed only by the in-memory map
// (no SQLite). This is sufficient for testing business logic since the
// Store gracefully handles a nil DB.
func newTestStore() *Store {
	return NewStore(nil, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
}

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

func TestGetTier_Active(t *testing.T) {
	s := newTestStore()

	_ = s.SetSubscription(&Subscription{
		AdminEmail: "pro@example.com",
		Tier:       TierPro,
		Status:     StatusActive,
	})
	_ = s.SetSubscription(&Subscription{
		AdminEmail: "premium@example.com",
		Tier:       TierPremium,
		Status:     StatusTrialing,
	})

	assert.Equal(t, TierPro, s.GetTier("pro@example.com"))
	assert.Equal(t, TierPremium, s.GetTier("premium@example.com"))
}

func TestGetTier_Expired(t *testing.T) {
	s := newTestStore()

	_ = s.SetSubscription(&Subscription{
		AdminEmail: "expired@example.com",
		Tier:       TierPro,
		Status:     StatusActive,
		ExpiresAt:  time.Now().Add(-24 * time.Hour), // expired yesterday
	})

	assert.Equal(t, TierFree, s.GetTier("expired@example.com"),
		"expired subscription should return TierFree")
}

func TestGetTier_Canceled(t *testing.T) {
	s := newTestStore()

	_ = s.SetSubscription(&Subscription{
		AdminEmail: "canceled@example.com",
		Tier:       TierPremium,
		Status:     StatusCanceled,
	})

	assert.Equal(t, TierFree, s.GetTier("canceled@example.com"),
		"canceled subscription should return TierFree")
}

func TestGetTier_NonExistent(t *testing.T) {
	s := newTestStore()

	assert.Equal(t, TierFree, s.GetTier("nobody@example.com"),
		"non-existent user should return TierFree")
}

func TestConcurrentAccess(t *testing.T) {
	s := newTestStore()
	const goroutines = 50

	var wg sync.WaitGroup
	wg.Add(goroutines * 2) // half writers, half readers

	// Spawn concurrent writers.
	for i := 0; i < goroutines; i++ {
		go func(n int) {
			defer wg.Done()
			_ = s.SetSubscription(&Subscription{
				AdminEmail: fmt.Sprintf("user%d@example.com", n),
				Tier:       TierPro,
				Status:     StatusActive,
			})
		}(i)
	}

	// Spawn concurrent readers.
	for i := 0; i < goroutines; i++ {
		go func(n int) {
			defer wg.Done()
			_ = s.GetTier(fmt.Sprintf("user%d@example.com", n))
			_ = s.GetSubscription(fmt.Sprintf("user%d@example.com", n))
		}(i)
	}

	wg.Wait()

	// After all goroutines finish, every user should have a subscription.
	for i := 0; i < goroutines; i++ {
		got := s.GetSubscription(fmt.Sprintf("user%d@example.com", i))
		require.NotNil(t, got, "user%d should have a subscription", i)
	}
}

// ---------------------------------------------------------------------------
// Tiers tests
// ---------------------------------------------------------------------------

func TestRequiredTier_AllToolsMapped(t *testing.T) {
	// Verify the toolTiers map is populated and every entry maps to a valid tier.
	// The cross-package check (every tool in GetAllTools has a tier) lives in
	// mcp/common_test.go to avoid an import cycle.
	require.NotEmpty(t, toolTiers, "toolTiers should have entries")

	validTiers := map[Tier]bool{TierFree: true, TierPro: true, TierPremium: true}
	for name, tier := range toolTiers {
		assert.Truef(t, validTiers[tier],
			"tool %q has invalid tier %d", name, tier)
		// RequiredTier should return the same value.
		assert.Equal(t, tier, RequiredTier(name),
			"RequiredTier(%q) should match toolTiers entry", name)
	}
}

func TestRequiredTier_UnknownToolDefaultsFree(t *testing.T) {
	assert.Equal(t, TierFree, RequiredTier("nonexistent_tool_xyz"),
		"unknown tools should default to TierFree")
}

func TestTierOrdering(t *testing.T) {
	assert.Less(t, TierFree, TierPro, "Free should be less than Pro")
	assert.Less(t, TierPro, TierPremium, "Pro should be less than Premium")
	assert.Less(t, TierFree, TierPremium, "Free should be less than Premium")
}

// ---------------------------------------------------------------------------
// SQLite-backed integration tests
// ---------------------------------------------------------------------------

// openTestDB creates an in-memory SQLite DB for integration tests.
func openTestDB(t *testing.T) *alerts.DB {
	t.Helper()
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}

func TestGetTierForUser_FamilyInheritance(t *testing.T) {
	db := openTestDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := NewStore(db, logger)
	require.NoError(t, s.InitTable())

	// Admin has Pro subscription
	require.NoError(t, s.SetSubscription(&Subscription{
		AdminEmail: "admin@example.com",
		Tier:       TierPro,
		Status:     StatusActive,
		MaxUsers:   5,
	}))

	// Family member has no direct subscription
	// adminEmailFn simulates the user store lookup
	adminEmailFn := func(email string) string {
		if email == "family@example.com" {
			return "admin@example.com"
		}
		return ""
	}

	// Family member inherits Pro
	assert.Equal(t, TierPro, s.GetTierForUser("family@example.com", adminEmailFn))

	// Admin gets Pro directly
	assert.Equal(t, TierPro, s.GetTierForUser("admin@example.com", adminEmailFn))

	// Unknown user gets Free
	assert.Equal(t, TierFree, s.GetTierForUser("nobody@example.com", adminEmailFn))

	// Nil adminEmailFn works (no inheritance)
	assert.Equal(t, TierFree, s.GetTierForUser("family@example.com", nil))
}

func TestMaxUsers_Persistence(t *testing.T) {
	db := openTestDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := NewStore(db, logger)
	require.NoError(t, s.InitTable())

	require.NoError(t, s.SetSubscription(&Subscription{
		AdminEmail: "admin@example.com",
		Tier:       TierPremium,
		Status:     StatusActive,
		MaxUsers:   20,
	}))

	// Reload from DB
	s2 := NewStore(db, logger)
	require.NoError(t, s2.InitTable())
	require.NoError(t, s2.LoadFromDB())

	sub := s2.GetSubscription("admin@example.com")
	require.NotNil(t, sub)
	assert.Equal(t, 20, sub.MaxUsers)
	assert.Equal(t, TierPremium, sub.Tier)
}

func TestGetTierForUser_ExpiredAdmin(t *testing.T) {
	db := openTestDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := NewStore(db, logger)
	require.NoError(t, s.InitTable())

	require.NoError(t, s.SetSubscription(&Subscription{
		AdminEmail: "admin@example.com",
		Tier:       TierPro,
		Status:     StatusCanceled,
		MaxUsers:   5,
	}))

	adminEmailFn := func(email string) string {
		if email == "family@example.com" {
			return "admin@example.com"
		}
		return ""
	}

	// Canceled admin = family gets Free
	assert.Equal(t, TierFree, s.GetTierForUser("family@example.com", adminEmailFn))
}

func TestHandleCheckoutCompleted_CreatesSubscription(t *testing.T) {
	db := openTestDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := NewStore(db, logger)
	require.NoError(t, s.InitTable())

	// Simulate: admin pays, webhook fires, subscription created
	sub := &Subscription{
		AdminEmail:       "admin@example.com",
		Tier:             TierPro,
		StripeCustomerID: "cus_test123",
		StripeSubID:      "sub_test456",
		Status:           StatusActive,
		MaxUsers:         5,
	}
	require.NoError(t, s.SetSubscription(sub))

	// Verify subscription stored
	got := s.GetSubscription("admin@example.com")
	require.NotNil(t, got)
	assert.Equal(t, TierPro, got.Tier)
	assert.Equal(t, "cus_test123", got.StripeCustomerID)
	assert.Equal(t, 5, got.MaxUsers)
	assert.Equal(t, StatusActive, got.Status)

	// Verify GetEmailByCustomerID works
	email := s.GetEmailByCustomerID("cus_test123")
	assert.Equal(t, "admin@example.com", email)

	// Verify tier for family member
	adminEmailFn := func(e string) string {
		if e == "family@example.com" {
			return "admin@example.com"
		}
		return ""
	}
	assert.Equal(t, TierPro, s.GetTierForUser("family@example.com", adminEmailFn))
}

func TestSubscriptionUpdate_StatusChange(t *testing.T) {
	db := openTestDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := NewStore(db, logger)
	require.NoError(t, s.InitTable())

	// Create active subscription
	require.NoError(t, s.SetSubscription(&Subscription{
		AdminEmail: "admin@example.com",
		Tier:       TierPro,
		Status:     StatusActive,
		MaxUsers:   5,
	}))

	// Simulate: subscription canceled via webhook
	existing := s.GetSubscription("admin@example.com")
	require.NotNil(t, existing)
	existing.Status = StatusCanceled
	existing.Tier = TierFree
	require.NoError(t, s.SetSubscription(existing))

	// Family member should now get Free
	adminEmailFn := func(e string) string {
		if e == "family@example.com" {
			return "admin@example.com"
		}
		return ""
	}
	assert.Equal(t, TierFree, s.GetTierForUser("family@example.com", adminEmailFn))
	assert.Equal(t, TierFree, s.GetTier("admin@example.com"))
}

func TestEventIdempotency(t *testing.T) {
	db := openTestDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := NewStore(db, logger)
	require.NoError(t, s.InitEventLogTable())

	// First time: not processed
	assert.False(t, s.IsEventProcessed("evt_test_001"))

	// Mark as processed
	require.NoError(t, s.MarkEventProcessed("evt_test_001", "checkout.session.completed"))

	// Second time: already processed
	assert.True(t, s.IsEventProcessed("evt_test_001"))

	// Different event: not processed
	assert.False(t, s.IsEventProcessed("evt_test_002"))
}
