package billing

import (
	"fmt"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		Email:  "alice@example.com",
		Tier:   TierPro,
		Status: StatusActive,
	}
	err := s.SetSubscription(sub)
	require.NoError(t, err)

	got := s.GetSubscription("alice@example.com")
	require.NotNil(t, got)
	assert.Equal(t, "alice@example.com", got.Email)
	assert.Equal(t, TierPro, got.Tier)
	assert.Equal(t, StatusActive, got.Status)
	assert.WithinDuration(t, time.Now(), got.UpdatedAt, 2*time.Second)
}

func TestSetSubscription_Update(t *testing.T) {
	s := newTestStore()

	// Create initial subscription.
	err := s.SetSubscription(&Subscription{
		Email:  "bob@example.com",
		Tier:   TierPro,
		Status: StatusActive,
	})
	require.NoError(t, err)

	// Update to Premium.
	err = s.SetSubscription(&Subscription{
		Email:  "bob@example.com",
		Tier:   TierPremium,
		Status: StatusActive,
	})
	require.NoError(t, err)

	got := s.GetSubscription("bob@example.com")
	require.NotNil(t, got)
	assert.Equal(t, TierPremium, got.Tier)
}

func TestSetSubscription_EmailNormalization(t *testing.T) {
	s := newTestStore()

	err := s.SetSubscription(&Subscription{
		Email:  "Alice@Example.COM",
		Tier:   TierPro,
		Status: StatusActive,
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
		Email:  "pro@example.com",
		Tier:   TierPro,
		Status: StatusActive,
	})
	_ = s.SetSubscription(&Subscription{
		Email:  "premium@example.com",
		Tier:   TierPremium,
		Status: StatusTrialing,
	})

	assert.Equal(t, TierPro, s.GetTier("pro@example.com"))
	assert.Equal(t, TierPremium, s.GetTier("premium@example.com"))
}

func TestGetTier_Expired(t *testing.T) {
	s := newTestStore()

	_ = s.SetSubscription(&Subscription{
		Email:     "expired@example.com",
		Tier:      TierPro,
		Status:    StatusActive,
		ExpiresAt: time.Now().Add(-24 * time.Hour), // expired yesterday
	})

	assert.Equal(t, TierFree, s.GetTier("expired@example.com"),
		"expired subscription should return TierFree")
}

func TestGetTier_Canceled(t *testing.T) {
	s := newTestStore()

	_ = s.SetSubscription(&Subscription{
		Email:  "canceled@example.com",
		Tier:   TierPremium,
		Status: StatusCanceled,
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
				Email:  fmt.Sprintf("user%d@example.com", n),
				Tier:   TierPro,
				Status: StatusActive,
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
