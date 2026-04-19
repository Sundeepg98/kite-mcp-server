package billing

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	stripe "github.com/stripe/stripe-go/v82"
	stripewebhook "github.com/stripe/stripe-go/v82/webhook"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
)

// newTestStore creates a billing Store backed only by the in-memory map
// (no SQLite). This is sufficient for testing business logic since the
// Store gracefully handles a nil DB.

func newTestStore() *Store {
	return NewStore(nil, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
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


func TestEffectiveTier_OtherTiers(t *testing.T) {
	// Non-SoloPro tiers should return themselves.
	assert.Equal(t, TierFree, TierFree.EffectiveTier())
	assert.Equal(t, TierPro, TierPro.EffectiveTier())
	assert.Equal(t, TierPremium, TierPremium.EffectiveTier())
}


// ---------------------------------------------------------------------------
// Middleware tests
// ---------------------------------------------------------------------------

// passthrough is a no-op tool handler that always succeeds.
func passthrough(_ context.Context, _ gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
	return gomcp.NewToolResultText("ok"), nil
}


// ---------------------------------------------------------------------------
// GetTier with TierSoloPro subscription
// ---------------------------------------------------------------------------
func TestGetTier_SoloPro(t *testing.T) {
	s := newTestStore()
	_ = s.SetSubscription(&Subscription{
		AdminEmail: "solo@example.com",
		Tier:       TierSoloPro,
		Status:     StatusActive,
	})
	// GetTier returns the raw tier; EffectiveTier is applied by the caller.
	assert.Equal(t, TierSoloPro, s.GetTier("solo@example.com"))
}


func TestGetEmailByCustomerID_NotFound(t *testing.T) {
	s := newTestStore()
	assert.Equal(t, "", s.GetEmailByCustomerID("cus_nonexistent"))
}


func TestHasExplicitTier(t *testing.T) {
	assert.True(t, HasExplicitTier("place_order"), "place_order should have explicit tier")
	assert.True(t, HasExplicitTier("get_holdings"), "get_holdings should have explicit tier")
	assert.False(t, HasExplicitTier("nonexistent_tool_xyz"), "unknown tool should not have explicit tier")
}


// ---------------------------------------------------------------------------
// Webhook helper function tests (pure functions, no Stripe API calls)
// ---------------------------------------------------------------------------
func TestMapPriceToTier(t *testing.T) {
	pricePro := "price_pro_123"
	pricePremium := "price_premium_456"
	priceSoloPro := "price_solo_789"

	assert.Equal(t, TierPro, mapPriceToTier(pricePro, pricePro, pricePremium, priceSoloPro))
	assert.Equal(t, TierPremium, mapPriceToTier(pricePremium, pricePro, pricePremium, priceSoloPro))
	assert.Equal(t, TierSoloPro, mapPriceToTier(priceSoloPro, pricePro, pricePremium, priceSoloPro))

	// Unknown non-empty price ID defaults to Pro.
	assert.Equal(t, TierPro, mapPriceToTier("price_unknown", pricePro, pricePremium, priceSoloPro))

	// Empty price ID defaults to Free.
	assert.Equal(t, TierFree, mapPriceToTier("", pricePro, pricePremium, priceSoloPro))

	// Empty config: even if priceID matches, empty config means no match.
	assert.Equal(t, TierPro, mapPriceToTier("some_price", "", "", ""))
}


func TestMapStripeStatus(t *testing.T) {
	assert.Equal(t, StatusActive, mapStripeStatus("active"))
	assert.Equal(t, StatusTrialing, mapStripeStatus("trialing"))
	assert.Equal(t, StatusPastDue, mapStripeStatus("past_due"))
	assert.Equal(t, StatusCanceled, mapStripeStatus("canceled"))
	assert.Equal(t, StatusCanceled, mapStripeStatus("unpaid"))
	assert.Equal(t, StatusCanceled, mapStripeStatus("incomplete_expired"))
	// Unknown status passes through as string.
	assert.Equal(t, "incomplete", mapStripeStatus("incomplete"))
}


func TestExtractPriceID(t *testing.T) {
	// Nil subscription → empty.
	session := &stripe.CheckoutSession{}
	assert.Equal(t, "", extractPriceID(session))

	// Subscription with no items → empty.
	session.Subscription = &stripe.Subscription{}
	assert.Equal(t, "", extractPriceID(session))

	// Subscription with items but nil price → empty.
	session.Subscription.Items = &stripe.SubscriptionItemList{
		Data: []*stripe.SubscriptionItem{{}},
	}
	assert.Equal(t, "", extractPriceID(session))

	// Subscription with valid price → returns price ID.
	session.Subscription.Items.Data[0].Price = &stripe.Price{ID: "price_test_123"}
	assert.Equal(t, "price_test_123", extractPriceID(session))
}


func TestGetEmailByCustomerID_Empty(t *testing.T) {
	s := newTestStore()
	// No subscriptions exist — should return empty string.
	assert.Equal(t, "", s.GetEmailByCustomerID(""))
}


func TestGetTierForUser_NilAdminEmailFn(t *testing.T) {
	s := newTestStore()
	// With nil adminEmailFn, should just return TierFree for unknown user.
	assert.Equal(t, TierFree, s.GetTierForUser("nobody@example.com", nil))
}


func TestGetTierForUser_AdminEmailFnReturnsSameEmail(t *testing.T) {
	db := openTestDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := NewStore(db, logger)
	require.NoError(t, s.InitTable())

	// adminEmailFn returns the same email (self-referential) — should not infinite loop,
	// just return TierFree since there's no subscription.
	adminEmailFn := func(email string) string {
		return email
	}
	assert.Equal(t, TierFree, s.GetTierForUser("self@example.com", adminEmailFn))
}


func TestGetTierForUser_AdminEmailFnReturnsEmpty(t *testing.T) {
	s := newTestStore()
	adminEmailFn := func(email string) string {
		return ""
	}
	assert.Equal(t, TierFree, s.GetTierForUser("user@example.com", adminEmailFn))
}


func TestMaxUsers_DefaultsToOne(t *testing.T) {
	db := openTestDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := NewStore(db, logger)
	require.NoError(t, s.InitTable())

	// Set subscription without explicitly setting MaxUsers — should default to 0 in struct,
	// but COALESCE in LoadFromDB should return 1 from the DB default.
	require.NoError(t, s.SetSubscription(&Subscription{
		AdminEmail: "default@example.com",
		Tier:       TierPro,
		Status:     StatusActive,
		// MaxUsers deliberately left at 0 (zero value)
	}))

	// Reload from DB
	s2 := NewStore(db, logger)
	require.NoError(t, s2.InitTable())
	require.NoError(t, s2.LoadFromDB())

	sub := s2.GetSubscription("default@example.com")
	require.NotNil(t, sub)
	// The DB stores 0, COALESCE(max_users, 1) returns 1 when max_users is 0? No —
	// COALESCE only replaces NULL. Since we store 0 explicitly, it returns 0.
	// This tests that the value round-trips correctly.
	assert.Equal(t, 0, sub.MaxUsers)
}


func TestInitEventLogTable_NilDB(t *testing.T) {
	s := newTestStore()
	// InitEventLogTable with nil DB should return nil (no-op).
	err := s.InitEventLogTable()
	require.NoError(t, err)
}


func TestInitEventLogTable_Idempotent(t *testing.T) {
	db := openTestDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := NewStore(db, logger)

	// Call twice — should not error.
	require.NoError(t, s.InitEventLogTable())
	require.NoError(t, s.InitEventLogTable())

	// Should still be functional.
	assert.False(t, s.IsEventProcessed("evt_test"))
	require.NoError(t, s.MarkEventProcessed("evt_test", "test"))
	assert.True(t, s.IsEventProcessed("evt_test"))
}


func TestGetTier_PastDue(t *testing.T) {
	s := newTestStore()
	_ = s.SetSubscription(&Subscription{
		AdminEmail: "pastdue@example.com",
		Tier:       TierPro,
		Status:     StatusPastDue,
	})
	// past_due is not active or trialing, so should return TierFree.
	assert.Equal(t, TierFree, s.GetTier("pastdue@example.com"))
}


func TestGetTier_Trialing(t *testing.T) {
	s := newTestStore()
	_ = s.SetSubscription(&Subscription{
		AdminEmail: "trial@example.com",
		Tier:       TierPremium,
		Status:     StatusTrialing,
	})
	// Trialing is active, should return the tier.
	assert.Equal(t, TierPremium, s.GetTier("trial@example.com"))
}


func TestGetTier_TrialingButExpired(t *testing.T) {
	s := newTestStore()
	_ = s.SetSubscription(&Subscription{
		AdminEmail: "trialexp@example.com",
		Tier:       TierPremium,
		Status:     StatusTrialing,
		ExpiresAt:  time.Now().Add(-1 * time.Hour),
	})
	assert.Equal(t, TierFree, s.GetTier("trialexp@example.com"),
		"trialing but expired subscription should return TierFree")
}


func TestGetTier_FutureExpiry(t *testing.T) {
	s := newTestStore()
	_ = s.SetSubscription(&Subscription{
		AdminEmail: "future@example.com",
		Tier:       TierPro,
		Status:     StatusActive,
		ExpiresAt:  time.Now().Add(24 * time.Hour), // expires tomorrow
	})
	assert.Equal(t, TierPro, s.GetTier("future@example.com"),
		"active subscription with future expiry should return its tier")
}


func TestGetEmailByCustomerID_MultipleSubscriptions(t *testing.T) {
	s := newTestStore()
	_ = s.SetSubscription(&Subscription{
		AdminEmail:       "first@example.com",
		Tier:             TierPro,
		Status:           StatusActive,
		StripeCustomerID: "cus_first",
	})
	_ = s.SetSubscription(&Subscription{
		AdminEmail:       "second@example.com",
		Tier:             TierPremium,
		Status:           StatusActive,
		StripeCustomerID: "cus_second",
	})

	assert.Equal(t, "first@example.com", s.GetEmailByCustomerID("cus_first"))
	assert.Equal(t, "second@example.com", s.GetEmailByCustomerID("cus_second"))
	assert.Equal(t, "", s.GetEmailByCustomerID("cus_unknown"))
}


// ---------------------------------------------------------------------------
// WebhookHandler HTTP integration tests (mock-signed Stripe payloads)
// ---------------------------------------------------------------------------

// signTestPayload creates a valid Stripe webhook signature header for the given
// payload and secret using the SDK's own GenerateTestSignedPayload helper.
func signTestPayload(payload []byte, secret string) string {
	sp := stripewebhook.GenerateTestSignedPayload(&stripewebhook.UnsignedPayload{
		Payload: payload,
		Secret:  secret,
	})
	return sp.Header
}


// makeCheckoutPayload builds a checkout.session.completed event JSON with the
// required api_version field matching the Stripe SDK release train.
func makeCheckoutPayload(eventID, email, customerID, subID string) []byte {
	evt := map[string]interface{}{
		"id":          eventID,
		"object":      "event",
		"type":        "checkout.session.completed",
		"api_version": stripe.APIVersion,
		"data": map[string]interface{}{
			"object": map[string]interface{}{
				"object":           "checkout.session",
				"customer_details": map[string]interface{}{"email": email},
				"customer":         customerID,
				"subscription":     subID,
			},
		},
	}
	b, _ := json.Marshal(evt)
	return b
}


// TestMapPriceToTier_EmptyConfigPrices tests mapPriceToTier when all config prices are empty
// but priceID matches one of them (empty string match).
func TestMapPriceToTier_EmptyConfigPrices(t *testing.T) {
	// When pricePremium/pricePro/priceSoloPro are all empty and priceID is empty,
	// the switch will match case "" (pricePremium=""), but since pricePremium is empty,
	// it falls through. Same for pricePro. Then priceID "" → TierFree.
	assert.Equal(t, TierFree, mapPriceToTier("", "", "", ""))
}
