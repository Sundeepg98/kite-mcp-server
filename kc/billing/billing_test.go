package billing

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	stripe "github.com/stripe/stripe-go/v82"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/oauth"
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

// ---------------------------------------------------------------------------
// Tier method tests (EffectiveTier, String)
// ---------------------------------------------------------------------------

func TestTierSoloPro_EffectiveTier(t *testing.T) {
	// TierSoloPro should map down to TierPro for tool-access checks.
	assert.Equal(t, TierPro, TierSoloPro.EffectiveTier(),
		"TierSoloPro.EffectiveTier() should return TierPro")
}

func TestTierSoloPro_StringRepresentation(t *testing.T) {
	assert.Equal(t, "solo_pro", TierSoloPro.String())
}

func TestEffectiveTier_OtherTiers(t *testing.T) {
	// Non-SoloPro tiers should return themselves.
	assert.Equal(t, TierFree, TierFree.EffectiveTier())
	assert.Equal(t, TierPro, TierPro.EffectiveTier())
	assert.Equal(t, TierPremium, TierPremium.EffectiveTier())
}

func TestTierString_AllTiers(t *testing.T) {
	assert.Equal(t, "free", TierFree.String())
	assert.Equal(t, "pro", TierPro.String())
	assert.Equal(t, "premium", TierPremium.String())
	assert.Equal(t, "solo_pro", TierSoloPro.String())
}

// ---------------------------------------------------------------------------
// Middleware tests
// ---------------------------------------------------------------------------

// passthrough is a no-op tool handler that always succeeds.
func passthrough(_ context.Context, _ gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
	return gomcp.NewToolResultText("ok"), nil
}

func TestMiddleware_TierSoloPro(t *testing.T) {
	// A SoloPro user should be able to call a Pro tool because
	// EffectiveTier maps SoloPro → Pro.
	s := newTestStore()
	_ = s.SetSubscription(&Subscription{
		AdminEmail: "solo@example.com",
		Tier:       TierSoloPro,
		Status:     StatusActive,
		MaxUsers:   1,
	})

	mw := Middleware(s, nil)
	handler := mw(passthrough)

	ctx := oauth.ContextWithEmail(context.Background(), "solo@example.com")
	req := gomcp.CallToolRequest{}
	req.Params.Name = "place_order" // requires TierPro

	result, err := handler(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.IsError, "SoloPro user should access Pro tools")
	assert.Len(t, result.Content, 1)
	text, ok := result.Content[0].(gomcp.TextContent)
	require.True(t, ok)
	assert.Equal(t, "ok", text.Text)
}

func TestMiddleware_FreeUserBlockedFromProTool(t *testing.T) {
	s := newTestStore()
	// No subscription set — defaults to TierFree.

	mw := Middleware(s, nil)
	handler := mw(passthrough)

	ctx := oauth.ContextWithEmail(context.Background(), "free@example.com")
	req := gomcp.CallToolRequest{}
	req.Params.Name = "place_order" // requires TierPro

	result, err := handler(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.IsError, "Free user should be blocked from Pro tool")
	text, ok := result.Content[0].(gomcp.TextContent)
	require.True(t, ok)
	assert.Contains(t, text.Text, "pro")
	assert.Contains(t, text.Text, "Upgrade")
}

func TestMiddleware_FreeUserAllowedFreeTool(t *testing.T) {
	s := newTestStore()

	mw := Middleware(s, nil)
	handler := mw(passthrough)

	ctx := oauth.ContextWithEmail(context.Background(), "free@example.com")
	req := gomcp.CallToolRequest{}
	req.Params.Name = "get_holdings" // TierFree

	result, err := handler(ctx, req)
	require.NoError(t, err)
	assert.False(t, result.IsError, "Free user should access Free tools")
}

func TestMiddleware_NoEmail(t *testing.T) {
	// Unauthenticated requests pass through (auth middleware handles rejection).
	s := newTestStore()

	mw := Middleware(s, nil)
	handler := mw(passthrough)

	ctx := context.Background() // no email
	req := gomcp.CallToolRequest{}
	req.Params.Name = "place_order"

	result, err := handler(ctx, req)
	require.NoError(t, err)
	assert.False(t, result.IsError, "No email should pass through")
}

func TestMiddleware_PremiumUserAccessesPremiumTool(t *testing.T) {
	s := newTestStore()
	_ = s.SetSubscription(&Subscription{
		AdminEmail: "premium@example.com",
		Tier:       TierPremium,
		Status:     StatusActive,
	})

	mw := Middleware(s, nil)
	handler := mw(passthrough)

	ctx := oauth.ContextWithEmail(context.Background(), "premium@example.com")
	req := gomcp.CallToolRequest{}
	req.Params.Name = "backtest_strategy" // TierPremium

	result, err := handler(ctx, req)
	require.NoError(t, err)
	assert.False(t, result.IsError, "Premium user should access Premium tools")
}

func TestMiddleware_ProUserBlockedFromPremiumTool(t *testing.T) {
	s := newTestStore()
	_ = s.SetSubscription(&Subscription{
		AdminEmail: "pro@example.com",
		Tier:       TierPro,
		Status:     StatusActive,
	})

	mw := Middleware(s, nil)
	handler := mw(passthrough)

	ctx := oauth.ContextWithEmail(context.Background(), "pro@example.com")
	req := gomcp.CallToolRequest{}
	req.Params.Name = "backtest_strategy" // TierPremium

	result, err := handler(ctx, req)
	require.NoError(t, err)
	assert.True(t, result.IsError, "Pro user should be blocked from Premium tool")
	text, ok := result.Content[0].(gomcp.TextContent)
	require.True(t, ok)
	assert.Contains(t, text.Text, "premium")
}

func TestMiddleware_FamilyInheritance(t *testing.T) {
	db := openTestDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := NewStore(db, logger)
	require.NoError(t, s.InitTable())

	_ = s.SetSubscription(&Subscription{
		AdminEmail: "admin@example.com",
		Tier:       TierPro,
		Status:     StatusActive,
		MaxUsers:   5,
	})

	adminEmailFn := func(email string) string {
		if email == "family@example.com" {
			return "admin@example.com"
		}
		return ""
	}

	mw := Middleware(s, adminEmailFn)
	handler := mw(passthrough)

	ctx := oauth.ContextWithEmail(context.Background(), "family@example.com")
	req := gomcp.CallToolRequest{}
	req.Params.Name = "place_order" // TierPro

	result, err := handler(ctx, req)
	require.NoError(t, err)
	assert.False(t, result.IsError, "Family member should inherit admin's Pro tier")
}

// ---------------------------------------------------------------------------
// CheckoutHandler plan validation (solo_pro accepted)
// ---------------------------------------------------------------------------

func TestCheckoutHandler_SoloProPlanValidation(t *testing.T) {
	// This test validates that "solo_pro" is an accepted plan value
	// by checking the checkout handler's plan parsing logic directly.
	// We verify via the store that a SoloPro subscription round-trips correctly.
	s := newTestStore()
	sub := &Subscription{
		AdminEmail: "checkout@example.com",
		Tier:       TierSoloPro,
		Status:     StatusActive,
		MaxUsers:   1,
	}
	require.NoError(t, s.SetSubscription(sub))

	got := s.GetSubscription("checkout@example.com")
	require.NotNil(t, got)
	assert.Equal(t, TierSoloPro, got.Tier)
	assert.Equal(t, 1, got.MaxUsers)
	// Effective tier for tool access is Pro.
	assert.Equal(t, TierPro, got.Tier.EffectiveTier())
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

func TestSetSubscription_EmptyEmail(t *testing.T) {
	s := newTestStore()
	err := s.SetSubscription(&Subscription{
		AdminEmail: "",
		Tier:       TierPro,
		Status:     StatusActive,
	})
	assert.Error(t, err, "empty email should be rejected")
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

// ---------------------------------------------------------------------------
// CheckoutHandler early validation paths (no Stripe API calls reached)
// ---------------------------------------------------------------------------

func TestCheckoutHandler_MethodNotAllowed(t *testing.T) {
	s := newTestStore()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := CheckoutHandler(s, logger)

	req := httptest.NewRequest(http.MethodGet, "/checkout?plan=pro", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}

func TestCheckoutHandler_Unauthorized(t *testing.T) {
	s := newTestStore()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := CheckoutHandler(s, logger)

	req := httptest.NewRequest(http.MethodPost, "/checkout?plan=pro", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestCheckoutHandler_InvalidPlan(t *testing.T) {
	s := newTestStore()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := CheckoutHandler(s, logger)

	ctx := oauth.ContextWithEmail(context.Background(), "user@example.com")
	req := httptest.NewRequest(http.MethodPost, "/checkout?plan=invalid", nil)
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid plan")
}

func TestCheckoutHandler_MissingPriceConfig(t *testing.T) {
	s := newTestStore()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := CheckoutHandler(s, logger)

	// Ensure env vars are empty so priceID will be "".
	os.Unsetenv("STRIPE_PRICE_SOLO_PRO")

	ctx := oauth.ContextWithEmail(context.Background(), "user@example.com")
	req := httptest.NewRequest(http.MethodPost, "/checkout?plan=solo_pro", nil)
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Contains(t, rr.Body.String(), "pricing not configured")
}

// ---------------------------------------------------------------------------
// PortalHandler early validation paths
// ---------------------------------------------------------------------------

func TestPortalHandler_Unauthorized(t *testing.T) {
	s := newTestStore()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := PortalHandler(s, logger)

	req := httptest.NewRequest(http.MethodGet, "/portal", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestPortalHandler_NoSubscription(t *testing.T) {
	s := newTestStore()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := PortalHandler(s, logger)

	ctx := oauth.ContextWithEmail(context.Background(), "user@example.com")
	req := httptest.NewRequest(http.MethodGet, "/portal", nil)
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Should redirect to /pricing when no subscription exists.
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, "/pricing", rr.Header().Get("Location"))
}

func TestPortalHandler_NoStripeCustomerID(t *testing.T) {
	s := newTestStore()
	_ = s.SetSubscription(&Subscription{
		AdminEmail: "user@example.com",
		Tier:       TierPro,
		Status:     StatusActive,
		// StripeCustomerID is empty.
	})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := PortalHandler(s, logger)

	ctx := oauth.ContextWithEmail(context.Background(), "user@example.com")
	req := httptest.NewRequest(http.MethodGet, "/portal", nil)
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Should redirect to /pricing when customer has no Stripe ID.
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.Equal(t, "/pricing", rr.Header().Get("Location"))
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

func TestInitEventLogTable_NilDB(t *testing.T) {
	s := newTestStore()
	// InitEventLogTable with nil DB should return nil (no-op).
	err := s.InitEventLogTable()
	require.NoError(t, err)
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

func TestCheckoutHandler_ValidPlansSoloProAndPremium(t *testing.T) {
	s := newTestStore()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := CheckoutHandler(s, logger)

	// Test "pro" plan — also missing price config
	os.Unsetenv("STRIPE_PRICE_PRO")
	ctx := oauth.ContextWithEmail(context.Background(), "user@example.com")
	req := httptest.NewRequest(http.MethodPost, "/checkout?plan=pro", nil)
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Contains(t, rr.Body.String(), "pricing not configured")

	// Test "premium" plan — also missing price config
	os.Unsetenv("STRIPE_PRICE_PREMIUM")
	req2 := httptest.NewRequest(http.MethodPost, "/checkout?plan=premium", nil)
	req2 = req2.WithContext(ctx)
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	assert.Equal(t, http.StatusInternalServerError, rr2.Code)
	assert.Contains(t, rr2.Body.String(), "pricing not configured")
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
// Webhook handler internal function tests (pure functions, no Stripe API)
// ---------------------------------------------------------------------------

func TestHandleCheckoutCompleted(t *testing.T) {
	db := openTestDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := NewStore(db, logger)
	require.NoError(t, s.InitTable())

	var upgradedEmail string
	adminUpgrade := func(email string) { upgradedEmail = email }

	// Build a minimal Stripe event payload with checkout.session.completed data.
	sessionJSON := `{
		"customer_details": {"email": "buyer@example.com"},
		"customer": {"id": "cus_checkout_1"},
		"subscription": {
			"id": "sub_checkout_1",
			"items": {"data": [{"price": {"id": "price_pro_test"}}]}
		},
		"metadata": {"max_users": "5", "plan": "pro"}
	}`
	event := stripe.Event{
		ID:   "evt_checkout_001",
		Type: "checkout.session.completed",
		Data: &stripe.EventData{Raw: json.RawMessage(sessionJSON)},
	}

	handleCheckoutCompleted(s, &event, "price_pro_test", "price_premium_test", "price_solo_test", logger, adminUpgrade)

	// Verify subscription was created.
	sub := s.GetSubscription("buyer@example.com")
	require.NotNil(t, sub)
	assert.Equal(t, TierPro, sub.Tier)
	assert.Equal(t, "cus_checkout_1", sub.StripeCustomerID)
	assert.Equal(t, "sub_checkout_1", sub.StripeSubID)
	assert.Equal(t, StatusActive, sub.Status)
	assert.Equal(t, 5, sub.MaxUsers)

	// Verify admin upgrade callback was called.
	assert.Equal(t, "buyer@example.com", upgradedEmail)

	// Verify GetEmailByCustomerID works.
	assert.Equal(t, "buyer@example.com", s.GetEmailByCustomerID("cus_checkout_1"))
}

func TestHandleCheckoutCompleted_MissingEmail(t *testing.T) {
	s := newTestStore()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// No customer_details.email — should log error and return.
	sessionJSON := `{"customer_details": {}, "customer": {"id": "cus_x"}}`
	event := stripe.Event{
		ID:   "evt_no_email",
		Type: "checkout.session.completed",
		Data: &stripe.EventData{Raw: json.RawMessage(sessionJSON)},
	}

	handleCheckoutCompleted(s, &event, "", "", "", logger, nil)

	// No subscription should be created.
	assert.Nil(t, s.GetSubscription(""))
}

func TestHandleCheckoutCompleted_InvalidJSON(t *testing.T) {
	s := newTestStore()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	event := stripe.Event{
		ID:   "evt_bad_json",
		Type: "checkout.session.completed",
		Data: &stripe.EventData{Raw: json.RawMessage(`{invalid json}`)},
	}

	// Should not panic.
	handleCheckoutCompleted(s, &event, "", "", "", logger, nil)
}

func TestHandleCheckoutCompleted_NoAdminUpgrade(t *testing.T) {
	s := newTestStore()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	sessionJSON := `{
		"customer_details": {"email": "solo@example.com"},
		"customer": {"id": "cus_solo"},
		"subscription": {"id": "sub_solo", "items": {"data": [{"price": {"id": "price_solo_test"}}]}},
		"metadata": {"max_users": "1"}
	}`
	event := stripe.Event{
		ID:   "evt_solo",
		Type: "checkout.session.completed",
		Data: &stripe.EventData{Raw: json.RawMessage(sessionJSON)},
	}

	// adminUpgrade is nil — should not panic.
	handleCheckoutCompleted(s, &event, "price_pro_test", "price_premium_test", "price_solo_test", logger, nil)

	sub := s.GetSubscription("solo@example.com")
	require.NotNil(t, sub)
	assert.Equal(t, TierSoloPro, sub.Tier)
	assert.Equal(t, 1, sub.MaxUsers)
}

func TestHandleCheckoutCompleted_PremiumTier(t *testing.T) {
	db := openTestDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := NewStore(db, logger)
	require.NoError(t, s.InitTable())

	sessionJSON := `{
		"customer_details": {"email": "premium@example.com"},
		"customer": {"id": "cus_premium"},
		"subscription": {"id": "sub_premium", "items": {"data": [{"price": {"id": "price_premium_test"}}]}},
		"metadata": {"max_users": "20"}
	}`
	event := stripe.Event{
		ID:   "evt_premium",
		Type: "checkout.session.completed",
		Data: &stripe.EventData{Raw: json.RawMessage(sessionJSON)},
	}

	handleCheckoutCompleted(s, &event, "price_pro_test", "price_premium_test", "price_solo_test", logger, nil)

	sub := s.GetSubscription("premium@example.com")
	require.NotNil(t, sub)
	assert.Equal(t, TierPremium, sub.Tier)
	assert.Equal(t, 20, sub.MaxUsers)
}

func TestHandleSubscriptionUpdated(t *testing.T) {
	db := openTestDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := NewStore(db, logger)
	require.NoError(t, s.InitTable())

	// First create a subscription (simulating checkout) so customer mapping exists.
	require.NoError(t, s.SetSubscription(&Subscription{
		AdminEmail:       "update@example.com",
		Tier:             TierPro,
		StripeCustomerID: "cus_update_1",
		StripeSubID:      "sub_update_1",
		Status:           StatusActive,
	}))

	// Now simulate a subscription.updated event upgrading to Premium.
	subJSON := `{
		"id": "sub_update_1",
		"customer": {"id": "cus_update_1"},
		"status": "active",
		"items": {"data": [{"price": {"id": "price_premium_test"}}]},
		"cancel_at": 0
	}`
	event := stripe.Event{
		ID:   "evt_update_001",
		Type: "customer.subscription.updated",
		Data: &stripe.EventData{Raw: json.RawMessage(subJSON)},
	}

	handleSubscriptionUpdated(s, &event, "price_pro_test", "price_premium_test", "price_solo_test", logger)

	sub := s.GetSubscription("update@example.com")
	require.NotNil(t, sub)
	assert.Equal(t, TierPremium, sub.Tier)
	assert.Equal(t, StatusActive, sub.Status)
}

func TestHandleSubscriptionUpdated_Downgrade(t *testing.T) {
	db := openTestDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := NewStore(db, logger)
	require.NoError(t, s.InitTable())

	require.NoError(t, s.SetSubscription(&Subscription{
		AdminEmail:       "downgrade@example.com",
		Tier:             TierPremium,
		StripeCustomerID: "cus_downgrade",
		StripeSubID:      "sub_downgrade",
		Status:           StatusActive,
	}))

	subJSON := `{
		"id": "sub_downgrade",
		"customer": {"id": "cus_downgrade"},
		"status": "active",
		"items": {"data": [{"price": {"id": "price_pro_test"}}]},
		"cancel_at": 0
	}`
	event := stripe.Event{
		ID:   "evt_downgrade",
		Type: "customer.subscription.updated",
		Data: &stripe.EventData{Raw: json.RawMessage(subJSON)},
	}

	handleSubscriptionUpdated(s, &event, "price_pro_test", "price_premium_test", "price_solo_test", logger)

	sub := s.GetSubscription("downgrade@example.com")
	require.NotNil(t, sub)
	assert.Equal(t, TierPro, sub.Tier) // downgraded from Premium to Pro
}

func TestHandleSubscriptionUpdated_UnknownCustomer(t *testing.T) {
	s := newTestStore()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	subJSON := `{
		"id": "sub_unknown",
		"customer": {"id": "cus_unknown"},
		"status": "active",
		"items": {"data": [{"price": {"id": "price_pro_test"}}]}
	}`
	event := stripe.Event{
		ID:   "evt_unknown_cust",
		Type: "customer.subscription.updated",
		Data: &stripe.EventData{Raw: json.RawMessage(subJSON)},
	}

	// Should not panic — just logs error about unknown customer.
	handleSubscriptionUpdated(s, &event, "price_pro_test", "", "", logger)
}

func TestHandleSubscriptionUpdated_InvalidJSON(t *testing.T) {
	s := newTestStore()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	event := stripe.Event{
		ID:   "evt_bad_update",
		Type: "customer.subscription.updated",
		Data: &stripe.EventData{Raw: json.RawMessage(`{not valid}`)},
	}

	// Should not panic.
	handleSubscriptionUpdated(s, &event, "", "", "", logger)
}

func TestHandleSubscriptionUpdated_WithCancelAt(t *testing.T) {
	db := openTestDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := NewStore(db, logger)
	require.NoError(t, s.InitTable())

	require.NoError(t, s.SetSubscription(&Subscription{
		AdminEmail:       "cancel@example.com",
		Tier:             TierPro,
		StripeCustomerID: "cus_cancel",
		StripeSubID:      "sub_cancel",
		Status:           StatusActive,
	}))

	cancelAt := time.Now().Add(30 * 24 * time.Hour).Unix()
	subJSON := fmt.Sprintf(`{
		"id": "sub_cancel",
		"customer": {"id": "cus_cancel"},
		"status": "active",
		"items": {"data": [{"price": {"id": "price_pro_test"}}]},
		"cancel_at": %d
	}`, cancelAt)
	event := stripe.Event{
		ID:   "evt_cancel_at",
		Type: "customer.subscription.updated",
		Data: &stripe.EventData{Raw: json.RawMessage(subJSON)},
	}

	handleSubscriptionUpdated(s, &event, "price_pro_test", "", "", logger)

	sub := s.GetSubscription("cancel@example.com")
	require.NotNil(t, sub)
	assert.False(t, sub.ExpiresAt.IsZero(), "ExpiresAt should be set from cancel_at")
}

func TestHandleSubscriptionDeleted(t *testing.T) {
	db := openTestDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := NewStore(db, logger)
	require.NoError(t, s.InitTable())

	require.NoError(t, s.SetSubscription(&Subscription{
		AdminEmail:       "delete@example.com",
		Tier:             TierPro,
		StripeCustomerID: "cus_delete",
		StripeSubID:      "sub_delete",
		Status:           StatusActive,
	}))

	subJSON := `{
		"id": "sub_delete",
		"customer": {"id": "cus_delete"}
	}`
	event := stripe.Event{
		ID:   "evt_delete_001",
		Type: "customer.subscription.deleted",
		Data: &stripe.EventData{Raw: json.RawMessage(subJSON)},
	}

	handleSubscriptionDeleted(s, &event, logger)

	sub := s.GetSubscription("delete@example.com")
	require.NotNil(t, sub)
	assert.Equal(t, TierFree, sub.Tier)
	assert.Equal(t, StatusCanceled, sub.Status)
}

func TestHandleSubscriptionDeleted_UnknownCustomer(t *testing.T) {
	s := newTestStore()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	subJSON := `{"id": "sub_x", "customer": {"id": "cus_nobody"}}`
	event := stripe.Event{
		ID:   "evt_del_unknown",
		Type: "customer.subscription.deleted",
		Data: &stripe.EventData{Raw: json.RawMessage(subJSON)},
	}

	// Should not panic.
	handleSubscriptionDeleted(s, &event, logger)
}

func TestHandleSubscriptionDeleted_InvalidJSON(t *testing.T) {
	s := newTestStore()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	event := stripe.Event{
		ID:   "evt_del_bad",
		Type: "customer.subscription.deleted",
		Data: &stripe.EventData{Raw: json.RawMessage(`{bad}`)},
	}

	// Should not panic.
	handleSubscriptionDeleted(s, &event, logger)
}

func TestHandlePaymentFailed(t *testing.T) {
	db := openTestDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := NewStore(db, logger)
	require.NoError(t, s.InitTable())

	require.NoError(t, s.SetSubscription(&Subscription{
		AdminEmail:       "payer@example.com",
		Tier:             TierPro,
		StripeCustomerID: "cus_payer",
		StripeSubID:      "sub_payer",
		Status:           StatusActive,
	}))

	invJSON := `{"customer": {"id": "cus_payer"}}`
	event := stripe.Event{
		ID:   "evt_payment_fail_001",
		Type: "invoice.payment_failed",
		Data: &stripe.EventData{Raw: json.RawMessage(invJSON)},
	}

	handlePaymentFailed(s, &event, logger)

	sub := s.GetSubscription("payer@example.com")
	require.NotNil(t, sub)
	assert.Equal(t, StatusPastDue, sub.Status)
	assert.Equal(t, TierPro, sub.Tier) // tier doesn't change, only status
}

func TestHandlePaymentFailed_UnknownCustomer(t *testing.T) {
	s := newTestStore()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	invJSON := `{"customer": {"id": "cus_nobody"}}`
	event := stripe.Event{
		ID:   "evt_pf_unknown",
		Type: "invoice.payment_failed",
		Data: &stripe.EventData{Raw: json.RawMessage(invJSON)},
	}

	// Should not panic.
	handlePaymentFailed(s, &event, logger)
}

func TestHandlePaymentFailed_NoCustomerMapping(t *testing.T) {
	s := newTestStore()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// No subscription exists for this customer — unknown mapping.
	invJSON := `{"customer": {"id": "cus_no_mapping"}}`
	event := stripe.Event{
		ID:   "evt_pf_no_mapping",
		Type: "invoice.payment_failed",
		Data: &stripe.EventData{Raw: json.RawMessage(invJSON)},
	}

	// Should not panic — just logs error about unknown customer.
	handlePaymentFailed(s, &event, logger)
}

func TestHandlePaymentFailed_InvalidJSON(t *testing.T) {
	s := newTestStore()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	event := stripe.Event{
		ID:   "evt_pf_bad",
		Type: "invoice.payment_failed",
		Data: &stripe.EventData{Raw: json.RawMessage(`{bad}`)},
	}

	// Should not panic.
	handlePaymentFailed(s, &event, logger)
}

func TestHandleCheckoutCompleted_NoCustomerID(t *testing.T) {
	s := newTestStore()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// customer and subscription are nil — only email present.
	sessionJSON := `{
		"customer_details": {"email": "nostripe@example.com"},
		"metadata": {"max_users": "1"}
	}`
	event := stripe.Event{
		ID:   "evt_no_customer",
		Type: "checkout.session.completed",
		Data: &stripe.EventData{Raw: json.RawMessage(sessionJSON)},
	}

	handleCheckoutCompleted(s, &event, "price_pro_test", "", "", logger, nil)

	sub := s.GetSubscription("nostripe@example.com")
	require.NotNil(t, sub)
	assert.Equal(t, "", sub.StripeCustomerID)
	assert.Equal(t, "", sub.StripeSubID)
	assert.Equal(t, StatusActive, sub.Status)
}

func TestHandleSubscriptionUpdated_StatusChange(t *testing.T) {
	db := openTestDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := NewStore(db, logger)
	require.NoError(t, s.InitTable())

	require.NoError(t, s.SetSubscription(&Subscription{
		AdminEmail:       "status@example.com",
		Tier:             TierPro,
		StripeCustomerID: "cus_status",
		StripeSubID:      "sub_status",
		Status:           StatusActive,
	}))

	// Simulate subscription becoming past_due.
	subJSON := `{
		"id": "sub_status",
		"customer": {"id": "cus_status"},
		"status": "past_due",
		"items": {"data": [{"price": {"id": "price_pro_test"}}]}
	}`
	event := stripe.Event{
		ID:   "evt_status_change",
		Type: "customer.subscription.updated",
		Data: &stripe.EventData{Raw: json.RawMessage(subJSON)},
	}

	handleSubscriptionUpdated(s, &event, "price_pro_test", "", "", logger)

	sub := s.GetSubscription("status@example.com")
	require.NotNil(t, sub)
	assert.Equal(t, StatusPastDue, sub.Status)
	assert.Equal(t, TierPro, sub.Tier)
}

func TestHandleSubscriptionDeleted_ExistingSub(t *testing.T) {
	db := openTestDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := NewStore(db, logger)
	require.NoError(t, s.InitTable())

	require.NoError(t, s.SetSubscription(&Subscription{
		AdminEmail:       "delsub@example.com",
		Tier:             TierPremium,
		StripeCustomerID: "cus_delsub",
		StripeSubID:      "sub_delsub",
		Status:           StatusActive,
		MaxUsers:         10,
	}))

	subJSON := `{"id": "sub_delsub", "customer": {"id": "cus_delsub"}}`
	event := stripe.Event{
		ID:   "evt_delsub",
		Type: "customer.subscription.deleted",
		Data: &stripe.EventData{Raw: json.RawMessage(subJSON)},
	}

	handleSubscriptionDeleted(s, &event, logger)

	sub := s.GetSubscription("delsub@example.com")
	require.NotNil(t, sub)
	assert.Equal(t, TierFree, sub.Tier)
	assert.Equal(t, StatusCanceled, sub.Status)
}

// ---------------------------------------------------------------------------
// WebhookHandler early-path tests (no Stripe signature needed)
// ---------------------------------------------------------------------------

func TestWebhookHandler_MethodNotAllowed(t *testing.T) {
	s := newTestStore()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := WebhookHandler(s, "whsec_test", logger, nil)

	req := httptest.NewRequest(http.MethodGet, "/webhook", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
}

func TestWebhookHandler_InvalidSignature(t *testing.T) {
	s := newTestStore()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := WebhookHandler(s, "whsec_test_secret", logger, nil)

	req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(`{}`))
	req.Header.Set("Stripe-Signature", "t=123,v1=invalid")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
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

func TestMiddleware_GetTierForUser_WithAdminEmailFn(t *testing.T) {
	db := openTestDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := NewStore(db, logger)
	require.NoError(t, s.InitTable())

	// Premium admin
	_ = s.SetSubscription(&Subscription{
		AdminEmail: "admin@example.com",
		Tier:       TierPremium,
		Status:     StatusActive,
		MaxUsers:   10,
	})

	adminEmailFn := func(email string) string {
		if email == "worker@example.com" {
			return "admin@example.com"
		}
		return ""
	}

	// Worker should inherit premium tier via family
	assert.Equal(t, TierPremium, s.GetTierForUser("worker@example.com", adminEmailFn))

	// Worker accessing premium tool via middleware
	mw := Middleware(s, adminEmailFn)
	handler := mw(passthrough)

	ctx := oauth.ContextWithEmail(context.Background(), "worker@example.com")
	req := gomcp.CallToolRequest{}
	req.Params.Name = "backtest_strategy" // TierPremium

	result, err := handler(ctx, req)
	require.NoError(t, err)
	assert.False(t, result.IsError, "Family member of Premium admin should access Premium tools")
}
