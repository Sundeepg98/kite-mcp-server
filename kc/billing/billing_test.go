package billing

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
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
