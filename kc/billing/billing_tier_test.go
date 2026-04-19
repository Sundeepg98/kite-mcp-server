package billing

import (
	"context"
	"io"
	"log/slog"
	"testing"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// newTestStore creates a billing Store backed only by the in-memory map
// (no SQLite). This is sufficient for testing business logic since the
// Store gracefully handles a nil DB.


func TestTierOrdering(t *testing.T) {
	assert.Less(t, TierFree, TierPro, "Free should be less than Pro")
	assert.Less(t, TierPro, TierPremium, "Pro should be less than Premium")
	assert.Less(t, TierFree, TierPremium, "Free should be less than Premium")
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


func TestTierString_AllTiers(t *testing.T) {
	assert.Equal(t, "free", TierFree.String())
	assert.Equal(t, "pro", TierPro.String())
	assert.Equal(t, "premium", TierPremium.String())
	assert.Equal(t, "solo_pro", TierSoloPro.String())
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
	req.Params.Name = "options_greeks" // TierPremium

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
	req.Params.Name = "options_greeks" // TierPremium

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
	req.Params.Name = "options_greeks" // TierPremium

	result, err := handler(ctx, req)
	require.NoError(t, err)
	assert.False(t, result.IsError, "Family member of Premium admin should access Premium tools")
}
