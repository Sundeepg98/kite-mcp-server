package ops

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/billing"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// newTestDashboardWithAudit is defined in coverage_final_test.go — reuse it here.

// mockBillingStore implements billingStoreIface for testing.
type mockBillingStore struct {
	subs map[string]*billing.Subscription
}

func (m *mockBillingStore) GetSubscription(email string) *billing.Subscription {
	return m.subs[email]
}

// ===========================================================================
// buildPortfolioResponse — unit test (0% -> 100%)
// ===========================================================================

func TestBuildPortfolioResponse_Empty(t *testing.T) {
	t.Parallel()
	_ = newTestDashboard(t)
	resp := buildPortfolioResponse(nil, kiteconnect.Positions{})

	assert.Equal(t, 0, resp.Summary.HoldingsCount)
	assert.Equal(t, 0, resp.Summary.PositionsCount)
	assert.Empty(t, resp.Holdings)
	assert.Empty(t, resp.Positions)
}

func TestBuildPortfolioResponse_WithData(t *testing.T) {
	t.Parallel()
	_ = newTestDashboard(t)

	holdings := kiteconnect.Holdings{
		{
			Tradingsymbol:      "INFY",
			Exchange:           "NSE",
			Quantity:           10,
			AveragePrice:       1500.0,
			LastPrice:          1600.0,
			PnL:                1000.0,
			DayChangePercentage: 2.5,
			Product:            "CNC",
		},
		{
			Tradingsymbol: "TCS",
			Exchange:      "NSE",
			Quantity:      5,
			AveragePrice:  3000.0,
			LastPrice:     3200.0,
			PnL:           1000.0,
			Product:       "CNC",
		},
	}
	positions := kiteconnect.Positions{
		Net: []kiteconnect.Position{
			{
				Tradingsymbol: "RELIANCE",
				Exchange:      "NSE",
				Quantity:      2,
				AveragePrice:  2500.0,
				LastPrice:     2600.0,
				PnL:           200.0,
				Product:       "MIS",
			},
		},
	}

	resp := buildPortfolioResponse(holdings, positions)

	assert.Equal(t, 2, resp.Summary.HoldingsCount)
	assert.Equal(t, 1, resp.Summary.PositionsCount)
	assert.Len(t, resp.Holdings, 2)
	assert.Len(t, resp.Positions, 1)

	// Check totals
	expectedInvested := 1500.0*10 + 3000.0*5 // 15000 + 15000 = 30000
	expectedCurrent := 1600.0*10 + 3200.0*5   // 16000 + 16000 = 32000
	assert.Equal(t, expectedInvested, resp.Summary.TotalInvested)
	assert.Equal(t, expectedCurrent, resp.Summary.TotalCurrent)
	assert.Equal(t, 2000.0, resp.Summary.TotalPnL) // 1000 + 1000
	assert.Equal(t, 200.0, resp.Summary.PositionsPnL)

	// Verify first holding fields
	assert.Equal(t, "INFY", resp.Holdings[0].Tradingsymbol)
	assert.Equal(t, "NSE", resp.Holdings[0].Exchange)
	assert.Equal(t, 10, resp.Holdings[0].Quantity)
	assert.Equal(t, 2.5, resp.Holdings[0].DayChangePercent)

	// Verify position fields
	assert.Equal(t, "RELIANCE", resp.Positions[0].Tradingsymbol)
	assert.Equal(t, "MIS", resp.Positions[0].Product)
}

// ===========================================================================
// computeDashboardSectorExposure — unit test (0% -> 100%)
// ===========================================================================

func TestComputeDashboardSectorExposure_Empty(t *testing.T) {
	t.Parallel()
	_ = newTestDashboard(t)
	resp := computeDashboardSectorExposure(nil)

	assert.Empty(t, resp.Sectors)
	assert.Equal(t, 0, resp.HoldingsCount)
}

func TestComputeDashboardSectorExposure_ZeroValue(t *testing.T) {
	t.Parallel()
	_ = newTestDashboard(t)

	holdings := kiteconnect.Holdings{
		{Tradingsymbol: "INFY", LastPrice: 0, Quantity: 10},
	}
	resp := computeDashboardSectorExposure(holdings)

	assert.Equal(t, 1, resp.HoldingsCount)
	assert.Empty(t, resp.Sectors)
}

func TestComputeDashboardSectorExposure_WithData(t *testing.T) {
	t.Parallel()
	_ = newTestDashboard(t)

	holdings := kiteconnect.Holdings{
		{Tradingsymbol: "INFY", Exchange: "NSE", LastPrice: 1600, Quantity: 100},
		{Tradingsymbol: "TCS", Exchange: "NSE", LastPrice: 3200, Quantity: 50},
		{Tradingsymbol: "HDFCBANK", Exchange: "NSE", LastPrice: 1500, Quantity: 100},
		{Tradingsymbol: "UNKNOWNSYM", Exchange: "NSE", LastPrice: 500, Quantity: 10},
	}

	resp := computeDashboardSectorExposure(holdings)

	assert.Equal(t, 4, resp.HoldingsCount)
	assert.Equal(t, 3, resp.MappedCount)
	assert.Equal(t, 1, resp.UnmappedCount)
	assert.Greater(t, resp.TotalValue, 0.0)
	assert.NotEmpty(t, resp.Sectors)

	// Sectors should be sorted by pct descending
	for i := 1; i < len(resp.Sectors); i++ {
		assert.GreaterOrEqual(t, resp.Sectors[i-1].Pct, resp.Sectors[i].Pct)
	}
}

func TestComputeDashboardSectorExposure_OverExposure(t *testing.T) {
	t.Parallel()
	_ = newTestDashboard(t)

	// All in IT sector — way over 30% threshold
	holdings := kiteconnect.Holdings{
		{Tradingsymbol: "INFY", LastPrice: 1600, Quantity: 1000},
	}

	resp := computeDashboardSectorExposure(holdings)

	// Single sector should be 100% and over-exposed
	assert.Len(t, resp.Sectors, 1)
	assert.True(t, resp.Sectors[0].OverExposed)
	assert.NotEmpty(t, resp.Warnings)
}

func TestComputeDashboardSectorExposure_SuffixStripping(t *testing.T) {
	t.Parallel()
	_ = newTestDashboard(t)

	// Test that -BE, -EQ suffixes are stripped for sector lookup
	holdings := kiteconnect.Holdings{
		{Tradingsymbol: "INFY-BE", LastPrice: 1600, Quantity: 10},
		{Tradingsymbol: "TCS-EQ", LastPrice: 3200, Quantity: 5},
	}

	resp := computeDashboardSectorExposure(holdings)

	assert.Equal(t, 2, resp.MappedCount)
	assert.Equal(t, 0, resp.UnmappedCount)
}

// ===========================================================================
// computeTaxAnalysis — unit test (0% -> 100%)
// ===========================================================================

func TestComputeTaxAnalysis_Empty(t *testing.T) {
	t.Parallel()
	_ = newTestDashboard(t)
	resp := computeTaxAnalysis(nil)

	assert.Empty(t, resp.Holdings)
	assert.Equal(t, 0, resp.Summary.HoldingsAnalyzed)
}

func TestComputeTaxAnalysis_WithGains(t *testing.T) {
	t.Parallel()
	_ = newTestDashboard(t)

	holdings := kiteconnect.Holdings{
		{
			Tradingsymbol: "INFY",
			Exchange:      "NSE",
			Quantity:      10,
			AveragePrice:  1500.0,
			LastPrice:     1600.0,
		},
	}

	resp := computeTaxAnalysis(holdings)

	require.Len(t, resp.Holdings, 1)
	assert.Equal(t, "INFY", resp.Holdings[0].Symbol)
	assert.Equal(t, "STCG", resp.Holdings[0].Classification)
	assert.Equal(t, 20.0, resp.Holdings[0].TaxRate)
	assert.False(t, resp.Holdings[0].Harvestable)
	assert.Greater(t, resp.Holdings[0].TaxIfSold, 0.0)
	assert.Equal(t, 1, resp.Summary.HoldingsAnalyzed)
	assert.Greater(t, resp.Summary.TotalSTCGGains, 0.0)
}

func TestComputeTaxAnalysis_WithLosses(t *testing.T) {
	t.Parallel()
	_ = newTestDashboard(t)

	holdings := kiteconnect.Holdings{
		{
			Tradingsymbol: "TCS",
			Exchange:      "NSE",
			Quantity:      10,
			AveragePrice:  3200.0,
			LastPrice:     3000.0,
		},
	}

	resp := computeTaxAnalysis(holdings)

	require.Len(t, resp.Holdings, 1)
	assert.True(t, resp.Holdings[0].Harvestable)
	assert.Equal(t, 0.0, resp.Holdings[0].TaxIfSold) // No tax on losses
	assert.Less(t, resp.Summary.TotalSTCGLosses, 0.0)
	assert.Less(t, resp.Summary.HarvestableLoss, 0.0)
	assert.Greater(t, resp.Summary.PotentialTaxSaving, 0.0)
}

func TestComputeTaxAnalysis_MixedSorted(t *testing.T) {
	t.Parallel()
	_ = newTestDashboard(t)

	holdings := kiteconnect.Holdings{
		{Tradingsymbol: "GAIN1", Quantity: 10, AveragePrice: 100, LastPrice: 200},
		{Tradingsymbol: "LOSS1", Quantity: 10, AveragePrice: 200, LastPrice: 100},
		{Tradingsymbol: "GAIN2", Quantity: 5, AveragePrice: 100, LastPrice: 300},
	}

	resp := computeTaxAnalysis(holdings)

	// Losses should sort first (harvestable), then by ascending P&L
	require.Len(t, resp.Holdings, 3)
	assert.True(t, resp.Holdings[0].Harvestable, "first entry should be harvestable (loss)")
}

// ===========================================================================
// buildOrderSummary — unit test (0% -> 100%)
// ===========================================================================

func TestBuildOrderSummary_Empty(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	summary := d.orders.buildOrderSummary(nil)
	assert.Equal(t, 0, summary.TotalOrders)
	assert.Nil(t, summary.TotalPnL)
}

func TestBuildOrderSummary_WithEntries(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)

	pnl1 := 500.0
	pnl2 := -200.0
	entries := []orderEntry{
		{Status: "COMPLETE", PnL: &pnl1},
		{Status: "COMPLETE", PnL: &pnl2},
		{Status: "REJECTED"},
	}

	summary := d.orders.buildOrderSummary(entries)

	assert.Equal(t, 3, summary.TotalOrders)
	assert.Equal(t, 2, summary.Completed)
	assert.Equal(t, 1, summary.WinningTrades)
	assert.Equal(t, 1, summary.LosingTrades)
	require.NotNil(t, summary.TotalPnL)
	assert.Equal(t, 300.0, *summary.TotalPnL)
}

// ===========================================================================
// buildOrderEntries — unit test (0% -> 100%)
// ===========================================================================

func TestBuildOrderEntries_NilToolCalls(t *testing.T) {
	t.Parallel()
	d := newTestDashboardWithAudit(t)
	entries := d.orders.buildOrderEntries(nil, "user@test.com")
	assert.Empty(t, entries)
}

func TestBuildOrderEntries_WithToolCalls(t *testing.T) {
	t.Parallel()
	d := newTestDashboardWithAudit(t)

	now := time.Now()
	toolCalls := []*audit.ToolCall{
		{
			OrderID:     "ORD-001",
			StartedAt:   now,
			InputParams: `{"tradingsymbol":"INFY","exchange":"NSE","transaction_type":"BUY","order_type":"MARKET","quantity":10}`,
		},
		nil, // should be skipped
		{
			OrderID:     "ORD-002",
			StartedAt:   now,
			InputParams: `{}`,
		},
	}

	entries := d.orders.buildOrderEntries(toolCalls, "user@test.com")

	assert.Len(t, entries, 2)
	assert.Equal(t, "ORD-001", entries[0].OrderID)
	assert.Equal(t, "INFY", entries[0].Symbol)
	assert.Equal(t, "NSE", entries[0].Exchange)
	assert.Equal(t, "BUY", entries[0].Side)
	assert.Equal(t, "MARKET", entries[0].OrderType)
	assert.Equal(t, 10.0, entries[0].Quantity)

	// Second entry has no params parsed
	assert.Equal(t, "ORD-002", entries[1].OrderID)
	assert.Equal(t, "", entries[1].Symbol)
}

// ===========================================================================
// servePageFallback — unit test (0% -> 100%)
// ===========================================================================

func TestServePageFallback_ValidFile(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)

	rec := httptest.NewRecorder()
	d.servePageFallback(rec, "dashboard.html")

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
	assert.NotEmpty(t, rec.Body.String())
}

func TestServePageFallback_InvalidFile(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)

	rec := httptest.NewRecorder()
	d.servePageFallback(rec, "nonexistent.html")

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// ===========================================================================
// serveBillingPage — with billing store (0% -> covered)
// ===========================================================================

func TestServeBillingPage_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	d.SetBillingStore(&mockBillingStore{subs: map[string]*billing.Subscription{}})
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	// No email in context -> redirect to login
	req := httptest.NewRequest(http.MethodGet, "/dashboard/billing", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusFound, rec.Code)
	assert.Contains(t, rec.Header().Get("Location"), "/auth/login")
}

func TestServeBillingPage_FreeUser(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	d.SetBillingStore(&mockBillingStore{subs: map[string]*billing.Subscription{}})
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/billing", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "Free")
	assert.Contains(t, body, "user@test.com")
}

func TestServeBillingPage_ProUser(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	d.SetBillingStore(&mockBillingStore{
		subs: map[string]*billing.Subscription{
			"user@test.com": {
				AdminEmail:       "user@test.com",
				Tier:             billing.TierPro,
				Status:           "active",
				StripeCustomerID: "cus_123",
				MaxUsers:         5,
			},
		},
	})
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/billing", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "Pro")
	assert.Contains(t, body, "Manage in Stripe")
}

func TestServeBillingPage_AdminUser(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	d.SetBillingStore(&mockBillingStore{
		subs: map[string]*billing.Subscription{
			"admin@test.com": {
				AdminEmail: "admin@test.com",
				Tier:       billing.TierPro,
				Status:     "active",
				MaxUsers:   5,
			},
		},
	})
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/billing", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "Family Plan")
}

func TestServeBillingPage_PastDue(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	d.SetBillingStore(&mockBillingStore{
		subs: map[string]*billing.Subscription{
			"user@test.com": {
				AdminEmail: "user@test.com",
				Tier:       billing.TierPro,
				Status:     "past_due",
			},
		},
	})
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/billing", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Past Due")
}

func TestServeBillingPage_Canceled(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	d.SetBillingStore(&mockBillingStore{
		subs: map[string]*billing.Subscription{
			"user@test.com": {
				AdminEmail: "user@test.com",
				Tier:       billing.TierPro,
				Status:     "canceled",
			},
		},
	})
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/billing", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Canceled")
}

// ===========================================================================
// activityStreamSSE — handler test (0% -> covered)
// ===========================================================================

func TestActivityStreamSSE_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newTestDashboardWithAudit(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/dashboard/api/activity/stream", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestActivityStreamSSE_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newTestDashboardWithAudit(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/activity/stream", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestActivityStreamSSE_NoAuditStore(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t) // no audit store
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/activity/stream", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestActivityStreamSSE_ConnectAndCancel(t *testing.T) {
	t.Parallel()
	d := newTestDashboardWithAudit(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	// Use a cancellable context to simulate client disconnect
	ctx, cancel := context.WithCancel(context.Background())
	ctx = oauth.ContextWithEmail(ctx, "user@test.com")
	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/activity/stream", nil).WithContext(ctx)

	// Cancel immediately to avoid blocking
	cancel()

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	// Should have set SSE headers before exiting
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/event-stream")
}

// ===========================================================================
// ordersAPI with audit store — (21% -> higher)
// ===========================================================================

func TestOrdersAPI_WithAuditStore_Empty(t *testing.T) {
	t.Parallel()
	d := newTestDashboardWithAudit(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/orders", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp ordersResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, 0, resp.Summary.TotalOrders)
}

func TestOrdersAPI_WithSinceParam(t *testing.T) {
	t.Parallel()
	d := newTestDashboardWithAudit(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	since := time.Now().AddDate(0, 0, -30).Format(time.RFC3339)
	req := requestWithEmail(http.MethodGet, "/dashboard/api/orders?since="+since, "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestOrdersAPI_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newTestDashboardWithAudit(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/orders", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// ===========================================================================
// activityAPI with audit store — enhanced coverage
// ===========================================================================

func TestActivityAPI_WithAuditStore_Empty(t *testing.T) {
	t.Parallel()
	d := newTestDashboardWithAudit(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/activity", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]interface{}
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Contains(t, resp, "entries")
	assert.Contains(t, resp, "total")
}

func TestActivityAPI_WithFilters(t *testing.T) {
	t.Parallel()
	d := newTestDashboardWithAudit(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	since := time.Now().AddDate(0, 0, -7).Format(time.RFC3339)
	until := time.Now().Format(time.RFC3339)
	url := fmt.Sprintf("/dashboard/api/activity?limit=10&offset=0&category=order&errors=true&since=%s&until=%s", since, until)
	req := requestWithEmail(http.MethodGet, url, "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// activityExport with audit store — enhanced coverage
// ===========================================================================

func TestActivityExport_CSV(t *testing.T) {
	t.Parallel()
	d := newTestDashboardWithAudit(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/activity/export?format=csv", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/csv", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Header().Get("Content-Disposition"), "activity.csv")
}

func TestActivityExport_JSON(t *testing.T) {
	t.Parallel()
	d := newTestDashboardWithAudit(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/activity/export?format=json", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Contains(t, rec.Header().Get("Content-Disposition"), "activity.json")
}

func TestActivityExport_DefaultFormat(t *testing.T) {
	t.Parallel()
	d := newTestDashboardWithAudit(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/activity/export", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/csv", rec.Header().Get("Content-Type"))
}

func TestActivityExport_WithFilters(t *testing.T) {
	t.Parallel()
	d := newTestDashboardWithAudit(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	since := time.Now().AddDate(0, 0, -7).Format(time.RFC3339)
	until := time.Now().Format(time.RFC3339)
	url := fmt.Sprintf("/dashboard/api/activity/export?format=csv&category=order&errors=true&since=%s&until=%s", since, until)
	req := requestWithEmail(http.MethodGet, url, "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestActivityExport_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newTestDashboardWithAudit(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/dashboard/api/activity/export", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// ===========================================================================
// pnlChartAPI — enhanced coverage (24% -> higher)
// ===========================================================================

func TestPnLChartAPI_WithAuditStore(t *testing.T) {
	t.Parallel()
	d := newTestDashboardWithAudit(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/pnl-chart", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp pnlChartResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, 90, resp.Period) // default
}

func TestPnLChartAPI_WithPeriod(t *testing.T) {
	t.Parallel()
	d := newTestDashboardWithAudit(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/pnl-chart?period=30", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp pnlChartResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, 30, resp.Period)
}

func TestPnLChartAPI_PeriodClamped(t *testing.T) {
	t.Parallel()
	d := newTestDashboardWithAudit(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	// Over 365 should be clamped
	req := requestWithEmail(http.MethodGet, "/dashboard/api/pnl-chart?period=500", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp pnlChartResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, 365, resp.Period)
}

func TestPnLChartAPI_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newTestDashboardWithAudit(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/pnl-chart", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestPnLChartAPI_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newTestDashboardWithAudit(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/dashboard/api/pnl-chart", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// ===========================================================================
// orderAttributionAPI — enhanced coverage (30% -> higher)
// ===========================================================================

func TestOrderAttributionAPI_WithAuditStore(t *testing.T) {
	t.Parallel()
	d := newTestDashboardWithAudit(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/order-attribution?order_id=ORD-123", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp attributionResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "ORD-123", resp.OrderID)
}

func TestOrderAttributionAPI_MissingOrderID(t *testing.T) {
	t.Parallel()
	d := newTestDashboardWithAudit(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/order-attribution", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestOrderAttributionAPI_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newTestDashboardWithAudit(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/dashboard/api/order-attribution?order_id=ORD-1", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestOrderAttributionAPI_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newTestDashboardWithAudit(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/order-attribution?order_id=ORD-1", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// ===========================================================================
// alertsEnrichedAPI — enhanced coverage (27% -> higher)
// ===========================================================================

func TestAlertsEnrichedAPI_DeleteNoAlertID(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodDelete, "/dashboard/api/alerts-enriched", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestAlertsEnrichedAPI_DeleteNonexistent(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodDelete, "/dashboard/api/alerts-enriched?alert_id=nonexistent", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	// Alert doesn't exist -> error from store
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestAlertsEnrichedAPI_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/dashboard/api/alerts-enriched", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestAlertsEnrichedAPI_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/alerts-enriched", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestAlertsEnrichedAPI_EmptyAlerts(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/alerts-enriched", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp enrichedAlertsResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, 0, resp.Summary.ActiveCount)
	assert.Equal(t, 0, resp.Summary.TriggeredCount)
}

// ===========================================================================
// marketIndices — enhanced coverage
// ===========================================================================

func TestMarketIndices_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/dashboard/api/market-indices", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestMarketIndices_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/market-indices", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// ===========================================================================
// portfolio API — enhanced coverage
// ===========================================================================

func TestPortfolio_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/dashboard/api/portfolio", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// ===========================================================================
// alerts API — enhanced coverage
// ===========================================================================

func TestAlerts_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/dashboard/api/alerts", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestAlerts_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/alerts", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// ===========================================================================
// paper trading — enhanced coverage
// ===========================================================================

func TestPaperStatus_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/dashboard/api/paper/status", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestPaperStatus_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/paper/status", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestPaperHoldings_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/dashboard/api/paper/holdings", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestPaperHoldings_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/paper/holdings", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestPaperPositions_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/dashboard/api/paper/positions", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestPaperPositions_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/paper/positions", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestPaperOrders_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/dashboard/api/paper/orders", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestPaperOrders_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/paper/orders", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestPaperReset_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodPost, "/dashboard/api/paper/reset", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// ===========================================================================
// sectorExposureAPI — enhanced coverage
// ===========================================================================

func TestSectorExposure_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/dashboard/api/sector-exposure", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestSectorExposure_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/sector-exposure", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// ===========================================================================
// taxAnalysisAPI — enhanced coverage
// ===========================================================================

func TestTaxAnalysis_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/dashboard/api/tax-analysis", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestTaxAnalysis_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/tax-analysis", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// ===========================================================================
// safetyStatus — enhanced coverage
// ===========================================================================

func TestSafetyStatus_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/dashboard/api/safety/status", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestSafetyStatus_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/safety/status", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// ===========================================================================
// selfDeleteAccount — enhanced coverage
// ===========================================================================

func TestSelfDelete_NoConfirm(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	body := strings.NewReader(`{"confirm":false}`)
	req := requestWithEmail(http.MethodPost, "/dashboard/api/account/delete", "user@test.com", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestSelfDelete_InvalidJSON(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	body := strings.NewReader(`not json`)
	req := requestWithEmail(http.MethodPost, "/dashboard/api/account/delete", "user@test.com", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestSelfDelete_Success(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	body := strings.NewReader(`{"confirm":true}`)
	req := requestWithEmail(http.MethodPost, "/dashboard/api/account/delete", "user@test.com", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Account deleted")
}

// ===========================================================================
// selfManageCredentials — enhanced coverage
// ===========================================================================

func TestSelfCredentials_PUT_MissingFields(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	body := strings.NewReader(`{"api_key":"only_key"}`)
	req := requestWithEmail(http.MethodPut, "/dashboard/api/account/credentials", "user@test.com", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestSelfCredentials_PUT_InvalidJSON(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	body := strings.NewReader(`not json`)
	req := requestWithEmail(http.MethodPut, "/dashboard/api/account/credentials", "user@test.com", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestSelfCredentials_WrongMethod(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPatch, "/dashboard/api/account/credentials", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestSelfCredentials_GET_WithStoredCreds(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	// First store credentials
	d.manager.CredentialStore().Set("user@test.com", &kc.KiteCredentialEntry{
		APIKey:    "test_api_key_123",
		APISecret: "test_api_secret_123",
	})

	req := requestWithEmail(http.MethodGet, "/dashboard/api/account/credentials", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp map[string]interface{}
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, true, resp["has_credentials"])
	// Key should be masked
	apiKey := resp["api_key"].(string)
	assert.Contains(t, apiKey, "****")
}

// ===========================================================================
// Fragment endpoints — enhanced coverage
// ===========================================================================

func TestPortfolioFragment(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/portfolio-fragment", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
}

func TestPortfolioFragment_NilTemplate(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	d.fragmentTmpl = nil // simulate template parse failure
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/portfolio-fragment", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestSafetyFragment(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/safety-fragment", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
}

func TestSafetyFragment_NilTemplate(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	d.fragmentTmpl = nil
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/safety-fragment", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestPaperFragment(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/paper-fragment", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
}

func TestPaperFragment_NilTemplate(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	d.fragmentTmpl = nil
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/paper-fragment", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestPaperFragment_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/paper-fragment", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "not enabled")
}

// ===========================================================================
// SSR page rendering — enhanced coverage for edge cases
// ===========================================================================

func TestServeActivityPageSSR_WithAudit(t *testing.T) {
	t.Parallel()
	d := newTestDashboardWithAudit(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/activity", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
}

func TestServeOrdersPageSSR_WithAudit(t *testing.T) {
	t.Parallel()
	d := newTestDashboardWithAudit(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/orders", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
}

func TestServeAlertsPageSSR_Authenticated(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/alerts", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestServePaperPageSSR_Authenticated(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/paper", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestServeSafetyPageSSR_Authenticated(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/safety", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// maskKey, dashboardNormalizeSymbol, tierDisplayName tests exist in dashboard_render_test.go / render_test.go

// ===========================================================================
// Admin handler: logStream SSE endpoint
// ===========================================================================

func TestAdminLogStream_WrongMethod(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/admin/ops/api/logs", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestAdminLogStream_NonAdmin(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/admin/ops/api/logs", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestAdminLogStream_ConnectAndCancel(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	ctx, cancel := context.WithCancel(context.Background())
	ctx = oauth.ContextWithEmail(ctx, "admin@test.com")
	req := httptest.NewRequest(http.MethodGet, "/admin/ops/api/logs", nil).WithContext(ctx)

	// Cancel immediately
	cancel()

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Contains(t, rec.Header().Get("Content-Type"), "text/event-stream")
}

// ===========================================================================
// Admin handler: metricsFragment endpoint
// ===========================================================================

func TestAdminMetricsFragment_WrongMethod(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodPost, "/admin/ops/api/metrics-fragment", "admin@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestAdminMetricsFragment_NonAdmin(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/admin/ops/api/metrics-fragment", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestAdminMetricsFragment_WithPeriods(t *testing.T) {
	t.Parallel()
	h := newTestAdminOpsHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, noopAuth)

	for _, period := range []string{"1h", "24h", "7d", "30d"} {
		t.Run(period, func(t *testing.T) {
			req := requestWithEmail(http.MethodGet, "/admin/ops/api/metrics-fragment?period="+period, "admin@test.com", nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			// Should render HTML or return service unavailable (if no audit store)
			assert.NotEqual(t, http.StatusInternalServerError, rec.Code)
		})
	}
}

// ===========================================================================
// ordersAPI with seeded audit data — push coverage higher
// ===========================================================================

func TestOrdersAPI_WithSeededData(t *testing.T) {
	t.Parallel()
	d := newTestDashboardWithAudit(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	// Seed some audit entries directly via the store
	email := "user@test.com"
	d.auditStore.Record(&audit.ToolCall{
		Email:        email,
		ToolName:     "place_order",
		ToolCategory: "order",
		OrderID:      "ORD-TEST-1",
		InputParams:  `{"tradingsymbol":"INFY","exchange":"NSE","transaction_type":"BUY","order_type":"MARKET","quantity":10}`,
		InputSummary: "BUY INFY",
		OutputSummary: "Order placed",
		StartedAt:    time.Now(),
		DurationMs:   100,
	})

	req := requestWithEmail(http.MethodGet, "/dashboard/api/orders", email, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp ordersResponse
	err := json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, resp.Summary.TotalOrders, 1)
	if len(resp.Orders) > 0 {
		assert.Equal(t, "ORD-TEST-1", resp.Orders[0].OrderID)
		assert.Equal(t, "INFY", resp.Orders[0].Symbol)
	}
}

// ===========================================================================
// SSR pages with audit store — covers more template paths
// ===========================================================================

func TestServePortfolioPage_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
}

func TestServeActivityPageSSR_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/activity", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestServeOrdersPageSSR_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/orders", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestServeAlertsPageSSR_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/alerts", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestServePaperPageSSR_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/paper", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestServeSafetyPageSSR_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/safety", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// Fragment endpoints — with unauthenticated requests
// ===========================================================================

func TestPortfolioFragment_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/portfolio-fragment", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestSafetyFragment_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/safety-fragment", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

// ===========================================================================
// Alerts page with seeded alerts — pushes serveAlertsPageSSR coverage
// ===========================================================================

func TestServeAlertsPageSSR_WithAlerts(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	// Seed an alert
	_, err := d.manager.AlertStore().Add("user@test.com", "INFY", "NSE", 0, 1600, "above")
	require.NoError(t, err)

	req := requestWithEmail(http.MethodGet, "/dashboard/alerts", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "INFY")
}

func TestAlertsEnrichedAPI_WithAlerts(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	// Seed alerts
	_, err := d.manager.AlertStore().Add("user@test.com", "INFY", "NSE", 0, 1600, "above")
	require.NoError(t, err)
	_, err = d.manager.AlertStore().Add("user@test.com", "TCS", "NSE", 0, 3000, "below")
	require.NoError(t, err)

	req := requestWithEmail(http.MethodGet, "/dashboard/api/alerts-enriched", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp enrichedAlertsResponse
	err = json.NewDecoder(rec.Body).Decode(&resp)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, resp.Summary.ActiveCount, 2)
}

// ===========================================================================
// SSR pages with nil template fallback
// ===========================================================================

func TestServeAlertsPageSSR_NilTemplate(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	d.alertsTmpl = nil // force fallback
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/alerts", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestServeOrdersPageSSR_NilTemplate(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	d.ordersTmpl = nil
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/orders", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestServePaperPageSSR_NilTemplate(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	d.paperTmpl = nil
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/paper", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestServeSafetyPageSSR_NilTemplate(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	d.safetyTmpl = nil
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/safety", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestServePortfolioPage_NilTemplate(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	d.portfolioTmpl = nil
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestServeActivityPageSSR_NilTemplate(t *testing.T) {
	t.Parallel()
	d := newTestDashboard(t)
	d.activityTmpl = nil
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := requestWithEmail(http.MethodGet, "/dashboard/activity", "user@test.com", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}
