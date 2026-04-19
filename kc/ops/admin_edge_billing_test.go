package ops

// coverage_max_test.go: push ops coverage toward 100%.
// Targets remaining uncovered branches across handler.go, data.go,
// dashboard.go, dashboard_templates.go, and overview_sse.go.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/zerodha/kite-mcp-server/kc/billing"
)

// --- Helpers (unique names to avoid collisions) ---

// newHandlerWithAuditAndMetrics creates a handler with audit store, user store, riskguard and metrics.


// ===========================================================================
// dashboard.go: RegisterRoutes - billing page without billingStore
// ===========================================================================
func TestMax_BillingPage_NoBillingStore(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/billing", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Free Plan")
}


// ===========================================================================
// dashboard.go: serveBillingPage - no email redirect
// ===========================================================================
func TestMax_ServeBillingPage_NoEmail(t *testing.T) {
	t.Parallel()
	d := newDashboardWithAuditAndPaper(t)
	d.SetBillingStore(&mockBillingStore{subs: map[string]*billing.Subscription{}})

	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/billing", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusFound, rec.Code)
}


// ===========================================================================
// dashboard.go: serveBillingPage with admin and billing store
// ===========================================================================
func TestFinal_BillingPage_Unauthenticated(t *testing.T) {
	t.Parallel()
	d := newFullTestDashboard(t, "")
	// Must set a billing store so RegisterRoutes registers serveBillingPage
	// (without it, the fallback "Free plan" handler always returns 200).
	d.SetBillingStore(&mockBillingStore{subs: map[string]*billing.Subscription{}})
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodGet, "/dashboard/billing", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	// Should redirect to login
	assert.Equal(t, http.StatusFound, rec.Code)
}
