package billing

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	stripe "github.com/stripe/stripe-go/v82"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// ===========================================================================
// Coverage push: hit remaining uncovered lines in billing package.
// ===========================================================================

// ---------------------------------------------------------------------------
// webhook.go line 191-193 — handleSubscriptionUpdated when existing == nil
// ---------------------------------------------------------------------------

func TestSubscriptionUpdated_NilExistingSub(t *testing.T) {
	t.Parallel()
	s := newTestStore()

	// Inject mismatched key so GetEmailByCustomerID returns email but
	// GetSubscription(email) returns nil.
	s.mu.Lock()
	s.subs["different-key@test.com"] = &Subscription{
		AdminEmail:       "found@test.com",
		StripeCustomerID: "cus_nil_existing",
		Status:           StatusActive,
		Tier:             TierPro,
	}
	s.mu.Unlock()

	event := &stripe.Event{
		ID:   "evt_nil_existing_upd",
		Type: "customer.subscription.updated",
		Data: &stripe.EventData{},
	}
	sub := map[string]any{
		"id":       "sub_nil",
		"customer": map[string]any{"id": "cus_nil_existing"},
		"status":   "active",
	}
	raw, _ := json.Marshal(sub)
	event.Data.Raw = raw

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handleSubscriptionUpdated(s, event, "", "", "", logger)

	got := s.GetSubscription("found@test.com")
	require.NotNil(t, got)
	assert.Equal(t, StatusActive, got.Status)
}

// ---------------------------------------------------------------------------
// webhook.go line 240-242 — handleSubscriptionDeleted when existing == nil
// ---------------------------------------------------------------------------

func TestSubscriptionDeleted_NilExistingSub(t *testing.T) {
	t.Parallel()
	s := newTestStore()

	s.mu.Lock()
	s.subs["other-key@test.com"] = &Subscription{
		AdminEmail:       "del-found@test.com",
		StripeCustomerID: "cus_nil_del",
		Status:           StatusActive,
		Tier:             TierPro,
	}
	s.mu.Unlock()

	event := &stripe.Event{
		ID:   "evt_nil_existing_del",
		Type: "customer.subscription.deleted",
		Data: &stripe.EventData{},
	}
	sub := map[string]any{
		"id":       "sub_nil_del",
		"customer": map[string]any{"id": "cus_nil_del"},
	}
	raw, _ := json.Marshal(sub)
	event.Data.Raw = raw

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handleSubscriptionDeleted(s, event, logger)

	got := s.GetSubscription("del-found@test.com")
	require.NotNil(t, got)
	assert.Equal(t, TierFree, got.Tier)
	assert.Equal(t, StatusCanceled, got.Status)
}

// ---------------------------------------------------------------------------
// webhook.go line 273-276 — handlePaymentFailed when existing == nil
// ---------------------------------------------------------------------------

func TestPaymentFailed_NilExistingSub(t *testing.T) {
	t.Parallel()
	s := newTestStore()

	s.mu.Lock()
	s.subs["pf-other@test.com"] = &Subscription{
		AdminEmail:       "pf-found@test.com",
		StripeCustomerID: "cus_pf_nil",
		Status:           StatusActive,
	}
	s.mu.Unlock()

	event := &stripe.Event{
		ID:   "evt_pf_nil_sub",
		Type: "invoice.payment_failed",
		Data: &stripe.EventData{},
	}
	inv := map[string]any{
		"customer": map[string]any{"id": "cus_pf_nil"},
	}
	raw, _ := json.Marshal(inv)
	event.Data.Raw = raw

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handlePaymentFailed(s, event, logger)

	// Returns early (warn log) because existing == nil
	got := s.GetSubscription("pf-found@test.com")
	assert.Nil(t, got)
}

// ---------------------------------------------------------------------------
// checkout.go line 49-53 — priceID == "" (no env var for the plan)
// ---------------------------------------------------------------------------

func TestCheckoutHandler_PriceNotConfigured(t *testing.T) {
	t.Parallel()
	s := newTestStore()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	handler := CheckoutHandler(s, logger)
	ctx := oauth.ContextWithEmail(context.Background(), "test@test.com")
	req := httptest.NewRequest(http.MethodPost, "/checkout?plan=solo_pro", nil).WithContext(ctx)
	rr := httptest.NewRecorder()
	handler(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	assert.Contains(t, rr.Body.String(), "pricing not configured")
}

// ---------------------------------------------------------------------------
// checkout.go line 84-87 — reuse existing Stripe customer
// ---------------------------------------------------------------------------

func TestCheckoutHandler_ExistingCustomerReuse(t *testing.T) {
	// Cannot use t.Parallel() because t.Setenv is required.
	s := newTestStore()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	require.NoError(t, s.SetSubscription(&Subscription{
		AdminEmail:       "reuse@test.com",
		StripeCustomerID: "cus_reuse",
		Status:           StatusActive,
	}))

	handler := CheckoutHandler(s, logger)
	ctx := oauth.ContextWithEmail(context.Background(), "reuse@test.com")
	t.Setenv("STRIPE_PRICE_PREMIUM", "price_test_premium")
	req := httptest.NewRequest(http.MethodPost, "/checkout?plan=premium", nil).WithContext(ctx)
	rr := httptest.NewRecorder()
	handler(rr, req)

	// Stripe API call fails (no real key) → 500, but the customer reuse path is hit
	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

// ---------------------------------------------------------------------------
// portal.go line 41-47 — billingportal.New fails (no real Stripe key)
// ---------------------------------------------------------------------------

func TestPortalHandler_StripeFail(t *testing.T) {
	t.Parallel()
	s := newTestStore()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	require.NoError(t, s.SetSubscription(&Subscription{
		AdminEmail:       "portal@test.com",
		StripeCustomerID: "cus_portal",
		Status:           StatusActive,
	}))

	handler := PortalHandler(s, logger)
	ctx := oauth.ContextWithEmail(context.Background(), "portal@test.com")
	req := httptest.NewRequest(http.MethodGet, "/portal", nil).WithContext(ctx)
	rr := httptest.NewRecorder()
	handler(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

// ---------------------------------------------------------------------------
// webhook.go — handlePaymentFailed SetSubscription error (line 279-281)
// ---------------------------------------------------------------------------

func TestPaymentFailed_SetSubscriptionError(t *testing.T) {
	t.Parallel()
	s, db := newTestStoreWithDB(t)

	require.NoError(t, s.SetSubscription(&Subscription{
		AdminEmail:       "pf-err@test.com",
		StripeCustomerID: "cus_pf_err",
		Status:           StatusActive,
		Tier:             TierPro,
	}))

	db.Close()

	event := &stripe.Event{
		ID:   "evt_pf_setsub_err",
		Type: "invoice.payment_failed",
		Data: &stripe.EventData{},
	}
	inv := map[string]any{
		"customer": map[string]any{"id": "cus_pf_err"},
	}
	raw, _ := json.Marshal(inv)
	event.Data.Raw = raw

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handlePaymentFailed(s, event, logger)
}

// ---------------------------------------------------------------------------
// webhook.go — handleCheckoutCompleted / handleSubscriptionDeleted / handlePaymentFailed
// unmarshal error paths
// ---------------------------------------------------------------------------

func TestCheckoutCompleted_UnmarshalErr(t *testing.T) {
	t.Parallel()
	s := newTestStore()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	event := &stripe.Event{
		ID: "evt_chk_bad", Type: "checkout.session.completed",
		Data: &stripe.EventData{Raw: json.RawMessage(`{bad}`)},
	}
	handleCheckoutCompleted(s, event, "", "", "", logger, nil)
}

func TestSubscriptionDeleted_UnmarshalErr(t *testing.T) {
	t.Parallel()
	s := newTestStore()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	event := &stripe.Event{
		ID: "evt_del_bad", Type: "customer.subscription.deleted",
		Data: &stripe.EventData{Raw: json.RawMessage(`{bad}`)},
	}
	handleSubscriptionDeleted(s, event, logger)
}

func TestPaymentFailed_UnmarshalErr(t *testing.T) {
	t.Parallel()
	s := newTestStore()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	event := &stripe.Event{
		ID: "evt_pf_bad", Type: "invoice.payment_failed",
		Data: &stripe.EventData{Raw: json.RawMessage(`{bad}`)},
	}
	handlePaymentFailed(s, event, logger)
}
