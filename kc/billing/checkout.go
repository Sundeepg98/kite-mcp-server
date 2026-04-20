package billing

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	stripe "github.com/stripe/stripe-go/v82"
	checkoutsession "github.com/stripe/stripe-go/v82/checkout/session"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// maxUsersByPlan maps plan names to the subscription's max_users metadata
// value. Kept separate from Config so plan sizing remains a pure
// constant rather than an env-injected knob.
var maxUsersByPlan = map[string]int{
	"solo_pro": 1,
	"pro":      5,
	"premium":  20,
}

// CheckoutHandler creates a Stripe Checkout Session and returns the URL.
// Protected by RequireAuthBrowser. Accepts plan query param (solo_pro/pro/premium).
//
// Reads STRIPE_PRICE_* and EXTERNAL_URL from the environment. Prefer
// CheckoutHandlerWithConfig when you can pass a Config constructed at
// app wiring time — it makes tests t.Parallel-safe.
func CheckoutHandler(store *Store, logger *slog.Logger) http.HandlerFunc {
	return CheckoutHandlerWithConfig(store, logger, ConfigFromEnv())
}

// CheckoutHandlerWithConfig is the injected-config variant of CheckoutHandler.
// Production wiring passes ConfigFromEnv(); tests pass a hand-built Config
// so they can run with t.Parallel() instead of t.Setenv.
func CheckoutHandlerWithConfig(store *Store, logger *slog.Logger, cfg Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		email := oauth.EmailFromContext(r.Context())
		if email == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		plan := r.URL.Query().Get("plan")
		maxUsers, ok := maxUsersByPlan[plan]
		if !ok {
			http.Error(w, "invalid plan: use ?plan=solo_pro, ?plan=pro, or ?plan=premium", http.StatusBadRequest)
			return
		}

		priceID := cfg.priceIDForPlan(plan)
		if priceID == "" {
			logger.Error("Stripe price ID not configured", "plan", plan)
			http.Error(w, "pricing not configured", http.StatusInternalServerError)
			return
		}

		externalURL := cfg.effectiveExternalURL()

		params := &stripe.CheckoutSessionParams{
			Mode:          stripe.String(string(stripe.CheckoutSessionModeSubscription)),
			CustomerEmail: stripe.String(email),
			SuccessURL:    stripe.String(externalURL + "/checkout/success"),
			CancelURL:     stripe.String(externalURL + "/pricing"),
			LineItems: []*stripe.CheckoutSessionLineItemParams{
				{
					Price:    stripe.String(priceID),
					Quantity: stripe.Int64(1),
				},
			},
			Metadata: map[string]string{
				"max_users": strconv.Itoa(maxUsers),
				"plan":      plan,
			},
			SubscriptionData: &stripe.CheckoutSessionSubscriptionDataParams{
				Metadata: map[string]string{
					"max_users": strconv.Itoa(maxUsers),
					"plan":      plan,
				},
			},
		}

		// Reuse existing Stripe customer if user already has a subscription.
		if existing := store.GetSubscription(email); existing != nil && existing.StripeCustomerID != "" {
			params.Customer = stripe.String(existing.StripeCustomerID)
			params.CustomerEmail = nil // mutually exclusive with Customer
		}

		session, err := checkoutsession.New(params)
		if err != nil {
			logger.Error("Failed to create Stripe checkout session", "email", email, "plan", plan, "error", err)
			http.Error(w, "failed to create checkout session", http.StatusInternalServerError)
			return
		}

		logger.Info("Stripe checkout session created", "email", email, "plan", plan, "session_id", session.ID)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"checkout_url": session.URL,
		})
	}
}
