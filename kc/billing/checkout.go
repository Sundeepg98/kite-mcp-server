package billing

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"strconv"

	stripe "github.com/stripe/stripe-go/v82"
	checkoutsession "github.com/stripe/stripe-go/v82/checkout/session"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// CheckoutHandler creates a Stripe Checkout Session and returns the URL.
// Protected by RequireAuthBrowser. Accepts plan query param (pro/premium).
func CheckoutHandler(store *Store, logger *slog.Logger) http.HandlerFunc {
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
		if plan != "pro" && plan != "premium" {
			http.Error(w, "invalid plan: use ?plan=pro or ?plan=premium", http.StatusBadRequest)
			return
		}

		var priceID string
		var maxUsers int
		switch plan {
		case "pro":
			priceID = os.Getenv("STRIPE_PRICE_PRO")
			maxUsers = 5
		case "premium":
			priceID = os.Getenv("STRIPE_PRICE_PREMIUM")
			maxUsers = 20
		}
		if priceID == "" {
			logger.Error("Stripe price ID not configured", "plan", plan)
			http.Error(w, "pricing not configured", http.StatusInternalServerError)
			return
		}

		externalURL := os.Getenv("EXTERNAL_URL")
		if externalURL == "" {
			externalURL = "http://localhost:8080"
		}

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
		json.NewEncoder(w).Encode(map[string]string{
			"checkout_url": session.URL,
		})
	}
}
