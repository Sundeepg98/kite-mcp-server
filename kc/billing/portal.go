package billing

import (
	"log/slog"
	"net/http"
	"os"

	stripe "github.com/stripe/stripe-go/v82"
	billingportal "github.com/stripe/stripe-go/v82/billingportal/session"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// PortalHandler redirects the user to their Stripe Customer Portal where they
// can manage payment methods, view invoices, and cancel their subscription.
// If the user has no Stripe customer ID, they are redirected to /pricing.
func PortalHandler(store *Store, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		email := oauth.EmailFromContext(r.Context())
		if email == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		sub := store.GetSubscription(email)
		if sub == nil || sub.StripeCustomerID == "" {
			http.Redirect(w, r, "/pricing", http.StatusFound)
			return
		}

		returnURL := os.Getenv("EXTERNAL_URL")
		if returnURL == "" {
			returnURL = "http://localhost:8080"
		}
		returnURL += "/dashboard/billing"

		params := &stripe.BillingPortalSessionParams{
			Customer:  stripe.String(sub.StripeCustomerID),
			ReturnURL: stripe.String(returnURL),
		}

		session, err := billingportal.New(params)
		if err != nil {
			logger.Error("Failed to create Stripe billing portal session",
				"email", email, "customer_id", sub.StripeCustomerID, "error", err)
			http.Error(w, "failed to create portal session", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, session.URL, http.StatusFound)
	}
}
