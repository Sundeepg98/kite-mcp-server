package billing

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"

	stripe "github.com/stripe/stripe-go/v82"
	"github.com/stripe/stripe-go/v82/webhook"
)

// WebhookHandler returns an http.HandlerFunc that verifies and processes Stripe
// webhook events. It handles:
//   - checkout.session.completed  → create subscription (email + customer mapping)
//   - customer.subscription.updated → update tier/status/expiry
//   - customer.subscription.deleted → downgrade to Free, mark canceled
//   - invoice.payment_failed       → mark subscription past_due
//
// Events are checked for idempotency via the webhook_events table before processing.
// The handler returns 200 immediately; processing is synchronous but fast (no API calls).
func WebhookHandler(store *Store, signingSecret string, logger *slog.Logger, adminUpgrade func(email string)) http.HandlerFunc {
	pricePro := os.Getenv("STRIPE_PRICE_PRO")
	pricePremium := os.Getenv("STRIPE_PRICE_PREMIUM")

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		const maxBodyBytes = 65536
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
		if err != nil {
			logger.Error("stripe webhook: failed to read body", "error", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		sigHeader := r.Header.Get("Stripe-Signature")
		event, err := webhook.ConstructEvent(body, sigHeader, signingSecret)
		if err != nil {
			logger.Warn("stripe webhook: signature verification failed", "error", err)
			http.Error(w, "invalid signature", http.StatusBadRequest)
			return
		}

		logger.Info("stripe webhook received", "type", event.Type, "id", event.ID)

		// Idempotency: skip already-processed events.
		if store.IsEventProcessed(event.ID) {
			logger.Info("stripe webhook: duplicate event, skipping", "id", event.ID)
			w.WriteHeader(http.StatusOK)
			return
		}

		// Process the event synchronously (no Stripe API calls — all data is in the event payload).
		switch event.Type {
		case "checkout.session.completed":
			handleCheckoutCompleted(store, &event, pricePro, pricePremium, logger, adminUpgrade)

		case "customer.subscription.updated":
			handleSubscriptionUpdated(store, &event, pricePro, pricePremium, logger)

		case "customer.subscription.deleted":
			handleSubscriptionDeleted(store, &event, logger)

		case "invoice.payment_failed":
			handlePaymentFailed(store, &event, logger)

		default:
			logger.Debug("stripe webhook: unhandled event type", "type", event.Type)
		}

		// Mark event as processed regardless of handler outcome to avoid reprocessing.
		if err := store.MarkEventProcessed(event.ID, string(event.Type)); err != nil {
			logger.Error("stripe webhook: failed to mark event processed", "id", event.ID, "error", err)
		}

		w.WriteHeader(http.StatusOK)
	}
}

// handleCheckoutCompleted processes a checkout.session.completed event.
// It extracts the customer email and price ID to create a subscription mapping.
func handleCheckoutCompleted(store *Store, event *stripe.Event, pricePro, pricePremium string, logger *slog.Logger, adminUpgrade func(email string)) {
	var session stripe.CheckoutSession
	if err := json.Unmarshal(event.Data.Raw, &session); err != nil {
		logger.Error("stripe webhook: failed to unmarshal checkout session", "error", err)
		return
	}

	// Extract email from customer_details.
	email := ""
	if session.CustomerDetails != nil {
		email = session.CustomerDetails.Email
	}
	if email == "" {
		logger.Error("stripe webhook: checkout.session.completed missing customer email", "event_id", event.ID)
		return
	}

	// Extract Stripe customer ID.
	customerID := ""
	if session.Customer != nil {
		customerID = session.Customer.ID
	}

	// Extract subscription ID.
	subID := ""
	if session.Subscription != nil {
		subID = session.Subscription.ID
	}

	// Extract max_users from checkout metadata.
	maxUsers := 1
	if session.Metadata != nil {
		if val, ok := session.Metadata["max_users"]; ok {
			if parsed, err := strconv.Atoi(val); err == nil && parsed > 0 {
				maxUsers = parsed
			}
		}
	}

	// Determine tier from the price ID in the line items (from subscription object).
	tier := mapPriceToTier(extractPriceID(&session), pricePro, pricePremium)

	sub := &Subscription{
		Email:            email,
		Tier:             tier,
		StripeCustomerID: customerID,
		StripeSubID:      subID,
		Status:           StatusActive,
		MaxUsers:         maxUsers,
	}

	if err := store.SetSubscription(sub); err != nil {
		logger.Error("stripe webhook: failed to set subscription on checkout", "email", email, "error", err)
		return
	}

	// Upgrade payer to admin role.
	if adminUpgrade != nil {
		adminUpgrade(email)
		logger.Info("stripe webhook: upgraded payer to admin role", "email", email)
	}
	logger.Info("stripe webhook: subscription created from checkout", "email", email, "tier", tier.String(), "customer_id", customerID, "max_users", maxUsers)
}

// handleSubscriptionUpdated processes a customer.subscription.updated event.
// It updates the tier, status, and expiry from the subscription object.
func handleSubscriptionUpdated(store *Store, event *stripe.Event, pricePro, pricePremium string, logger *slog.Logger) {
	var sub stripe.Subscription
	if err := json.Unmarshal(event.Data.Raw, &sub); err != nil {
		logger.Error("stripe webhook: failed to unmarshal subscription", "error", err)
		return
	}

	// Look up email from the customer mapping stored during checkout.
	customerID := ""
	if sub.Customer != nil {
		customerID = sub.Customer.ID
	}
	email := store.GetEmailByCustomerID(customerID)
	if email == "" {
		logger.Error("stripe webhook: subscription.updated has unknown customer", "customer_id", customerID, "sub_id", sub.ID)
		return
	}

	// Determine tier from the first item's price.
	priceID := ""
	if sub.Items != nil && len(sub.Items.Data) > 0 && sub.Items.Data[0].Price != nil {
		priceID = sub.Items.Data[0].Price.ID
	}
	tier := mapPriceToTier(priceID, pricePro, pricePremium)

	// Map Stripe status to our status constants.
	status := mapStripeStatus(sub.Status)

	// Compute expiry from cancel_at if set.
	var expiresAt time.Time
	if sub.CancelAt > 0 {
		expiresAt = time.Unix(sub.CancelAt, 0)
	}

	existing := store.GetSubscription(email)
	if existing == nil {
		existing = &Subscription{Email: email}
	}
	existing.Tier = tier
	existing.Status = status
	existing.ExpiresAt = expiresAt
	existing.StripeSubID = sub.ID
	if customerID != "" {
		existing.StripeCustomerID = customerID
	}

	if err := store.SetSubscription(existing); err != nil {
		logger.Error("stripe webhook: failed to update subscription", "email", email, "error", err)
		return
	}
	logger.Info("stripe webhook: subscription updated", "email", email, "tier", tier.String(), "status", status)
}

// handleSubscriptionDeleted processes a customer.subscription.deleted event.
// It downgrades the user to TierFree and marks status as canceled.
func handleSubscriptionDeleted(store *Store, event *stripe.Event, logger *slog.Logger) {
	var sub stripe.Subscription
	if err := json.Unmarshal(event.Data.Raw, &sub); err != nil {
		logger.Error("stripe webhook: failed to unmarshal deleted subscription", "error", err)
		return
	}

	customerID := ""
	if sub.Customer != nil {
		customerID = sub.Customer.ID
	}
	email := store.GetEmailByCustomerID(customerID)
	if email == "" {
		logger.Error("stripe webhook: subscription.deleted has unknown customer", "customer_id", customerID, "sub_id", sub.ID)
		return
	}

	existing := store.GetSubscription(email)
	if existing == nil {
		existing = &Subscription{Email: email}
	}
	existing.Tier = TierFree
	existing.Status = StatusCanceled

	if err := store.SetSubscription(existing); err != nil {
		logger.Error("stripe webhook: failed to cancel subscription", "email", email, "error", err)
		return
	}
	logger.Info("stripe webhook: subscription canceled", "email", email, "customer_id", customerID)
}

// handlePaymentFailed processes an invoice.payment_failed event.
// It marks the associated subscription as past_due.
func handlePaymentFailed(store *Store, event *stripe.Event, logger *slog.Logger) {
	var inv stripe.Invoice
	if err := json.Unmarshal(event.Data.Raw, &inv); err != nil {
		logger.Error("stripe webhook: failed to unmarshal invoice", "error", err)
		return
	}

	customerID := ""
	if inv.Customer != nil {
		customerID = inv.Customer.ID
	}
	email := store.GetEmailByCustomerID(customerID)
	if email == "" {
		logger.Error("stripe webhook: invoice.payment_failed has unknown customer", "customer_id", customerID)
		return
	}

	existing := store.GetSubscription(email)
	if existing == nil {
		logger.Warn("stripe webhook: payment failed for user with no subscription record", "email", email)
		return
	}
	existing.Status = StatusPastDue

	if err := store.SetSubscription(existing); err != nil {
		logger.Error("stripe webhook: failed to mark subscription past_due", "email", email, "error", err)
		return
	}
	logger.Info("stripe webhook: subscription marked past_due", "email", email, "customer_id", customerID)
}

// extractPriceID returns the price ID from a checkout session. It looks at
// the subscription's first item, since the session is in subscription mode.
func extractPriceID(session *stripe.CheckoutSession) string {
	if session.Subscription != nil &&
		session.Subscription.Items != nil &&
		len(session.Subscription.Items.Data) > 0 &&
		session.Subscription.Items.Data[0].Price != nil {
		return session.Subscription.Items.Data[0].Price.ID
	}
	return ""
}

// mapPriceToTier maps a Stripe price ID to a billing tier using env-configured price IDs.
func mapPriceToTier(priceID, pricePro, pricePremium string) Tier {
	switch priceID {
	case pricePremium:
		if pricePremium != "" {
			return TierPremium
		}
	case pricePro:
		if pricePro != "" {
			return TierPro
		}
	}
	// Default to Pro for any paid checkout with an unrecognized price ID.
	if priceID != "" {
		return TierPro
	}
	return TierFree
}

// mapStripeStatus converts a Stripe subscription status string to our internal status.
func mapStripeStatus(s stripe.SubscriptionStatus) string {
	switch s {
	case "active":
		return StatusActive
	case "trialing":
		return StatusTrialing
	case "past_due":
		return StatusPastDue
	case "canceled", "unpaid", "incomplete_expired":
		return StatusCanceled
	default:
		return string(s)
	}
}
