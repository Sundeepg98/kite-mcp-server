package billing

import "os"

// Config carries the Stripe price IDs and the external URL used by the
// checkout and portal HTTP handlers. It replaces the former pattern of
// reading STRIPE_PRICE_* / EXTERNAL_URL via os.Getenv at every request,
// which forced tests to use t.Setenv and therefore blocked t.Parallel.
//
// Construct a Config once at app wiring time (via ConfigFromEnv) and
// pass it into CheckoutHandlerWithConfig / PortalHandlerWithConfig. Tests
// can construct a zero-valued Config or populate only the fields they
// care about and run with t.Parallel().
type Config struct {
	// PriceSoloPro is the Stripe price ID for the Solo Pro plan.
	PriceSoloPro string
	// PricePro is the Stripe price ID for the Pro plan (5 users).
	PricePro string
	// PricePremium is the Stripe price ID for the Premium plan (20 users).
	PricePremium string
	// ExternalURL is the public base URL used when constructing Stripe
	// success/cancel/return URLs. Falls back to http://localhost:8080
	// when empty.
	ExternalURL string
}

// ConfigFromEnv builds a Config from the STRIPE_PRICE_* and EXTERNAL_URL
// environment variables. Intended for production wiring (called once at
// startup from app/). Tests should build Config directly.
func ConfigFromEnv() Config {
	return Config{
		PriceSoloPro: os.Getenv("STRIPE_PRICE_SOLO_PRO"),
		PricePro:     os.Getenv("STRIPE_PRICE_PRO"),
		PricePremium: os.Getenv("STRIPE_PRICE_PREMIUM"),
		ExternalURL:  os.Getenv("EXTERNAL_URL"),
	}
}

// effectiveExternalURL returns the configured ExternalURL or the local
// dev fallback. Centralised so Checkout and Portal handlers agree on
// the default.
func (c Config) effectiveExternalURL() string {
	if c.ExternalURL == "" {
		return "http://localhost:8080"
	}
	return c.ExternalURL
}

// priceIDForPlan returns the Stripe price ID mapped to the given plan
// name, or "" when the plan is unknown or unconfigured.
func (c Config) priceIDForPlan(plan string) string {
	switch plan {
	case "solo_pro":
		return c.PriceSoloPro
	case "pro":
		return c.PricePro
	case "premium":
		return c.PricePremium
	}
	return ""
}
