package app

import "github.com/zerodha/kite-mcp-server/kc/billing"

// tierRateMultiplier maps a user's billing tier to a rate-limit bucket
// multiplier. Premium users get 10x, Pro (and Solo Pro) get 3x, free users
// stay at the base limit. Kept as a pure function so it is trivially
// testable and wire-time composable.
func tierRateMultiplier(t billing.Tier) int {
	switch t.EffectiveTier() {
	case billing.TierPremium:
		return 10
	case billing.TierPro:
		return 3
	default:
		return 1
	}
}
