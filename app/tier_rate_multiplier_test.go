package app

import (
	"testing"

	"github.com/zerodha/kite-mcp-server/kc/billing"
)

func TestTierRateMultiplier(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		tier billing.Tier
		want int
	}{
		{"free", billing.TierFree, 1},
		{"pro", billing.TierPro, 3},
		{"premium", billing.TierPremium, 10},
		{"solo_pro_maps_to_pro", billing.TierSoloPro, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tierRateMultiplier(tc.tier); got != tc.want {
				t.Fatalf("tierRateMultiplier(%s) = %d, want %d", tc.tier, got, tc.want)
			}
		})
	}
}
