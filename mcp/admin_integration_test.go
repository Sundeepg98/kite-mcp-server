package mcp

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// admin_integration_test.go — end-to-end integration coverage for the three
// observability / forensics admin tools:
//
//   admin_get_user_baseline   → reads UserOrderStats
//   admin_stats_cache_info    → reads StatsCacheHitRate
//   admin_list_anomaly_flags  → scans the audit trail for ORDER BLOCKED rows
//
// Each tool has its own unit-test file pinning single-tool behaviour. What
// this file adds is the *chain*: seeding a real audit workload through
// seedBaselineOrders and seedBlockedAnomaly (already-shared helpers in
// admin_baseline_tool_test.go and admin_anomaly_tool_test.go), then calling
// all three tools against that same store and asserting the pieces line up
// — baseline stats reflect the seeded orders, cache exercises cleanly, and
// the anomaly listing surfaces the flagged user with the expected reason.
//
// We deliberately reuse the helpers from admin_tools_test.go and the two
// unit-test files (seedUsers, newAdminTestManager, wireAuditForAdminTest,
// seedBaselineOrders, seedBlockedAnomaly, callAdminTool, resultText) rather
// than minting new variants. The integration contract is: all three tools
// see the same concrete audit.Store once the manager is wired via
// manager.SetAuditStore.

// -----------------------------------------------------------------------------
// TestAdminIntegration_BaselineToAnomalyFlow — single admin, single trader.
// Seed baseline → query baseline → query cache → seed anomaly block → query
// anomaly flags. Asserts the chain holds end-to-end.
// -----------------------------------------------------------------------------

func TestAdminIntegration_BaselineToAnomalyFlow(t *testing.T) {
	mgr := newAdminTestManager(t)
	seedUsers(t, mgr)
	auditStore := wireAuditForAdminTest(t, mgr)

	const traderEmail = "trader@example.com"
	const adminEmail = "admin@example.com"

	// --- Step 1: seed 10 orders at Rs 5000 each (qty=10, price=500) for trader.
	// Matches the baseline-tool test fixture exactly so the math is already
	// validated: mean=5000, stdev=0, count=10.
	seedBaselineOrders(t, auditStore, traderEmail, 10, 10, 500)

	// --- Step 2: call admin_get_user_baseline as admin.
	baselineResult := callAdminTool(t, mgr, "admin_get_user_baseline", adminEmail, map[string]any{
		"email": traderEmail,
	})
	require.False(t, baselineResult.IsError, "admin_get_user_baseline must succeed in the chain")

	var baseline adminUserBaselineResponse
	require.NoError(t, json.Unmarshal([]byte(resultText(t, baselineResult)), &baseline))
	assert.Equal(t, traderEmail, baseline.Email)
	assert.Equal(t, 10, baseline.BaselineCount,
		"baseline_count must reflect the 10 seeded orders")
	assert.InDelta(t, 5000.0, baseline.BaselineMeanINR, 100.0,
		"baseline_mean must be close to Rs 5000 from seeded 10*500 orders")
	assert.True(t, baseline.IsSufficient,
		"count=10 >= min floor of 5 ⇒ is_sufficient=true")

	// --- Step 3: call admin_stats_cache_info as admin.
	// Just exercise the tool — the unit tests already pin specific hit-rate
	// invariants. Here we only want to confirm the tool runs against the
	// same wired store without error and returns a well-formed payload.
	cacheResult := callAdminTool(t, mgr, "admin_stats_cache_info", adminEmail, nil)
	require.False(t, cacheResult.IsError, "admin_stats_cache_info must succeed in the chain")

	var cache adminStatsCacheInfoResponse
	require.NoError(t, json.Unmarshal([]byte(resultText(t, cacheResult)), &cache))
	assert.Equal(t, "audit.statsCache", cache.CacheName)
	assert.GreaterOrEqual(t, cache.HitRate, 0.0, "hit rate must be non-negative")
	assert.LessOrEqual(t, cache.HitRate, 1.0, "hit rate must not exceed 1.0")

	// --- Step 4: simulate an anomaly block by recording a blocked order
	// whose value (Rs 50,000) is 10x the seeded mean — exactly the kind of
	// row riskguard writes when μ+3σ + 10*μ both trip.
	seedBlockedAnomaly(t, auditStore, traderEmail, "integ-anom-1", 50000, 30*time.Minute)

	// --- Step 5: call admin_list_anomaly_flags as admin over a 24h window.
	flagsResult := callAdminTool(t, mgr, "admin_list_anomaly_flags", adminEmail, map[string]any{
		"hours": 24,
	})
	require.False(t, flagsResult.IsError, "admin_list_anomaly_flags must succeed in the chain")

	var flags adminAnomalyFlagsResponse
	require.NoError(t, json.Unmarshal([]byte(resultText(t, flagsResult)), &flags))
	assert.Equal(t, 24, flags.WindowHours)
	assert.GreaterOrEqual(t, flags.TotalFlags, 1,
		"at least the Rs 50,000 anomaly block must surface in the listing")

	// trader must appear in the by_user aggregate.
	var traderAgg *adminAnomalyUserAgg
	for i := range flags.ByUser {
		if flags.ByUser[i].Email == traderEmail {
			traderAgg = &flags.ByUser[i]
			break
		}
	}
	require.NotNil(t, traderAgg, "trader must appear in anomaly-flag aggregation")
	assert.GreaterOrEqual(t, traderAgg.FlagCount, 1)
	require.NotEmpty(t, traderAgg.Events)
	assert.Equal(t, "anomaly_high", traderAgg.Events[0].Reason,
		"reason code must be extracted from the seeded ORDER BLOCKED [anomaly_high] message")
	assert.True(t, traderAgg.Events[0].Blocked,
		"anomaly events are hard-blocks today")
}

// -----------------------------------------------------------------------------
// TestAdminIntegration_AllToolsBlockNonAdmin — the three tools must uniformly
// reject a non-admin caller. Verifies the adminCheck / withAdminCheck wrapper
// is wired on every one of them, not just the ones covered by unit tests in
// isolation. A regression here (e.g. someone removes withAdminCheck from one
// of the tools in a refactor) would let a trader role read operator-grade
// internals (baseline stats of other users, cache metrics, audit anomaly
// events across the tenant) — a privilege-escalation bug. Cheap to guard.
// -----------------------------------------------------------------------------

func TestAdminIntegration_AllToolsBlockNonAdmin(t *testing.T) {
	mgr := newAdminTestManager(t)
	seedUsers(t, mgr)
	_ = wireAuditForAdminTest(t, mgr)

	const traderEmail = "trader@example.com"

	// Each tool needs its own minimum valid arg shape. admin_get_user_baseline
	// requires an "email" string; the other two are argless for the happy path.
	cases := []struct {
		tool string
		args map[string]any
	}{
		{"admin_get_user_baseline", map[string]any{"email": traderEmail}},
		{"admin_stats_cache_info", nil},
		{"admin_list_anomaly_flags", map[string]any{"hours": 24}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.tool, func(t *testing.T) {
			result := callAdminTool(t, mgr, tc.tool, traderEmail, tc.args)
			require.NotNil(t, result, "tool must return a result (error or otherwise)")
			assert.True(t, result.IsError,
				"non-admin caller must be blocked from %s (admin-only)", tc.tool)
		})
	}
}
