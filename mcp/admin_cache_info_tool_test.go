package mcp

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/audit"
)

// -----------------------------------------------------------------------------
// TestAdminCacheInfo_NonAdminBlocked — trader role gets ErrAdminRequired.
//
// Rationale: cache hit rate is an operator-grade signal. Exposing it to a
// regular trader leaks internal details (e.g. how often their baseline is
// being re-scanned) and is not a user-facing concern.
// -----------------------------------------------------------------------------

func TestAdminCacheInfo_NonAdminBlocked(t *testing.T) {
	mgr := newAdminTestManager(t)
	seedUsers(t, mgr)
	_ = wireAuditForAdminTest(t, mgr)

	result := callAdminTool(t, mgr, "admin_stats_cache_info", "trader@example.com", nil)
	assert.True(t, result.IsError, "non-admin must be blocked from admin_stats_cache_info")
}

// -----------------------------------------------------------------------------
// TestAdminCacheInfo_UnauthenticatedBlocked — no email in context → error.
// -----------------------------------------------------------------------------

func TestAdminCacheInfo_UnauthenticatedBlocked(t *testing.T) {
	mgr := newAdminTestManager(t)
	seedUsers(t, mgr)
	_ = wireAuditForAdminTest(t, mgr)

	result := callAdminTool(t, mgr, "admin_stats_cache_info", "", nil)
	assert.True(t, result.IsError, "unauthenticated caller must be blocked")
}

// -----------------------------------------------------------------------------
// TestAdminCacheInfo_AdminReturnsStructuredResponse — admin call returns
// the full observability payload with the constants we know are stable:
// cache name, max size, TTL, and the alert thresholds.
//
// The hit rate is 0 here because no UserOrderStats queries have run yet;
// the follow-up test exercises the rate computation after priming.
// -----------------------------------------------------------------------------

func TestAdminCacheInfo_AdminReturnsStructuredResponse(t *testing.T) {
	mgr := newAdminTestManager(t)
	seedUsers(t, mgr)
	_ = wireAuditForAdminTest(t, mgr)

	result := callAdminTool(t, mgr, "admin_stats_cache_info", "admin@example.com", nil)
	require.False(t, result.IsError, "admin should get cache info successfully. content=%+v", result.Content)

	raw := resultText(t, result)
	require.NotEmpty(t, raw, "response must carry text content")

	var payload adminStatsCacheInfoResponse
	require.NoError(t, json.Unmarshal([]byte(raw), &payload))

	// Stable constants (must match audit package + tool defaults).
	assert.Equal(t, "audit.statsCache", payload.CacheName)
	assert.Equal(t, audit.DefaultMaxStatsCacheEntries, payload.MaxEntries)
	assert.Equal(t, int64(adminCacheInfoTTLSeconds), payload.TTLSeconds)
	assert.InDelta(t, 0.7, payload.Thresholds.HitRateAlertBelow, 1e-9)
	assert.InDelta(t, 0.9, payload.Thresholds.SizeAlertAboveFraction, 1e-9)

	// Hit rate is zero before any baseline queries have run.
	assert.Equal(t, 0.0, payload.HitRate)

	// current_entries, hits, misses are not exposed by audit.Store today; the
	// tool must signal this with the sentinel -1 rather than mislead operators
	// with a zero that could mean "empty" or "unknown".
	assert.Equal(t, int64(-1), payload.CurrentEntries,
		"audit.Store does not expose current size — tool must report -1")
	assert.Equal(t, int64(-1), payload.Hits,
		"audit.Store does not expose raw hit counter — tool must report -1")
	assert.Equal(t, int64(-1), payload.Misses,
		"audit.Store does not expose raw miss counter — tool must report -1")

	// With hit_rate=0 and unknown size, healthy must be false (hit_rate < 0.7).
	assert.False(t, payload.Healthy,
		"a cache with hit_rate=0 is below the 0.7 alert threshold and must not report healthy")
}

// -----------------------------------------------------------------------------
// TestAdminCacheInfo_HitRateSanity — after priming the cache with a real
// UserOrderStats workload, the reported hit rate must match what the audit
// store reports directly and must fall in [0, 1]. Healthy flag must flip on
// when the hit rate rises above the 0.7 threshold.
//
// Priming: seed 5 place_order rows, call UserOrderStats once to populate,
// then call it 10 more times — all 10 should hit → 10/11 ≈ 0.909.
// -----------------------------------------------------------------------------

func TestAdminCacheInfo_HitRateSanity(t *testing.T) {
	mgr := newAdminTestManager(t)
	seedUsers(t, mgr)
	auditStore := wireAuditForAdminTest(t, mgr)

	// Seed a baseline for a known user and prime the cache so hit rate is high.
	seedBaselineOrders(t, auditStore, "trader@example.com", 5, 10, 100)

	// First call populates the cache → 1 miss.
	_, _, _ = auditStore.UserOrderStats("trader@example.com", 30)
	// 10 follow-up calls → all hits. Total: 10 hits / 11 ops ≈ 0.909.
	for i := 0; i < 10; i++ {
		_, _, _ = auditStore.UserOrderStats("trader@example.com", 30)
	}

	result := callAdminTool(t, mgr, "admin_stats_cache_info", "admin@example.com", nil)
	require.False(t, result.IsError)

	var payload adminStatsCacheInfoResponse
	require.NoError(t, json.Unmarshal([]byte(resultText(t, result)), &payload))

	// Hit rate from the store and from the tool must agree to full float precision.
	// This is the contract: the tool is a thin projection over StatsCacheHitRate.
	assert.Equal(t, auditStore.StatsCacheHitRate(), payload.HitRate,
		"tool must report exactly what audit.Store reports — no rounding, no derivation")

	// Sanity: the rate must be in [0, 1] and above the 0.7 threshold after priming.
	assert.GreaterOrEqual(t, payload.HitRate, 0.0)
	assert.LessOrEqual(t, payload.HitRate, 1.0)
	assert.Greater(t, payload.HitRate, 0.7,
		"after 10 hits vs 1 miss, rate should exceed the 0.7 alert floor")

	// healthy = hit_rate > 0.7 AND current < 0.9*max.
	// With current_entries unknown (-1), the size check is treated as passing
	// (we can't alert on unknown). So healthy should follow hit_rate alone.
	assert.True(t, payload.Healthy,
		"hit_rate above 0.7 and size unknown → healthy")
}
