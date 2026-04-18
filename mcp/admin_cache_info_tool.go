package mcp

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/audit"
)

// ─────────────────────────────────────────────────────────────────────────────
// Tool: admin_stats_cache_info (read-only, admin-only)
//
// Surfaces observability for the UserOrderStats baseline cache
// (audit.statsCache). Operators need a way to answer "is the anomaly cache
// actually working?" without SSH'ing to the Fly.io machine and scraping
// internal metrics. The monitoring playbook (Agent 89) says: alert if the
// hit rate drops below 0.7. This tool makes that check a single MCP call.
//
// Data gaps (intentional, not a bug):
//   - current_entries, hits, misses are returned as -1 because audit.Store
//     does not currently expose a CurrentEntries/Hits/Misses accessor. The
//     standing rule "do not modify kc/audit/store.go" (owned by other agents)
//     means we project only what is already public: StatsCacheHitRate().
//   - When those accessors land, this tool will pick them up automatically
//     via a one-line change in the handler below. Until then the sentinel
//     -1 signals "unknown" distinctly from 0 (which would mean "empty").
// ─────────────────────────────────────────────────────────────────────────────

// adminCacheInfoTTLSeconds mirrors the statsCacheTTL package var in
// kc/audit/store.go. Kept local because audit does not export the value
// and the store-level instruction forbids editing store.go here. If the
// audit TTL changes, this mirror must be updated — the TestAdminCacheInfo
// response test pins the constant so a mismatch will surface in CI.
const adminCacheInfoTTLSeconds = 900

// adminCacheInfoHitRateAlertBelow is the threshold below which the cache
// is considered unhealthy. Sourced from the Agent 89 monitoring doc: a
// sustained rate < 0.7 implies the UserOrderStats workload is dominated
// by cache misses and the 30-day SQL scan is running on almost every
// place_order — i.e. the cache is either undersized or incorrectly
// invalidated.
const adminCacheInfoHitRateAlertBelow = 0.7

// adminCacheInfoSizeAlertAboveFraction is the fraction of maxEntries at
// which the cache is considered at risk of eviction churn. 0.9 gives
// operators a 10% headroom to add capacity before random eviction starts
// degrading the hit rate.
const adminCacheInfoSizeAlertAboveFraction = 0.9

// AdminStatsCacheInfoTool exposes the UserOrderStats cache's runtime stats
// (hit rate, size, ttl, configured thresholds) for admin observability.
type AdminStatsCacheInfoTool struct{}

func (*AdminStatsCacheInfoTool) Tool() mcp.Tool {
	return mcp.NewTool("admin_stats_cache_info",
		mcp.WithDescription(
			"Return runtime observability for the UserOrderStats anomaly-baseline cache: "+
				"hit rate, configured TTL, max size, and alert thresholds. Use to verify "+
				"the anomaly detector is hitting the cache (target: >70% hit rate) instead "+
				"of burning SQL scans. Admin-only.",
		),
		mcp.WithTitleAnnotation("Admin: Stats Cache Info"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
	)
}

// adminCacheInfoThresholds surfaces the alert cutoffs so operators can see
// them next to the live values without consulting docs.
type adminCacheInfoThresholds struct {
	HitRateAlertBelow      float64 `json:"hit_rate_alert_below"`
	SizeAlertAboveFraction float64 `json:"size_alert_above_fraction"`
}

// adminStatsCacheInfoResponse is the structured payload returned by the tool.
// Sentinel -1 on CurrentEntries/Hits/Misses means "audit.Store does not
// currently expose this value", distinct from 0 which would be a legitimate
// "cache is empty" reading.
type adminStatsCacheInfoResponse struct {
	CacheName      string                   `json:"cache_name"`
	HitRate        float64                  `json:"hit_rate"`
	Hits           int64                    `json:"hits"`
	Misses         int64                    `json:"misses"`
	CurrentEntries int64                    `json:"current_entries"`
	MaxEntries     int                      `json:"max_entries"`
	TTLSeconds     int64                    `json:"ttl_seconds"`
	Healthy        bool                     `json:"healthy"`
	Thresholds     adminCacheInfoThresholds `json:"thresholds"`
}

// cacheHealthy applies the monitoring playbook: hit_rate above the alert
// floor AND current entries below the eviction-risk fraction of max. When
// currentEntries is -1 (unknown) we cannot evaluate the size gate, so we
// fall back to hit-rate-only — reporting "unhealthy" purely because of a
// missing accessor would be a false alarm for operators.
func cacheHealthy(hitRate float64, currentEntries int64, maxEntries int) bool {
	if hitRate <= adminCacheInfoHitRateAlertBelow {
		return false
	}
	if currentEntries < 0 || maxEntries <= 0 {
		// Size unknown → trust the hit-rate signal alone.
		return true
	}
	return float64(currentEntries) < adminCacheInfoSizeAlertAboveFraction*float64(maxEntries)
}

func (*AdminStatsCacheInfoTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return withAdminCheck(manager, func(ctx context.Context, _ string, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "admin_stats_cache_info")

		// Concrete store is the only path to StatsCacheHitRate — this accessor
		// is not part of AuditStoreInterface, and as a read-only admin tool we
		// are the legitimate place to reach for the concrete type (same
		// pattern as admin_get_user_baseline).
		auditStore := manager.AuditStoreConcrete()
		if auditStore == nil {
			return mcp.NewToolResultError("Audit store not available (requires database persistence)."), nil
		}

		hitRate := auditStore.StatsCacheHitRate()

		// Unknowns: audit.Store does not expose these today. -1 distinguishes
		// "not available" from "legitimately zero". When a future audit.Store
		// change adds getters, wire them in here and drop the sentinels.
		const unknown = int64(-1)

		resp := adminStatsCacheInfoResponse{
			CacheName:      "audit.statsCache",
			HitRate:        hitRate,
			Hits:           unknown,
			Misses:         unknown,
			CurrentEntries: unknown,
			MaxEntries:     audit.DefaultMaxStatsCacheEntries,
			TTLSeconds:     adminCacheInfoTTLSeconds,
			Healthy:        cacheHealthy(hitRate, unknown, audit.DefaultMaxStatsCacheEntries),
			Thresholds: adminCacheInfoThresholds{
				HitRateAlertBelow:      adminCacheInfoHitRateAlertBelow,
				SizeAlertAboveFraction: adminCacheInfoSizeAlertAboveFraction,
			},
		}

		return handler.MarshalResponse(&resp, "admin_stats_cache_info")
	})
}
