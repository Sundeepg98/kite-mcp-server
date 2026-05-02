package audit

import (
	"fmt"
	"time"
)

// ToolHistogramBucket is a single Prometheus-style cumulative bucket
// for the tool latency histogram. LeMs is the bucket upper bound in
// milliseconds (Prometheus `le` label); Count is the cumulative count
// of calls with duration ≤ LeMs.
//
// The +Inf bucket is NOT in this slice — it equals the parent
// ToolHistogram.CallCount. Prometheus exposition format expects the
// +Inf bucket to be emitted explicitly with `le="+Inf"` matching
// total count.
type ToolHistogramBucket struct {
	LeMs  int64 `json:"le_ms"`
	Count int   `json:"count"`
}

// ToolHistogram holds the per-tool latency distribution since a given
// time. Closes the §1.2 metrics-axis gap surfaced in
// observability-audit-and-roadmap.md (per-tool latency p50/p95/p99
// previously available only via the server_metrics MCP tool — NOT
// in Prometheus exposition format, blocking Grafana / Datadog
// Agent / Loki integrations).
//
// The histogram is computed at query time via SQL CASE binning. No
// in-memory histogram state. This trades a small per-scrape SQL cost
// (~1ms at 100K rows) for zero ongoing memory overhead — appropriate
// at the codebase's current scale and matches the existing
// query-time-aggregation pattern in GetToolMetrics.
type ToolHistogram struct {
	ToolName  string                `json:"tool_name"`
	CallCount int                   `json:"call_count"`
	SumMs     float64               `json:"sum_ms"`
	Buckets   []ToolHistogramBucket `json:"buckets"`
}

// MetricsBuckets are the Prometheus `le` boundaries for tool latency
// histograms (in milliseconds). Bucket choice tuned for the typical
// MCP tool latency profile observed in audit data:
//   - 10ms covers cached / no-IO tools (server_version, get_quotes
//     against in-memory instruments)
//   - 50ms covers most read tools (broker GET round-trip)
//   - 100ms covers most write tools (broker POST + audit + persist)
//   - 500ms is the riskguard sub-millisecond p99 target's slack
//   - 1000ms / 5000ms catch the long tail (paginated history, slow
//     broker)
//   - +Inf covers everything (timeout middleware caps at 30s)
//
// Bucket count is 6 — small enough to fit comfortably in Prometheus
// cardinality budgets even at 80+ tools (480 series) and large
// enough to reconstruct percentiles via histogram_quantile.
var MetricsBuckets = []int64{10, 50, 100, 500, 1000, 5000}

// GetToolHistograms returns per-tool latency histograms for tool
// calls since the given time. Histograms are bucketed by
// MetricsBuckets; results exclude the synthetic __chain_break row
// (matches GetToolMetrics convention).
//
// Implementation note: the SQL builds one CASE-binning column per
// bucket boundary. This is straightforward at 6 buckets; if the
// boundary list grows past ~15, the query should be split into
// per-bucket UNION ALL or moved to in-memory histograms.
func (s *Store) GetToolHistograms(since time.Time) ([]ToolHistogram, error) {
	// Build the SELECT clause: one SUM(CASE WHEN duration_ms <= N
	// THEN 1 ELSE 0 END) AS bucket_N column per boundary, plus
	// COUNT(*) and SUM(duration_ms) for the +Inf and _sum lines.
	cols := "tool_name, COUNT(*) AS calls, COALESCE(SUM(duration_ms), 0) AS sum_ms"
	for _, le := range MetricsBuckets {
		cols += fmt.Sprintf(", SUM(CASE WHEN duration_ms <= %d THEN 1 ELSE 0 END) AS le_%d", le, le)
	}

	query := "SELECT " + cols + ` FROM tool_calls
		WHERE started_at > ? AND tool_name != '__chain_break'
		GROUP BY tool_name
		ORDER BY tool_name`

	rows, err := s.db.RawQuery(query, since.Format(time.RFC3339Nano))
	if err != nil {
		return nil, fmt.Errorf("audit: get tool histograms: %w", err)
	}
	defer rows.Close()

	var results []ToolHistogram
	for rows.Next() {
		var h ToolHistogram
		// Scan into a positional slice: tool_name, calls, sum_ms,
		// then one int per bucket.
		bucketCounts := make([]int, len(MetricsBuckets))
		scanArgs := make([]any, 3+len(MetricsBuckets))
		scanArgs[0] = &h.ToolName
		scanArgs[1] = &h.CallCount
		scanArgs[2] = &h.SumMs
		for i := range bucketCounts {
			scanArgs[3+i] = &bucketCounts[i]
		}
		if err := rows.Scan(scanArgs...); err != nil {
			return nil, fmt.Errorf("audit: scan tool histogram: %w", err)
		}
		h.Buckets = make([]ToolHistogramBucket, len(MetricsBuckets))
		for i, le := range MetricsBuckets {
			h.Buckets[i] = ToolHistogramBucket{
				LeMs:  le,
				Count: bucketCounts[i],
			}
		}
		results = append(results, h)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: iterate tool histograms: %w", err)
	}
	return results, nil
}
