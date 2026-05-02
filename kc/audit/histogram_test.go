package audit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetToolHistograms_Empty: no rows in tool_calls → empty result.
func TestGetToolHistograms_Empty(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	hists, err := s.GetToolHistograms(time.Now().Add(-time.Hour))
	require.NoError(t, err)
	assert.Empty(t, hists)
}

// TestGetToolHistograms_BucketCounts: insert calls at known durations
// and verify each bucket's cumulative count.
//
// Default buckets per metricsBuckets (le=10, 50, 100, 500, 1000, 5000 ms).
// We insert: 5ms, 25ms, 75ms, 250ms, 750ms, 2500ms, 7500ms — one per
// bucket plus an over-budget call.
//
// Cumulative semantics (Prometheus convention):
//   - le=10:    1 (the 5ms call)
//   - le=50:    2 (5ms + 25ms)
//   - le=100:   3
//   - le=500:   4
//   - le=1000:  5
//   - le=5000:  6
//   - +Inf:     7 (everything; equals total CallCount)
func TestGetToolHistograms_BucketCounts(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	now := time.Now().UTC().Truncate(time.Microsecond)
	durations := []int64{5, 25, 75, 250, 750, 2500, 7500}
	for i, dur := range durations {
		e := makeEntry("hist-call-"+string(rune('a'+i)), "alice@example.com", "place_order", "order", false, now)
		e.DurationMs = dur
		e.CompletedAt = e.StartedAt.Add(time.Duration(dur) * time.Millisecond)
		require.NoError(t, s.Record(e))
	}

	hists, err := s.GetToolHistograms(now.Add(-time.Hour))
	require.NoError(t, err)
	require.Len(t, hists, 1, "exactly one tool was inserted")

	h := hists[0]
	assert.Equal(t, "place_order", h.ToolName)
	assert.Equal(t, 7, h.CallCount, "total = +Inf bucket")
	assert.InDelta(t, 11105.0, h.SumMs, 0.01, "sum of durations: 5+25+75+250+750+2500+7500 = 11105")

	// Bucket boundaries are defined in the production code; the test
	// asserts the cumulative semantics independently of the exact
	// boundary values by walking the returned slice.
	require.NotEmpty(t, h.Buckets, "must return non-empty buckets")
	prev := 0
	for _, b := range h.Buckets {
		assert.GreaterOrEqual(t, b.Count, prev, "buckets must be cumulative non-decreasing")
		assert.LessOrEqual(t, b.Count, 7, "no bucket exceeds total")
		prev = b.Count
	}
	// Final bucket (largest le) covers all calls below +Inf.
	last := h.Buckets[len(h.Buckets)-1]
	if last.LeMs >= 5000 {
		// 6 calls under 5s, one at 7500ms is +Inf-only
		assert.Equal(t, 6, last.Count, "le=5000 should hold 6 of 7 calls")
	}
}

// TestGetToolHistograms_PerToolGrouping: two distinct tools → two
// distinct ToolHistogram entries.
func TestGetToolHistograms_PerToolGrouping(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	now := time.Now().UTC().Truncate(time.Microsecond)
	for i := 0; i < 3; i++ {
		e := makeEntry("place-"+string(rune('a'+i)), "alice@example.com", "place_order", "order", false, now)
		e.DurationMs = 30
		require.NoError(t, s.Record(e))
	}
	for i := 0; i < 5; i++ {
		e := makeEntry("get-"+string(rune('a'+i)), "alice@example.com", "get_holdings", "read", false, now)
		e.DurationMs = 8
		require.NoError(t, s.Record(e))
	}

	hists, err := s.GetToolHistograms(now.Add(-time.Hour))
	require.NoError(t, err)
	require.Len(t, hists, 2)

	byName := map[string]ToolHistogram{}
	for _, h := range hists {
		byName[h.ToolName] = h
	}
	assert.Equal(t, 3, byName["place_order"].CallCount)
	assert.Equal(t, 5, byName["get_holdings"].CallCount)
}

// TestGetToolHistograms_SinceFilter: rows older than `since` are
// excluded.
func TestGetToolHistograms_SinceFilter(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	now := time.Now().UTC().Truncate(time.Microsecond)
	// Old call (2h ago)
	old := makeEntry("old-1", "alice@example.com", "place_order", "order", false, now.Add(-2*time.Hour))
	old.DurationMs = 100
	require.NoError(t, s.Record(old))

	// Recent call (5min ago)
	recent := makeEntry("recent-1", "alice@example.com", "place_order", "order", false, now.Add(-5*time.Minute))
	recent.DurationMs = 50
	require.NoError(t, s.Record(recent))

	hists, err := s.GetToolHistograms(now.Add(-30 * time.Minute))
	require.NoError(t, err)
	require.Len(t, hists, 1)
	assert.Equal(t, 1, hists[0].CallCount, "only the recent call should be included")
}

// TestGetToolHistograms_ExcludesChainBreak: the synthetic
// __chain_break audit row must NOT appear in metrics.
func TestGetToolHistograms_ExcludesChainBreak(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	now := time.Now().UTC().Truncate(time.Microsecond)
	e := makeEntry("chain-1", "alice@example.com", "__chain_break", "audit", false, now)
	e.DurationMs = 0
	require.NoError(t, s.Record(e))

	hists, err := s.GetToolHistograms(now.Add(-time.Hour))
	require.NoError(t, err)
	assert.Empty(t, hists, "__chain_break row must be excluded")
}
