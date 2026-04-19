package mcp

import (
	"testing"
	"time"

	"github.com/zerodha/kite-mcp-server/broker"
)

// TestSameYMD spot-checks calendar-day equality independent of
// time-of-day or nanoseconds. Volume-spike relies on this to decide
// whether to drop an in-progress candle.
func TestSameYMD(t *testing.T) {
	t.Parallel()
	a := time.Date(2026, 4, 17, 9, 15, 0, 0, time.UTC)
	b := time.Date(2026, 4, 17, 15, 30, 0, 0, time.UTC)
	if !sameYMD(a, b) {
		t.Error("expected same YMD for times on the same day")
	}

	c := time.Date(2026, 4, 18, 9, 15, 0, 0, time.UTC)
	if sameYMD(a, c) {
		t.Error("expected different YMD for times one day apart")
	}
}

// TestFilterCompletedCandles verifies we drop only today's candle (the
// in-progress session) and never an older one.
func TestFilterCompletedCandles(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 17, 15, 0, 0, 0, time.UTC)

	candles := []broker.HistoricalCandle{
		{Date: time.Date(2026, 4, 15, 0, 0, 0, 0, time.UTC), Close: 100, Volume: 1000},
		{Date: time.Date(2026, 4, 16, 0, 0, 0, 0, time.UTC), Close: 102, Volume: 1200},
		{Date: time.Date(2026, 4, 17, 0, 0, 0, 0, time.UTC), Close: 101, Volume: 500}, // today, partial
	}

	got := filterCompletedCandles(candles, now)
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2 (today dropped)", len(got))
	}
	if sameYMD(got[len(got)-1].Date, now) {
		t.Error("today's candle should have been dropped")
	}

	// No today candle — all are already completed; nothing dropped.
	allPast := candles[:2]
	got = filterCompletedCandles(allPast, now)
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2 (nothing should be dropped)", len(got))
	}

	// Empty input should pass through unchanged.
	got = filterCompletedCandles(nil, now)
	if len(got) != 0 {
		t.Errorf("len = %d, want 0 for empty input", len(got))
	}
}

// TestAverageVolumeAndClose verifies both outputs are plain arithmetic
// means over the supplied slice — no exponential weighting, no median.
func TestAverageVolumeAndClose(t *testing.T) {
	t.Parallel()
	candles := []broker.HistoricalCandle{
		{Close: 100, Volume: 1000},
		{Close: 110, Volume: 2000},
		{Close: 120, Volume: 3000},
	}
	gotVol, gotPrice := averageVolumeAndClose(candles)
	if gotVol != 2000 {
		t.Errorf("avg volume = %v, want 2000", gotVol)
	}
	if gotPrice != 110 {
		t.Errorf("avg price = %v, want 110", gotPrice)
	}

	// Empty input must return (0, 0) not NaN / panic.
	gotVol, gotPrice = averageVolumeAndClose(nil)
	if gotVol != 0 || gotPrice != 0 {
		t.Errorf("empty: got (%v, %v), want (0, 0)", gotVol, gotPrice)
	}
}
