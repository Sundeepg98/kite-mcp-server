package audit

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordOrderEntry is a test helper that persists a place_order audit row
// with a given quantity * price (in INR) for the given email at startedAt.
// The JSON shape mirrors what audit.Middleware writes via SanitizeParams +
// json.Marshal(args): top-level numeric "quantity" and "price" fields.
func recordOrderEntry(t *testing.T, s *Store, email, tool string, qty float64, price float64, startedAt time.Time) {
	t.Helper()
	params := map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "RELIANCE",
		"transaction_type": "BUY",
		"quantity":         qty,
		"price":            price,
		"order_type":       "LIMIT",
	}
	paramJSON, err := json.Marshal(params)
	require.NoError(t, err)

	entry := &ToolCall{
		CallID:       fmt.Sprintf("anom-%d-%d", startedAt.UnixNano(), int64(qty*price)),
		Email:        email,
		SessionID:    "sess-anom",
		ToolName:     tool,
		ToolCategory: "order",
		InputParams:  string(paramJSON),
		InputSummary: fmt.Sprintf("BUY %.0f RELIANCE", qty),
		StartedAt:    startedAt,
		CompletedAt:  startedAt.Add(50 * time.Millisecond),
		DurationMs:   50,
	}
	require.NoError(t, s.Record(entry))
}

// TestUserOrderStats_InsufficientHistory verifies that fewer than 5 orders
// returns zero stats (no baseline yet). This is the safety floor — the
// riskguard caller treats (count<5) as "skip the anomaly check".
func TestUserOrderStats_InsufficientHistory(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	email := "new@user.com"
	now := time.Now().UTC()

	// Only 4 orders — below the minimum baseline threshold.
	for i := range 4 {
		recordOrderEntry(t, s, email, "place_order", 10, 500, now.Add(-time.Duration(i)*time.Hour))
	}

	mean, stdev, count := s.UserOrderStats(email, 30)
	assert.Equal(t, 0.0, mean, "insufficient history must return 0 mean")
	assert.Equal(t, 0.0, stdev, "insufficient history must return 0 stdev")
	assert.Equal(t, 4.0, count, "count should reflect actual rows found")
}

// TestUserOrderStats_SteadyBaseline verifies mean and stdev are computed
// correctly for a user with consistent small orders.
func TestUserOrderStats_SteadyBaseline(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	email := "steady@user.com"
	now := time.Now().UTC()

	// 10 orders at exactly Rs 5000 each — zero variance.
	for i := range 10 {
		recordOrderEntry(t, s, email, "place_order", 10, 500, now.Add(-time.Duration(i)*time.Hour))
	}

	mean, stdev, count := s.UserOrderStats(email, 30)
	assert.Equal(t, 10.0, count)
	assert.InDelta(t, 5000.0, mean, 0.01, "mean of 10x Rs 5000 orders should be 5000")
	assert.InDelta(t, 0.0, stdev, 0.01, "zero variance series must have stdev 0")
}

// TestUserOrderStats_VariedBaseline verifies stdev is non-zero for a mixed
// dataset with known mean and sample-variance.
func TestUserOrderStats_VariedBaseline(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	email := "varied@user.com"
	now := time.Now().UTC()

	// 5 orders: values 1000, 2000, 3000, 4000, 5000 (Rs)
	// mean = 3000, population stdev = sqrt(((1000-3000)^2 + ... )/5)
	//      = sqrt((4_000_000 + 1_000_000 + 0 + 1_000_000 + 4_000_000)/5)
	//      = sqrt(2_000_000) ~= 1414.21
	values := []float64{1000, 2000, 3000, 4000, 5000}
	for i, v := range values {
		// qty=1, price=v → order value = v
		recordOrderEntry(t, s, email, "place_order", 1, v, now.Add(-time.Duration(i)*time.Hour))
	}

	mean, stdev, count := s.UserOrderStats(email, 30)
	assert.Equal(t, 5.0, count)
	assert.InDelta(t, 3000.0, mean, 0.1)
	assert.InDelta(t, 1414.21, stdev, 1.0)
}

// TestUserOrderStats_WindowExcludesOldOrders confirms the days-parameter
// windows the query: orders older than the cutoff must NOT contribute.
func TestUserOrderStats_WindowExcludesOldOrders(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	email := "windowed@user.com"
	now := time.Now().UTC()

	// 10 small recent orders (within 30d).
	for i := range 10 {
		recordOrderEntry(t, s, email, "place_order", 1, 1000, now.Add(-time.Duration(i)*time.Hour))
	}
	// 5 giant old orders from 60 days ago — must be excluded by the 30-day window.
	for i := range 5 {
		recordOrderEntry(t, s, email, "place_order", 1, 1_000_000, now.Add(-60*24*time.Hour).Add(-time.Duration(i)*time.Hour))
	}

	mean, _, count := s.UserOrderStats(email, 30)
	assert.Equal(t, 10.0, count, "only the 10 recent orders should be counted")
	assert.InDelta(t, 1000.0, mean, 1.0, "old giant orders must not skew the 30-day mean")
}

// TestUserOrderStats_OnlyOrderTools verifies that non-order tool calls do
// not contaminate the baseline (e.g. get_ltp, get_holdings).
func TestUserOrderStats_OnlyOrderTools(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	email := "mixed@user.com"
	now := time.Now().UTC()

	// 5 order rows at 1000.
	for i := range 5 {
		recordOrderEntry(t, s, email, "place_order", 1, 1000, now.Add(-time.Duration(i)*time.Hour))
	}
	// 10 non-order rows that happen to mention "quantity"/"price" in params.
	for i := range 10 {
		recordOrderEntry(t, s, email, "get_ltp", 100, 99999, now.Add(-time.Duration(i)*time.Hour))
	}

	mean, _, count := s.UserOrderStats(email, 30)
	assert.Equal(t, 5.0, count, "only place_order/modify_order rows should count")
	assert.InDelta(t, 1000.0, mean, 1.0)
}

// TestUserOrderStats_ModifyOrderCounted verifies that modify_order rows are
// also folded into the baseline (they represent a real trading action).
func TestUserOrderStats_ModifyOrderCounted(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	email := "modifier@user.com"
	now := time.Now().UTC()

	for i := range 3 {
		recordOrderEntry(t, s, email, "place_order", 1, 1000, now.Add(-time.Duration(i)*time.Hour))
	}
	for i := range 3 {
		recordOrderEntry(t, s, email, "modify_order", 1, 2000, now.Add(-time.Duration(i+3)*time.Hour))
	}

	_, _, count := s.UserOrderStats(email, 30)
	assert.Equal(t, 6.0, count, "place_order + modify_order rows should both count")
}

// TestUserOrderStats_UnknownUser returns zero for an email with no history.
func TestUserOrderStats_UnknownUser(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	mean, stdev, count := s.UserOrderStats("ghost@nowhere.com", 30)
	assert.Equal(t, 0.0, mean)
	assert.Equal(t, 0.0, stdev)
	assert.Equal(t, 0.0, count)
}
