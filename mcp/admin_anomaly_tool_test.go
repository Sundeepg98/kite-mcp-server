package mcp

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/audit"
)

// seedBlockedAnomaly persists an audit row that looks exactly like what the
// riskguard middleware writes when an order is blocked by the anomaly check:
// IsError=true, ErrorMessage carrying the "ORDER BLOCKED [anomaly_high]" text.
// Uses an offset hours/minutes back from now so a single test can stage multiple
// events within the query window.
func seedBlockedAnomaly(
	t *testing.T,
	s *audit.Store,
	email string,
	callID string,
	orderValue float64,
	offset time.Duration,
) {
	t.Helper()
	now := time.Now().UTC().Add(-offset)
	params := map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "RELIANCE",
		"transaction_type": "BUY",
		"quantity":         1.0,
		"price":            orderValue,
		"order_type":       "LIMIT",
	}
	b, err := json.Marshal(params)
	require.NoError(t, err)
	msg := fmt.Sprintf(
		"ERROR: ORDER BLOCKED [anomaly_high]: Order value Rs %.0f is a statistical anomaly...",
		orderValue,
	)
	entry := &audit.ToolCall{
		CallID:        callID,
		Email:         email,
		SessionID:     "sess-anomaly",
		ToolName:      "place_order",
		ToolCategory:  "order",
		InputParams:   string(b),
		InputSummary:  "BUY RELIANCE",
		OutputSummary: msg,
		IsError:       true,
		ErrorMessage:  msg,
		ErrorType:     "tool_error",
		StartedAt:     now,
		CompletedAt:   now.Add(50 * time.Millisecond),
		DurationMs:    50,
	}
	require.NoError(t, s.Record(entry))
}

// seedBlockedNonAnomaly persists a blocked-order row with a DIFFERENT reason
// (order_value_limit) so we can assert the tool filters anomaly events out of
// general blocking noise.
func seedBlockedNonAnomaly(t *testing.T, s *audit.Store, email, callID string) {
	t.Helper()
	now := time.Now().UTC()
	params := map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         1.0,
		"price":            999999.0,
		"order_type":       "LIMIT",
	}
	b, err := json.Marshal(params)
	require.NoError(t, err)
	msg := "ERROR: ORDER BLOCKED [order_value_limit]: Order value Rs 999999 exceeds limit Rs 50000"
	entry := &audit.ToolCall{
		CallID:        callID,
		Email:         email,
		SessionID:     "sess-cap",
		ToolName:      "place_order",
		ToolCategory:  "order",
		InputParams:   string(b),
		InputSummary:  "BUY INFY",
		OutputSummary: msg,
		IsError:       true,
		ErrorMessage:  msg,
		ErrorType:     "tool_error",
		StartedAt:     now,
		CompletedAt:   now.Add(50 * time.Millisecond),
		DurationMs:    50,
	}
	require.NoError(t, s.Record(entry))
}

// -----------------------------------------------------------------------------
// TestAdminAnomalyFlags_NonAdminBlocked — trader role → ErrAdminRequired.
// -----------------------------------------------------------------------------

func TestAdminAnomalyFlags_NonAdminBlocked(t *testing.T) {
	t.Parallel()
	mgr := newAdminTestManager(t)
	seedUsers(t, mgr)
	_ = wireAuditForAdminTest(t, mgr)

	result := callAdminTool(t, mgr, "admin_list_anomaly_flags", "trader@example.com", nil)
	assert.True(t, result.IsError, "non-admin must be blocked from admin_list_anomaly_flags")
}

// -----------------------------------------------------------------------------
// TestAdminAnomalyFlags_Unauthenticated — no email in context → error.
// -----------------------------------------------------------------------------

func TestAdminAnomalyFlags_Unauthenticated(t *testing.T) {
	t.Parallel()
	mgr := newAdminTestManager(t)
	seedUsers(t, mgr)
	_ = wireAuditForAdminTest(t, mgr)

	result := callAdminTool(t, mgr, "admin_list_anomaly_flags", "", nil)
	assert.True(t, result.IsError, "unauthenticated caller must be blocked")
}

// -----------------------------------------------------------------------------
// TestAdminAnomalyFlags_EmptyWindow — admin, audit store has no anomaly rows
// → well-formed empty response (not an error).
// -----------------------------------------------------------------------------

func TestAdminAnomalyFlags_EmptyWindow(t *testing.T) {
	t.Parallel()
	mgr := newAdminTestManager(t)
	seedUsers(t, mgr)
	s := wireAuditForAdminTest(t, mgr)

	// Non-anomaly block in the window — must be filtered out.
	seedBlockedNonAnomaly(t, s, "trader@example.com", "cap-1")

	result := callAdminTool(t, mgr, "admin_list_anomaly_flags", "admin@example.com", nil)
	require.False(t, result.IsError, "admin with empty window should get a clean response")

	raw := resultText(t, result)
	require.NotEmpty(t, raw)

	var payload adminAnomalyFlagsResponse
	require.NoError(t, json.Unmarshal([]byte(raw), &payload))

	assert.Equal(t, 24, payload.WindowHours, "default window is 24h")
	assert.Equal(t, 0, payload.TotalFlags)
	assert.Empty(t, payload.ByUser, "no anomaly rows ⇒ no users in aggregate")
}

// -----------------------------------------------------------------------------
// TestAdminAnomalyFlags_AdminWithFlags — aggregates by user, surfaces event
// details (reason, order value, blocked flag) in the structured payload.
// -----------------------------------------------------------------------------

func TestAdminAnomalyFlags_AdminWithFlags(t *testing.T) {
	t.Parallel()
	mgr := newAdminTestManager(t)
	seedUsers(t, mgr)
	s := wireAuditForAdminTest(t, mgr)

	// Two users, total three anomaly flags, plus one unrelated block.
	seedBlockedAnomaly(t, s, "trader@example.com", "anom-1", 148000, 1*time.Hour)
	seedBlockedAnomaly(t, s, "trader@example.com", "anom-2", 210000, 2*time.Hour)
	seedBlockedAnomaly(t, s, "alice@example.com", "anom-3", 99000, 30*time.Minute)
	seedBlockedNonAnomaly(t, s, "bob@example.com", "cap-1") // must NOT appear

	result := callAdminTool(t, mgr, "admin_list_anomaly_flags", "admin@example.com", map[string]any{
		"hours": 48, // widen the window so the 2h-old row is included
	})
	require.False(t, result.IsError, "admin should succeed. content=%+v", result.Content)

	raw := resultText(t, result)
	require.NotEmpty(t, raw)

	var payload adminAnomalyFlagsResponse
	require.NoError(t, json.Unmarshal([]byte(raw), &payload))

	assert.Equal(t, 48, payload.WindowHours)
	assert.Equal(t, 3, payload.TotalFlags, "3 anomaly events (non-anomaly block excluded)")
	require.Len(t, payload.ByUser, 2, "two distinct flagged users")

	// Locate trader@example.com — should have 2 events.
	var trader, alice *adminAnomalyUserAgg
	for i := range payload.ByUser {
		switch payload.ByUser[i].Email {
		case "trader@example.com":
			trader = &payload.ByUser[i]
		case "alice@example.com":
			alice = &payload.ByUser[i]
		}
	}
	require.NotNil(t, trader, "trader must be in aggregated output")
	require.NotNil(t, alice, "alice must be in aggregated output")
	assert.Equal(t, 2, trader.FlagCount)
	assert.Equal(t, 1, alice.FlagCount)
	require.Len(t, trader.Events, 2)
	require.Len(t, alice.Events, 1)

	// Each event should carry the anomaly_high reason + blocked=true + non-zero
	// order value. Order-value surfacing is best-effort: the middleware stores
	// the order params as JSON and we parse quantity*price back out.
	for _, ev := range trader.Events {
		assert.Equal(t, "anomaly_high", ev.Reason)
		assert.True(t, ev.Blocked, "anomaly events are hard-blocks today")
		assert.Greater(t, ev.OrderValue, 0.0, "order value must be extracted from params")
	}
	assert.Equal(t, "anomaly_high", alice.Events[0].Reason)
	assert.InDelta(t, 99000.0, alice.Events[0].OrderValue, 0.01)
}

// -----------------------------------------------------------------------------
// TestAdminAnomalyFlags_HoursArgDefaultsTo24 — missing hours arg → 24;
// invalid (negative / zero) also falls back to 24. Ensures the tool never
// queries with a non-positive window.
// -----------------------------------------------------------------------------

func TestAdminAnomalyFlags_HoursArgDefaultsTo24(t *testing.T) {
	t.Parallel()
	mgr := newAdminTestManager(t)
	seedUsers(t, mgr)
	_ = wireAuditForAdminTest(t, mgr)

	tests := []struct {
		name string
		args map[string]any
	}{
		{"missing_hours", map[string]any{}},
		{"zero_hours", map[string]any{"hours": 0}},
		{"negative_hours", map[string]any{"hours": -5}},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			result := callAdminTool(t, mgr, "admin_list_anomaly_flags", "admin@example.com", tc.args)
			require.False(t, result.IsError)
			raw := resultText(t, result)
			require.NotEmpty(t, raw)
			var payload adminAnomalyFlagsResponse
			require.NoError(t, json.Unmarshal([]byte(raw), &payload))
			assert.Equal(t, 24, payload.WindowHours, "hours must default to 24")
		})
	}
}

// -----------------------------------------------------------------------------
// TestAdminAnomalyFlags_NoAuditStore — admin but audit store not wired →
// clear error, no panic.
// -----------------------------------------------------------------------------

func TestAdminAnomalyFlags_NoAuditStore(t *testing.T) {
	t.Parallel()
	mgr := newAdminTestManager(t)
	seedUsers(t, mgr)
	// Intentionally do NOT call wireAuditForAdminTest.

	result := callAdminTool(t, mgr, "admin_list_anomaly_flags", "admin@example.com", nil)
	assert.True(t, result.IsError, "missing audit store must surface a clean error, not panic")
}
