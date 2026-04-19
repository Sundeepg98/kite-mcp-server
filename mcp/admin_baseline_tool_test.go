package mcp

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/audit"
)

// seedBaselineOrders persists `n` place_order audit rows for the given email
// at the given qty*price. Used to populate a baseline for the tool-under-test.
func seedBaselineOrders(t *testing.T, s *audit.Store, email string, n int, qty, price float64) {
	t.Helper()
	now := time.Now().UTC()
	for i := 0; i < n; i++ {
		params := map[string]any{
			"exchange":         "NSE",
			"tradingsymbol":    "RELIANCE",
			"transaction_type": "BUY",
			"quantity":         qty,
			"price":            price,
			"order_type":       "LIMIT",
		}
		b, err := json.Marshal(params)
		require.NoError(t, err)
		entry := &audit.ToolCall{
			CallID:       fmt.Sprintf("baseline-%s-%d", email, i),
			Email:        email,
			SessionID:    "sess-baseline",
			ToolName:     "place_order",
			ToolCategory: "order",
			InputParams:  string(b),
			InputSummary: "BUY RELIANCE",
			StartedAt:    now.Add(-time.Duration(i) * time.Hour),
			CompletedAt:  now.Add(-time.Duration(i)*time.Hour + 50*time.Millisecond),
			DurationMs:   50,
		}
		require.NoError(t, s.Record(entry))
	}
}

// wireAuditForAdminTest opens an in-memory SQLite audit store and wires it
// onto the manager so the baseline tool can query it.
func wireAuditForAdminTest(t *testing.T, mgr *kc.Manager) *audit.Store {
	t.Helper()
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	s := audit.New(db)
	require.NoError(t, s.InitTable())
	mgr.SetAuditStore(s)
	return s
}

// -----------------------------------------------------------------------------
// TestAdminBaseline_NonAdminBlocked — trader role gets ErrAdminRequired.
// -----------------------------------------------------------------------------

func TestAdminBaseline_NonAdminBlocked(t *testing.T) {
	t.Parallel()
	mgr := newAdminTestManager(t)
	seedUsers(t, mgr)
	_ = wireAuditForAdminTest(t, mgr)

	result := callAdminTool(t, mgr, "admin_get_user_baseline", "trader@example.com", map[string]any{
		"email": "trader@example.com",
	})
	assert.True(t, result.IsError, "non-admin must be blocked from admin_get_user_baseline")
}

// -----------------------------------------------------------------------------
// TestAdminBaseline_UnauthenticatedBlocked — no email in context → error.
// -----------------------------------------------------------------------------

func TestAdminBaseline_UnauthenticatedBlocked(t *testing.T) {
	t.Parallel()
	mgr := newAdminTestManager(t)
	seedUsers(t, mgr)
	_ = wireAuditForAdminTest(t, mgr)

	result := callAdminTool(t, mgr, "admin_get_user_baseline", "", map[string]any{
		"email": "trader@example.com",
	})
	assert.True(t, result.IsError, "unauthenticated caller must be blocked")
}

// -----------------------------------------------------------------------------
// TestAdminBaseline_EmailRequired — admin without email arg → error.
// -----------------------------------------------------------------------------

func TestAdminBaseline_EmailRequired(t *testing.T) {
	t.Parallel()
	mgr := newAdminTestManager(t)
	seedUsers(t, mgr)
	_ = wireAuditForAdminTest(t, mgr)

	result := callAdminTool(t, mgr, "admin_get_user_baseline", "admin@example.com", map[string]any{})
	assert.True(t, result.IsError, "missing email arg should error")
}

// -----------------------------------------------------------------------------
// TestAdminBaseline_AdminWithHistory — baseline stats returned for a user
// with >=5 rows; is_sufficient=true; threshold = mean + 3*stdev.
// -----------------------------------------------------------------------------

func TestAdminBaseline_AdminWithHistory(t *testing.T) {
	t.Parallel()
	mgr := newAdminTestManager(t)
	seedUsers(t, mgr)
	auditStore := wireAuditForAdminTest(t, mgr)

	// 10 identical orders at Rs 5000 → mean=5000, stdev=0, count=10.
	seedBaselineOrders(t, auditStore, "trader@example.com", 10, 10, 500)

	result := callAdminTool(t, mgr, "admin_get_user_baseline", "admin@example.com", map[string]any{
		"email": "trader@example.com",
	})
	require.False(t, result.IsError, "admin should get baseline successfully. content=%+v", result.Content)

	raw := resultText(t, result)
	require.NotEmpty(t, raw, "response must carry text content")

	var payload adminUserBaselineResponse
	require.NoError(t, json.Unmarshal([]byte(raw), &payload))

	assert.Equal(t, "trader@example.com", payload.Email)
	assert.InDelta(t, 5000.0, payload.BaselineMeanINR, 0.01)
	assert.InDelta(t, 0.0, payload.BaselineStdevINR, 0.01)
	assert.Equal(t, 10, payload.BaselineCount)
	assert.Equal(t, 30, payload.BaselineDays)
	assert.True(t, payload.IsSufficient, "10 >= 5 must be sufficient")
	// Threshold = mean + 3*stdev. With stdev=0, threshold == mean.
	assert.InDelta(t, 5000.0, payload.Thresholds.AnomalyBlockAtINR, 0.01)
	assert.Equal(t, 10.0, payload.Thresholds.AnomalySoftMultiplier)
	assert.Equal(t, "02:00-06:00", payload.Thresholds.OffHoursWindowIST)
}

// -----------------------------------------------------------------------------
// TestAdminBaseline_UnknownUser — zero stats, is_sufficient=false.
// -----------------------------------------------------------------------------

func TestAdminBaseline_UnknownUser(t *testing.T) {
	t.Parallel()
	mgr := newAdminTestManager(t)
	seedUsers(t, mgr)
	_ = wireAuditForAdminTest(t, mgr)

	result := callAdminTool(t, mgr, "admin_get_user_baseline", "admin@example.com", map[string]any{
		"email": "ghost@nowhere.com",
	})
	require.False(t, result.IsError, "admin querying unknown user should not error")

	raw := resultText(t, result)
	require.NotEmpty(t, raw)

	var payload adminUserBaselineResponse
	require.NoError(t, json.Unmarshal([]byte(raw), &payload))

	assert.Equal(t, "ghost@nowhere.com", payload.Email)
	assert.Equal(t, 0.0, payload.BaselineMeanINR)
	assert.Equal(t, 0.0, payload.BaselineStdevINR)
	assert.Equal(t, 0, payload.BaselineCount)
	assert.False(t, payload.IsSufficient, "unknown user must be insufficient")
	assert.Equal(t, 0.0, payload.Thresholds.AnomalyBlockAtINR)
}
