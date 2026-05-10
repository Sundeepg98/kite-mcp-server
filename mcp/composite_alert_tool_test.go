package mcp

import (
	"encoding/json"
	"testing"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/algo2go/kite-mcp-alerts"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/testutil/kcfixture"
)

// compositeTestManager builds a test manager with instrument IDs set so
// GetByTradingsymbol can resolve NSE:INFY / NSE:RELIANCE / NSE:SBIN.
// The shared kcfixture.DefaultTestData omits the ID field, which leaves
// idToInst keyed by the empty string and breaks resolution — so we build
// the map ourselves with explicit exchange:tradingsymbol IDs.
func compositeTestManager(t *testing.T) *kc.Manager {
	t.Helper()
	td := map[uint32]*instruments.Instrument{
		256265: {InstrumentToken: 256265, ID: "NSE:INFY", Tradingsymbol: "INFY", Exchange: "NSE", Segment: "NSE", InstrumentType: "EQ"},
		408065: {InstrumentToken: 408065, ID: "NSE:RELIANCE", Tradingsymbol: "RELIANCE", Exchange: "NSE", Segment: "NSE", InstrumentType: "EQ"},
		779521: {InstrumentToken: 779521, ID: "NSE:SBIN", Tradingsymbol: "SBIN", Exchange: "NSE", Segment: "NSE", InstrumentType: "EQ"},
	}
	return kcfixture.NewTestManager(t, kcfixture.WithTestData(td), kcfixture.WithRiskGuard())
}

// Anchor 1 PR 1.8: TestParseCompositeCondition_HappyPath,
// TestParseCompositeCondition_Validation, TestValidCompositeExchange
// moved to mcp/alerts/composite_alert_tool_test.go because they
// reference unexported alerts-package symbols (parseCompositeCondition,
// validCompositeExchange).

// compositeCondShape is a black-box duplicate of
// alerts.compositeCondition (which is unexported). Used to decode the
// JSON payload in end-to-end tests without re-exporting the type.
type compositeCondShape struct {
	Exchange        string  `json:"exchange"`
	Tradingsymbol   string  `json:"tradingsymbol"`
	Operator        string  `json:"operator"`
	Value           float64 `json:"value"`
	ReferencePrice  float64 `json:"reference_price,omitempty"`
	InstrumentToken uint32  `json:"instrument_token"`
}

// compositeAlertResponseShape is a black-box duplicate of
// alerts.compositeAlertResponse used by the end-to-end tests below to
// decode the JSON payload. Inlined to avoid exporting the unexported
// alerts-package type.
type compositeAlertResponseShape struct {
	Status     string               `json:"status"`
	Message    string               `json:"message"`
	AlertID    string               `json:"alert_id,omitempty"`
	Name       string               `json:"name"`
	Logic      string               `json:"logic"`
	Conditions []compositeCondShape `json:"conditions"`
	Note       string               `json:"note,omitempty"`
}

// TestCompositeAlertTool_EndToEnd_AND drives the full tool → CQRS →
// use case → store chain and checks that the response carries a real
// alert ID and the alert is visible in the store.
func TestCompositeAlertTool_EndToEnd_AND(t *testing.T) {
	t.Parallel()
	mgr := compositeTestManager(t)
	email := "trader@example.com"

	result := callToolWithManager(t, mgr, "composite_alert", email, map[string]any{
		"name":  "nifty_vix_correlation",
		"logic": "AND",
		"conditions": []any{
			map[string]any{
				"exchange":      "NSE",
				"tradingsymbol": "INFY",
				"operator":      "above",
				"value":         2000.0,
			},
			map[string]any{
				"exchange":      "NSE",
				"tradingsymbol": "RELIANCE",
				"operator":      "below",
				"value":         3000.0,
			},
		},
	})
	require.NotNil(t, result)
	require.False(t, result.IsError, "expected success, got error: %s", firstText(result))

	// Parse the MarshalResponse payload so the assertions remain stable
	// against cosmetic changes (it's a JSON block in the first text block).
	var resp compositeAlertResponseShape
	raw := firstText(result)
	require.NoError(t, json.Unmarshal([]byte(raw), &resp), "tool response should be JSON: %s", raw)
	assert.Equal(t, "created", resp.Status)
	assert.NotEmpty(t, resp.AlertID, "alert ID should be populated")
	assert.Equal(t, "nifty_vix_correlation", resp.Name)
	assert.Equal(t, "AND", resp.Logic)
	require.Len(t, resp.Conditions, 2)

	// Verify it was persisted to the alert store.
	list := mgr.AlertStore().List(email)
	require.Len(t, list, 1)
	assert.Equal(t, resp.AlertID, list[0].ID)
	assert.Equal(t, alerts.AlertTypeComposite, list[0].AlertType)
	assert.Equal(t, alerts.CompositeLogicAnd, list[0].CompositeLogic)
	assert.Equal(t, "nifty_vix_correlation", list[0].CompositeName)
	require.Len(t, list[0].Conditions, 2)
}

// TestCompositeAlertTool_EndToEnd_ANY covers the ANY logic branch.
func TestCompositeAlertTool_EndToEnd_ANY(t *testing.T) {
	t.Parallel()
	mgr := compositeTestManager(t)
	email := "trader@example.com"

	result := callToolWithManager(t, mgr, "composite_alert", email, map[string]any{
		"name":  "any_breakout",
		"logic": "ANY",
		"conditions": []any{
			map[string]any{
				"exchange":      "NSE",
				"tradingsymbol": "INFY",
				"operator":      "above",
				"value":         2000.0,
			},
			map[string]any{
				"exchange":      "NSE",
				"tradingsymbol": "SBIN",
				"operator":      "above",
				"value":         800.0,
			},
		},
	})
	require.NotNil(t, result)
	require.False(t, result.IsError, "expected success, got error: %s", firstText(result))

	var resp compositeAlertResponseShape
	require.NoError(t, json.Unmarshal([]byte(firstText(result)), &resp))
	assert.Equal(t, "created", resp.Status)
	assert.Equal(t, "ANY", resp.Logic)

	list := mgr.AlertStore().List(email)
	require.Len(t, list, 1)
	assert.Equal(t, alerts.CompositeLogicAny, list[0].CompositeLogic)
}

// TestCompositeAlertTool_EndToEnd_UnknownInstrument bubbles the
// instrument-resolution failure back through the tool surface as an
// error result (not a panic, not a tool-level Go error).
func TestCompositeAlertTool_EndToEnd_UnknownInstrument(t *testing.T) {
	t.Parallel()
	mgr := compositeTestManager(t)

	result := callToolWithManager(t, mgr, "composite_alert", "trader@example.com", map[string]any{
		"name":  "bad",
		"logic": "AND",
		"conditions": []any{
			map[string]any{
				"exchange":      "NSE",
				"tradingsymbol": "NO_SUCH_SYMBOL",
				"operator":      "above",
				"value":         100.0,
			},
			map[string]any{
				"exchange":      "NSE",
				"tradingsymbol": "INFY",
				"operator":      "above",
				"value":         2000.0,
			},
		},
	})
	require.NotNil(t, result)
	assert.True(t, result.IsError, "expected error for unknown instrument")
	assert.Contains(t, firstText(result), "not found")
}

// TestCompositeAlertTool_EndToEnd_MissingEmail matches the existing
// no-auth guard (OAuth is required for every per-user tool).
func TestCompositeAlertTool_EndToEnd_MissingEmail(t *testing.T) {
	t.Parallel()
	mgr := compositeTestManager(t)

	result := callToolWithManager(t, mgr, "composite_alert", "", map[string]any{
		"name":  "no_auth",
		"logic": "AND",
		"conditions": []any{
			map[string]any{"exchange": "NSE", "tradingsymbol": "INFY", "operator": "above", "value": 1.0},
			map[string]any{"exchange": "NSE", "tradingsymbol": "SBIN", "operator": "above", "value": 1.0},
		},
	})
	require.NotNil(t, result)
	assert.True(t, result.IsError)
	assert.Contains(t, firstText(result), "Email required")
}

// TestCompositeAlertTool_CQRSCommandShape guards against accidental drift
// in the cqrs command shape that the tool handler constructs. If someone
// renames a field (e.g. Conditions -> Legs) the compile will pass but the
// dispatch will blow up at runtime — this test catches the rename early.
func TestCompositeAlertTool_CQRSCommandShape(t *testing.T) {
	t.Parallel()
	// Static shape check — if the fields rename, this fails at compile time
	// before the tests even run.
	_ = cqrs.CreateCompositeAlertCommand{
		Email: "x",
		Name:  "y",
		Logic: "AND",
		Conditions: []cqrs.CompositeConditionSpec{
			{Exchange: "NSE", Tradingsymbol: "INFY", Operator: "above", Value: 1.0},
		},
	}
}

// firstText returns the text of the first content block, or an empty
// string if there's none. Mirrors the helper pattern in mcp/helpers_test.go
// without depending on its internals.
func firstText(r *gomcp.CallToolResult) string {
	if r == nil || len(r.Content) == 0 {
		return ""
	}
	if tc, ok := r.Content[0].(gomcp.TextContent); ok {
		return tc.Text
	}
	return ""
}
