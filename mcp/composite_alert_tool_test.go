package mcp

import (
	"encoding/json"
	"strings"
	"testing"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
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

// TestParseCompositeCondition_HappyPath covers the canonical above/below
// and drop_pct/rise_pct cases. Kept table-driven to match this package's
// existing pattern (see tools_validation_test.go).
func TestParseCompositeCondition_HappyPath(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]interface{}
		wantExch string
		wantOp   string
		wantVal  float64
		wantRef  float64
	}{
		{
			name: "above",
			input: map[string]interface{}{
				"exchange":      "nse",
				"tradingsymbol": "RELIANCE",
				"operator":      "above",
				"value":         2500.0,
			},
			wantExch: "NSE",
			wantOp:   "above",
			wantVal:  2500.0,
		},
		{
			name: "below",
			input: map[string]interface{}{
				"exchange":      "NSE",
				"tradingsymbol": "TCS",
				"operator":      "BELOW", // mixed case should be normalized
				"value":         3200.0,
			},
			wantExch: "NSE",
			wantOp:   "below",
			wantVal:  3200.0,
		},
		{
			name: "drop_pct with reference",
			input: map[string]interface{}{
				"exchange":        "NSE",
				"tradingsymbol":   "NIFTY 50",
				"operator":        "drop_pct",
				"value":           0.5,
				"reference_price": 22000.0,
			},
			wantExch: "NSE",
			wantOp:   "drop_pct",
			wantVal:  0.5,
			wantRef:  22000.0,
		},
		{
			name: "rise_pct with reference",
			input: map[string]interface{}{
				"exchange":        "NSE",
				"tradingsymbol":   "INDIA VIX",
				"operator":        "rise_pct",
				"value":           15.0,
				"reference_price": 13.5,
			},
			wantExch: "NSE",
			wantOp:   "rise_pct",
			wantVal:  15.0,
			wantRef:  13.5,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseCompositeCondition(0, tc.input)
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if got.Exchange != tc.wantExch {
				t.Errorf("Exchange = %q, want %q", got.Exchange, tc.wantExch)
			}
			if got.Operator != tc.wantOp {
				t.Errorf("Operator = %q, want %q", got.Operator, tc.wantOp)
			}
			if got.Value != tc.wantVal {
				t.Errorf("Value = %v, want %v", got.Value, tc.wantVal)
			}
			if got.ReferencePrice != tc.wantRef {
				t.Errorf("ReferencePrice = %v, want %v", got.ReferencePrice, tc.wantRef)
			}
		})
	}
}

// TestParseCompositeCondition_Validation covers every explicit rejection
// path so a caller always sees the right error pointing at the right
// leg index.
func TestParseCompositeCondition_Validation(t *testing.T) {
	tests := []struct {
		name       string
		input      interface{}
		wantErrSub string
	}{
		{
			name:       "not an object",
			input:      "just a string",
			wantErrSub: "expected an object",
		},
		{
			name: "missing exchange",
			input: map[string]interface{}{
				"tradingsymbol": "RELIANCE",
				"operator":      "above",
				"value":         2500.0,
			},
			wantErrSub: "exchange is required",
		},
		{
			name: "unsupported exchange",
			input: map[string]interface{}{
				"exchange":      "NASDAQ",
				"tradingsymbol": "AAPL",
				"operator":      "above",
				"value":         100.0,
			},
			wantErrSub: "not supported",
		},
		{
			name: "missing tradingsymbol",
			input: map[string]interface{}{
				"exchange": "NSE",
				"operator": "above",
				"value":    2500.0,
			},
			wantErrSub: "tradingsymbol is required",
		},
		{
			name: "unknown operator",
			input: map[string]interface{}{
				"exchange":      "NSE",
				"tradingsymbol": "TCS",
				"operator":      "equals",
				"value":         100.0,
			},
			wantErrSub: "must be one of",
		},
		{
			name: "non-positive value",
			input: map[string]interface{}{
				"exchange":      "NSE",
				"tradingsymbol": "TCS",
				"operator":      "above",
				"value":         0.0,
			},
			wantErrSub: "value must be > 0",
		},
		{
			name: "drop_pct without reference",
			input: map[string]interface{}{
				"exchange":      "NSE",
				"tradingsymbol": "NIFTY 50",
				"operator":      "drop_pct",
				"value":         0.5,
			},
			wantErrSub: "reference_price is required",
		},
		{
			name: "rise_pct exceeds 100",
			input: map[string]interface{}{
				"exchange":        "NSE",
				"tradingsymbol":   "INDIA VIX",
				"operator":        "rise_pct",
				"value":           150.0,
				"reference_price": 13.5,
			},
			wantErrSub: "cannot exceed 100",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseCompositeCondition(3, tc.input)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Errorf("error = %q, expected to contain %q", err.Error(), tc.wantErrSub)
			}
			// Every validation error must echo the leg index so the
			// caller can pinpoint the bad entry.
			if !strings.Contains(err.Error(), "conditions[3]") {
				t.Errorf("error = %q, expected to contain leg index 'conditions[3]'", err.Error())
			}
		})
	}
}

// TestValidCompositeExchange pins the supported exchange list so
// regressions in validation don't accidentally accept (or reject) an
// exchange silently.
func TestValidCompositeExchange(t *testing.T) {
	valid := []string{"NSE", "NFO", "BSE", "BFO", "MCX", "CDS", "BCD"}
	for _, e := range valid {
		if !validCompositeExchange(e) {
			t.Errorf("expected %q to be valid", e)
		}
	}

	invalid := []string{"", "nse", "NASDAQ", "NYSE", "UNKNOWN"}
	for _, e := range invalid {
		if validCompositeExchange(e) {
			t.Errorf("expected %q to be invalid", e)
		}
	}
}

// TestCompositeAlertTool_EndToEnd_AND drives the full tool → CQRS →
// use case → store chain and checks that the response carries a real
// alert ID and the alert is visible in the store.
func TestCompositeAlertTool_EndToEnd_AND(t *testing.T) {
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
	var resp compositeAlertResponse
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

	var resp compositeAlertResponse
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
