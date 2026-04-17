package mcp

import (
	"strings"
	"testing"
)

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
