package mcp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Anchor 1 PR 1.7: integration tests for peer_compare — moved from
// mcp/analytics/peer_compare_tool_test.go. The tool now lives in
// mcp/analytics (registered via init()); these black-box tests invoke
// it by name via callToolWithManager + newDevModeManager.

// peerCompareIntegrationResponse is a black-box duplicate of
// analytics.peerCompareResponse (which is unexported). Tests need
// this shape to assert structured output.
type peerCompareIntegrationResponse struct {
	Symbols          []string `json:"symbols"`
	MetricsRequested []string `json:"metrics_requested"`
	ComparisonTable  []struct {
		Symbol      string `json:"symbol"`
		CompanyName string `json:"company_name,omitempty"`
		Exchange    string `json:"exchange,omitempty"`
		Status      string `json:"status"`
		Metrics     map[string]struct {
			Metric     string `json:"metric"`
			Status     string `json:"status"`
			SourceHint string `json:"source_hint,omitempty"`
			Formula    string `json:"formula,omitempty"`
		} `json:"metrics"`
	} `json:"comparison_table"`
	Formulas   map[string]string `json:"formulas"`
	NextSteps  []string          `json:"next_steps"`
	Disclaimer string            `json:"disclaimer"`
}

// TestPeerCompare_TwoSymbols verifies a valid 2-symbol request returns a
// comparison_table with the expected shape and echoes both symbols.
func TestPeerCompare_TwoSymbols(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolWithManager(t, mgr, "peer_compare", "trader@example.com", map[string]any{
		"symbols": []any{"HDFCBANK", "ICICIBANK"},
	})
	assert.False(t, result.IsError, "2-symbol request should not error: %s", resultText(t, result))
	text := resultText(t, result)

	var parsed peerCompareIntegrationResponse
	err := json.Unmarshal([]byte(text), &parsed)
	assert.NoError(t, err, "response must be valid JSON: %s", text)

	assert.Equal(t, []string{"HDFCBANK", "ICICIBANK"}, parsed.Symbols)
	assert.Len(t, parsed.ComparisonTable, 2, "comparison_table must have one row per symbol")
	assert.NotEmpty(t, parsed.MetricsRequested, "metrics_requested should default to all")
	assert.NotEmpty(t, parsed.NextSteps, "next_steps should guide the LLM")
	assert.NotEmpty(t, parsed.Formulas, "formulas block should be populated")
	assert.NotEmpty(t, parsed.Disclaimer)

	// Response should point the LLM at Screener.in (our data-gap source of
	// choice for Indian fundamentals).
	lower := strings.ToLower(text)
	assert.Contains(t, lower, "screener.in", "response should point LLM at screener.in")
}

// TestPeerCompare_SixSymbols verifies the upper bound (6 symbols) is accepted.
func TestPeerCompare_SixSymbols(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolWithManager(t, mgr, "peer_compare", "trader@example.com", map[string]any{
		"symbols": []any{"HDFCBANK", "ICICIBANK", "SBIN", "AXISBANK", "KOTAKBANK", "INDUSINDBK"},
	})
	assert.False(t, result.IsError, "6-symbol request should not error: %s", resultText(t, result))

	var parsed peerCompareIntegrationResponse
	err := json.Unmarshal([]byte(resultText(t, result)), &parsed)
	assert.NoError(t, err)
	assert.Len(t, parsed.ComparisonTable, 6, "comparison_table must have 6 rows")
}

// TestPeerCompare_TooManySymbols verifies that 7+ symbols are rejected with a
// clear error message (enforces MVP cap).
func TestPeerCompare_TooManySymbols(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolWithManager(t, mgr, "peer_compare", "trader@example.com", map[string]any{
		"symbols": []any{"A", "B", "C", "D", "E", "F", "G"}, // 7 → too many
	})
	assert.True(t, result.IsError, "7 symbols should return error")
	assertResultContains(t, result, "symbols")
}

// TestPeerCompare_TooFewSymbols verifies that 1 symbol is rejected (peer
// compare requires at least 2 to make sense).
func TestPeerCompare_TooFewSymbols(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolWithManager(t, mgr, "peer_compare", "trader@example.com", map[string]any{
		"symbols": []any{"HDFCBANK"}, // 1 → too few
	})
	assert.True(t, result.IsError, "1 symbol should return error")
	assertResultContains(t, result, "symbols")
}

// TestPeerCompare_InvalidMetric verifies that an unknown metric name produces
// a clear validation error rather than silently returning empty data.
func TestPeerCompare_InvalidMetric(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolWithManager(t, mgr, "peer_compare", "trader@example.com", map[string]any{
		"symbols": []any{"HDFCBANK", "ICICIBANK"},
		"metrics": []any{"Piotroski", "GIBBERISH"},
	})
	assert.True(t, result.IsError, "invalid metric should return error")
	assertResultContains(t, result, "metric")
}
