package mcp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Anchor 1 PR 1.7: integration tests for get_fii_dii_flow — moved from
// mcp/analytics/fii_dii_tool_test.go. The tool now lives in mcp/analytics
// (registered via init()); these black-box tests invoke it by name via
// callToolWithManager + newDevModeManager.

// fiiDIIIntegrationResponse is a black-box duplicate of analytics.fiiDIIResponse
// (which is unexported). Tests need this shape to assert structured output.
type fiiDIIIntegrationResponse struct {
	Date       string `json:"date"`
	Segment    string `json:"segment"`
	Days       int    `json:"days"`
	DataSource string `json:"data_source"`
	URLs       struct {
		NSEDaily           string `json:"nse_daily"`
		NSEFIIDII          string `json:"nse_fii_dii"`
		MoneycontrolFIIDII string `json:"moneycontrol_fii_dii"`
	} `json:"urls"`
	Themes     []string `json:"themes_to_extract"`
	NextSteps  []string `json:"next_steps"`
	Disclaimer string   `json:"disclaimer"`
}

// TestGetFIIDIIFlow_DefaultDate verifies that omitting `date` resolves to the
// latest trading day (not an error) and returns the expected URL pointers.
func TestGetFIIDIIFlow_DefaultDate(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolWithManager(t, mgr, "get_fii_dii_flow", "trader@example.com", map[string]any{
		// date intentionally omitted — should resolve to latest trading day
	})
	assert.False(t, result.IsError, "default date should resolve: %s", resultText(t, result))
	text := resultText(t, result)
	// URL pointers must be present
	assert.Contains(t, text, "nseindia.com", "response should include NSE URL")
	assert.Contains(t, text, "moneycontrol.com", "response should include Moneycontrol URL")
	// Default date must be a valid YYYY-MM-DD string
	assert.Regexp(t, `\d{4}-\d{2}-\d{2}`, text, "default date must follow YYYY-MM-DD")
	// Default segment is cash
	assert.Contains(t, text, "cash", "default segment should be cash")
}

// TestGetFIIDIIFlow_SpecificDate verifies that a well-formed date is echoed
// back in the response (and the URLs are rendered correctly).
func TestGetFIIDIIFlow_SpecificDate(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolWithManager(t, mgr, "get_fii_dii_flow", "trader@example.com", map[string]any{
		"date":    "2026-04-15",
		"segment": "cash",
	})
	assert.False(t, result.IsError, "valid date should not error: %s", resultText(t, result))
	text := resultText(t, result)
	assert.Contains(t, text, "2026-04-15", "response should echo the specific date")
	assert.Contains(t, text, "cash", "response should echo segment")
}

// TestGetFIIDIIFlow_DaysClamping verifies `days` is clamped to the 1..30 range.
func TestGetFIIDIIFlow_DaysClamping(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)

	tests := []struct {
		name       string
		input      int
		wantInResp int
	}{
		{"below-min clamps to 1", 0, 1},
		{"negative clamps to 1", -5, 1},
		{"above-max clamps to 30", 100, 30},
		{"within range unchanged", 7, 7},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := callToolWithManager(t, mgr, "get_fii_dii_flow", "trader@example.com", map[string]any{
				"days": tc.input,
			})
			assert.False(t, result.IsError, "days input %d should not error: %s", tc.input, resultText(t, result))
			text := resultText(t, result)

			// Parse JSON payload and assert Days field exactly matches expectation.
			var parsed fiiDIIIntegrationResponse
			require := false
			if err := json.Unmarshal([]byte(text), &parsed); err == nil {
				require = true
			}
			// Sanity: response must be valid JSON with the clamped value.
			assert.True(t, require, "response should be JSON-decodable: %s", text)
			assert.Equal(t, tc.wantInResp, parsed.Days, "days should be clamped to %d", tc.wantInResp)
		})
	}
}

// TestGetFIIDIIFlow_InvalidSegment verifies unknown `segment` values are
// rejected with a helpful error.
func TestGetFIIDIIFlow_InvalidSegment(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolWithManager(t, mgr, "get_fii_dii_flow", "trader@example.com", map[string]any{
		"segment": "gibberish",
	})
	assert.True(t, result.IsError, "invalid segment should return error")
	assertResultContains(t, result, "segment")
}

// TestGetFIIDIIFlow_SegmentVariants verifies all accepted segment values
// (cash, fo, both — case-insensitive) pass.
func TestGetFIIDIIFlow_SegmentVariants(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	for _, seg := range []string{"cash", "fo", "both", "CASH", "FO", "Both"} {
		seg := seg
		t.Run(seg, func(t *testing.T) {
			t.Parallel()
			result := callToolWithManager(t, mgr, "get_fii_dii_flow", "trader@example.com", map[string]any{
				"segment": seg,
			})
			assert.False(t, result.IsError, "segment %q should be accepted: %s", seg, resultText(t, result))
			text := resultText(t, result)
			assert.Contains(t, strings.ToLower(text), strings.ToLower(seg))
		})
	}
}

// TestGetFIIDIIFlow_OutputStructure validates the JSON response shape — URLs,
// themes, next_steps, and disclaimer are all present so the LLM has actionable
// guidance.
func TestGetFIIDIIFlow_OutputStructure(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolWithManager(t, mgr, "get_fii_dii_flow", "trader@example.com", map[string]any{
		"date":    "2026-04-15",
		"days":    5,
		"segment": "both",
	})
	assert.False(t, result.IsError)
	text := resultText(t, result)

	var parsed fiiDIIIntegrationResponse
	err := json.Unmarshal([]byte(text), &parsed)
	assert.NoError(t, err, "response must be valid JSON: %s", text)

	assert.Equal(t, "2026-04-15", parsed.Date)
	assert.Equal(t, "both", parsed.Segment)
	assert.Equal(t, 5, parsed.Days)
	assert.NotEmpty(t, parsed.DataSource)
	assert.NotEmpty(t, parsed.URLs.NSEDaily)
	assert.NotEmpty(t, parsed.URLs.NSEFIIDII)
	assert.NotEmpty(t, parsed.URLs.MoneycontrolFIIDII)
	assert.NotEmpty(t, parsed.Themes, "themes_to_extract should not be empty")
	assert.NotEmpty(t, parsed.NextSteps, "next_steps should not be empty")
	assert.NotEmpty(t, parsed.Disclaimer)
	// Guidance must point the LLM at WebFetch / Tavily so it knows what to do next.
	joinedSteps := strings.ToLower(strings.Join(parsed.NextSteps, " "))
	assert.True(t,
		strings.Contains(joinedSteps, "webfetch") || strings.Contains(joinedSteps, "tavily") || strings.Contains(joinedSteps, "fetch"),
		"next_steps should mention WebFetch/Tavily/fetch")
}

// TestGetFIIDIIFlow_InvalidDateFormat verifies malformed date strings are
// rejected (so the LLM gets a clear signal rather than silently-wrong data).
func TestGetFIIDIIFlow_InvalidDateFormat(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolWithManager(t, mgr, "get_fii_dii_flow", "trader@example.com", map[string]any{
		"date": "15-04-2026", // DD-MM-YYYY (wrong — we require YYYY-MM-DD)
	})
	assert.True(t, result.IsError, "bad date format should error")
	assertResultContains(t, result, "date")
}
