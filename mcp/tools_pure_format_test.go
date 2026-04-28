package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/ticker"
)

// Pure function tests: backtest, indicators, options pricing, sector mapping, portfolio analysis, prompts.

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------


func TestNormalizeSymbol(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "RELIANCE", normalizeSymbol("RELIANCE"))
	assert.Equal(t, "RELIANCE", normalizeSymbol("reliance"))
	assert.Equal(t, "RELIANCE", normalizeSymbol(" RELIANCE "))
	assert.Equal(t, "RELIANCE", normalizeSymbol("RELIANCE-BE"))
	assert.Equal(t, "RELIANCE", normalizeSymbol("RELIANCE-EQ"))
	assert.Equal(t, "RELIANCE", normalizeSymbol("RELIANCE-BZ"))
	assert.Equal(t, "RELIANCE", normalizeSymbol("RELIANCE-BL"))
	assert.Equal(t, "INFY", normalizeSymbol("INFY-EQ"))
}


func TestFormatPct(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "50%", formatPct(50.0))
	assert.Equal(t, "100%", formatPct(100.0))
	assert.Equal(t, "0%", formatPct(0.0))
	assert.Equal(t, "33.3%", formatPct(33.3))
	assert.Equal(t, "12.5%", formatPct(12.5))
}


func TestFormatINR(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "Rs 500", formatINR(500))
	assert.Equal(t, "Rs 99999", formatINR(99999))
	assert.Equal(t, "Rs 1,00,000", formatINR(100000))
	assert.Equal(t, "Rs 5,00,000", formatINR(500000))
	assert.Equal(t, "Rs 10,00,000", formatINR(1000000))
	assert.Equal(t, "Rs 1.50 L", formatINR(150000))
	assert.Equal(t, "Rs 2.75 L", formatINR(275000))
	assert.Equal(t, "Rs 0", formatINR(0))
}


func TestFormatRHS_Constant(t *testing.T) {
	t.Parallel()
	params := broker.NativeAlertParams{
		RHSType:     "constant",
		RHSConstant: 1500.50,
	}
	assert.Equal(t, "1500.50", formatNativeAlertRHS(params))
}


func TestFormatRHS_Instrument(t *testing.T) {
	t.Parallel()
	params := broker.NativeAlertParams{
		RHSType:          "instrument",
		RHSExchange:      "NSE",
		RHSTradingSymbol: "INFY",
		RHSAttribute:     "last_price",
	}
	assert.Equal(t, "NSE:INFY (last_price)", formatNativeAlertRHS(params))
}


func TestSplitAndTrim(t *testing.T) {
	t.Parallel()
	assert.Equal(t, []string{"a", "b", "c"}, splitAndTrim("a, b, c"))
	assert.Equal(t, []string{"NSE:INFY"}, splitAndTrim("NSE:INFY"))
	assert.Equal(t, []string{"a", "b"}, splitAndTrim("  a  ,  b  "))
	// Empty string splits to one empty part, which gets trimmed to empty
	result := splitAndTrim("")
	assert.Empty(t, result)
	result2 := splitAndTrim(", , ,")
	assert.Empty(t, result2)
}


func TestParseInstrumentList(t *testing.T) {
	t.Parallel()
	assert.Equal(t, []string{"NSE:INFY", "NSE:RELIANCE"}, parseInstrumentList("NSE:INFY, NSE:RELIANCE"))
	assert.Equal(t, []string{"NSE:INFY"}, parseInstrumentList("NSE:INFY"))
	result := parseInstrumentList("")
	assert.Empty(t, result)
	assert.Equal(t, []string{"a", "b"}, parseInstrumentList("  a  ,  b  "))
	result2 := parseInstrumentList(", , ,")
	assert.Empty(t, result2)
}


func TestResolveTickerMode(t *testing.T) {
	t.Parallel()
	assert.Equal(t, ticker.ModeLTP, resolveTickerMode("ltp"))
	assert.Equal(t, ticker.ModeQuote, resolveTickerMode("quote"))
	assert.Equal(t, ticker.ModeFull, resolveTickerMode("full"))
	assert.Equal(t, ticker.ModeFull, resolveTickerMode("unknown"))
	assert.Equal(t, ticker.ModeFull, resolveTickerMode(""))
}


func TestResolveInstrumentTokens_AllInvalid(t *testing.T) {
	mgr := newTestManager(t)
	// Test data instruments don't have ID field set, so GetByID won't find them
	tokens, failed := resolveInstrumentTokens(mgr.InstrumentsManager(), []string{"NSE:NONEXISTENT"})
	assert.Empty(t, tokens)
	assert.Len(t, failed, 1)
	assert.Equal(t, "NSE:NONEXISTENT", failed[0])
}


func TestResolveInstrumentTokens_Empty(t *testing.T) {
	mgr := newTestManager(t)
	tokens, failed := resolveInstrumentTokens(mgr.InstrumentsManager(), []string{})
	assert.Empty(t, tokens)
	assert.Empty(t, failed)
}


func TestResolveInstrumentTokens_MultipleFailed(t *testing.T) {
	mgr := newTestManager(t)
	tokens, failed := resolveInstrumentTokens(mgr.InstrumentsManager(), []string{"NSE:AAA", "NSE:BBB", "NSE:CCC"})
	assert.Empty(t, tokens)
	assert.Len(t, failed, 3)
}


func TestFormatINR_LargeNumber(t *testing.T) {
	result := formatINR(10000000) // 1 crore
	assert.Contains(t, result, "Rs")
}


func TestFormatPct_NegativeValue(t *testing.T) {
	result := formatPct(-5.5)
	assert.Equal(t, "-5.5%", result)
}


func TestNormalizeSymbol_NoSuffix(t *testing.T) {
	assert.Equal(t, "TCS", normalizeSymbol("TCS"))
}


func TestParseInstrumentList_SingleItem(t *testing.T) {
	result := parseInstrumentList("NSE:INFY")
	assert.Equal(t, []string{"NSE:INFY"}, result)
}


func TestParseInstrumentList_TrailingComma(t *testing.T) {
	result := parseInstrumentList("NSE:INFY,")
	assert.Equal(t, []string{"NSE:INFY"}, result)
}


func TestParseInstrumentList_V2(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input    string
		expected int
	}{
		{"NSE:INFY", 1},
		{"NSE:INFY,NSE:TCS", 2},
		{"NSE:INFY, NSE:TCS, NSE:RELIANCE", 3},
		{"", 0},
		{" , , ", 0},
	}
	for _, tc := range tests {
		result := parseInstrumentList(tc.input)
		assert.Equal(t, tc.expected, len(result), "parseInstrumentList(%q)", tc.input)
	}
}


func TestResolveTickerMode_V2(t *testing.T) {
	t.Parallel()
	assert.NotNil(t, resolveTickerMode("ltp"))
	assert.NotNil(t, resolveTickerMode("quote"))
	assert.NotNil(t, resolveTickerMode("full"))
	assert.NotNil(t, resolveTickerMode("unknown"))
}


func TestResolveInstrumentTokens_AllFailed(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	tokens, failed := resolveInstrumentTokens(mgr.InstrumentsManager(), []string{"NSE:UNKNOWN1", "NSE:UNKNOWN2"})
	assert.Empty(t, tokens)
	assert.Len(t, failed, 2)
}
