package audit

import (
	"strings"
	"testing"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
)

func TestSummarizeInput_PlaceOrder(t *testing.T) {
	args := map[string]any{
		"transaction_type": "BUY",
		"quantity":         10,
		"tradingsymbol":    "RELIANCE",
		"exchange":         "NSE",
		"order_type":       "MARKET",
		"product":          "CNC",
	}
	result := SummarizeInput("place_order", args)
	assert.Equal(t, "BUY 10 RELIANCE NSE MARKET CNC", result)
}

func TestSummarizeInput_ModifyOrder(t *testing.T) {
	args := map[string]any{
		"transaction_type": "SELL",
		"quantity":         5,
		"tradingsymbol":    "INFY",
		"exchange":         "NSE",
		"order_type":       "LIMIT",
		"product":          "MIS",
	}
	result := SummarizeInput("modify_order", args)
	assert.Equal(t, "SELL 5 INFY NSE LIMIT MIS", result)
}

func TestSummarizeInput_CancelOrder(t *testing.T) {
	args := map[string]any{
		"variety":  "regular",
		"order_id": "220101000012345",
	}
	result := SummarizeInput("cancel_order", args)
	assert.Equal(t, "Cancel regular 220101000012345", result)
}

func TestSummarizeInput_CancelOrderDefaultVariety(t *testing.T) {
	args := map[string]any{
		"order_id": "220101000012345",
	}
	result := SummarizeInput("cancel_order", args)
	assert.Equal(t, "Cancel regular 220101000012345", result)
}

func TestSummarizeInput_PlaceGTTOrder(t *testing.T) {
	args := map[string]any{
		"transaction_type": "BUY",
		"tradingsymbol":    "RELIANCE",
		"quantity":         10,
		"trigger_price":    2800,
	}
	result := SummarizeInput("place_gtt_order", args)
	assert.Equal(t, "GTT BUY RELIANCE 10 @ 2800", result)
}

func TestSummarizeInput_DeleteGTTOrder(t *testing.T) {
	args := map[string]any{
		"trigger_id": "123456",
	}
	result := SummarizeInput("delete_gtt_order", args)
	assert.Equal(t, "Delete GTT 123456", result)
}

func TestSummarizeInput_GetLTP(t *testing.T) {
	args := map[string]any{
		"instruments": "NSE:RELIANCE,NSE:INFY",
	}
	result := SummarizeInput("get_ltp", args)
	assert.Equal(t, "NSE:RELIANCE,NSE:INFY", result)
}

func TestSummarizeInput_GetOHLC(t *testing.T) {
	args := map[string]any{
		"instruments": "NSE:RELIANCE",
	}
	result := SummarizeInput("get_ohlc", args)
	assert.Equal(t, "NSE:RELIANCE", result)
}

func TestSummarizeInput_GetQuotes(t *testing.T) {
	args := map[string]any{
		"instruments": "NSE:RELIANCE",
	}
	result := SummarizeInput("get_quotes", args)
	assert.Equal(t, "NSE:RELIANCE", result)
}

func TestSummarizeInput_SetAlert(t *testing.T) {
	args := map[string]any{
		"instrument_id": "NSE:RELIANCE",
		"direction":     "above",
		"target_price":  2800,
	}
	result := SummarizeInput("set_alert", args)
	assert.Equal(t, "RELIANCE above 2800", result)
}

func TestSummarizeInput_SetAlertNoExchange(t *testing.T) {
	args := map[string]any{
		"instrument_id": "RELIANCE",
		"direction":     "below",
		"target_price":  2500,
	}
	result := SummarizeInput("set_alert", args)
	assert.Equal(t, "RELIANCE below 2500", result)
}

func TestSummarizeInput_DeleteAlert(t *testing.T) {
	args := map[string]any{
		"alert_id": "abc123",
	}
	result := SummarizeInput("delete_alert", args)
	assert.Equal(t, "Delete alert abc123", result)
}

func TestSummarizeInput_SearchInstruments(t *testing.T) {
	args := map[string]any{
		"query": "RELIANCE",
	}
	result := SummarizeInput("search_instruments", args)
	assert.Equal(t, `search "RELIANCE"`, result)
}

func TestSummarizeInput_GetHistoricalData(t *testing.T) {
	args := map[string]any{
		"instrument_id": "NSE:RELIANCE",
		"interval":      "5minute",
		"from":          "2026-03-01",
		"to":            "2026-03-26",
	}
	result := SummarizeInput("get_historical_data", args)
	assert.Equal(t, "NSE:RELIANCE 5minute 2026-03-01\u21922026-03-26", result)
}

func TestSummarizeInput_StartTicker(t *testing.T) {
	args := map[string]any{
		"email": "user@example.com",
	}
	result := SummarizeInput("start_ticker", args)
	assert.Equal(t, "user@example.com", result)
}

func TestSummarizeInput_StopTicker(t *testing.T) {
	args := map[string]any{
		"email": "user@example.com",
	}
	result := SummarizeInput("stop_ticker", args)
	assert.Equal(t, "user@example.com", result)
}

func TestSummarizeInput_SubscribeInstruments(t *testing.T) {
	args := map[string]any{
		"instruments": "NSE:RELIANCE,NSE:INFY",
	}
	result := SummarizeInput("subscribe_instruments", args)
	assert.Equal(t, "NSE:RELIANCE,NSE:INFY", result)
}

func TestSummarizeInput_SetupTelegram(t *testing.T) {
	args := map[string]any{
		"chat_id": "12345",
	}
	result := SummarizeInput("setup_telegram", args)
	assert.Equal(t, "chat_id=12345", result)
}

func TestSummarizeInput_GetOrderHistory(t *testing.T) {
	args := map[string]any{
		"order_id": "220101000012345",
	}
	result := SummarizeInput("get_order_history", args)
	assert.Equal(t, "order 220101000012345", result)
}

func TestSummarizeInput_GetOrderTrades(t *testing.T) {
	args := map[string]any{
		"order_id": "220101000012345",
	}
	result := SummarizeInput("get_order_trades", args)
	assert.Equal(t, "order 220101000012345", result)
}

func TestSummarizeInput_NoParams(t *testing.T) {
	result := SummarizeInput("any_tool", nil)
	assert.Equal(t, "(no params)", result)

	result = SummarizeInput("any_tool", map[string]any{})
	assert.Equal(t, "(no params)", result)
}

func TestSummarizeInput_DefaultTool(t *testing.T) {
	args := map[string]any{
		"alpha": "one",
		"beta":  "two",
	}
	result := SummarizeInput("unknown_tool", args)
	assert.Equal(t, "2 params: alpha, beta", result)
}

func TestSummarizeInput_DefaultToolManyParams(t *testing.T) {
	args := map[string]any{
		"alpha":   "one",
		"beta":    "two",
		"gamma":   "three",
		"delta":   "four",
		"epsilon": "five",
	}
	result := SummarizeInput("unknown_tool", args)
	// Should list first 3 sorted keys with "..."
	assert.Contains(t, result, "5 params:")
	assert.True(t, strings.HasSuffix(result, "..."))
}

func TestSummarizeOutput_Success(t *testing.T) {
	result := gomcp.NewToolResultText(`{"status":"ok","data":[1,2,3]}`)
	summary := SummarizeOutput("any_tool", result)
	assert.Equal(t, `{"status":"ok","data":[1,2,3]}`, summary)
}

func TestSummarizeOutput_Error(t *testing.T) {
	result := gomcp.NewToolResultError("something went wrong")
	summary := SummarizeOutput("any_tool", result)
	assert.Equal(t, "ERROR: something went wrong", summary)
}

func TestSummarizeOutput_ErrorTruncated(t *testing.T) {
	longMsg := strings.Repeat("x", 300)
	result := gomcp.NewToolResultError(longMsg)
	summary := SummarizeOutput("any_tool", result)
	assert.True(t, strings.HasPrefix(summary, "ERROR: "))
	assert.LessOrEqual(t, len(summary), 200)
	assert.True(t, strings.HasSuffix(summary, "..."))
}

func TestSummarizeOutput_Nil(t *testing.T) {
	summary := SummarizeOutput("any_tool", nil)
	assert.Equal(t, "(no result)", summary)
}

func TestSummarizeOutput_EmptyContent(t *testing.T) {
	result := &gomcp.CallToolResult{
		Content: []gomcp.Content{},
	}
	summary := SummarizeOutput("any_tool", result)
	assert.Equal(t, "(empty response)", summary)
}

func TestSummarizeOutput_SuccessTruncated(t *testing.T) {
	longText := strings.Repeat("a", 300)
	result := gomcp.NewToolResultText(longText)
	summary := SummarizeOutput("any_tool", result)
	assert.LessOrEqual(t, len(summary), 200)
	assert.True(t, strings.HasSuffix(summary, "..."))
}

// --- Per-tool output summarizer tests ---

func TestSummarizeOutput_Holdings(t *testing.T) {
	holdingsJSON := `{"data":[
		{"tradingsymbol":"RELIANCE","average_price":2500,"quantity":10,"last_price":2600},
		{"tradingsymbol":"INFY","average_price":1500,"quantity":20,"last_price":1400}
	],"pagination":{"total":2}}`
	result := gomcp.NewToolResultText(holdingsJSON)
	summary := SummarizeOutput("get_holdings", result)
	assert.Contains(t, summary, "2 holdings")
	assert.Contains(t, summary, "invested")
	assert.Contains(t, summary, "current")
}

func TestSummarizeOutput_HoldingsEmpty(t *testing.T) {
	result := gomcp.NewToolResultText(`{"data":[],"pagination":{"total":0}}`)
	summary := SummarizeOutput("get_holdings", result)
	assert.Equal(t, "No holdings", summary)
}

func TestSummarizeOutput_HoldingsInvalidJSON(t *testing.T) {
	result := gomcp.NewToolResultText("not json at all")
	summary := SummarizeOutput("get_holdings", result)
	assert.Equal(t, "not json at all", summary)
}

func TestSummarizeOutput_Positions(t *testing.T) {
	posJSON := `{"data":[
		{"tradingsymbol":"RELIANCE","pnl":1250.50},
		{"tradingsymbol":"INFY","pnl":-500}
	]}`
	result := gomcp.NewToolResultText(posJSON)
	summary := SummarizeOutput("get_positions", result)
	assert.Contains(t, summary, "2 positions")
	assert.Contains(t, summary, "P&L")
}

func TestSummarizeOutput_PositionsEmpty(t *testing.T) {
	result := gomcp.NewToolResultText(`{"data":[]}`)
	summary := SummarizeOutput("get_positions", result)
	assert.Equal(t, "No positions", summary)
}

func TestSummarizeOutput_Orders(t *testing.T) {
	ordersJSON := `{"data":[
		{"order_id":"1","status":"COMPLETE"},
		{"order_id":"2","status":"COMPLETE"},
		{"order_id":"3","status":"OPEN"},
		{"order_id":"4","status":"CANCELLED"}
	]}`
	result := gomcp.NewToolResultText(ordersJSON)
	summary := SummarizeOutput("get_orders", result)
	assert.Contains(t, summary, "4 orders")
	assert.Contains(t, summary, "2 complete")
	assert.Contains(t, summary, "1 open")
	assert.Contains(t, summary, "1 cancelled")
}

func TestSummarizeOutput_Profile(t *testing.T) {
	profileJSON := `{"data":{"user_id":"CQP281","user_name":"Sundeep","email":"sundeepg8@gmail.com","pan":"ABCDE1234F"}}`
	result := gomcp.NewToolResultText(profileJSON)
	summary := SummarizeOutput("get_profile", result)
	// PII must be redacted — only a fixed string
	assert.Equal(t, "Profile retrieved", summary)
	assert.NotContains(t, summary, "sundeepg8")
	assert.NotContains(t, summary, "Sundeep")
	assert.NotContains(t, summary, "ABCDE")
}

func TestSummarizeOutput_PlaceOrderResult(t *testing.T) {
	result := gomcp.NewToolResultText(`{"data":{"order_id":"220101000012345"}}`)
	summary := SummarizeOutput("place_order", result)
	assert.Equal(t, "Order ID: 220101000012345", summary)
}

func TestSummarizeOutput_PlaceOrderResultTopLevel(t *testing.T) {
	result := gomcp.NewToolResultText(`{"order_id":"99999"}`)
	summary := SummarizeOutput("place_order", result)
	assert.Equal(t, "Order ID: 99999", summary)
}

func TestSummarizeOutput_LTP(t *testing.T) {
	ltpJSON := `{"data":{"NSE:RELIANCE":{"last_price":2600},"NSE:INFY":{"last_price":1400}}}`
	result := gomcp.NewToolResultText(ltpJSON)
	summary := SummarizeOutput("get_ltp", result)
	assert.Contains(t, summary, "2 instruments")
	assert.Contains(t, summary, "RELIANCE")
	assert.Contains(t, summary, "INFY")
}

func TestSummarizeOutput_Margins(t *testing.T) {
	marginsJSON := `{"data":{"equity":{"available":125000},"commodity":{"available":50000}}}`
	result := gomcp.NewToolResultText(marginsJSON)
	summary := SummarizeOutput("get_margins", result)
	assert.Contains(t, summary, "Available")
	assert.Contains(t, summary, "equity")
}

func TestSummarizeOutput_Search(t *testing.T) {
	searchJSON := `{"data":[{"instrument_token":1},{"instrument_token":2},{"instrument_token":3}]}`
	result := gomcp.NewToolResultText(searchJSON)
	summary := SummarizeOutput("search_instruments", result)
	assert.Equal(t, "Found 3 instruments", summary)
}

func TestFormatRupee(t *testing.T) {
	assert.Equal(t, "\u20b9500", formatRupee(500))
	assert.Equal(t, "\u20b925K", formatRupee(25000))
	assert.Equal(t, "\u20b91.2L", formatRupee(120000))
	assert.Equal(t, "\u20b95.5L", formatRupee(550000))
	assert.Equal(t, "\u20b91.0Cr", formatRupee(10000000))
	assert.Equal(t, "-\u20b91.2L", formatRupee(-120000))
}

func TestExtractDataArray(t *testing.T) {
	// Paginated format
	arr := extractDataArray(`{"data":[1,2,3],"pagination":{"total":3}}`)
	assert.Len(t, arr, 3)

	// Raw array
	arr = extractDataArray(`[1,2,3]`)
	assert.Len(t, arr, 3)

	// Invalid JSON
	arr = extractDataArray("not json")
	assert.Nil(t, arr)

	// Object without data key
	arr = extractDataArray(`{"status":"ok"}`)
	assert.Nil(t, arr)
}

func TestJSONFloat(t *testing.T) {
	m := map[string]any{
		"f":   3.14,
		"i":   float64(42),
		"nil": nil,
		"str": "hello",
	}
	assert.InDelta(t, 3.14, jsonFloat(m, "f"), 0.001)
	assert.InDelta(t, 42.0, jsonFloat(m, "i"), 0.001)
	assert.InDelta(t, 0.0, jsonFloat(m, "nil"), 0.001)
	assert.InDelta(t, 0.0, jsonFloat(m, "str"), 0.001)
	assert.InDelta(t, 0.0, jsonFloat(m, "missing"), 0.001)
}

func TestJSONString(t *testing.T) {
	m := map[string]any{
		"str": "hello",
		"num": 42,
		"nil": nil,
	}
	assert.Equal(t, "hello", jsonString(m, "str"))
	assert.Equal(t, "42", jsonString(m, "num"))
	assert.Equal(t, "", jsonString(m, "nil"))
	assert.Equal(t, "", jsonString(m, "missing"))
}

func TestExtractText_NilResult(t *testing.T) {
	text := extractText(nil)
	assert.Equal(t, "", text)
}

func TestExtractText_NoTextContent(t *testing.T) {
	result := &gomcp.CallToolResult{
		Content: []gomcp.Content{
			gomcp.ImageContent{
				Type:     "image",
				Data:     "base64data",
				MIMEType: "image/png",
			},
		},
	}
	text := extractText(result)
	assert.Equal(t, "", text)
}

func TestTruncate(t *testing.T) {
	assert.Equal(t, "hello", truncate("hello", 10))
	assert.Equal(t, "hello", truncate("hello", 5))
	assert.Equal(t, "he...", truncate("hello world", 5))
	assert.Equal(t, "hel", truncate("hello", 3))
}

func TestNonEmpty(t *testing.T) {
	assert.Equal(t, []string{"a", "b"}, nonEmpty([]string{"a", "", "b", ""}))
	assert.Equal(t, []string{}, nonEmpty([]string{"", ""}))
}

func TestStrVal(t *testing.T) {
	args := map[string]any{
		"str":    "hello",
		"num":    42,
		"float":  3.14,
		"nil":    nil,
		"bool":   true,
	}
	assert.Equal(t, "hello", strVal(args, "str"))
	assert.Equal(t, "42", strVal(args, "num"))
	assert.Equal(t, "3.14", strVal(args, "float"))
	assert.Equal(t, "", strVal(args, "nil"))
	assert.Equal(t, "", strVal(args, "missing"))
	assert.Equal(t, "true", strVal(args, "bool"))
}

// ===========================================================================
// Log-injection sanitation — user-controlled fields must not break row format
// ===========================================================================

func TestSanitizeForLog(t *testing.T) {
	assert.Equal(t, `foo\nbar`, sanitizeForLog("foo\nbar"))
	assert.Equal(t, `foo\rbar`, sanitizeForLog("foo\rbar"))
	assert.Equal(t, `foo\tbar`, sanitizeForLog("foo\tbar"))
	assert.Equal(t, `a\r\nb`, sanitizeForLog("a\r\nb"))
	assert.Equal(t, "clean", sanitizeForLog("clean"))
	assert.Equal(t, "", sanitizeForLog(""))

	// None of the escape outputs contains a raw control character.
	out := sanitizeForLog("foo\nFAKE LOG: admin_change_role")
	assert.NotContains(t, out, "\n")
	assert.NotContains(t, out, "\r")
	assert.NotContains(t, out, "\t")
}

func TestStrVal_SanitizesNewlines(t *testing.T) {
	// Attacker-controlled watchlist name: attempt to inject a fake row.
	args := map[string]any{
		"name": "foo\nFAKE LOG: admin_change_role target=victim@test.com",
	}
	out := strVal(args, "name")
	assert.NotContains(t, out, "\n", "raw newline must be escaped")
	assert.Contains(t, out, `\n`, "newline replaced with literal \\n")
	assert.Contains(t, out, "FAKE LOG")
}

func TestSummarizeInput_CreateWatchlist_InjectionAttempt(t *testing.T) {
	// End-to-end: injected newline in watchlist name must not appear raw
	// in the rendered summary — otherwise an attacker could forge rows in
	// the activity audit widget.
	args := map[string]any{
		"name": "holdings\nFAKE ROW: place_order SELL 1000 RELIANCE",
	}
	result := SummarizeInput("create_watchlist", args)
	assert.NotContains(t, result, "\n", "summary must not contain raw newline")
	assert.Contains(t, result, `\n`)
}

func TestSummarizeInput_AddToWatchlist_InjectionAttempt(t *testing.T) {
	// instruments and watchlist are both user-controlled string fields.
	args := map[string]any{
		"watchlist":  "main\nFAKE",
		"instruments": "NSE:INFY\nFAKE",
	}
	result := SummarizeInput("add_to_watchlist", args)
	assert.NotContains(t, result, "\n")
}

func TestJSONString_SanitizesNewlines(t *testing.T) {
	m := map[string]any{"status": "open\nINJECTED"}
	out := jsonString(m, "status")
	assert.NotContains(t, out, "\n")
	assert.Contains(t, out, `\n`)
}
