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
