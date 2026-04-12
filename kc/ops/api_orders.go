package ops

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"time"

	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// --- Orders P&L types ---

type orderLifecycleStep struct {
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
	Message   string `json:"message,omitempty"`
}

type orderEntry struct {
	OrderID      string               `json:"order_id"`
	Symbol       string               `json:"symbol"`
	Exchange     string               `json:"exchange"`
	Side         string               `json:"side"`
	Quantity     float64              `json:"quantity"`
	OrderType    string               `json:"order_type"`
	PlacedAt     string               `json:"placed_at"`
	Status       string               `json:"status"`
	FillPrice    *float64             `json:"fill_price"`
	CurrentPrice *float64             `json:"current_price"`
	PnL          *float64             `json:"pnl"`
	PnLPct       *float64             `json:"pnl_pct"`
	Error        string               `json:"error,omitempty"`
	Lifecycle    []orderLifecycleStep `json:"lifecycle,omitempty"`
}

type ordersSummary struct {
	TotalOrders   int      `json:"total_orders"`
	Completed     int      `json:"completed"`
	TotalPnL      *float64 `json:"total_pnl"`
	WinningTrades int      `json:"winning_trades"`
	LosingTrades  int      `json:"losing_trades"`
}

type ordersResponse struct {
	Orders  []orderEntry  `json:"orders"`
	Summary ordersSummary `json:"summary"`
}

// --- Order Attribution types ---

type attributionStep struct {
	Time          string `json:"time"`
	ToolName      string `json:"tool_name"`
	ToolCategory  string `json:"tool_category"`
	InputSummary  string `json:"input_summary"`
	OutputSummary string `json:"output_summary"`
	DurationMs    int64  `json:"duration_ms"`
	IsError       bool   `json:"is_error"`
	IsOrder       bool   `json:"is_order"`
}

type attributionResponse struct {
	OrderID string            `json:"order_id"`
	Steps   []attributionStep `json:"steps"`
}

// formatDuration formats a time.Duration into a human-readable string like "5d 1h 32m".
func formatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm", minutes)
	}
	secs := int(d.Seconds())
	if secs > 0 {
		return fmt.Sprintf("%ds", secs)
	}
	return "0s"
}

// ordersAPI returns order entries with P&L enrichment from the Kite API.
func (h *OrdersHandler) ordersAPI(w http.ResponseWriter, r *http.Request) {
	d := h.core
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated", "Not authenticated.")
		return
	}
	if d.auditStore == nil {
		d.writeJSONError(w, http.StatusServiceUnavailable, "not_available", "Audit trail not enabled")
		return
	}

	since := time.Now().AddDate(0, 0, -7)
	if s := r.URL.Query().Get("since"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			since = t
		}
	}

	toolCalls, err := d.auditStore.ListOrders(email, since)
	if err != nil {
		d.logger.Error("Failed to list orders", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	entries := make([]orderEntry, 0, len(toolCalls))
	for _, tc := range toolCalls {
		oe := orderEntry{
			OrderID:  tc.OrderID,
			PlacedAt: tc.StartedAt.Format(time.RFC3339),
		}

		if tc.InputParams != "" {
			var params map[string]interface{}
			if jsonErr := json.Unmarshal([]byte(tc.InputParams), &params); jsonErr == nil {
				if v, ok := params["tradingsymbol"].(string); ok {
					oe.Symbol = v
				}
				if v, ok := params["exchange"].(string); ok {
					oe.Exchange = v
				}
				if v, ok := params["transaction_type"].(string); ok {
					oe.Side = v
				}
				if v, ok := params["order_type"].(string); ok {
					oe.OrderType = v
				}
				if v, ok := params["quantity"].(float64); ok {
					oe.Quantity = v
				}
			}
		}

		entries = append(entries, oe)
	}

	var client *kiteconnect.Client
	credEntry, hasCreds := d.manager.CredentialStore().Get(email)
	tokenEntry, hasToken := d.manager.TokenStore().Get(email)
	if hasCreds && hasToken {
		client = d.manager.KiteClientFactory().NewClientWithToken(credEntry.APIKey, tokenEntry.AccessToken)
	}

	if client != nil {
		type ltpKey struct {
			exchange string
			symbol   string
		}
		ltpKeys := make(map[string]ltpKey)
		for i := range entries {
			oe := &entries[i]
			history, histErr := client.GetOrderHistory(oe.OrderID)
			if histErr != nil {
				oe.Error = "order history: " + histErr.Error()
				continue
			}

			if len(history) > 0 {
				latest := history[len(history)-1]
				oe.Status = latest.Status

				lifecycle := make([]orderLifecycleStep, 0, len(history))
				for _, h := range history {
					step := orderLifecycleStep{
						Status:    h.Status,
						Timestamp: h.OrderTimestamp.Time.Format(time.RFC3339),
						Message:   h.StatusMessage,
					}
					lifecycle = append(lifecycle, step)
				}
				oe.Lifecycle = lifecycle

				if oe.Symbol == "" {
					oe.Symbol = latest.TradingSymbol
				}
				if oe.Exchange == "" {
					oe.Exchange = latest.Exchange
				}
				if oe.Side == "" {
					oe.Side = latest.TransactionType
				}
				if oe.OrderType == "" {
					oe.OrderType = latest.OrderType
				}
				if oe.Quantity == 0 {
					oe.Quantity = latest.Quantity
				}

				if latest.Status == "COMPLETE" && latest.AveragePrice > 0 {
					fp := latest.AveragePrice
					oe.FillPrice = &fp
					if latest.FilledQuantity > 0 {
						oe.Quantity = latest.FilledQuantity
					}

					if oe.Exchange != "" && oe.Symbol != "" {
						key := oe.Exchange + ":" + oe.Symbol
						ltpKeys[key] = ltpKey{exchange: oe.Exchange, symbol: oe.Symbol}
					}
				}
			}
		}

		if len(ltpKeys) > 0 {
			instruments := make([]string, 0, len(ltpKeys))
			for k := range ltpKeys {
				instruments = append(instruments, k)
			}
			ltpMap, ltpErr := client.GetLTP(instruments...)
			if ltpErr != nil {
				d.logger.Error("Failed to get LTP for orders", "email", email, "error", ltpErr)
			} else {
				for i := range entries {
					oe := &entries[i]
					if oe.FillPrice == nil || oe.Exchange == "" || oe.Symbol == "" {
						continue
					}
					key := oe.Exchange + ":" + oe.Symbol
					if quote, ok := ltpMap[key]; ok && quote.LastPrice > 0 {
						cp := quote.LastPrice
						oe.CurrentPrice = &cp

						dir := 1.0
						if oe.Side == "SELL" {
							dir = -1.0
						}
						pnl := (cp - *oe.FillPrice) * oe.Quantity * dir
						pnl = math.Round(pnl*100) / 100
						oe.PnL = &pnl

						if *oe.FillPrice > 0 {
							pnlPct := ((cp - *oe.FillPrice) / *oe.FillPrice) * 100 * dir
							pnlPct = math.Round(pnlPct*100) / 100
							oe.PnLPct = &pnlPct
						}
					}
				}
			}
		}
	}

	summary := ordersSummary{TotalOrders: len(entries)}
	var totalPnL float64
	hasPnL := false
	for _, oe := range entries {
		if oe.Status == "COMPLETE" {
			summary.Completed++
		}
		if oe.PnL != nil {
			hasPnL = true
			totalPnL += *oe.PnL
			if *oe.PnL > 0 {
				summary.WinningTrades++
			} else if *oe.PnL < 0 {
				summary.LosingTrades++
			}
		}
	}
	if hasPnL {
		rounded := math.Round(totalPnL*100) / 100
		summary.TotalPnL = &rounded
	}

	d.writeJSON(w, ordersResponse{
		Orders:  entries,
		Summary: summary,
	})
}

// orderAttributionAPI returns the tool call sequence that led to a specific order.
// Query params: order_id (required)
func (h *OrdersHandler) orderAttributionAPI(w http.ResponseWriter, r *http.Request) {
	d := h.core
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated", "Not authenticated.")
		return
	}

	orderID := r.URL.Query().Get("order_id")
	if orderID == "" {
		d.writeJSONError(w, http.StatusBadRequest, "bad_request", "order_id parameter is required.")
		return
	}

	if d.auditStore == nil {
		d.writeJSON(w, attributionResponse{OrderID: orderID, Steps: []attributionStep{}})
		return
	}

	toolCalls, err := d.auditStore.GetOrderAttribution(email, orderID)
	if err != nil {
		d.logger.Error("Failed to get order attribution", "email", email, "order_id", orderID, "error", err)
		d.writeJSON(w, attributionResponse{OrderID: orderID, Steps: []attributionStep{}})
		return
	}

	steps := make([]attributionStep, 0, len(toolCalls))
	for _, tc := range toolCalls {
		steps = append(steps, attributionStep{
			Time:          tc.StartedAt.Format("15:04:05"),
			ToolName:      tc.ToolName,
			ToolCategory:  tc.ToolCategory,
			InputSummary:  tc.InputSummary,
			OutputSummary: tc.OutputSummary,
			DurationMs:    tc.DurationMs,
			IsError:       tc.IsError,
			IsOrder:       tc.OrderID != "",
		})
	}

	d.writeJSON(w, attributionResponse{
		OrderID: orderID,
		Steps:   steps,
	})
}
