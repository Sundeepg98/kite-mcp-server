package ops

import (
	"encoding/json"
	"math"
	"net/http"
	"time"

	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/audit"
)

// serveOrdersPageSSR renders the user orders page.
func (d *DashboardHandler) serveOrdersPageSSR(w http.ResponseWriter, r *http.Request) {
	if d.ordersTmpl == nil {
		d.servePageFallback(w, "orders.html")
		return
	}

	email, role, tokenValid := d.userContext(r)
	data := OrdersPageData{
		Email:      email,
		Role:       role,
		TokenValid: tokenValid,
		UpdatedAt:  nowTimestamp(),
	}

	if d.auditStore != nil && email != "" {
		since := time.Now().Truncate(24 * time.Hour)
		toolCalls, _ := d.auditStore.ListOrders(email, since)
		entries := d.buildOrderEntries(toolCalls, email)
		summary := d.buildOrderSummary(entries)

		data.Stats = ordersToStatsData(summary)
		data.Orders = ordersToTableData(entries)
	} else {
		data.Stats = ordersToStatsData(ordersSummary{})
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := d.ordersTmpl.Execute(w, data); err != nil {
		d.logger.Error("Failed to render orders page", "error", err)
	}
}

// buildOrderEntries constructs order entries from audit tool calls, optionally enriching with Kite API.
func (d *DashboardHandler) buildOrderEntries(toolCalls []*audit.ToolCall, email string) []orderEntry {
	entries := make([]orderEntry, 0, len(toolCalls))
	for _, tc := range toolCalls {
		if tc == nil {
			continue
		}
		oe := orderEntry{
			OrderID:  tc.OrderID,
			PlacedAt: tc.StartedAt.Format(time.RFC3339),
		}
		parseOrderParamsJSON(tc.InputParams, &oe)
		entries = append(entries, oe)
	}

	credEntry, hasCreds := d.manager.CredentialStore().Get(email)
	tokenEntry, hasToken := d.manager.TokenStore().Get(email)
	if hasCreds && hasToken && !kc.IsKiteTokenExpired(tokenEntry.StoredAt) {
		client := d.manager.KiteClientFactory().NewClientWithToken(credEntry.APIKey, tokenEntry.AccessToken)
		d.enrichOrdersWithKite(client, entries)
	}

	return entries
}

// enrichOrdersWithKite enriches order entries with fill details and current prices from Kite API.
func (d *DashboardHandler) enrichOrdersWithKite(client *kiteconnect.Client, entries []orderEntry) {
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

	if len(ltpKeys) == 0 {
		return
	}
	instruments := make([]string, 0, len(ltpKeys))
	for k := range ltpKeys {
		instruments = append(instruments, k)
	}
	ltpMap, ltpErr := client.GetLTP(instruments...)
	if ltpErr != nil {
		return
	}
	for i := range entries {
		oe := &entries[i]
		if oe.FillPrice == nil || oe.Exchange == "" || oe.Symbol == "" {
			continue
		}
		key := oe.Exchange + ":" + oe.Symbol
		quote, ok := ltpMap[key]
		if !ok || quote.LastPrice <= 0 {
			continue
		}
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

// buildOrderSummary computes order summary from entries.
func (d *DashboardHandler) buildOrderSummary(entries []orderEntry) ordersSummary {
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
	return summary
}

// parseOrderParamsJSON parses order input params from JSON into an orderEntry.
func parseOrderParamsJSON(raw string, oe *orderEntry) {
	if raw == "" {
		return
	}
	var params map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &params); err != nil {
		return
	}
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
