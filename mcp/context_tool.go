package mcp

import (
	"context"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/scheduler"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// --- Trading Context Tool ---

// TradingContextTool returns a unified snapshot of the user's current trading state.
type TradingContextTool struct{}

func (*TradingContextTool) Tool() mcp.Tool {
	return mcp.NewTool("trading_context",
		mcp.WithDescription("Get a unified trading context snapshot — positions, margins, active alerts, pending orders, and portfolio summary in one call. Use this to understand the user's current trading state before making decisions. More efficient than calling multiple tools separately."),
		mcp.WithReadOnlyHintAnnotation(true),
	)
}

// TradingContext is the structured response returned by the trading_context tool.
type TradingContext struct {
	// Market status
	MarketStatus string `json:"market_status"`

	// Margin status
	MarginAvailable   float64 `json:"margin_available"`
	MarginUsed        float64 `json:"margin_used"`
	MarginUtilization float64 `json:"margin_utilization_pct"`

	// Positions summary
	OpenPositions   int               `json:"open_positions"`
	PositionsPnL    float64           `json:"positions_pnl"`
	MISPositions    int               `json:"mis_positions"`
	NRMLPositions   int               `json:"nrml_positions"`
	PositionDetails []positionDetail  `json:"position_details,omitempty"`

	// Orders
	PendingOrders int `json:"pending_orders"`
	ExecutedToday int `json:"executed_today"`
	RejectedToday int `json:"rejected_today"`

	// Holdings snapshot
	HoldingsCount  int     `json:"holdings_count"`
	HoldingsDayPnL float64 `json:"holdings_day_pnl"`

	// Alerts
	ActiveAlerts int            `json:"active_alerts"`
	AlertDetails []alertSummary `json:"alert_details,omitempty"`

	// Warnings (AI should pay attention to these)
	Warnings []string `json:"warnings,omitempty"`

	// Errors from API calls that failed
	Errors map[string]string `json:"errors,omitempty"`

}

// positionDetail shows per-trade P&L for each open position.
type positionDetail struct {
	Symbol       string  `json:"symbol"`
	Exchange     string  `json:"exchange"`
	Product      string  `json:"product"`
	Quantity     int     `json:"quantity"`
	AveragePrice float64 `json:"average_price"`
	LTP          float64 `json:"ltp"`
	PnL          float64 `json:"pnl"`
	PnLPct       float64 `json:"pnl_pct"`
}

// alertSummary is a compact representation of an active alert.
type alertSummary struct {
	Symbol    string  `json:"symbol"`
	Exchange  string  `json:"exchange"`
	Direction string  `json:"direction"`
	Target    float64 `json:"target"`
}

// apiResult holds the result from a parallel API call.
type apiResult struct {
	key string
	val any
	err error
}

func (*TradingContextTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "trading_context")

		return handler.WithSession(ctx, "trading_context", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			client := session.Kite.Client

			ch := make(chan apiResult, 4)
			var wg sync.WaitGroup
			wg.Add(4)

			// Parallel API calls
			go func() {
				defer wg.Done()
				margins, err := client.GetUserMargins()
				ch <- apiResult{"margins", margins, err}
			}()
			go func() {
				defer wg.Done()
				positions, err := client.GetPositions()
				ch <- apiResult{"positions", positions, err}
			}()
			go func() {
				defer wg.Done()
				orders, err := client.GetOrders()
				ch <- apiResult{"orders", orders, err}
			}()
			go func() {
				defer wg.Done()
				holdings, err := client.GetHoldings()
				ch <- apiResult{"holdings", holdings, err}
			}()

			// Close channel once all goroutines complete
			go func() {
				wg.Wait()
				close(ch)
			}()

			// Collect results
			data := make(map[string]any)
			errs := make(map[string]string)
			for r := range ch {
				if r.err != nil {
					errs[r.key] = r.err.Error()
				} else {
					data[r.key] = r.val
				}
			}

			// Get alerts from the alert store
			email := oauth.EmailFromContext(ctx)

			tradingCtx := buildTradingContext(data, errs, manager, email)
			return handler.MarshalResponse(tradingCtx, "trading_context")
		})
	}
}

// buildTradingContext processes the raw API responses into a structured TradingContext.
func buildTradingContext(data map[string]any, apiErrors map[string]string, manager *kc.Manager, email string) *TradingContext {
	tc := &TradingContext{
		Warnings: make([]string, 0),
	}

	// Market status
	tc.MarketStatus = scheduler.MarketStatus(time.Now())
	switch tc.MarketStatus {
	case "closed":
		tc.Warnings = append(tc.Warnings, "Market is closed. Orders will queue for next trading session.")
	case "closed_weekend":
		tc.Warnings = append(tc.Warnings, "Market is closed (weekend). Orders will queue for Monday.")
	case "closed_holiday":
		tc.Warnings = append(tc.Warnings, "Market is closed (holiday). Orders will queue for next trading day.")
	case "pre_open":
		tc.Warnings = append(tc.Warnings, "Market is in pre-open session (9:00-9:15 AM IST).")
	case "closing_session":
		tc.Warnings = append(tc.Warnings, "Market is in closing session (3:30-4:00 PM IST).")
	}

	// Copy API errors
	if len(apiErrors) > 0 {
		tc.Errors = apiErrors
	}

	// Process margins
	if marginsRaw, ok := data["margins"]; ok {
		margins := marginsRaw.(kiteconnect.AllMargins)
		eqAvail := margins.Equity.Net
		eqUsed := margins.Equity.Used.Debits
		tc.MarginAvailable = roundTo2(eqAvail)
		tc.MarginUsed = roundTo2(eqUsed)

		total := eqAvail + eqUsed
		if total > 0 {
			tc.MarginUtilization = roundTo2(eqUsed / total * 100)
		}

		if tc.MarginUtilization > 80 {
			tc.Warnings = append(tc.Warnings,
				fmt.Sprintf("High margin utilization (%.0f%%) — consider reducing positions", tc.MarginUtilization))
		}
	}

	// Process positions
	if positionsRaw, ok := data["positions"]; ok {
		positions := positionsRaw.(kiteconnect.Positions)
		var totalPnL float64
		var misCount, nrmlCount, openCount int
		var details []positionDetail

		for _, p := range positions.Net {
			if p.Quantity != 0 {
				openCount++
				totalPnL += p.PnL

				switch strings.ToUpper(p.Product) {
				case "MIS":
					misCount++
				case "NRML":
					nrmlCount++
				}

				pnlPct := 0.0
				if p.AveragePrice > 0 && p.Quantity != 0 {
					pnlPct = (p.PnL / (p.AveragePrice * math.Abs(float64(p.Quantity)))) * 100
				}
				details = append(details, positionDetail{
					Symbol:       p.Tradingsymbol,
					Exchange:     p.Exchange,
					Product:      p.Product,
					Quantity:     p.Quantity,
					AveragePrice: roundTo2(p.AveragePrice),
					LTP:          roundTo2(p.LastPrice),
					PnL:          roundTo2(p.PnL),
					PnLPct:       roundTo2(pnlPct),
				})
			}
		}

		tc.OpenPositions = openCount
		tc.PositionsPnL = roundTo2(totalPnL)
		tc.MISPositions = misCount
		tc.NRMLPositions = nrmlCount
		if len(details) > 0 {
			tc.PositionDetails = details
		}

		// MIS close warning: market closes at 3:30 PM IST, auto square-off around 3:15-3:20 PM
		if misCount > 0 {
			ist, err := time.LoadLocation("Asia/Kolkata")
			if err == nil {
				now := time.Now().In(ist)
				cutoff := time.Date(now.Year(), now.Month(), now.Day(), 13, 15, 0, 0, ist) // 1:15 PM IST
				if now.After(cutoff) {
					closing := time.Date(now.Year(), now.Month(), now.Day(), 15, 30, 0, 0, ist)
					remaining := closing.Sub(now)
					if remaining > 0 {
						hours := int(remaining.Hours())
						mins := int(remaining.Minutes()) % 60
						tc.Warnings = append(tc.Warnings,
							fmt.Sprintf("%d MIS position(s) open — market closes in %dh %dm", misCount, hours, mins))
					}
				}
			}
		}
	}

	// Process orders
	if ordersRaw, ok := data["orders"]; ok {
		orders := ordersRaw.(kiteconnect.Orders)
		var pending, executed, rejected int

		for _, o := range orders {
			switch strings.ToUpper(o.Status) {
			case "COMPLETE":
				executed++
			case "REJECTED":
				rejected++
			case "OPEN", "TRIGGER PENDING", "AMO REQ RECEIVED":
				pending++
			}
		}

		tc.PendingOrders = pending
		tc.ExecutedToday = executed
		tc.RejectedToday = rejected

		if rejected > 3 {
			tc.Warnings = append(tc.Warnings,
				fmt.Sprintf("%d rejected orders today — check order parameters", rejected))
		}
	}

	// Process holdings
	if holdingsRaw, ok := data["holdings"]; ok {
		holdings := holdingsRaw.(kiteconnect.Holdings)
		tc.HoldingsCount = len(holdings)

		var dayPnL float64
		for _, h := range holdings {
			dayPnL += h.DayChange
		}
		tc.HoldingsDayPnL = roundTo2(dayPnL)
	}

	// Process alerts from alert store
	if email != "" && manager.AlertStore() != nil {
		alertList := manager.AlertStore().List(email)
		var activeCount int
		details := make([]alertSummary, 0)

		for _, a := range alertList {
			if !a.Triggered {
				activeCount++
				details = append(details, alertSummary{
					Symbol:    a.Tradingsymbol,
					Exchange:  a.Exchange,
					Direction: string(a.Direction),
					Target:    a.TargetPrice,
				})
			}
		}

		tc.ActiveAlerts = activeCount
		if len(details) > 0 {
			tc.AlertDetails = details
		}
	}

	return tc
}
