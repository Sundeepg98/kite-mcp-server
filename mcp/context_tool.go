package mcp

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	"github.com/zerodha/kite-mcp-server/kc/scheduler"
	"github.com/zerodha/kite-mcp-server/kc/usecases"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// --- Trading Context Tool ---

// TradingContextTool returns a unified snapshot of the user's current trading state.
type TradingContextTool struct{}

func (*TradingContextTool) Tool() mcp.Tool {
	return mcp.NewTool("trading_context",
		mcp.WithDescription("Get a unified trading context snapshot — positions, margins, active alerts, pending orders, and portfolio summary in one call. Use this to understand the user's current trading state before making decisions. More efficient than calling multiple tools separately."),
		mcp.WithTitleAnnotation("Trading Context"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(false),
		mcp.WithOpenWorldHintAnnotation(true),
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

func (*TradingContextTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "trading_context")

		return handler.WithSession(ctx, "trading_context", func(_ *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			email := oauth.EmailFromContext(ctx)

			// Route data gathering through CQRS query bus.
			raw, err := handler.QueryBus().DispatchWithResult(ctx, cqrs.TradingContextQuery{Email: email})
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			ucResult, terr := BusResult[*usecases.TradingContextResult](raw)
			if terr != nil {
				handler.Logger().Error("trading_context bus result type mismatch", "error", terr)
				return mcp.NewToolResultError(terr.Error()), nil
			}

			tradingCtx := buildTradingContext(ucResult, manager, email)
			return handler.MarshalResponse(tradingCtx, "trading_context")
		})
	}
}

// buildTradingContext processes the raw API responses into a structured TradingContext.
// Consumes the typed *usecases.TradingContextResult directly so broker types flow
// end-to-end without map[string]any reboxing at the tool layer.
//
// Phase 3a Batch 6: alertProvider is the narrow port surface this function
// actually needs (single AlertStore() accessor). *kc.Manager satisfies
// kc.AlertStoreProvider, so existing callers compile unchanged — narrowing
// is signature-only, no semantic change.
func buildTradingContext(data *usecases.TradingContextResult, alertProvider kc.AlertStoreProvider, email string) *TradingContext {
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

	if data == nil {
		return tc
	}

	// Copy API errors
	if len(data.Errors) > 0 {
		tc.Errors = data.Errors
	}

	// Process margins (broker-agnostic)
	if data.Margins != nil {
		eqAvail := data.Margins.Equity.Available
		eqUsed := data.Margins.Equity.Used
		tc.MarginAvailable = roundTo2(eqAvail)
		tc.MarginUsed = roundTo2(eqUsed)

		total := data.Margins.Equity.Total
		if total > 0 {
			tc.MarginUtilization = roundTo2(eqUsed / total * 100)
		}

		if tc.MarginUtilization > 80 {
			tc.Warnings = append(tc.Warnings,
				fmt.Sprintf("High margin utilization (%.0f%%) — consider reducing positions", tc.MarginUtilization))
		}
	}

	// Process positions
	if data.Positions != nil {
		var totalPnL float64
		var misCount, nrmlCount, openCount int
		var details []positionDetail

		for _, p := range data.Positions.Net {
			pos := domain.NewPositionFromBroker(p)
			if pos.IsOpen() {
				openCount++
				totalPnL += p.PnL

				if pos.IsIntraday() {
					misCount++
				} else if p.Product == domain.ProductNRML {
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
					// Slice 6: route the per-position PnL JSON-emit
					// through the domain.Position accessor so the
					// figure is type-tagged INR (currency-aware) at
					// the boundary; .Float64() drops back to the
					// wire-compatible float64.
					PnL:    roundTo2(pos.PnL().Float64()),
					PnLPct: roundTo2(pnlPct),
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
	if len(data.Orders) > 0 {
		var pending, executed, rejected int

		for _, o := range data.Orders {
			ord := domain.NewOrderFromBroker(o)
			switch {
			case ord.IsComplete():
				executed++
			case ord.IsRejected():
				rejected++
			case ord.IsPending():
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
	if len(data.Holdings) > 0 {
		tc.HoldingsCount = len(data.Holdings)

		var dayPnL float64
		for _, h := range data.Holdings {
			dayPnL += h.PnL
		}
		tc.HoldingsDayPnL = roundTo2(dayPnL)
	}

	// Process alerts from alert store
	if email != "" && alertProvider.AlertStore() != nil {
		alertList := alertProvider.AlertStore().List(email)
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

func init() { RegisterInternalTool(&TradingContextTool{}) }
