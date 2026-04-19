package ops

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// ============================================================================
// Orders page
// ============================================================================

// OrdersStatsData is the template data for user_orders_stats.
type OrdersStatsData struct {
	Cards []UserStatCard
}

// OrderRow is a single row in the orders table template.
type OrderRow struct {
	Symbol          string
	Side            string
	SideClass       string // "side-buy" or "side-sell"
	QuantityFmt     string
	FillPriceFmt    string
	CurrentPriceFmt string
	PnLFmt          string
	PnLClass        string // "pnl-pos", "pnl-neg", "pnl-zero"
	PnLPctFmt       string
	PnLPctClass     string
	Status          string
	StatusBadge     string // CSS class for the status badge
	TimeFmt         string
}

// OrdersTableData is the template data for user_orders_table.
type OrdersTableData struct {
	Orders []OrderRow
}

func statusBadgeClass(status string) string {
	switch strings.ToUpper(status) {
	case domain.OrderStatusComplete:
		return "status-complete"
	case domain.OrderStatusCancelled:
		return "status-cancelled"
	case domain.OrderStatusRejected:
		return "status-rejected"
	case domain.OrderStatusOpen, domain.OrderStatusTriggerPending:
		return "status-open"
	default:
		return "status-pending"
	}
}

func pnlDisplayClass(v *float64) string {
	if v == nil {
		return "pnl-zero"
	}
	if *v > 0 {
		return "pnl-pos"
	}
	if *v < 0 {
		return "pnl-neg"
	}
	return "pnl-zero"
}

// ordersToStatsData converts ordersSummary into stat cards.
func ordersToStatsData(s ordersSummary) OrdersStatsData {
	pnlVal := "--"
	pnlCls := ""
	if s.TotalPnL != nil {
		pnlVal = fmtINR(*s.TotalPnL)
		pnlCls = pnlClass(*s.TotalPnL)
	}

	winRate := "--"
	winSub := ""
	total := s.WinningTrades + s.LosingTrades
	if total > 0 {
		pct := float64(s.WinningTrades) / float64(total) * 100
		winRate = fmt.Sprintf("%.0f%%", pct)
		winSub = fmt.Sprintf("%dW / %dL", s.WinningTrades, s.LosingTrades)
	}

	return OrdersStatsData{Cards: []UserStatCard{
		{Label: "Total Orders", Value: strconv.Itoa(s.TotalOrders)},
		{Label: "Completed", Value: strconv.Itoa(s.Completed)},
		{Label: "Total P&L", Value: pnlVal, Class: pnlCls},
		{Label: "Win Rate", Value: winRate, Sub: winSub},
	}}
}

// ordersToTableData converts order entries into template rows.
func ordersToTableData(entries []orderEntry) OrdersTableData {
	rows := make([]OrderRow, 0, len(entries))
	for _, oe := range entries {
		sideCls := "side-buy"
		if oe.Side == "SELL" {
			sideCls = "side-sell"
		}

		fillFmt := "--"
		if oe.FillPrice != nil {
			fillFmt = fmtPrice(*oe.FillPrice)
		}
		currFmt := "--"
		if oe.CurrentPrice != nil {
			currFmt = fmtPrice(*oe.CurrentPrice)
		}
		pnlFmt := "--"
		if oe.PnL != nil {
			pnlFmt = fmtINR(*oe.PnL)
		}
		pnlPctFmt := "--"
		if oe.PnLPct != nil {
			pnlPctFmt = fmtPct(*oe.PnLPct)
		}

		t, _ := time.Parse(time.RFC3339, oe.PlacedAt)

		rows = append(rows, OrderRow{
			Symbol:          oe.Symbol,
			Side:            oe.Side,
			SideClass:       sideCls,
			QuantityFmt:     fmt.Sprintf("%.0f", oe.Quantity),
			FillPriceFmt:    fillFmt,
			CurrentPriceFmt: currFmt,
			PnLFmt:          pnlFmt,
			PnLClass:        pnlDisplayClass(oe.PnL),
			PnLPctFmt:       pnlPctFmt,
			PnLPctClass:     pnlDisplayClass(oe.PnLPct),
			Status:          oe.Status,
			StatusBadge:     statusBadgeClass(oe.Status),
			TimeFmt:         fmtTimeDDMon(t),
		})
	}
	return OrdersTableData{Orders: rows}
}
