package ops

import (
	"fmt"
	"strconv"
)

// ============================================================================
// Portfolio page
// ============================================================================

// PortfolioStatsData is the template data for user_portfolio_stats.
type PortfolioStatsData struct {
	Cards []UserStatCard
}

// HoldingRow is a single row in the holdings table template.
type HoldingRow struct {
	Tradingsymbol  string
	Exchange       string
	Quantity       int
	AvgPriceFmt    string
	LastPriceFmt   string
	PnLFmt         string
	PnLClass       string
	DayChangeFmt   string
	DayChangeClass string
}

// PortfolioHoldingsData is the template data for user_portfolio_holdings.
type PortfolioHoldingsData struct {
	Holdings []HoldingRow
}

// PositionRow is a single row in the positions table template.
type PositionRow struct {
	Tradingsymbol string
	Exchange      string
	Product       string
	Quantity      int
	AvgPriceFmt   string
	LastPriceFmt  string
	PnLFmt        string
	PnLClass      string
}

// PortfolioPositionsData is the template data for user_portfolio_positions.
type PortfolioPositionsData struct {
	Positions []PositionRow
}

// MarketIndex represents one entry in the market bar.
type MarketIndex struct {
	Label       string
	PriceFmt    string
	ChangeFmt   string
	ChangeClass string // "up" or "down"
}

// MarketBarData is the template data for user_market_bar.
type MarketBarData struct {
	Indices []MarketIndex
}

// portfolioToStatsData converts status + portfolio API data into stat cards.
func portfolioToStatsData(status statusResponse, portfolio portfolioResponse, alertCount int) PortfolioStatsData {
	tokenVal := "Expired"
	tokenCls := "red"
	if status.KiteToken.Valid {
		tokenVal = "Active"
		tokenCls = "green"
	}

	tickerVal := "Off"
	tickerCls := ""
	if status.Ticker.Running {
		tickerVal = fmt.Sprintf("%d feeds", status.Ticker.Subscriptions)
		tickerCls = "green"
	}

	todayPnl := portfolio.Summary.TotalPnL + portfolio.Summary.PositionsPnL
	pnlSub := ""
	if portfolio.Summary.TotalCurrent > 0 {
		pnlPct := (todayPnl / portfolio.Summary.TotalCurrent) * 100
		pnlSub = fmtPct(pnlPct)
	}

	return PortfolioStatsData{
		Cards: []UserStatCard{
			{Label: "Kite Token", Value: tokenVal, Class: tokenCls},
			{Label: "Holdings", Value: strconv.Itoa(portfolio.Summary.HoldingsCount)},
			{Label: "Today's P&L", Value: fmtINR(todayPnl), Class: pnlClass(todayPnl), Sub: pnlSub, Hero: true},
			{Label: "Active Alerts", Value: strconv.Itoa(alertCount)},
			{Label: "Ticker", Value: tickerVal, Class: tickerCls},
		},
	}
}

// portfolioToHoldingsData converts API holdings into template rows.
func portfolioToHoldingsData(holdings []holdingItem) PortfolioHoldingsData {
	rows := make([]HoldingRow, 0, len(holdings))
	for _, h := range holdings {
		rows = append(rows, HoldingRow{
			Tradingsymbol:  h.Tradingsymbol,
			Exchange:       h.Exchange,
			Quantity:       h.Quantity,
			AvgPriceFmt:    fmtPrice(h.AveragePrice),
			LastPriceFmt:   fmtPrice(h.LastPrice),
			PnLFmt:         fmtINR(h.PnL),
			PnLClass:       pnlClass(h.PnL),
			DayChangeFmt:   fmtPct(h.DayChangePercent),
			DayChangeClass: pnlClass(h.DayChangePercent),
		})
	}
	return PortfolioHoldingsData{Holdings: rows}
}

// portfolioToPositionsData converts API positions into template rows.
func portfolioToPositionsData(positions []positionItem) PortfolioPositionsData {
	rows := make([]PositionRow, 0, len(positions))
	for _, p := range positions {
		rows = append(rows, PositionRow{
			Tradingsymbol: p.Tradingsymbol,
			Exchange:      p.Exchange,
			Product:       p.Product,
			Quantity:      p.Quantity,
			AvgPriceFmt:   fmtPrice(p.AveragePrice),
			LastPriceFmt:  fmtPrice(p.LastPrice),
			PnLFmt:        fmtINR(p.PnL),
			PnLClass:      pnlClass(p.PnL),
		})
	}
	return PortfolioPositionsData{Positions: rows}
}

// marketIndicesToBarData converts the market indices API map into template data.
func marketIndicesToBarData(indices map[string]any) MarketBarData {
	order := []struct {
		key   string
		label string
	}{
		{"NSE:NIFTY 50", "NIFTY 50"},
		{"NSE:NIFTY BANK", "BANK NIFTY"},
		{"BSE:SENSEX", "SENSEX"},
	}

	items := make([]MarketIndex, 0, len(order))
	for _, o := range order {
		idx, ok := indices[o.key]
		if !ok {
			items = append(items, MarketIndex{Label: o.label, PriceFmt: "--", ChangeFmt: "--"})
			continue
		}
		m, ok := idx.(map[string]any)
		if !ok {
			items = append(items, MarketIndex{Label: o.label, PriceFmt: "--", ChangeFmt: "--"})
			continue
		}

		lastPrice, _ := m["last_price"].(float64)
		change, _ := m["change"].(float64)
		changePct, _ := m["change_pct"].(float64)

		cls := "down"
		prefix := ""
		if change >= 0 {
			cls = "up"
			prefix = "+"
		}

		items = append(items, MarketIndex{
			Label:       o.label,
			PriceFmt:    fmt.Sprintf("%.0f", lastPrice),
			ChangeFmt:   fmt.Sprintf("%s%.0f (%.2f%%)", prefix, change, changePct),
			ChangeClass: cls,
		})
	}
	return MarketBarData{Indices: items}
}
