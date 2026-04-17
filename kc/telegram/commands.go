package telegram

import (
	"fmt"
	"html"
	"math"
	"sort"
	"strings"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
)

// escapeHTML escapes HTML special characters.
func escapeHTML(s string) string {
	return html.EscapeString(s)
}

// formatRupee formats a float as an INR value with sign.
func formatRupee(v float64) string {
	sign := "+"
	if v < 0 {
		sign = "-"
		v = math.Abs(v)
	}
	if v >= 10000 {
		return fmt.Sprintf("%s\u20B9%.0f", sign, v)
	}
	return fmt.Sprintf("%s\u20B9%.2f", sign, v)
}

// formatPctChange formats a percentage change with arrow.
func formatPctChange(pct float64) string {
	if pct >= 0 {
		return fmt.Sprintf("+%.2f%%", pct)
	}
	return fmt.Sprintf("%.2f%%", pct)
}

// handleHelp returns the help text listing all available commands.
func (h *BotHandler) handleHelp(_ int64) string {
	return `<b>Kite Trading Bot</b>

<b>Market Data:</b>
/price SYMBOL — Check stock price
/prices SYM1,SYM2 — Check multiple prices
/portfolio — Holdings summary
/positions — Open positions
/orders — Today's orders
/pnl — Today's P&amp;L
/mywatchlist — View MCP watchlist with LTP

<b>Trading:</b>
/buy SYMBOL QTY [PRICE] — Buy (market or limit)
/sell SYMBOL QTY [PRICE] — Sell (market or limit)
/quick SYM QTY SIDE TYPE [PRICE] — Quick order

<b>Alerts:</b>
/alerts — Active price alerts
/setalert SYM DIRECTION PRICE — Set alert

<b>System:</b>
/status — Token and system status
/disclaimer — Classification statement &amp; ToS excerpt
/help — This message

<i>Trading orders require confirmation before execution.</i>`
}

// handleDisclaimer returns the full classification statement /
// Terms-of-Service §3 excerpt. The text lives in disclaimer.go as
// DisclaimerFullText so automated compliance checks can grep the
// wording in one place.
func (h *BotHandler) handleDisclaimer(_ int64) string {
	return DisclaimerFullText
}

// handlePrice looks up a stock price via the Kite API.
func (h *BotHandler) handlePrice(_ int64, email string, args string) string {
	if args == "" {
		return "Usage: /price RELIANCE\nOr: /price NSE:RELIANCE"
	}

	client, errMsg := h.newKiteClient(email)
	if client == nil {
		return errMsg
	}

	symbol := normalizeSymbol(args)

	quotes, err := client.GetQuote(symbol)
	if err != nil {
		return fmt.Sprintf("Failed to fetch quote: %s", escapeHTML(err.Error()))
	}

	q, ok := quotes[symbol]
	if !ok {
		return fmt.Sprintf("No data found for <b>%s</b>", escapeHTML(symbol))
	}

	change := q.LastPrice - q.OHLC.Close
	changePct := 0.0
	if q.OHLC.Close > 0 {
		changePct = change / q.OHLC.Close * 100
	}

	return fmt.Sprintf(
		"<b>%s</b>\n\u20B9%.2f (%s)\nH: %.2f | L: %.2f\nO: %.2f | Prev: %.2f\nVol: %s",
		escapeHTML(symbol),
		q.LastPrice,
		formatPctChange(changePct),
		q.OHLC.High,
		q.OHLC.Low,
		q.OHLC.Open,
		q.OHLC.Close,
		formatVolume(uint64(q.Volume)), // #nosec G115 -- Volume is always non-negative from Kite API
	)
}

// handlePortfolio returns a summary of the user's holdings.
func (h *BotHandler) handlePortfolio(_ int64, email string) string {
	client, errMsg := h.newKiteClient(email)
	if client == nil {
		return errMsg
	}

	holdings, err := client.GetHoldings()
	if err != nil {
		return fmt.Sprintf("Failed to fetch holdings: %s", escapeHTML(err.Error()))
	}

	if len(holdings) == 0 {
		return "No holdings found."
	}

	var totalInvested, totalCurrent, totalDayPnL float64
	type holdingRow struct {
		Symbol   string
		Qty      int
		DayPct   float64
		DayPnL   float64
		TotalPnL float64
	}

	var rows []holdingRow
	for _, h := range holdings {
		invested := h.AveragePrice * float64(h.Quantity)
		current := h.LastPrice * float64(h.Quantity)
		totalInvested += invested
		totalCurrent += current
		totalDayPnL += h.DayChange
		rows = append(rows, holdingRow{
			Symbol:   h.Tradingsymbol,
			Qty:      h.Quantity,
			DayPct:   h.DayChangePercentage,
			DayPnL:   h.DayChange,
			TotalPnL: current - invested,
		})
	}

	totalPnL := totalCurrent - totalInvested
	totalPnLPct := 0.0
	if totalInvested > 0 {
		totalPnLPct = totalPnL / totalInvested * 100
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "<b>Portfolio (%d stocks)</b>\n", len(holdings))
	fmt.Fprintf(&sb, "Invested: \u20B9%.0f\n", totalInvested)
	fmt.Fprintf(&sb, "Current: \u20B9%.0f\n", totalCurrent)
	fmt.Fprintf(&sb, "P&amp;L: %s (%s)\n", formatRupee(totalPnL), formatPctChange(totalPnLPct))
	fmt.Fprintf(&sb, "Day P&amp;L: %s\n", formatRupee(totalDayPnL))

	// Top 5 by day change
	sort.Slice(rows, func(i, j int) bool { return rows[i].DayPct > rows[j].DayPct })
	sb.WriteString("\n<b>Top movers today:</b>\n")
	shown := 0
	for _, r := range rows {
		if shown >= 5 {
			break
		}
		if r.DayPct == 0 {
			continue
		}
		fmt.Fprintf(&sb, "  %s %s\n", escapeHTML(r.Symbol), formatPctChange(r.DayPct))
		shown++
	}

	return sb.String()
}

// handlePositions returns open positions.
func (h *BotHandler) handlePositions(_ int64, email string) string {
	client, errMsg := h.newKiteClient(email)
	if client == nil {
		return errMsg
	}

	positions, err := client.GetPositions()
	if err != nil {
		return fmt.Sprintf("Failed to fetch positions: %s", escapeHTML(err.Error()))
	}

	// Show net positions with non-zero quantity.
	var open []struct {
		Symbol  string
		Qty     int
		PnL     float64
		Product string
	}

	for _, p := range positions.Net {
		if p.Quantity != 0 {
			open = append(open, struct {
				Symbol  string
				Qty     int
				PnL     float64
				Product string
			}{
				Symbol:  p.Tradingsymbol,
				Qty:     p.Quantity,
				PnL:     p.PnL,
				Product: p.Product,
			})
		}
	}

	if len(open) == 0 {
		return "No open positions."
	}

	var sb strings.Builder
	var totalPnL float64
	fmt.Fprintf(&sb, "<b>Open Positions (%d)</b>\n\n", len(open))
	for _, p := range open {
		direction := "LONG"
		if p.Qty < 0 {
			direction = "SHORT"
		}
		totalPnL += p.PnL
		fmt.Fprintf(&sb, "  %s %s %d [%s] %s\n",
			escapeHTML(p.Symbol), direction, absInt(p.Qty),
			escapeHTML(p.Product), formatRupee(p.PnL))
	}
	fmt.Fprintf(&sb, "\n<b>Total: %s</b>", formatRupee(totalPnL))

	return sb.String()
}

// handleOrders returns today's orders.
func (h *BotHandler) handleOrders(_ int64, email string) string {
	client, errMsg := h.newKiteClient(email)
	if client == nil {
		return errMsg
	}

	orders, err := client.GetOrders()
	if err != nil {
		return fmt.Sprintf("Failed to fetch orders: %s", escapeHTML(err.Error()))
	}

	if len(orders) == 0 {
		return "No orders today."
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "<b>Orders (%d)</b>\n\n", len(orders))

	// Show most recent first (last 10).
	start := 0
	if len(orders) > 10 {
		start = len(orders) - 10
		fmt.Fprintf(&sb, "(showing last 10 of %d)\n\n", len(orders))
	}

	for i := len(orders) - 1; i >= start; i-- {
		o := orders[i]
		var statusEmoji string
		switch strings.ToUpper(o.Status) {
		case "COMPLETE":
			statusEmoji = "\u2705"
		case "REJECTED":
			statusEmoji = "\u274C"
		case "CANCELLED":
			statusEmoji = "\U0001F6AB"
		default:
			statusEmoji = "\u23F3"
		}

		txType := strings.ToUpper(o.TransactionType)
		fmt.Fprintf(&sb, "%s %s %s %d x %s @ \u20B9%.2f [%s]\n",
			statusEmoji, txType, escapeHTML(o.TradingSymbol),
			int(o.Quantity), escapeHTML(o.Product),
			o.AveragePrice, escapeHTML(o.Status))
	}

	return sb.String()
}

// handlePnL returns today's combined P&L from holdings and positions.
func (h *BotHandler) handlePnL(_ int64, email string) string {
	client, errMsg := h.newKiteClient(email)
	if client == nil {
		return errMsg
	}

	var sb strings.Builder
	sb.WriteString("<b>Today's P&amp;L</b>\n\n")

	var holdingsPnL, positionsPnL float64

	holdings, err := client.GetHoldings()
	if err != nil {
		sb.WriteString("Holdings: <i>unavailable</i>\n")
	} else {
		for _, h := range holdings {
			holdingsPnL += h.DayChange
		}
		fmt.Fprintf(&sb, "Holdings: %s (%d stocks)\n", formatRupee(holdingsPnL), len(holdings))
	}

	positions, err := client.GetPositions()
	if err != nil {
		sb.WriteString("Positions: <i>unavailable</i>\n")
	} else {
		for _, p := range positions.Day {
			positionsPnL += p.PnL
		}
		fmt.Fprintf(&sb, "Positions: %s (%d)\n", formatRupee(positionsPnL), len(positions.Day))
	}

	net := holdingsPnL + positionsPnL
	fmt.Fprintf(&sb, "\n<b>Net: %s</b>", formatRupee(net))

	return sb.String()
}

// handleAlerts lists active (non-triggered) alerts for the user.
func (h *BotHandler) handleAlerts(_ int64, email string) string {
	store := h.manager.AlertStoreConcrete()
	all := store.List(email)

	var active []*alerts.Alert
	for _, a := range all {
		if !a.Triggered {
			active = append(active, a)
		}
	}

	if len(active) == 0 {
		return "No active alerts."
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "<b>Active Alerts (%d)</b>\n\n", len(active))

	for _, a := range active {
		if alerts.IsPercentageDirection(a.Direction) {
			fmt.Fprintf(&sb, "  <code>%s</code> %s:%s %s %.2f%% (ref \u20B9%.2f)\n",
				a.ID, escapeHTML(a.Exchange), escapeHTML(a.Tradingsymbol),
				a.Direction, a.TargetPrice, a.ReferencePrice)
		} else {
			fmt.Fprintf(&sb, "  <code>%s</code> %s:%s %s \u20B9%.2f\n",
				a.ID, escapeHTML(a.Exchange), escapeHTML(a.Tradingsymbol),
				a.Direction, a.TargetPrice)
		}
	}

	return sb.String()
}

// handlePrices fetches prices for a comma-separated list of symbols.
func (h *BotHandler) handlePrices(_ int64, email string, args string) string {
	if args == "" {
		return "Usage: /prices RELIANCE,TCS,INFY"
	}

	client, errMsg := h.newKiteClient(email)
	if client == nil {
		return errMsg
	}

	parts := strings.Split(args, ",")
	if len(parts) > 10 {
		return "Maximum 10 symbols at a time."
	}

	symbols := make([]string, 0, len(parts))
	for _, p := range parts {
		s := strings.TrimSpace(p)
		if s != "" {
			symbols = append(symbols, normalizeSymbol(s))
		}
	}

	if len(symbols) == 0 {
		return "No valid symbols provided."
	}

	quotes, err := client.GetQuote(symbols...)
	if err != nil {
		return fmt.Sprintf("Failed to fetch quotes: %s", escapeHTML(err.Error()))
	}

	var sb strings.Builder
	sb.WriteString("<b>Prices</b>\n\n")

	for _, sym := range symbols {
		q, ok := quotes[sym]
		if !ok {
			fmt.Fprintf(&sb, "  %s — not found\n", escapeHTML(sym))
			continue
		}

		change := q.LastPrice - q.OHLC.Close
		changePct := 0.0
		if q.OHLC.Close > 0 {
			changePct = change / q.OHLC.Close * 100
		}

		// Short symbol: strip "NSE:" prefix for display.
		display := sym
		if _, after, ok := strings.Cut(sym, ":"); ok {
			display = after
		}

		fmt.Fprintf(&sb, "  <b>%s</b> \u20B9%.2f (%s)\n",
			escapeHTML(display), q.LastPrice, formatPctChange(changePct))
	}

	return sb.String()
}

// handleMyWatchlist shows MCP watchlist items with current LTP.
func (h *BotHandler) handleMyWatchlist(_ int64, email string) string {
	store := h.manager.WatchlistStoreConcrete()
	if store == nil {
		return "Watchlist feature not available."
	}

	watchlists := store.ListWatchlists(email)
	if len(watchlists) == 0 {
		return "No watchlists configured. Create one via the MCP <code>create_watchlist</code> tool."
	}

	client, errMsg := h.newKiteClient(email)

	var sb strings.Builder
	fmt.Fprintf(&sb, "<b>My Watchlists (%d)</b>\n", len(watchlists))

	for _, wl := range watchlists {
		items := store.GetItems(wl.ID)
		fmt.Fprintf(&sb, "\n<b>%s</b> (%d items)\n", escapeHTML(wl.Name), len(items))

		if len(items) == 0 {
			sb.WriteString("  (empty)\n")
			continue
		}

		// Build instrument IDs for batch LTP
		instrIDs := make([]string, 0, len(items))
		for _, item := range items {
			instrIDs = append(instrIDs, item.Exchange+":"+item.Tradingsymbol)
		}

		// Fetch LTP if we have a valid client
		ltpMap := make(map[string]float64)
		if client != nil {
			ltpResp, err := client.GetLTP(instrIDs...)
			if err == nil {
				for key, data := range ltpResp {
					ltpMap[key] = data.LastPrice
				}
			}
		}

		for _, item := range items {
			instrID := item.Exchange + ":" + item.Tradingsymbol
			if ltp, ok := ltpMap[instrID]; ok && ltp > 0 {
				fmt.Fprintf(&sb, "  <b>%s</b> \u20B9%.2f", escapeHTML(item.Tradingsymbol), ltp)
				if item.TargetEntry > 0 {
					fmt.Fprintf(&sb, " (entry: \u20B9%.2f)", item.TargetEntry)
				}
				if item.TargetExit > 0 {
					fmt.Fprintf(&sb, " (exit: \u20B9%.2f)", item.TargetExit)
				}
				sb.WriteString("\n")
			} else {
				fmt.Fprintf(&sb, "  %s", escapeHTML(item.Tradingsymbol))
				if client == nil {
					fmt.Fprintf(&sb, " — %s", errMsg)
				}
				sb.WriteString("\n")
			}
		}
	}

	return sb.String()
}

// handleStatus shows the user's token status and system health.
func (h *BotHandler) handleStatus(_ int64, email string) string {
	var sb strings.Builder
	sb.WriteString("<b>Status</b>\n\n")

	// Token status.
	apiKey := h.manager.GetAPIKeyForEmail(email)
	accessToken := h.manager.GetAccessTokenForEmail(email)

	if apiKey == "" {
		sb.WriteString("API Key: <b>Not configured</b> \u274C\n")
	} else {
		fmt.Fprintf(&sb, "API Key: ...%s \u2705\n", escapeHTML(apiKey[max(0, len(apiKey)-4):]))
	}

	if accessToken == "" {
		sb.WriteString("Token: <b>Not found</b> \u274C\n")
	} else if h.manager.IsTokenValid(email) {
		sb.WriteString("Token: Valid \u2705\n")
	} else {
		sb.WriteString("Token: <b>Expired</b> \u274C\n")
	}

	// Alert count.
	store := h.manager.AlertStoreConcrete()
	alertCount := store.ActiveCount(email)
	fmt.Fprintf(&sb, "Active alerts: %d\n", alertCount)

	return sb.String()
}

// --- helpers ---

// normalizeSymbol adds "NSE:" prefix if no exchange is specified.
func normalizeSymbol(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if !strings.Contains(s, ":") {
		return "NSE:" + s
	}
	return s
}

// formatVolume formats a volume number in a human-readable way.
func formatVolume(v uint64) string {
	if v >= 10_000_000 {
		return fmt.Sprintf("%.1fCr", float64(v)/10_000_000)
	}
	if v >= 100_000 {
		return fmt.Sprintf("%.1fL", float64(v)/100_000)
	}
	if v >= 1_000 {
		return fmt.Sprintf("%.1fK", float64(v)/1_000)
	}
	return fmt.Sprintf("%d", v)
}

func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
