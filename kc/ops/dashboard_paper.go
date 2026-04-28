package ops

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// servePaperPageSSR renders the paper trading dashboard page.
func (h *PaperHandler) servePaperPageSSR(w http.ResponseWriter, r *http.Request) {
	d := h.core
	if d.paperTmpl == nil {
		d.servePageFallback(w, "paper.html")
		return
	}

	email, role, tokenValid := d.userContext(r)
	data := PaperPageData{
		Email:      email,
		Role:       role,
		TokenValid: tokenValid,
		UpdatedAt:  nowTimestamp(),
	}

	engine := d.manager.PaperEngine()
	if engine != nil && email != "" {
		statusMap, err := engine.Status(email)
		if err == nil {
			enabled, _ := statusMap["enabled"].(bool)
			data.Enabled = enabled

			if enabled {
				data.Banner = paperStatusToBanner(statusMap)
				data.Stats = paperStatusToStats(statusMap)

				holdings, _ := engine.GetHoldings(email)
				positions, _ := engine.GetPositions(email)
				orders, _ := engine.GetOrders(email)
				data.Tables = paperDataToTables(holdings, positions, orders)
			} else {
				data.Banner = PaperBannerData{Enabled: false}
			}
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := d.paperTmpl.Execute(w, data); err != nil {
		d.loggerPort.Error(r.Context(), "Failed to render paper page", err)
	}
}

// servePaperFragment renders paper trading partials for htmx refresh.
func (h *PaperHandler) servePaperFragment(w http.ResponseWriter, r *http.Request) {
	d := h.core
	if d.fragmentTmpl == nil {
		http.Error(w, "templates not initialized", http.StatusInternalServerError)
		return
	}

	email, _, _ := d.userContext(r)
	engine := d.manager.PaperEngine()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if engine == nil || email == "" {
		fmt.Fprint(w, `<div class="empty-state">Paper trading is not enabled.</div>`)
		return
	}

	statusMap, err := engine.Status(email)
	if err != nil {
		fmt.Fprint(w, `<div class="empty-state">Failed to load paper trading status.</div>`)
		return
	}

	enabled, _ := statusMap["enabled"].(bool)
	banner := paperStatusToBanner(statusMap)
	if fragment, err := renderUserFragment(d.fragmentTmpl, "user_paper_banner", banner); err == nil {
		_, _ = io.WriteString(w, fragment) // #nosec G705 -- html/template auto-escapes
	}

	if enabled {
		stats := paperStatusToStats(statusMap)
		fmt.Fprint(w, `<div class="stats-grid" id="statsGrid">`)
		if html, err := renderUserFragment(d.fragmentTmpl, "user_paper_stats", stats); err == nil {
			fmt.Fprint(w, html)
		}
		fmt.Fprint(w, `</div>`)

		holdings, _ := engine.GetHoldings(email)
		positions, _ := engine.GetPositions(email)
		orders, _ := engine.GetOrders(email)
		tables := paperDataToTables(holdings, positions, orders)
		if html, err := renderUserFragment(d.fragmentTmpl, "user_paper_tables", tables); err == nil {
			fmt.Fprint(w, html)
		}
	}
}

// paperStatusToBanner converts paper status map to banner template data.
func paperStatusToBanner(status map[string]any) PaperBannerData {
	enabled, _ := status["enabled"].(bool)
	if !enabled {
		return PaperBannerData{Enabled: false}
	}
	initialCash, _ := status["initial_cash"].(float64)
	createdAt, _ := status["created_at"].(string)
	createdFmt := ""
	if createdAt != "" {
		if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
			createdFmt = fmtTimeDDMon(t)
		}
	}
	return PaperBannerData{
		Enabled:        true,
		InitialCashFmt: fmtINR(initialCash),
		CreatedFmt:     createdFmt,
	}
}

// paperStatusToStats converts paper status map to stats cards.
func paperStatusToStats(status map[string]any) PaperStatsData {
	cash, _ := status["cash"].(float64)
	totalValue, _ := status["total_value"].(float64)
	totalPnl, _ := status["total_pnl"].(float64)
	pnlPct, _ := status["pnl_pct"].(float64)

	return PaperStatsData{Cards: []UserStatCard{
		{Label: "Cash Balance", Value: fmtINR(cash)},
		{Label: "Portfolio Value", Value: fmtINR(totalValue)},
		{Label: "Total P&L", Value: fmtINR(totalPnl), Class: pnlClass(totalPnl)},
		{Label: "P&L %", Value: fmtPct(pnlPct), Class: pnlClass(pnlPct)},
	}}
}

// paperDataToTables converts paper engine data to tables template data.
func paperDataToTables(holdings, positions, orders any) PaperTablesData {
	var tables PaperTablesData

	if holdingsList, ok := holdings.([]map[string]any); ok {
		for _, h := range holdingsList {
			ts, _ := h["tradingsymbol"].(string)
			ex, _ := h["exchange"].(string)
			qty := toInt(h["quantity"])
			avg := toFloat(h["average_price"])
			last := toFloat(h["last_price"])
			pnl := toFloat(h["pnl"])
			tables.Holdings = append(tables.Holdings, PaperHoldingRow{
				Tradingsymbol: ts, Exchange: ex, Quantity: qty,
				AvgPriceFmt: fmtPrice(avg), LastPriceFmt: fmtPrice(last),
				PnLFmt: fmtINR(pnl), PnLClass: pnlClass(pnl),
			})
		}
	}

	if posList, ok := positions.([]map[string]any); ok {
		for _, p := range posList {
			ts, _ := p["tradingsymbol"].(string)
			prod, _ := p["product"].(string)
			qty := toInt(p["quantity"])
			avg := toFloat(p["average_price"])
			last := toFloat(p["last_price"])
			pnl := toFloat(p["pnl"])
			tables.Positions = append(tables.Positions, PaperPositionRow{
				Tradingsymbol: ts, Product: prod, Quantity: qty,
				AvgPriceFmt: fmtPrice(avg), LastPriceFmt: fmtPrice(last),
				PnLFmt: fmtINR(pnl), PnLClass: pnlClass(pnl),
			})
		}
	}

	if ordersList, ok := orders.([]map[string]any); ok {
		for _, o := range ordersList {
			orderID, _ := o["order_id"].(string)
			ts, _ := o["tradingsymbol"].(string)
			txnType, _ := o["transaction_type"].(string)
			orderType, _ := o["order_type"].(string)
			qty := toInt(o["quantity"])
			price := toFloat(o["price"])
			status, _ := o["status"].(string)
			placedAt, _ := o["placed_at"].(string)

			sideBadge := "badge-green"
			if txnType == "SELL" {
				sideBadge = "badge-red"
			}
			statusBadge := "badge-amber"
			switch status {
			case "COMPLETE":
				statusBadge = "badge-green"
			case "REJECTED", "CANCELLED":
				statusBadge = "badge-red"
			}

			shortID := orderID
			if len(shortID) > 8 {
				shortID = shortID[:8]
			}

			timeFmt := ""
			if t, err := time.Parse(time.RFC3339, placedAt); err == nil {
				timeFmt = fmtTimeHMS(t)
			}

			tables.Orders = append(tables.Orders, PaperOrderRow{
				OrderIDShort: shortID, Tradingsymbol: ts,
				TransactionType: txnType, SideBadge: sideBadge,
				OrderType: orderType, Quantity: qty,
				PriceFmt: fmtPrice(price), Status: status,
				StatusBadge: statusBadge, TimeFmt: timeFmt,
			})
		}
	}

	return tables
}

func toFloat(v any) float64 {
	switch val := v.(type) {
	case float64:
		return val
	case int:
		return float64(val)
	case int64:
		return float64(val)
	case string:
		f, _ := strconv.ParseFloat(val, 64)
		return f
	}
	return 0
}

func toInt(v any) int {
	switch val := v.(type) {
	case float64:
		return int(val)
	case int:
		return val
	case int64:
		return int(val)
	}
	return 0
}
