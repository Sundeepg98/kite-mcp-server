package ops

import (
	"fmt"
	"math"
	"net/http"
	"time"

	"github.com/zerodha/kite-mcp-server/kc"
)

// servePortfolioPage renders the user portfolio dashboard via server-side templates.
func (h *PortfolioHandler) servePortfolioPage(w http.ResponseWriter, r *http.Request) {
	d := h.core
	if d.portfolioTmpl == nil {
		d.servePageFallback(w, "dashboard.html")
		return
	}

	email, role, tokenValid := d.userContext(r)
	data := PortfolioPageData{
		Email:      email,
		Role:       role,
		TokenValid: tokenValid,
		UpdatedAt:  nowTimestamp(),
		Expired:    !tokenValid,
		DevMode:    d.manager.DevMode(),
	}

	statusResp := d.buildUserStatus(email)

	alertCount := 0
	if email != "" {
		allAlerts := d.manager.AlertStore().List(email)
		for _, a := range allAlerts {
			if !a.Triggered {
				alertCount++
			}
		}
	}

	var portfolio portfolioResponse
	if tokenValid && email != "" {
		credEntry, hasCreds := d.manager.CredentialStore().Get(email)
		tokenEntry, hasToken := d.manager.TokenStore().Get(email)
		if hasCreds && hasToken {
			client := d.manager.KiteClientFactory().NewClientWithToken(credEntry.APIKey, tokenEntry.AccessToken)

			holdings, holdingsErr := client.GetHoldings()
			positions, positionsErr := client.GetPositions()

			if holdingsErr == nil && positionsErr == nil {
				portfolio = buildPortfolioResponse(holdings, positions)
			} else {
				if holdingsErr != nil {
					d.loggerPort.Error(r.Context(), "Failed to fetch holdings for SSR", holdingsErr, "email", email)
				}
				if positionsErr != nil {
					d.loggerPort.Error(r.Context(), "Failed to fetch positions for SSR", positionsErr, "email", email)
				}
			}
		}
	}

	data.Stats = portfolioToStatsData(statusResp, portfolio, alertCount)
	data.Holdings = portfolioToHoldingsData(portfolio.Holdings)
	data.Positions = portfolioToPositionsData(portfolio.Positions)

	if tokenValid && email != "" {
		data.Market = h.fetchMarketBar(email)
	}
	if len(data.Market.Indices) == 0 {
		data.Market = MarketBarData{
			Indices: []MarketIndex{
				{Label: "NIFTY 50", PriceFmt: "--", ChangeFmt: "--"},
				{Label: "BANK NIFTY", PriceFmt: "--", ChangeFmt: "--"},
				{Label: "SENSEX", PriceFmt: "--", ChangeFmt: "--"},
			},
		}
	}

	credEntry, hasCreds := d.manager.CredentialStore().Get(email)
	if hasCreds {
		data.Credentials = credentialStatus{Stored: true, APIKey: credEntry.APIKey}
	}
	data.HasKiteCredentials = hasCreds

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := d.portfolioTmpl.Execute(w, data); err != nil {
		d.loggerPort.Error(r.Context(), "Failed to render portfolio page", err)
	}
}

// fetchMarketBar pulls NIFTY / BANK NIFTY / SENSEX OHLC and maps it to the
// market bar template data. Returns an empty value on error.
func (h *PortfolioHandler) fetchMarketBar(email string) MarketBarData {
	d := h.core
	credEntry, hasCreds := d.manager.CredentialStore().Get(email)
	tokenEntry, hasToken := d.manager.TokenStore().Get(email)
	if !hasCreds || !hasToken {
		return MarketBarData{}
	}
	client := d.manager.KiteClientFactory().NewClientWithToken(credEntry.APIKey, tokenEntry.AccessToken)
	ohlcData, err := client.GetOHLC("NSE:NIFTY 50", "NSE:NIFTY BANK", "BSE:SENSEX")
	if err != nil {
		return MarketBarData{}
	}
	indices := make(map[string]any, len(ohlcData))
	for k, v := range ohlcData {
		change := v.LastPrice - v.OHLC.Close
		changePct := 0.0
		if v.OHLC.Close > 0 {
			changePct = (change / v.OHLC.Close) * 100
		}
		indices[k] = map[string]any{
			"last_price": v.LastPrice,
			"change":     math.Round(change*100) / 100,
			"change_pct": math.Round(changePct*100) / 100,
		}
	}
	return marketIndicesToBarData(indices)
}

// buildUserStatus builds a statusResponse for the given email (used in SSR).
func (d *DashboardHandler) buildUserStatus(email string) statusResponse {
	resp := statusResponse{Email: email}
	if d.adminCheck != nil && d.adminCheck(email) {
		resp.Role = "admin"
		resp.IsAdmin = true
	} else {
		resp.Role = "trader"
	}

	tokenEntry, hasToken := d.manager.TokenStore().Get(email)
	if hasToken {
		expired := kc.IsKiteTokenExpired(tokenEntry.StoredAt)
		resp.KiteToken = tokenStatus{
			Valid:    !expired,
			StoredAt: tokenEntry.StoredAt.Format(time.RFC3339),
		}
	}

	credEntry, hasCreds := d.manager.CredentialStore().Get(email)
	if hasCreds {
		resp.Credentials = credentialStatus{Stored: true, APIKey: credEntry.APIKey}
	}

	tickerSt, err := d.manager.TickerService().GetStatus(email)
	if err == nil {
		resp.Ticker = tickerStatus{Running: tickerSt.Running, Subscriptions: len(tickerSt.Subscriptions)}
	}

	return resp
}

// servePortfolioFragment renders just the portfolio stats + holdings + positions for htmx refresh.
func (h *PortfolioHandler) servePortfolioFragment(w http.ResponseWriter, r *http.Request) {
	d := h.core
	if d.fragmentTmpl == nil {
		http.Error(w, "templates not initialized", http.StatusInternalServerError)
		return
	}

	email, _, tokenValid := d.userContext(r)
	statusResp := d.buildUserStatus(email)

	alertCount := 0
	if email != "" {
		for _, a := range d.manager.AlertStore().List(email) {
			if !a.Triggered {
				alertCount++
			}
		}
	}

	var portfolio portfolioResponse
	if tokenValid && email != "" {
		credEntry, hasCreds := d.manager.CredentialStore().Get(email)
		tokenEntry, hasToken := d.manager.TokenStore().Get(email)
		if hasCreds && hasToken {
			client := d.manager.KiteClientFactory().NewClientWithToken(credEntry.APIKey, tokenEntry.AccessToken)
			holdings, herr := client.GetHoldings()
			positions, perr := client.GetPositions()
			if herr == nil && perr == nil {
				portfolio = buildPortfolioResponse(holdings, positions)
			}
		}
	}

	stats := portfolioToStatsData(statusResp, portfolio, alertCount)
	holdingsData := portfolioToHoldingsData(portfolio.Holdings)
	positionsData := portfolioToPositionsData(portfolio.Positions)

	var market MarketBarData
	if tokenValid && email != "" {
		market = h.fetchMarketBar(email)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, "<!-- portfolio fragment -->")

	if html, err := renderUserFragment(d.fragmentTmpl, "user_market_bar", market); err == nil {
		fmt.Fprint(w, html)
	}

	fmt.Fprint(w, `<div class="stats-grid" id="statusCards">`)
	if html, err := renderUserFragment(d.fragmentTmpl, "user_portfolio_stats", stats); err == nil {
		fmt.Fprint(w, html)
	}
	fmt.Fprint(w, `</div>`)

	fmt.Fprint(w, `<div class="section-header">Holdings</div>`)
	if html, err := renderUserFragment(d.fragmentTmpl, "user_portfolio_holdings", holdingsData); err == nil {
		fmt.Fprint(w, html)
	}

	fmt.Fprint(w, `<div class="section-header">Positions</div>`)
	if html, err := renderUserFragment(d.fragmentTmpl, "user_portfolio_positions", positionsData); err == nil {
		fmt.Fprint(w, html)
	}
}
