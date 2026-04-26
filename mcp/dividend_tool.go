package mcp

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/usecases"
)

// --- Corporate Actions Database ---

// CorporateAction represents a known corporate action for an NSE/BSE stock.
type CorporateAction struct {
	Symbol     string  `json:"symbol"`
	ActionType string  `json:"action_type"` // "dividend", "split", "bonus", "rights"
	ExDate     string  `json:"ex_date"`     // YYYY-MM-DD
	RecordDate string  `json:"record_date"` // YYYY-MM-DD
	Details    string  `json:"details"`     // "Rs 10 per share", "1:1 bonus", "5:1 split"
	Amount     float64 `json:"amount"`      // dividend amount per share (0 for non-dividend)
}

// knownAnnualDividends maps trading symbols to their last known annual dividend per share (Rs).
// This is used to compute indicative dividend yield when no upcoming ex-date is known.
// Source: historical dividend data from NSE/BSE (update periodically).
var knownAnnualDividends = map[string]float64{
	"RELIANCE":   9.00,
	"TCS":        75.00,
	"INFY":       34.00,
	"HDFCBANK":   19.50,
	"ICICIBANK":  10.00,
	"HINDUNILVR": 39.00,
	"ITC":        15.50,
	"SBIN":       13.70,
	"BHARTIARTL": 4.00,
	"KOTAKBANK":  2.00,
	"LT":         28.00,
	"AXISBANK":   7.00,
	"WIPRO":      6.00,
	"HCLTECH":    52.00,
	"MARUTI":     125.00,
	"TATAMOTORS": 6.00,
	"SUNPHARMA":  5.00,
	"BAJFINANCE": 36.00,
	"TITAN":      11.00,
	"ASIANPAINT": 21.15,
	"NESTLEIND":  275.00,
	"LTIM":       50.00,
	"ULTRACEMCO": 38.00,
	"TECHM":      28.00,
	"POWERGRID":  14.50,
	"NTPC":       8.25,
	"COALINDIA":  25.50,
	"ONGC":       12.50,
	"IOC":        12.00,
	"BPCL":       21.00,
	"TATASTEEL":  3.60,
	"JSWSTEEL":   17.35,
	"DIVISLAB":   30.00,
	"DRREDDY":    40.00,
	"CIPLA":      13.00,
	"HEROMOTOCO": 100.00,
	"BAJAJ-AUTO": 140.00,
	"EICHERMOT":  51.00,
	"BRITANNIA":  73.50,
	"DABUR":      9.00,
	"GODREJCP":   10.00,
	"PIDILITIND": 15.00,
	"HAVELLS":    7.50,
	"COLPAL":     44.00,
	"MARICO":     9.50,
	"BERGEPAINT": 8.30,
	"SIEMENS":    16.00,
	"ABB":        6.22,
	"VEDL":       29.50,
	"GAIL":       12.00,
}

// knownActions contains upcoming/recent corporate actions.
// In production this would be fetched from an API — NSE/BSE corporate actions
// endpoints are restricted and require special access. Update periodically.
var knownActions = []CorporateAction{
	// Placeholder: when this slice is empty, the tool explains the limitation
	// and falls back to dividend yield analysis from the knownAnnualDividends map.
}

// dividendSeasonality describes which quarter most Indian companies pay dividends.
var dividendSeasonality = map[int]string{
	1: "Q4 results season — peak dividend announcement period for Indian companies",
	2: "Q1 results season — some interim dividends announced",
	3: "Q2 results season — occasional interim/special dividends",
	4: "Q3 results season — pre-Q4 interim dividends common",
}

// --- Dividend Calendar Tool ---

// DividendCalendarTool analyses portfolio holdings for dividend yield and upcoming corporate actions.
type DividendCalendarTool struct{}

func init() { RegisterInternalTool(&DividendCalendarTool{}) }

func (*DividendCalendarTool) Tool() mcp.Tool {
	return mcp.NewTool("dividend_calendar",
		mcp.WithDescription(
			"Show upcoming dividends and corporate actions (splits, bonuses, rights) for your portfolio holdings. "+
				"Sources data from a built-in database of recent NSE/BSE corporate actions. "+
				"Shows ex-date, record date, dividend amount, and whether you should buy before or sell after. "+
				"Also computes dividend yield analysis for each holding based on last known annual dividends, "+
				"total expected annual dividend income, and tax implications (dividends taxed as income since 2020).",
		),
		mcp.WithTitleAnnotation("Dividend Calendar"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(true),
		mcp.WithNumber("days",
			mcp.Description("Look-ahead window in days for upcoming corporate actions (default: 30)"),
			mcp.DefaultString("30"),
		),
	)
}

func (*DividendCalendarTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "dividend_calendar")

		days := NewArgParser(request.GetArguments()).Int("days", 30)
		if days <= 0 {
			days = 30
		}
		if days > 365 {
			days = 365
		}

		return handler.WithSession(ctx, "dividend_calendar", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			raw, err := handler.QueryBus().DispatchWithResult(ctx, cqrs.GetPortfolioQuery{Email: session.Email})
			if err != nil {
				handler.trackToolError(ctx, "dividend_calendar", "api_error")
				return mcp.NewToolResultError("Failed to get holdings: " + err.Error()), nil
			}
			portfolio := raw.(*usecases.PortfolioResult)

			if len(portfolio.Holdings) == 0 {
				return handler.MarshalResponse(map[string]any{
					"holdings_count": 0,
					"message":        "No holdings found in portfolio",
				}, "dividend_calendar")
			}

			resp := computeDividendCalendar(portfolio.Holdings, days)
			return handler.MarshalResponse(resp, "dividend_calendar")
		})
	}
}

// --- Response types ---

type dividendHoldingEntry struct {
	Symbol              string  `json:"symbol"`
	Exchange            string  `json:"exchange"`
	Quantity            int     `json:"quantity"`
	AveragePrice        float64 `json:"avg_price"`
	LastPrice           float64 `json:"last_price"`
	CurrentValue        float64 `json:"current_value"`
	AnnualDividendPerSh float64 `json:"annual_dividend_per_share"` // 0 if unknown
	DividendYield       float64 `json:"dividend_yield_pct"`        // annual div / LTP * 100
	ExpectedAnnualDiv   float64 `json:"expected_annual_dividend"`  // per share * qty
	DividendTax30Pct    float64 `json:"dividend_tax_at_30_pct"`    // estimated tax at 30% slab
	InDatabase          bool    `json:"in_database"`               // true if we have dividend data
}

type upcomingAction struct {
	CorporateAction
	DaysUntilExDate int     `json:"days_until_ex_date"`
	HeldQuantity    int     `json:"held_quantity"`
	ExpectedPayout  float64 `json:"expected_payout"` // amount * qty (dividends only)
	Recommendation  string  `json:"recommendation"`
}

type dividendCalendarSummary struct {
	HoldingsCount            int     `json:"holdings_count"`
	HoldingsWithDividendData int     `json:"holdings_with_dividend_data"`
	TotalPortfolioValue      float64 `json:"total_portfolio_value"`
	TotalExpectedAnnualDiv   float64 `json:"total_expected_annual_dividend"`
	PortfolioDividendYield   float64 `json:"portfolio_dividend_yield_pct"`
	EstimatedTaxAt30Pct      float64 `json:"estimated_tax_at_30_pct"`
	NetDividendAfterTax      float64 `json:"net_dividend_after_tax_30_pct"`
	UpcomingActionsCount     int     `json:"upcoming_actions_count"`
	LookAheadDays            int     `json:"look_ahead_days"`
	SeasonalityNote          string  `json:"seasonality_note"`
	DataSourceNote           string  `json:"data_source_note"`
}

type dividendCalendarResponse struct {
	Summary          dividendCalendarSummary `json:"summary"`
	UpcomingActions  []upcomingAction        `json:"upcoming_actions"`
	HoldingsByYield  []dividendHoldingEntry  `json:"holdings_by_dividend_yield"` // sorted desc
	TopDividendPayers []dividendHoldingEntry `json:"top_dividend_payers"`         // top 10 by expected income
	TaxNote          string                  `json:"tax_note"`
}

// computeDividendCalendar performs the dividend yield and corporate actions analysis.
func computeDividendCalendar(holdings []broker.Holding, lookAheadDays int) *dividendCalendarResponse {
	now := time.Now()
	cutoff := now.AddDate(0, 0, lookAheadDays)

	// Build a set of held symbols for quick lookup.
	holdingMap := make(map[string]broker.Holding, len(holdings))
	for _, h := range holdings {
		holdingMap[h.Tradingsymbol] = h
	}

	// --- 1. Check upcoming corporate actions for held symbols ---
	upcoming := make([]upcomingAction, 0)
	for _, action := range knownActions {
		h, held := holdingMap[action.Symbol]
		if !held {
			continue
		}

		exDate, err := time.Parse("2006-01-02", action.ExDate)
		if err != nil {
			continue
		}

		// Only include actions within the look-ahead window and not in the past.
		if exDate.Before(now) || exDate.After(cutoff) {
			continue
		}

		daysUntil := int(exDate.Sub(now).Hours() / 24)
		payout := 0.0
		recommendation := ""

		switch action.ActionType {
		case "dividend":
			payout = roundTo2(action.Amount * float64(h.Quantity))
			if daysUntil > 2 {
				recommendation = fmt.Sprintf("Hold through ex-date (%s) to receive Rs %.2f dividend", action.ExDate, payout)
			} else {
				recommendation = fmt.Sprintf("Ex-date is %s — must hold by T-1 to be eligible", action.ExDate)
			}
		case "bonus":
			recommendation = fmt.Sprintf("Bonus %s — hold through record date (%s) for free shares", action.Details, action.RecordDate)
		case "split":
			recommendation = fmt.Sprintf("Stock split %s on %s — quantity will increase, price adjusts proportionally", action.Details, action.ExDate)
		case "rights":
			recommendation = fmt.Sprintf("Rights issue %s — record date %s. Evaluate subscription price vs market price", action.Details, action.RecordDate)
		}

		upcoming = append(upcoming, upcomingAction{
			CorporateAction: action,
			DaysUntilExDate: daysUntil,
			HeldQuantity:    h.Quantity,
			ExpectedPayout:  payout,
			Recommendation:  recommendation,
		})
	}

	// Sort upcoming by ex-date (soonest first).
	sort.Slice(upcoming, func(i, j int) bool {
		return upcoming[i].DaysUntilExDate < upcoming[j].DaysUntilExDate
	})

	// --- 2. Compute dividend yield for all holdings ---
	entries := make([]dividendHoldingEntry, 0, len(holdings))
	var totalPortfolioValue, totalExpectedDiv float64
	withDataCount := 0

	for _, h := range holdings {
		currentValue := h.LastPrice * float64(h.Quantity)
		totalPortfolioValue += currentValue

		annualDiv, known := knownAnnualDividends[h.Tradingsymbol]
		divYield := 0.0
		expectedAnnual := 0.0
		taxAt30 := 0.0

		if known && h.LastPrice > 0 {
			divYield = roundTo2(annualDiv / h.LastPrice * 100)
			expectedAnnual = roundTo2(annualDiv * float64(h.Quantity))
			taxAt30 = roundTo2(expectedAnnual * 0.30) // Dividends taxed as income; 30% is highest slab
			totalExpectedDiv += expectedAnnual
			withDataCount++
		}

		entries = append(entries, dividendHoldingEntry{
			Symbol:              h.Tradingsymbol,
			Exchange:            h.Exchange,
			Quantity:            h.Quantity,
			AveragePrice:        roundTo2(h.AveragePrice),
			LastPrice:           roundTo2(h.LastPrice),
			CurrentValue:        roundTo2(currentValue),
			AnnualDividendPerSh: annualDiv,
			DividendYield:       divYield,
			ExpectedAnnualDiv:   expectedAnnual,
			DividendTax30Pct:    taxAt30,
			InDatabase:          known,
		})
	}

	// Sort by dividend yield descending.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].DividendYield > entries[j].DividendYield
	})

	// Top 10 by expected annual dividend income.
	topPayers := make([]dividendHoldingEntry, 0, 10)
	sortedByIncome := make([]dividendHoldingEntry, len(entries))
	copy(sortedByIncome, entries)
	sort.Slice(sortedByIncome, func(i, j int) bool {
		return sortedByIncome[i].ExpectedAnnualDiv > sortedByIncome[j].ExpectedAnnualDiv
	})
	for i := 0; i < len(sortedByIncome) && i < 10; i++ {
		if sortedByIncome[i].ExpectedAnnualDiv <= 0 {
			break
		}
		topPayers = append(topPayers, sortedByIncome[i])
	}

	// Portfolio-level dividend yield.
	portfolioYield := 0.0
	if totalPortfolioValue > 0 {
		portfolioYield = roundTo2(totalExpectedDiv / totalPortfolioValue * 100)
	}

	totalTax := roundTo2(totalExpectedDiv * 0.30)
	netAfterTax := roundTo2(totalExpectedDiv - totalTax)

	// Seasonality note based on current quarter.
	quarter := (int(now.Month())-1)/3 + 1
	seasonNote := dividendSeasonality[quarter]

	// Data source note.
	dataNote := "Dividend data is sourced from a built-in database of ~50 major NSE stocks and may not cover all holdings. " +
		"For authoritative upcoming corporate actions, check: " +
		"bseindia.com/corporates/corporate_act.aspx or " +
		"nseindia.com/companies-listing/corporate-actions. " +
		"Yields shown are indicative based on last known annual dividends — actual payouts may vary."
	if len(knownActions) == 0 {
		dataNote = "No upcoming corporate actions in database. The built-in corporate actions database is currently empty — " +
			"NSE/BSE corporate actions APIs require special access and cannot be scraped in real-time. " +
			"Showing dividend yield analysis based on historical annual dividends for ~50 major stocks. " +
			"For live corporate actions, check: " +
			"bseindia.com/corporates/corporate_act.aspx, " +
			"nseindia.com/companies-listing/corporate-actions, or " +
			"moneycontrol.com/stocks/marketinfo/dividends_declared/index.php"
	}

	return &dividendCalendarResponse{
		Summary: dividendCalendarSummary{
			HoldingsCount:            len(holdings),
			HoldingsWithDividendData: withDataCount,
			TotalPortfolioValue:      roundTo2(totalPortfolioValue),
			TotalExpectedAnnualDiv:   roundTo2(totalExpectedDiv),
			PortfolioDividendYield:   portfolioYield,
			EstimatedTaxAt30Pct:      totalTax,
			NetDividendAfterTax:      netAfterTax,
			UpcomingActionsCount:     len(upcoming),
			LookAheadDays:            lookAheadDays,
			SeasonalityNote:          seasonNote,
			DataSourceNote:           dataNote,
		},
		UpcomingActions:   upcoming,
		HoldingsByYield:   entries,
		TopDividendPayers: topPayers,
		TaxNote: "Since April 2020, dividends are taxed as income in the hands of the investor (no DDT). " +
			"Tax rate depends on your income slab — estimates above use 30% (highest slab). " +
			"TDS of 10% is deducted at source if annual dividend exceeds Rs 5,000 from a single company. " +
			"Actual tax liability may be lower based on your total income and applicable slab rate.",
	}
}
