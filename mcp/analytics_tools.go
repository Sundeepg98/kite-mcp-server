package mcp

import (
	"context"
	"math"
	"sort"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	"github.com/zerodha/kite-mcp-server/kc/usecases"
)

// --- Portfolio Summary Tool ---

type PortfolioSummaryTool struct{}

func (*PortfolioSummaryTool) Tool() mcp.Tool {
	return mcp.NewTool("portfolio_summary",
		mcp.WithDescription("Get a comprehensive portfolio analysis including total invested value, current value, overall P&L, day P&L, top gainers/losers, and biggest holdings by value. More useful than raw get_holdings for understanding portfolio health."),
		mcp.WithTitleAnnotation("Portfolio Summary"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(true),
	)
}

// holdingSummaryEntry is a compact representation of a holding for top-N lists.
type holdingSummaryEntry struct {
	Symbol        string  `json:"symbol"`
	DayChangePct  float64 `json:"day_change_pct,omitempty"`
	PnL           float64 `json:"pnl,omitempty"`
	Value         float64 `json:"value,omitempty"`
	PctOfPortfolio float64 `json:"pct_of_portfolio,omitempty"`
}

type portfolioSummaryResponse struct {
	TotalInvested   float64               `json:"total_invested"`
	TotalCurrent    float64               `json:"total_current"`
	OverallPnL      float64               `json:"overall_pnl"`
	OverallPnLPct   float64               `json:"overall_pnl_pct"`
	DayPnL          float64               `json:"day_pnl"`
	DayPnLPct       float64               `json:"day_pnl_pct"`
	HoldingsCount   int                   `json:"holdings_count"`
	TopGainers      []holdingSummaryEntry  `json:"top_gainers"`
	TopLosers       []holdingSummaryEntry  `json:"top_losers"`
	BiggestHoldings []holdingSummaryEntry  `json:"biggest_holdings"`
}

func (*PortfolioSummaryTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "portfolio_summary")

		return handler.WithSession(ctx, "portfolio_summary", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			raw, err := handler.QueryBus().DispatchWithResult(ctx, cqrs.GetPortfolioQuery{Email: session.Email})
			if err != nil {
				handler.trackToolError(ctx, "portfolio_summary", "api_error")
				return mcp.NewToolResultError("Failed to get holdings: " + err.Error()), nil
			}
			portfolio := raw.(*usecases.PortfolioResult)

			if len(portfolio.Holdings) == 0 {
				return handler.MarshalResponse(map[string]any{
					"holdings_count": 0,
					"message":        "No holdings found in portfolio",
				}, "portfolio_summary")
			}

			resp := computePortfolioSummary(portfolio.Holdings)
			return handler.MarshalResponse(resp, "portfolio_summary")
		})
	}
}

func computePortfolioSummary(holdings []broker.Holding) *portfolioSummaryResponse {
	var totalInvested, totalCurrent, dayPnL float64

	for _, h := range holdings {
		totalInvested += h.AveragePrice * float64(h.Quantity)
		curVal := h.LastPrice * float64(h.Quantity)
		totalCurrent += curVal
		// DayChange (absolute) is not in broker.Holding; derive from DayChangePct.
		// dayChange = currentValue * dayChangePct / (100 + dayChangePct)
		if h.DayChangePct != -100 {
			dayPnL += curVal * h.DayChangePct / (100 + h.DayChangePct)
		}
	}

	overallPnL := totalCurrent - totalInvested
	overallPnLPct := 0.0
	if totalInvested != 0 {
		overallPnLPct = roundTo2(overallPnL / totalInvested * 100)
	}
	dayPnLPct := 0.0
	if totalCurrent != 0 {
		// Day P&L % relative to previous close value (current - dayChange)
		prevValue := totalCurrent - dayPnL
		if prevValue != 0 {
			dayPnLPct = roundTo2(dayPnL / prevValue * 100)
		}
	}

	// Top gainers by day_change_percentage (descending)
	sorted := make([]broker.Holding, len(holdings))
	copy(sorted, holdings)

	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].DayChangePct > sorted[j].DayChangePct
	})
	topGainers := make([]holdingSummaryEntry, 0, 5)
	for i := 0; i < len(sorted) && i < 5; i++ {
		if sorted[i].DayChangePct <= 0 {
			break
		}
		curVal := sorted[i].LastPrice * float64(sorted[i].Quantity)
		dayChange := 0.0
		if sorted[i].DayChangePct != -100 {
			dayChange = curVal * sorted[i].DayChangePct / (100 + sorted[i].DayChangePct)
		}
		topGainers = append(topGainers, holdingSummaryEntry{
			Symbol:       sorted[i].Tradingsymbol,
			DayChangePct: roundTo2(sorted[i].DayChangePct),
			PnL:          roundTo2(dayChange),
		})
	}

	// Top losers by day_change_percentage (ascending)
	topLosers := make([]holdingSummaryEntry, 0, 5)
	for i := len(sorted) - 1; i >= 0 && len(topLosers) < 5; i-- {
		if sorted[i].DayChangePct >= 0 {
			break
		}
		curVal := sorted[i].LastPrice * float64(sorted[i].Quantity)
		dayChange := 0.0
		if sorted[i].DayChangePct != -100 {
			dayChange = curVal * sorted[i].DayChangePct / (100 + sorted[i].DayChangePct)
		}
		topLosers = append(topLosers, holdingSummaryEntry{
			Symbol:       sorted[i].Tradingsymbol,
			DayChangePct: roundTo2(sorted[i].DayChangePct),
			PnL:          roundTo2(dayChange),
		})
	}

	// Biggest holdings by current value (descending)
	sort.Slice(sorted, func(i, j int) bool {
		vi := sorted[i].LastPrice * float64(sorted[i].Quantity)
		vj := sorted[j].LastPrice * float64(sorted[j].Quantity)
		return vi > vj
	})
	biggestHoldings := make([]holdingSummaryEntry, 0, 5)
	for i := 0; i < len(sorted) && i < 5; i++ {
		val := sorted[i].LastPrice * float64(sorted[i].Quantity)
		pct := 0.0
		if totalCurrent != 0 {
			pct = roundTo2(val / totalCurrent * 100)
		}
		biggestHoldings = append(biggestHoldings, holdingSummaryEntry{
			Symbol:         sorted[i].Tradingsymbol,
			Value:          roundTo2(val),
			PctOfPortfolio: pct,
		})
	}

	return &portfolioSummaryResponse{
		TotalInvested:   roundTo2(totalInvested),
		TotalCurrent:    roundTo2(totalCurrent),
		OverallPnL:      roundTo2(overallPnL),
		OverallPnLPct:   overallPnLPct,
		DayPnL:          roundTo2(dayPnL),
		DayPnLPct:       dayPnLPct,
		HoldingsCount:   len(holdings),
		TopGainers:      topGainers,
		TopLosers:       topLosers,
		BiggestHoldings: biggestHoldings,
	}
}

// --- Portfolio Concentration Tool ---

type PortfolioConcentrationTool struct{}

func (*PortfolioConcentrationTool) Tool() mcp.Tool {
	return mcp.NewTool("portfolio_concentration",
		mcp.WithDescription("Analyze portfolio concentration and diversification. Shows what percentage each holding represents, identifies over-concentration risks, and computes a Herfindahl-Hirschman Index (HHI) diversification score. HHI < 1500 = diversified, 1500-2500 = moderate, > 2500 = concentrated."),
		mcp.WithTitleAnnotation("Portfolio Concentration"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(true),
	)
}

type concentrationEntry struct {
	Symbol string  `json:"symbol"`
	Value  float64 `json:"value"`
	Pct    float64 `json:"pct"`
}

type portfolioConcentrationResponse struct {
	HoldingsCount     int                  `json:"holdings_count"`
	TotalValue        float64              `json:"total_value"`
	HHIScore          float64              `json:"hhi_score"`
	Concentration     string               `json:"concentration"`
	Top5CombinedPct   float64              `json:"top5_combined_pct"`
	Top5              []concentrationEntry `json:"top5"`
	NoisePositions    int                  `json:"noise_positions"`
	NoisePositionsVal float64              `json:"noise_positions_value"`
	NoisePositionsPct float64              `json:"noise_positions_pct"`
}

func (*PortfolioConcentrationTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "portfolio_concentration")

		return handler.WithSession(ctx, "portfolio_concentration", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			raw, err := handler.QueryBus().DispatchWithResult(ctx, cqrs.GetPortfolioQuery{Email: session.Email})
			if err != nil {
				handler.trackToolError(ctx, "portfolio_concentration", "api_error")
				return mcp.NewToolResultError("Failed to get holdings: " + err.Error()), nil
			}
			portfolio := raw.(*usecases.PortfolioResult)

			if len(portfolio.Holdings) == 0 {
				return handler.MarshalResponse(map[string]any{
					"holdings_count": 0,
					"message":        "No holdings found in portfolio",
				}, "portfolio_concentration")
			}

			resp := computePortfolioConcentration(portfolio.Holdings)
			return handler.MarshalResponse(resp, "portfolio_concentration")
		})
	}
}

func computePortfolioConcentration(holdings []broker.Holding) *portfolioConcentrationResponse {
	// Compute total value and per-holding values
	type holdingValue struct {
		symbol string
		value  float64
	}

	hvs := make([]holdingValue, 0, len(holdings))
	var totalValue float64
	for _, h := range holdings {
		val := h.LastPrice * float64(h.Quantity)
		totalValue += val
		hvs = append(hvs, holdingValue{symbol: h.Tradingsymbol, value: val})
	}

	// Handle zero total value
	if totalValue == 0 {
		return &portfolioConcentrationResponse{
			HoldingsCount: len(holdings),
			TotalValue:    0,
			HHIScore:      0,
			Concentration: "empty",
			Top5:          []concentrationEntry{},
		}
	}

	// Sort by value descending
	sort.Slice(hvs, func(i, j int) bool {
		return hvs[i].value > hvs[j].value
	})

	// Compute HHI and percentages
	var hhi float64
	var top5CombinedPct float64
	top5 := make([]concentrationEntry, 0, 5)
	noiseCount := 0
	var noiseValue float64

	for i, hv := range hvs {
		pct := hv.value / totalValue * 100
		hhi += pct * pct

		if i < 5 {
			top5 = append(top5, concentrationEntry{
				Symbol: hv.symbol,
				Value:  roundTo2(hv.value),
				Pct:    roundTo2(pct),
			})
			top5CombinedPct += pct
		}

		if pct < 1.0 {
			noiseCount++
			noiseValue += hv.value
		}
	}

	noisePct := 0.0
	if totalValue != 0 {
		noisePct = roundTo2(noiseValue / totalValue * 100)
	}

	concentration := "diversified"
	hhiRounded := roundTo2(hhi)
	if hhiRounded >= 2500 {
		concentration = "concentrated"
	} else if hhiRounded >= 1500 {
		concentration = "moderate"
	}

	return &portfolioConcentrationResponse{
		HoldingsCount:     len(holdings),
		TotalValue:        roundTo2(totalValue),
		HHIScore:          hhiRounded,
		Concentration:     concentration,
		Top5CombinedPct:   roundTo2(top5CombinedPct),
		Top5:              top5,
		NoisePositions:    noiseCount,
		NoisePositionsVal: roundTo2(noiseValue),
		NoisePositionsPct: noisePct,
	}
}

// --- Position Analysis Tool ---

type PositionAnalysisTool struct{}

func (*PositionAnalysisTool) Tool() mcp.Tool {
	return mcp.NewTool("position_analysis",
		mcp.WithDescription("Analyze open positions with detailed P&L breakdown by product type (MIS/NRML/CNC), net quantity, unrealized P&L, and day change. Provides aggregated view that is more actionable than raw get_positions."),
		mcp.WithTitleAnnotation("Position Analysis"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(true),
	)
}

type positionEntry struct {
	Symbol       string  `json:"symbol"`
	Exchange     string  `json:"exchange"`
	Product      string  `json:"product"`
	Quantity     int     `json:"quantity"`
	AveragePrice float64 `json:"average_price"`
	LastPrice    float64 `json:"last_price"`
	PnL          float64 `json:"pnl"`
	Unrealised   float64 `json:"unrealised"`
	Realised     float64 `json:"realised"`
	DayBuyValue  float64 `json:"day_buy_value"`
	DaySellValue float64 `json:"day_sell_value"`
}

type productGroupSummary struct {
	Product      string          `json:"product"`
	Count        int             `json:"count"`
	TotalPnL     float64         `json:"total_pnl"`
	Unrealised   float64         `json:"unrealised"`
	Realised     float64         `json:"realised"`
	Positions    []positionEntry `json:"positions"`
}

type positionAnalysisResponse struct {
	NetPositionsCount int                   `json:"net_positions_count"`
	TotalPnL          float64               `json:"total_pnl"`
	TotalUnrealised   float64               `json:"total_unrealised"`
	TotalRealised     float64               `json:"total_realised"`
	ByProduct         []productGroupSummary `json:"by_product"`
	TopGainers        []positionEntry       `json:"top_gainers"`
	TopLosers         []positionEntry       `json:"top_losers"`
}

func (*PositionAnalysisTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "position_analysis")

		return handler.WithSession(ctx, "position_analysis", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			raw, err := handler.QueryBus().DispatchWithResult(ctx, cqrs.GetPortfolioQuery{Email: session.Email})
			if err != nil {
				handler.trackToolError(ctx, "position_analysis", "api_error")
				return mcp.NewToolResultError("Failed to get positions: " + err.Error()), nil
			}
			portfolio := raw.(*usecases.PortfolioResult)

			if len(portfolio.Positions.Net) == 0 {
				return handler.MarshalResponse(map[string]any{
					"net_positions_count": 0,
					"message":             "No open positions",
				}, "position_analysis")
			}

			resp := computePositionAnalysis(portfolio.Positions.Net)
			return handler.MarshalResponse(resp, "position_analysis")
		})
	}
}

func computePositionAnalysis(netPositions []broker.Position) *positionAnalysisResponse {
	var totalPnL, totalUnrealised, totalRealised float64

	// Build position entries and group by product
	productMap := make(map[string]*productGroupSummary)
	entries := make([]positionEntry, 0, len(netPositions))

	for _, p := range netPositions {
		// Use the rich Position entity for broker-reported PnL; the
		// DTO still supplies the display fields.
		pos := domain.NewPositionFromBroker(p)
		entry := positionEntry{
			Symbol:       p.Tradingsymbol,
			Exchange:     p.Exchange,
			Product:      p.Product,
			Quantity:     p.Quantity,
			AveragePrice: roundTo2(p.AveragePrice),
			LastPrice:    roundTo2(p.LastPrice),
			PnL:          roundTo2(pos.PnL().Amount),
		}
		entries = append(entries, entry)

		totalPnL += pos.PnL().Amount

		group, ok := productMap[p.Product]
		if !ok {
			group = &productGroupSummary{
				Product:   p.Product,
				Positions: make([]positionEntry, 0),
			}
			productMap[p.Product] = group
		}
		group.Count++
		group.TotalPnL += pos.PnL().Amount
		group.Positions = append(group.Positions, entry)
	}

	// Collect product groups and round
	byProduct := make([]productGroupSummary, 0, len(productMap))
	for _, g := range productMap {
		g.TotalPnL = roundTo2(g.TotalPnL)
		byProduct = append(byProduct, *g)
	}
	// Sort product groups alphabetically for consistent output
	sort.Slice(byProduct, func(i, j int) bool {
		return byProduct[i].Product < byProduct[j].Product
	})

	// Top gainers (by PnL descending)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].PnL > entries[j].PnL
	})
	topGainers := make([]positionEntry, 0, 5)
	for i := 0; i < len(entries) && i < 5; i++ {
		if entries[i].PnL <= 0 {
			break
		}
		topGainers = append(topGainers, entries[i])
	}

	// Top losers (by PnL ascending)
	topLosers := make([]positionEntry, 0, 5)
	for i := len(entries) - 1; i >= 0 && len(topLosers) < 5; i-- {
		if entries[i].PnL >= 0 {
			break
		}
		topLosers = append(topLosers, entries[i])
	}

	return &positionAnalysisResponse{
		NetPositionsCount: len(netPositions),
		TotalPnL:          roundTo2(totalPnL),
		TotalUnrealised:   roundTo2(totalUnrealised),
		TotalRealised:     roundTo2(totalRealised),
		ByProduct:         byProduct,
		TopGainers:        topGainers,
		TopLosers:         topLosers,
	}
}

// --- Utilities ---

// roundTo2 rounds a float64 to 2 decimal places.
func roundTo2(v float64) float64 {
	return math.Round(v*100) / 100
}

func init() {
	RegisterInternalTool(&PortfolioConcentrationTool{})
	RegisterInternalTool(&PortfolioSummaryTool{})
	RegisterInternalTool(&PositionAnalysisTool{})
}
