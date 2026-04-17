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
	"github.com/zerodha/kite-mcp-server/kc/usecases"
)

// Indian equity capital gains tax rates (post Budget 2024, effective FY 2024-25 onwards).
const (
	// LTCG: 12.5% on listed equity held > 12 months, with ₹1.25L annual exemption.
	ltcgRate      = 0.125
	ltcgExemption = 125000.0

	// STCG: 20% on listed equity held ≤ 12 months.
	stcgRate = 0.20

	// Holdings within this many days of the 365-day LTCG threshold are flagged
	// as "approaching LTCG eligibility".
	ltcgApproachingDays = 30
)

// --- Tax Harvest Analysis Tool ---

// TaxHarvestTool analyses a portfolio for tax-loss harvesting opportunities.
type TaxHarvestTool struct{}

func (*TaxHarvestTool) Tool() mcp.Tool {
	return mcp.NewTool("tax_loss_analysis",
		mcp.WithDescription(
			"Compute unrealized capital gains and losses with LTCG vs STCG classification. "+
				"Shows invested vs current value, unrealized P&L per holding, holdings with unrealized "+
				"losses (flagged as potentially harvestable), and holdings within 30 days of LTCG "+
				"eligibility. India-specific rates: 12.5% LTCG (>12 months, above Rs 1.25L annual exemption), "+
				"20% STCG (<=12 months). "+
				"Note: Kite Holdings API does not expose individual lot purchase dates, so holdings "+
				"are classified as STCG by default. Pass an optional assume_ltcg_days parameter to "+
				"override the holding-period assumption. Not investment advice.",
		),
		mcp.WithTitleAnnotation("Tax Loss Analysis"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(true),
		mcp.WithNumber("assume_ltcg_days",
			mcp.Description("Assume all holdings have been held this many days (default: 0 = STCG). "+
				"Set to 366+ to classify as LTCG. Ignored for holdings that have an authorised_date."),
		),
	)
}

// --- Response types ---

type taxHoldingEntry struct {
	Symbol          string  `json:"symbol"`
	Exchange        string  `json:"exchange"`
	ISIN            string  `json:"isin,omitempty"`
	Quantity        int     `json:"quantity"`
	AveragePrice    float64 `json:"avg_price"`
	LastPrice       float64 `json:"last_price"`
	InvestedValue   float64 `json:"invested_value"`
	CurrentValue    float64 `json:"current_value"`
	UnrealizedPnL   float64 `json:"unrealized_pnl"`
	UnrealizedPct   float64 `json:"unrealized_pct"`
	HoldingDays     int     `json:"holding_days"`    // -1 if unknown
	HoldingPeriod   string  `json:"holding_period"`  // "LTCG", "STCG", or "unknown"
	TaxRate         float64 `json:"tax_rate"`         // applicable rate (0.125 or 0.20)
	EstimatedTax    float64 `json:"estimated_tax"`    // tax if sold at current price (pre-exemption for LTCG)
	Harvestable     bool    `json:"harvestable"`      // true if unrealized loss
	TaxSavings      float64 `json:"tax_savings"`      // loss * applicable rate (tax saved by harvesting)
	ApproachingLTCG bool    `json:"approaching_ltcg"` // within 30 days of LTCG threshold
}

type taxHarvestSummary struct {
	HoldingsCount       int     `json:"holdings_count"`
	TotalInvested       float64 `json:"total_invested"`
	TotalCurrent        float64 `json:"total_current"`
	TotalUnrealizedPnL  float64 `json:"total_unrealized_pnl"`
	TotalUnrealizedGain float64 `json:"total_unrealized_gain"`
	TotalUnrealizedLoss float64 `json:"total_unrealized_loss"`

	// LTCG bucket
	LTCGGains       float64 `json:"ltcg_gains"`
	LTCGLosses      float64 `json:"ltcg_losses"`
	LTCGTaxEstimate float64 `json:"ltcg_tax_estimate"` // 12.5% on net gains above ₹1.25L

	// STCG bucket
	STCGGains       float64 `json:"stcg_gains"`
	STCGLosses      float64 `json:"stcg_losses"`
	STCGTaxEstimate float64 `json:"stcg_tax_estimate"` // 20% on net gains

	// Harvesting potential
	TotalHarvestable     float64 `json:"total_harvestable_loss"`
	TotalTaxSavings      float64 `json:"total_tax_savings"`
	HarvestCandidatesCnt int     `json:"harvest_candidates_count"`
	ApproachingLTCGCnt   int     `json:"approaching_ltcg_count"`

	AssumedHoldingDays int    `json:"assumed_holding_days"`
	HoldingPeriodNote  string `json:"holding_period_note"`
}

type taxHarvestResponse struct {
	Summary           taxHarvestSummary  `json:"summary"`
	HarvestCandidates []taxHoldingEntry  `json:"harvest_candidates"` // sorted by tax_savings desc
	ApproachingLTCG   []taxHoldingEntry  `json:"approaching_ltcg"`   // holdings near 365-day mark
	AllHoldings       []taxHoldingEntry  `json:"all_holdings"`
}

func (*TaxHarvestTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "tax_loss_analysis")

		assumeDays := NewArgParser(request.GetArguments()).Int("assume_ltcg_days", 0)

		return handler.WithSession(ctx, "tax_loss_analysis", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			raw, err := manager.QueryBus().DispatchWithResult(ctx, cqrs.GetPortfolioQuery{Email: session.Email})
			if err != nil {
				handler.trackToolError(ctx, "tax_loss_analysis", "api_error")
				return mcp.NewToolResultError("Failed to get holdings: " + err.Error()), nil
			}
			portfolio := raw.(*usecases.PortfolioResult)

			if len(portfolio.Holdings) == 0 {
				return handler.MarshalResponse(map[string]any{
					"holdings_count": 0,
					"message":        "No holdings found in portfolio",
				}, "tax_loss_analysis")
			}

			resp := computeTaxHarvest(portfolio.Holdings, assumeDays)
			return handler.MarshalResponse(resp, "tax_loss_analysis")
		})
	}
}

// computeTaxHarvest performs the tax classification and harvest analysis.
func computeTaxHarvest(holdings []broker.Holding, assumeDays int) *taxHarvestResponse {
	entries := make([]taxHoldingEntry, 0, len(holdings))

	var (
		totalInvested, totalCurrent                     float64
		totalGain, totalLoss                            float64
		ltcgGains, ltcgLosses, stcgGains, stcgLosses   float64
		totalHarvestable, totalTaxSavings               float64
		harvestCount, approachingCount                  int
	)

	for _, h := range holdings {
		invested := h.AveragePrice * float64(h.Quantity)
		current := h.LastPrice * float64(h.Quantity)
		pnl := current - invested
		pnlPct := 0.0
		if invested != 0 {
			pnlPct = roundTo2(pnl / invested * 100)
		}

		totalInvested += invested
		totalCurrent += current
		if pnl >= 0 {
			totalGain += pnl
		} else {
			totalLoss += pnl // negative
		}

		// Determine holding period.
		// broker.Holding does not carry AuthorisedDate; rely on assumeDays param.
		holdingDays := -1
		holdingPeriod := "unknown"

		if assumeDays > 0 {
			holdingDays = assumeDays
		} else {
			// Default to 0 days (STCG) when unknown.
			holdingDays = 0
		}

		isLTCG := holdingDays > 365
		if isLTCG {
			holdingPeriod = "LTCG"
		} else {
			holdingPeriod = "STCG"
		}

		// Check if approaching LTCG eligibility (within 30 days of 365-day mark).
		approachingLTCG := !isLTCG && holdingDays >= 0 && (365-holdingDays) <= ltcgApproachingDays && (365-holdingDays) > 0

		// Tax computation.
		taxRate := stcgRate
		if isLTCG {
			taxRate = ltcgRate
		}

		estimatedTax := 0.0
		if pnl > 0 {
			estimatedTax = roundTo2(pnl * taxRate)
		}
		// Note: LTCG exemption of ₹1.25L is applied at the summary level, not per-holding.

		harvestable := pnl < 0
		taxSavings := 0.0
		if harvestable {
			taxSavings = roundTo2(math.Abs(pnl) * taxRate)
		}

		// Accumulate into buckets.
		if isLTCG {
			if pnl >= 0 {
				ltcgGains += pnl
			} else {
				ltcgLosses += pnl
			}
		} else {
			if pnl >= 0 {
				stcgGains += pnl
			} else {
				stcgLosses += pnl
			}
		}

		if harvestable {
			totalHarvestable += pnl // negative
			totalTaxSavings += taxSavings
			harvestCount++
		}
		if approachingLTCG {
			approachingCount++
		}

		entries = append(entries, taxHoldingEntry{
			Symbol:          h.Tradingsymbol,
			Exchange:        h.Exchange,
			ISIN:            h.ISIN,
			Quantity:        h.Quantity,
			AveragePrice:    roundTo2(h.AveragePrice),
			LastPrice:       roundTo2(h.LastPrice),
			InvestedValue:   roundTo2(invested),
			CurrentValue:    roundTo2(current),
			UnrealizedPnL:   roundTo2(pnl),
			UnrealizedPct:   pnlPct,
			HoldingDays:     holdingDays,
			HoldingPeriod:   holdingPeriod,
			TaxRate:         taxRate,
			EstimatedTax:    estimatedTax,
			Harvestable:     harvestable,
			TaxSavings:      taxSavings,
			ApproachingLTCG: approachingLTCG,
		})
	}

	// Compute summary-level tax estimates with LTCG exemption applied.
	netLTCGGain := ltcgGains + ltcgLosses // ltcgLosses is negative
	ltcgTax := 0.0
	if netLTCGGain > ltcgExemption {
		ltcgTax = roundTo2((netLTCGGain - ltcgExemption) * ltcgRate)
	}

	netSTCGGain := stcgGains + stcgLosses // stcgLosses is negative
	stcgTax := 0.0
	if netSTCGGain > 0 {
		stcgTax = roundTo2(netSTCGGain * stcgRate)
	}

	// Extract harvest candidates (sorted by tax savings descending).
	harvestCandidates := make([]taxHoldingEntry, 0, harvestCount)
	for _, e := range entries {
		if e.Harvestable {
			harvestCandidates = append(harvestCandidates, e)
		}
	}
	sort.Slice(harvestCandidates, func(i, j int) bool {
		return harvestCandidates[i].TaxSavings > harvestCandidates[j].TaxSavings
	})

	// Extract holdings approaching LTCG (sorted by days remaining ascending).
	approachingLTCGList := make([]taxHoldingEntry, 0, approachingCount)
	for _, e := range entries {
		if e.ApproachingLTCG {
			approachingLTCGList = append(approachingLTCGList, e)
		}
	}
	sort.Slice(approachingLTCGList, func(i, j int) bool {
		return approachingLTCGList[i].HoldingDays > approachingLTCGList[j].HoldingDays // closer to 365 first
	})

	holdingNote := "Kite Holdings API does not provide individual lot purchase dates. " +
		"AuthorisedDate (CDSL/NSDL pledge date) is used as a best-effort proxy when available. "
	if assumeDays > 0 {
		holdingNote += "User override: all holdings assumed held for the specified number of days."
	} else {
		holdingNote += "Holdings with unknown dates default to STCG (0 days). " +
			"Use assume_ltcg_days parameter to override."
	}

	return &taxHarvestResponse{
		Summary: taxHarvestSummary{
			HoldingsCount:        len(holdings),
			TotalInvested:        roundTo2(totalInvested),
			TotalCurrent:         roundTo2(totalCurrent),
			TotalUnrealizedPnL:   roundTo2(totalCurrent - totalInvested),
			TotalUnrealizedGain:  roundTo2(totalGain),
			TotalUnrealizedLoss:  roundTo2(totalLoss),
			LTCGGains:            roundTo2(ltcgGains),
			LTCGLosses:           roundTo2(ltcgLosses),
			LTCGTaxEstimate:      ltcgTax,
			STCGGains:            roundTo2(stcgGains),
			STCGLosses:           roundTo2(stcgLosses),
			STCGTaxEstimate:      stcgTax,
			TotalHarvestable:     roundTo2(totalHarvestable),
			TotalTaxSavings:      roundTo2(totalTaxSavings),
			HarvestCandidatesCnt: harvestCount,
			ApproachingLTCGCnt:   approachingCount,
			AssumedHoldingDays:   assumeDays,
			HoldingPeriodNote:    holdingNote,
		},
		HarvestCandidates: harvestCandidates,
		ApproachingLTCG:   approachingLTCGList,
		AllHoldings:       entries,
	}
}
