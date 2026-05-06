package portfolio

import (
	"context"
	"fmt"
	"math"
	"sort"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/algo2go/kite-mcp-broker"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/sectors"
	"github.com/zerodha/kite-mcp-server/kc/usecases"
	"github.com/zerodha/kite-mcp-server/mcp/common"
	"github.com/zerodha/kite-mcp-server/mcp/plugin"
)

// --- Sector Exposure Analysis Tool ---

// SectorExposureTool analyses portfolio holdings by sector/industry.
type SectorExposureTool struct{}

func (*SectorExposureTool) Tool() gomcp.Tool {
	return gomcp.NewTool("sector_exposure",
		gomcp.WithDescription("Analyze portfolio sector/industry exposure. Maps holdings to sectors (Banking, IT, Pharma, FMCG, Auto, Energy, Metals, Infra, Telecom, etc.) based on known Indian stock classifications. Shows concentration by sector and flags over-exposure (>30%)."),
		gomcp.WithTitleAnnotation("Sector Exposure Analysis"),
		gomcp.WithReadOnlyHintAnnotation(true),
		gomcp.WithIdempotentHintAnnotation(true),
		gomcp.WithOpenWorldHintAnnotation(true),
	)
}

// sectorAllocation represents one sector's share of the portfolio.
type sectorAllocation struct {
	Sector       string  `json:"sector"`
	Value        float64 `json:"value"`
	Pct          float64 `json:"pct"`
	Holdings     int     `json:"holdings"`
	OverExposed  bool    `json:"over_exposed,omitempty"`
}

// sectorHolding is a holding annotated with its resolved sector.
type sectorHolding struct {
	Symbol string  `json:"symbol"`
	Sector string  `json:"sector"`
	Value  float64 `json:"value"`
	Pct    float64 `json:"pct"`
}

type sectorExposureResponse struct {
	TotalValue     float64            `json:"total_value"`
	HoldingsCount  int                `json:"holdings_count"`
	MappedCount    int                `json:"mapped_count"`
	UnmappedCount  int                `json:"unmapped_count"`
	Sectors        []sectorAllocation `json:"sectors"`
	UnmappedStocks []sectorHolding    `json:"unmapped_stocks,omitempty"`
	Warnings       []string           `json:"warnings,omitempty"`
}

func (*SectorExposureTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := common.NewToolHandler(manager)
	return func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		handler.TrackToolCall(ctx, "sector_exposure")

		return handler.WithSession(ctx, "sector_exposure", func(session *kc.KiteSessionData) (*gomcp.CallToolResult, error) {
			raw, err := handler.QueryBus().DispatchWithResult(ctx, cqrs.GetPortfolioQuery{Email: session.Email})
			if err != nil {
				handler.TrackToolError(ctx, "sector_exposure", "api_error")
				return gomcp.NewToolResultError("Failed to get holdings: " + err.Error()), nil
			}
			portfolio := raw.(*usecases.PortfolioResult)

			if len(portfolio.Holdings) == 0 {
				return handler.MarshalResponse(map[string]any{
					"holdings_count": 0,
					"message":        "No holdings found in portfolio",
				}, "sector_exposure")
			}

			resp := computeSectorExposure(portfolio.Holdings)
			return handler.MarshalResponse(resp, "sector_exposure")
		})
	}
}

// overExposureThreshold is the percentage above which a sector is flagged.
const overExposureThreshold = 30.0

// computeSectorExposure maps holdings to sectors and computes allocation.
func computeSectorExposure(holdings []broker.Holding) *sectorExposureResponse {
	var totalValue float64
	for _, h := range holdings {
		totalValue += h.LastPrice * float64(h.Quantity)
	}

	if totalValue == 0 {
		return &sectorExposureResponse{
			HoldingsCount: len(holdings),
			Sectors:       []sectorAllocation{},
		}
	}

	// Accumulate per-sector values.
	type sectorAccum struct {
		value    float64
		holdings int
	}
	sectorMap := make(map[string]*sectorAccum)
	var unmapped []sectorHolding
	mappedCount := 0

	for _, h := range holdings {
		val := h.LastPrice * float64(h.Quantity)
		pct := roundTo2(val / totalValue * 100)

		// Normalize the trading symbol for lookup (strip exchange suffixes, etc.)
		symbol := NormalizeSymbol(h.Tradingsymbol)
		sector, ok := StockSectors[symbol]
		if !ok {
			unmapped = append(unmapped, sectorHolding{
				Symbol: h.Tradingsymbol,
				Sector: "Unknown",
				Value:  roundTo2(val),
				Pct:    pct,
			})
			sector = "Other"
		} else {
			mappedCount++
		}

		acc, exists := sectorMap[sector]
		if !exists {
			acc = &sectorAccum{}
			sectorMap[sector] = acc
		}
		acc.value += val
		acc.holdings++
	}

	// Convert to sorted slice.
	sectors := make([]sectorAllocation, 0, len(sectorMap))
	var warnings []string
	for name, acc := range sectorMap {
		pct := roundTo2(acc.value / totalValue * 100)
		overExposed := pct > overExposureThreshold
		sectors = append(sectors, sectorAllocation{
			Sector:      name,
			Value:       roundTo2(acc.value),
			Pct:         pct,
			Holdings:    acc.holdings,
			OverExposed: overExposed,
		})
		if overExposed {
			warnings = append(warnings, name+" is over-exposed at "+FormatPct(pct)+" of portfolio (threshold: 30%)")
		}
	}

	// Sort by allocation descending.
	sort.Slice(sectors, func(i, j int) bool {
		return sectors[i].Pct > sectors[j].Pct
	})

	// Sort unmapped by value descending.
	sort.Slice(unmapped, func(i, j int) bool {
		return unmapped[i].Value > unmapped[j].Value
	})

	return &sectorExposureResponse{
		TotalValue:     roundTo2(totalValue),
		HoldingsCount:  len(holdings),
		MappedCount:    mappedCount,
		UnmappedCount:  len(unmapped),
		Sectors:        sectors,
		UnmappedStocks: unmapped,
		Warnings:       warnings,
	}
}

// NormalizeSymbol strips common suffixes and normalises to uppercase for
// lookup.
//
// Deprecated: this is a thin alias for kc/sectors.NormalizeSymbol;
// retained for backward-compat with mcp/plugin_widget_sector_donut.go
// and any external callers. New code should import kc/sectors directly.
func NormalizeSymbol(ts string) string {
	return sectors.NormalizeSymbol(ts)
}

// FormatPct formats a percentage for display.
func FormatPct(v float64) string {
	if v == float64(int(v)) {
		return fmt.Sprintf("%d%%", int(v))
	}
	return fmt.Sprintf("%.1f%%", v)
}

// StockSectors maps NSE/BSE trading symbols to their primary sector
// classification.
//
// Deprecated: this is a re-export of kc/sectors.StockSectors; the
// canonical map now lives in the kc/sectors leaf package. Retained
// as a top-level package var for backward-compat with
// mcp/plugin_widget_sector_donut.go and the property-test suite at
// mcp/portfolio/sector_tool_property_test.go. New code should import
// kc/sectors directly.
var StockSectors = sectors.StockSectors

func init() { plugin.RegisterInternalTool(&SectorExposureTool{}) }

// roundTo2 rounds to 2 decimal places. Anchor 1 PR 1.6 added a local
// copy when this file moved to mcp/portfolio. analytics_tools.go (in
// mcp/ root) and other PR-1.5 trade files have their own copies for
// the same reason — small stand-alone math helper.
func roundTo2(v float64) float64 {
	return math.Round(v*100) / 100
}
