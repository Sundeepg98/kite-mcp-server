package mcp

import (
	"context"
	"fmt"
	"sort"
	"strings"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/usecases"
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
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "sector_exposure")

		return handler.WithSession(ctx, "sector_exposure", func(session *kc.KiteSessionData) (*gomcp.CallToolResult, error) {
			raw, err := handler.QueryBus().DispatchWithResult(ctx, cqrs.GetPortfolioQuery{Email: session.Email})
			if err != nil {
				handler.trackToolError(ctx, "sector_exposure", "api_error")
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
		symbol := normalizeSymbol(h.Tradingsymbol)
		sector, ok := stockSectors[symbol]
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
			warnings = append(warnings, name+" is over-exposed at "+formatPct(pct)+" of portfolio (threshold: 30%)")
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

// normalizeSymbol strips common suffixes and normalises to uppercase for lookup.
func normalizeSymbol(ts string) string {
	s := strings.ToUpper(strings.TrimSpace(ts))
	// Strip BSE/NSE trailing suffixes like "-BE", "-EQ"
	for _, suffix := range []string{"-BE", "-EQ", "-BZ", "-BL"} {
		s = strings.TrimSuffix(s, suffix)
	}
	return s
}

// formatPct formats a percentage for display.
func formatPct(v float64) string {
	if v == float64(int(v)) {
		return fmt.Sprintf("%d%%", int(v))
	}
	return fmt.Sprintf("%.1f%%", v)
}

// stockSectors maps NSE/BSE trading symbols to their primary sector classification.
// Covers Nifty 50, Nifty Next 50, and other commonly traded NSE stocks (~150+).
var stockSectors = map[string]string{
	// --- Banking ---
	"HDFCBANK":   "Banking",
	"ICICIBANK":  "Banking",
	"SBIN":       "Banking",
	"KOTAKBANK":  "Banking",
	"AXISBANK":   "Banking",
	"INDUSINDBK": "Banking",
	"BANKBARODA": "Banking",
	"PNB":        "Banking",
	"IDFCFIRSTB": "Banking",
	"FEDERALBNK": "Banking",
	"AUBANK":     "Banking",
	"BANDHANBNK": "Banking",
	"CANBK":      "Banking",
	"UNIONBANK":  "Banking",
	"IOB":        "Banking",
	"INDIANB":    "Banking",
	"YESBANK":    "Banking",
	"RBLBANK":    "Banking",
	"MAHABANK":   "Banking",

	// --- IT ---
	"TCS":      "IT",
	"INFY":     "IT",
	"HCLTECH":  "IT",
	"WIPRO":    "IT",
	"TECHM":    "IT",
	"LTIM":     "IT",
	"MPHASIS":  "IT",
	"COFORGE":  "IT",
	"PERSISTENT": "IT",
	"LTTS":     "IT",
	"OFSS":     "IT",
	"TATAELXSI": "IT",

	// --- FMCG ---
	"HINDUNILVR": "FMCG",
	"ITC":        "FMCG",
	"NESTLEIND":  "FMCG",
	"BRITANNIA":  "FMCG",
	"DABUR":      "FMCG",
	"TATACONSUM": "FMCG",
	"MARICO":     "FMCG",
	"GODREJCP":   "FMCG",
	"COLPAL":     "FMCG",
	"EMAMILTD":   "FMCG",
	"VBL":        "FMCG",
	"UBL":        "FMCG",

	// --- Pharma ---
	"SUNPHARMA": "Pharma",
	"DRREDDY":   "Pharma",
	"CIPLA":     "Pharma",
	"DIVISLAB":  "Pharma",
	"APOLLOHOSP": "Healthcare",
	"TORNTPHARM": "Pharma",
	"LUPIN":     "Pharma",
	"AUROPHARMA": "Pharma",
	"BIOCON":    "Pharma",
	"ALKEM":     "Pharma",
	"MAXHEALTH": "Healthcare",
	"FORTIS":    "Healthcare",
	"LALPATHLAB": "Healthcare",
	"METROPOLIS": "Healthcare",
	"IPCALAB":   "Pharma",
	"GLENMARK":  "Pharma",
	"ZYDUSLIFE": "Pharma",

	// --- Auto ---
	"MARUTI":     "Auto",
	"TATAMOTORS": "Auto",
	"M&M":        "Auto",
	"HEROMOTOCO": "Auto",
	"EICHERMOT":  "Auto",
	"BAJAJ-AUTO": "Auto",
	"ASHOKLEY":   "Auto",
	"TVSMOTOR":   "Auto",
	"MOTHERSON":  "Auto",
	"BALKRISIND": "Auto",
	"MRF":        "Auto",
	"EXIDEIND":   "Auto",
	"BHARATFORG": "Auto",
	"BOSCHLTD":   "Auto",
	"TIINDIA":    "Auto",

	// --- Energy ---
	"RELIANCE":  "Energy",
	"NTPC":      "Energy",
	"POWERGRID": "Energy",
	"ONGC":      "Energy",
	"COALINDIA": "Energy",
	"BPCL":      "Energy",
	"IOC":       "Energy",
	"GAIL":      "Energy",
	"TATAPOWER": "Energy",
	"ADANIGREEN": "Energy",
	"ADANIENSOL": "Energy",
	"NHPC":      "Energy",
	"SJVN":      "Energy",
	"IREDA":     "Energy",
	"PETRONET":  "Energy",

	// --- Metals ---
	"TATASTEEL": "Metals",
	"JSWSTEEL":  "Metals",
	"HINDALCO":  "Metals",
	"VEDL":      "Metals",
	"JINDALSTEL": "Metals",
	"NMDC":      "Metals",
	"NATIONALUM": "Metals",
	"SAIL":      "Metals",
	"COALINDIA2": "Metals", // placeholder for disambiguation

	// --- Infra ---
	"LT":         "Infra",
	"ADANIPORTS": "Infra",
	"ADANIENT":   "Conglomerate",
	"SIEMENS":    "Infra",
	"ABB":        "Infra",
	"HAVELLS":    "Infra",
	"POLYCAB":    "Infra",
	"CUMMINSIND": "Infra",
	"BEL":        "Infra",
	"HAL":        "Defence",
	"BHEL":       "Infra",
	"IRCON":      "Infra",
	"RVNL":       "Infra",
	"IRB":        "Infra",

	// --- Cement ---
	"ULTRACEMCO": "Cement",
	"GRASIM":     "Cement",
	"SHREECEM":   "Cement",
	"AMBUJACEM":  "Cement",
	"ACC":        "Cement",
	"DALBHARAT":  "Cement",
	"RAMCOCEM":   "Cement",

	// --- NBFC / Financial Services ---
	"BAJFINANCE": "NBFC",
	"BAJAJFINSV": "NBFC",
	"SBILIFE":    "Insurance",
	"HDFCLIFE":   "Insurance",
	"ICICIGI":    "Insurance",
	"ICICIPRULI": "Insurance",
	"MUTHOOTFIN": "NBFC",
	"SHRIRAMFIN": "NBFC",
	"CHOLAFIN":   "NBFC",
	"MANAPPURAM": "NBFC",
	"POONAWALLA": "NBFC",
	"LICHSGFIN":  "NBFC",
	"PFC":        "NBFC",
	"RECLTD":     "NBFC",
	"SBICARD":    "NBFC",
	"ANGELONE":   "NBFC",
	"JIOFIN":     "NBFC",

	// --- Telecom ---
	"BHARTIARTL": "Telecom",
	"IDEA":       "Telecom",

	// --- Consumer ---
	"TITAN":     "Consumer",
	"ASIANPAINT": "Consumer",
	"PIDILITIND": "Consumer",
	"PAGEIND":   "Consumer",
	"TRENT":     "Consumer",
	"DMART":     "Consumer",

	// --- Tech / New Economy ---
	"ZOMATO": "Tech",
	"PAYTM":  "Tech",
	"NYKAA":  "Tech",
	"POLICYBZR": "Tech",
	"CARTRADE":  "Tech",
	"DELHIVERY": "Tech",
	"INFOEDGE":  "Tech",

	// --- Media / Entertainment ---
	"SUNTV":  "Media",
	"PVR":    "Media",
	"PVRINOX": "Media",

	// --- Chemicals ---
	"PIIND":     "Chemicals",
	"SRF":       "Chemicals",
	"ATUL":      "Chemicals",
	"DEEPAKNTR": "Chemicals",
	"NAVINFLUOR": "Chemicals",
	"CLEAN":     "Chemicals",

	// --- Real Estate ---
	"DLF":       "Real Estate",
	"GODREJPROP": "Real Estate",
	"OBEROIRLTY": "Real Estate",
	"PRESTIGE":  "Real Estate",
	"LODHA":     "Real Estate",
	"BRIGADE":   "Real Estate",

	// --- Defence ---
	"BDL":        "Defence",
	"MAZAGON":    "Defence",
	"GRSE":       "Defence",
	"COCHINSHIP": "Defence",
	"SOLARINDS":  "Defence",
	"DATAPATTNS": "Defence",

	// --- PSU / Others ---
	"IRCTC":    "Services",
	"CONCOR":   "Services",
	"INDIGO":   "Aviation",
	"SPICEJET": "Aviation",
}
