package mcp

import (
	"context"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
)

// PeerCompareTool is a "frame the LLM" tool for side-by-side fundamental-strength
// comparison of 2-6 Indian listed stocks. It does NOT scrape Screener/Moneycontrol
// (same reason analyze_concall and get_fii_dii_flow don't): scraping at scale
// is brittle and expensive, and Kite Connect itself does not expose balance-sheet
// or income-statement data — only price and trade data. So we return structured
// data-gap pointers (Screener.in URL per symbol + the formula) that the LLM can
// feed into WebFetch/Tavily in the same chat session, then compute the classic
// financial-strength scores (PEG, Piotroski F-score, Altman Z-score) client-side.
//
// Why this matters (from agent 32's research-copilot audit):
//   - Tickertape charges Rs 2,399/yr specifically for peer comparison with
//     Piotroski/Altman Z/PEG. This is their headline premium feature.
//   - Side-by-side fundamental strength across 2-6 peers is how retail
//     investors sanity-check "should I buy HDFC Bank or ICICI Bank?" — one of
//     the most common questions in /r/IndianStreetBets.
//   - PEG, Piotroski (9-pt balance-sheet quality score), and Altman Z
//     (bankruptcy predictor) are the classic triad of fundamental screens.
//
// Design mirrors AnalyzeConcallTool (commit 682fc06) and GetFIIDIIFlowTool
// (commit 78837d9): return structured pointers + formulas + disclaimer. Zero
// scraping on our side.
type PeerCompareTool struct{}

// validMetrics is the allowlist of metric names accepted by the tool. Used for
// input validation — unknown metrics produce a clear error rather than silent
// empty output.
var validMetrics = map[string]bool{
	"PEG":       true,
	"Piotroski": true,
	"AltmanZ":   true,
	"PE":        true,
	"PB":        true,
	"ROE":       true,
	"DE":        true,
}

// defaultMetrics is the ordered set returned when the caller does not specify
// metrics. Keeps output deterministic for tests and LLM consumers.
var defaultMetrics = []string{"PEG", "Piotroski", "AltmanZ", "PE", "PB", "ROE", "DE"}

func (*PeerCompareTool) Tool() mcp.Tool {
	return mcp.NewTool("peer_compare",
		mcp.WithDescription("Compare 2-6 stocks side-by-side on fundamental strength (PEG, Piotroski F-score, Altman Z-score) + key ratios (PE, PB, ROE, DE). Returns a structured comparison table with a data-gap pointer (Screener.in URL + formula) per (symbol, metric) pair. Kite Connect does not expose fundamentals directly, so the LLM is expected to fetch the pointer URLs via WebFetch/Tavily and compute scores client-side using the formulas returned by this tool. Does not fetch external data itself."),
		mcp.WithTitleAnnotation("Peer Comparison (Fundamental Strength)"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(true),
		mcp.WithArray("symbols",
			mcp.Description("Trading symbols to compare, 2-6 entries (e.g. [\"HDFCBANK\",\"ICICIBANK\",\"SBIN\"]). Case-insensitive; uppercased internally."),
			mcp.Required(),
			mcp.Items(map[string]any{"type": "string"}),
		),
		mcp.WithArray("metrics",
			mcp.Description("Optional metric allowlist. Any of: PEG, Piotroski, AltmanZ, PE, PB, ROE, DE. Defaults to all seven."),
			mcp.Items(map[string]any{"type": "string"}),
		),
	)
}

// peerCompareMetricCell is one (symbol, metric) cell in the comparison table.
// Status is one of:
//   - "needs_external_data" — Kite doesn't expose this fundamental; LLM must
//     fetch from source_hint and compute using formula.
//   - "symbol_not_found"    — symbol didn't resolve in the instruments table;
//     LLM should warn user or try the source URL anyway.
//
// A future enhancement can add "computed" status once we wire up Kite
// historical data (for e.g. rolling-PE from OHLC + external EPS).
type peerCompareMetricCell struct {
	Metric     string `json:"metric"`
	Status     string `json:"status"`
	SourceHint string `json:"source_hint,omitempty"`
	Formula    string `json:"formula,omitempty"`
}

// peerCompareRow is one row of the comparison table — all metrics for one
// symbol. The map is keyed by metric name for easy LLM lookup.
type peerCompareRow struct {
	Symbol      string                           `json:"symbol"`
	CompanyName string                           `json:"company_name,omitempty"`
	Exchange    string                           `json:"exchange,omitempty"`
	Status      string                           `json:"status"` // "pointer_available" | "symbol_not_found"
	Metrics     map[string]peerCompareMetricCell `json:"metrics"`
}

// peerCompareResponse is the structured payload returned by peer_compare. The
// text fallback (via MarshalResponse) contains the same JSON so LLM clients
// without structuredContent parsing still get readable guidance.
type peerCompareResponse struct {
	Symbols          []string          `json:"symbols"`
	MetricsRequested []string          `json:"metrics_requested"`
	ComparisonTable  []peerCompareRow  `json:"comparison_table"`
	Formulas         map[string]string `json:"formulas"`
	NextSteps        []string          `json:"next_steps"`
	Disclaimer       string            `json:"disclaimer"`
}

// formulaForMetric returns the canonical formula / definition string for a
// metric name. Centralized so the formulas block and the per-cell formula
// stay in sync.
func formulaForMetric(metric string) string {
	switch metric {
	case "PEG":
		return "PEG = P/E / EPS growth % (trailing). Values < 1 suggest undervalued growth."
	case "Piotroski":
		return "Piotroski F-score (0-9): 1 pt each for (1) positive net income, (2) positive operating CF, (3) ROA rising YoY, (4) OCF > net income, (5) long-term debt falling, (6) current ratio rising, (7) no new shares issued, (8) gross margin rising, (9) asset turnover rising. Score >=7 = strong balance sheet."
	case "AltmanZ":
		return "Altman Z-score = 1.2*A + 1.4*B + 3.3*C + 0.6*D + 1.0*E, where A=working capital/total assets, B=retained earnings/total assets, C=EBIT/total assets, D=market cap/total liabilities, E=sales/total assets. Z > 2.99 = safe, 1.81-2.99 = grey, < 1.81 = distress zone."
	case "PE":
		return "P/E = Price / Trailing EPS. Compare to industry median, not absolute."
	case "PB":
		return "P/B = Price / Book Value per share. < 1 historically means trading below liquidation value."
	case "ROE":
		return "ROE = Net Income / Shareholders' Equity. > 15% is healthy for most sectors; banks typically 12-18%."
	case "DE":
		return "D/E = Total Debt / Shareholders' Equity. < 1 is conservative; varies by sector (banks/NBFCs run high)."
	}
	return ""
}

// screenerURL returns the Screener.in consolidated-view URL for a symbol. This
// is our canonical data-gap source for Indian fundamentals — cleaner HTML than
// Moneycontrol and covers all the ratios Piotroski/Altman need.
func screenerURL(symbol string) string {
	return fmt.Sprintf("https://www.screener.in/company/%s/consolidated/", symbol)
}

func (*PeerCompareTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "peer_compare")
		args := request.GetArguments()

		if err := ValidateRequired(args, "symbols"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		p := NewArgParser(args)

		// Extract + normalize symbols (uppercase, trim).
		rawSymbols := p.StringArray("symbols")
		symbols := make([]string, 0, len(rawSymbols))
		for _, s := range rawSymbols {
			s = strings.ToUpper(strings.TrimSpace(s))
			if s != "" {
				symbols = append(symbols, s)
			}
		}

		// MVP bounds — 2 to 6 peers is the sweet spot for side-by-side comparison.
		// < 2 doesn't need a "compare" tool; > 6 is visual noise in a chat UI.
		if len(symbols) < 2 {
			return mcp.NewToolResultError(
				fmt.Sprintf("parameter 'symbols' must contain at least 2 entries (got %d); peer compare requires at least two stocks to contrast", len(symbols)),
			), nil
		}
		if len(symbols) > 6 {
			return mcp.NewToolResultError(
				fmt.Sprintf("parameter 'symbols' may contain at most 6 entries (got %d); keep the comparison focused", len(symbols)),
			), nil
		}

		// Extract + validate metrics. Empty → default to all seven.
		rawMetrics := p.StringArray("metrics")
		metrics := make([]string, 0, len(rawMetrics))
		for _, m := range rawMetrics {
			m = strings.TrimSpace(m)
			if m == "" {
				continue
			}
			if !validMetrics[m] {
				return mcp.NewToolResultError(
					fmt.Sprintf("unknown metric %q; allowed: PEG, Piotroski, AltmanZ, PE, PB, ROE, DE", m),
				), nil
			}
			metrics = append(metrics, m)
		}
		if len(metrics) == 0 {
			metrics = append(metrics, defaultMetrics...)
		}

		// Build per-symbol rows. Best-effort instrument lookup for company name;
		// unknown symbols still get pointers so the LLM can try Screener anyway.
		rows := make([]peerCompareRow, 0, len(symbols))
		for _, sym := range symbols {
			row := peerCompareRow{
				Symbol:  sym,
				Status:  "pointer_available",
				Metrics: make(map[string]peerCompareMetricCell, len(metrics)),
			}
			// Phase 3a Batch 1: route through the InstrumentsManagerProvider port.
			if instr := handler.Instruments(); instr != nil {
				if inst, err := instr.GetByTradingsymbol("NSE", sym); err == nil {
					row.CompanyName = inst.Name
					row.Exchange = inst.Exchange
				} else if inst, err := instr.GetByTradingsymbol("BSE", sym); err == nil {
					row.CompanyName = inst.Name
					row.Exchange = inst.Exchange
				} else {
					row.Status = "symbol_not_found"
				}
			} else {
				row.Status = "symbol_not_found"
			}

			srcURL := screenerURL(sym)
			for _, metric := range metrics {
				row.Metrics[metric] = peerCompareMetricCell{
					Metric:     metric,
					Status:     "needs_external_data",
					SourceHint: srcURL,
					Formula:    formulaForMetric(metric),
				}
			}
			rows = append(rows, row)
		}

		// Formulas block — mirrors what's in each cell but keyed by metric name,
		// so the LLM has one canonical reference section to cite.
		formulas := make(map[string]string, len(metrics))
		for _, m := range metrics {
			if f := formulaForMetric(m); f != "" {
				formulas[m] = f
			}
		}

		resp := &peerCompareResponse{
			Symbols:          symbols,
			MetricsRequested: metrics,
			ComparisonTable:  rows,
			Formulas:         formulas,
			NextSteps: []string{
				"For each symbol, use WebFetch or Tavily on the source_hint URL (Screener.in consolidated view) to pull the fundamentals table",
				"Extract trailing P/E, EPS growth %, ROE, ROA, current ratio, long-term debt, gross margin, operating CF, net income, total assets, retained earnings, EBIT, market cap, total liabilities, and sales from the Screener page",
				"Compute the requested scores per symbol using the formulas block below",
				"Compare scores side-by-side and flag any symbol with Piotroski < 5 or Altman Z < 1.81 as a fundamental-strength concern",
				"If Moneycontrol has fresher data, cross-check PEG and ROE there (Screener lags quarterly filings by ~1 week)",
			},
			Disclaimer: "This tool does not fetch fundamentals itself; it returns structured data-gap pointers. All numbers must be verified on Screener.in / the source URL. Scores are screening tools, not investment advice — always do your own research and read the latest quarterly filings.",
		}

		return handler.MarshalResponse(resp, "peer_compare")
	}
}

func init() { RegisterInternalTool(&PeerCompareTool{}) }
