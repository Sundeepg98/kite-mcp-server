package mcp

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
)

// GetFIIDIIFlowTool is a "frame the LLM" tool for Indian institutional flow
// analysis. It returns a structured pointer to the NSE/BSE/Moneycontrol daily
// FII/DII data sources + guidance on what to extract — it does NOT scrape
// NSE itself (NSE aggressively rate-limits unauthenticated bots, and we want
// zero infrastructure burden).
//
// Why this matters (from agent 32's research-copilot audit):
//   - Every retail tool surfaces FII/DII daily flow. Not having it is a
//     disqualifying gap vs. Groww/Dhan/Smallcase's research layer.
//   - Tells the user *who* is net-buying/selling the market on any given day,
//     which is one of the most-watched leading indicators for Indian equities.
//   - FII vs DII divergence (one buying, the other selling heavily) is a
//     classic volatility setup that preceded several 2025 drawdowns.
//
// Design mirrors AnalyzeConcallTool (commit 682fc06): return structured
// metadata + a URL pointer, let the LLM do the fetching via WebFetch/Tavily
// in the same chat session. Zero scraping on our side.
type GetFIIDIIFlowTool struct{}

func (*GetFIIDIIFlowTool) Tool() mcp.Tool {
	return mcp.NewTool("get_fii_dii_flow",
		mcp.WithDescription("Get FII/DII (Foreign/Domestic Institutional Investor) daily buy/sell activity for the Indian equity market. Returns a structured URL pointer + guidance telling the LLM to fetch the data from NSE/Moneycontrol via WebFetch/Tavily. Does not fetch the data itself. Useful for checking which side institutions are net-buying/selling on any given day; divergence between FII and DII flows often precedes short-term volatility."),
		mcp.WithTitleAnnotation("FII/DII Daily Flow"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(true),
		mcp.WithString("date", mcp.Description("Date in YYYY-MM-DD format. Optional — defaults to the most recent trading day (weekends roll back to Friday). Future dates still render, but data won't exist yet.")),
		mcp.WithNumber("days", mcp.Description("Number of recent days to analyze, 1..30. Optional, default 1. Values outside the range are clamped.")),
		mcp.WithString("segment", mcp.Description("Market segment. One of 'cash' (default), 'fo' (futures+options), or 'both'. Case-insensitive.")),
	)
}

// fiiDIIURLs enumerates the data sources the LLM should fetch. NSE is the
// primary source (authoritative); Moneycontrol is a fallback that's easier
// to parse (clean HTML table) and is what most retail tools actually use.
type fiiDIIURLs struct {
	NSEDaily           string `json:"nse_daily"`
	NSEFIIDII          string `json:"nse_fii_dii"`
	MoneycontrolFIIDII string `json:"moneycontrol_fii_dii"`
}

// fiiDIIResponse is the structured payload returned by get_fii_dii_flow.
// The text fallback (via MarshalResponse) contains the same JSON so LLM
// clients without structuredContent parsing still get readable guidance.
type fiiDIIResponse struct {
	Date       string     `json:"date"`
	Segment    string     `json:"segment"`
	Days       int        `json:"days"`
	DataSource string     `json:"data_source"`
	URLs       fiiDIIURLs `json:"urls"`
	Themes     []string   `json:"themes_to_extract"`
	NextSteps  []string   `json:"next_steps"`
	Disclaimer string     `json:"disclaimer"`
}

func (*GetFIIDIIFlowTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "get_fii_dii_flow")
		p := NewArgParser(request.GetArguments())

		// Date — default to latest trading day. Validate format if provided so
		// the LLM gets a clear error rather than a URL with a mangled date.
		date := strings.TrimSpace(p.String("date", ""))
		if date == "" {
			date = latestTradingDay(time.Now())
		} else {
			if _, err := time.Parse("2006-01-02", date); err != nil {
				return mcp.NewToolResultError("parameter 'date' must be YYYY-MM-DD format (e.g. 2026-04-15), got: " + date), nil
			}
		}

		// Days — clamp to [1, 30].
		days := p.Int("days", 1)
		if days < 1 {
			days = 1
		} else if days > 30 {
			days = 30
		}

		// Segment — accept cash | fo | both (case-insensitive).
		segment := strings.ToLower(strings.TrimSpace(p.String("segment", "cash")))
		if segment == "" {
			segment = "cash"
		}
		switch segment {
		case "cash", "fo", "both":
			// ok
		default:
			return mcp.NewToolResultError("parameter 'segment' must be one of: cash, fo, both (got: " + segment + ")"), nil
		}

		resp := &fiiDIIResponse{
			Date:       date,
			Segment:    segment,
			Days:       days,
			DataSource: "NSE (primary), Moneycontrol (fallback; easier to parse)",
			URLs: fiiDIIURLs{
				NSEDaily:           "https://www.nseindia.com/reports/fao/recent",
				NSEFIIDII:          "https://www.nseindia.com/market-data/fii-dii-trading-activity",
				MoneycontrolFIIDII: "https://www.moneycontrol.com/stocks/marketstats/fii_dii_activity/index.php",
			},
			Themes: []string{
				"Net buy/sell amount by FII (Foreign Institutional Investors) in INR crore",
				"Net buy/sell amount by DII (Domestic Institutional Investors) in INR crore",
				"Cumulative flow trend over the requested lookback window",
				"Divergence: FII selling while DII buying (or vice versa) — classic volatility setup",
				"Sector-specific flow if reported (banks, IT, auto, etc.)",
				"F&O segment flow vs cash segment flow when segment='both'",
			},
			NextSteps: []string{
				"Use WebFetch or Tavily on the moneycontrol_fii_dii URL for a clean tabular daily view (easiest to parse)",
				"If the Moneycontrol page is incomplete, fall back to the nse_fii_dii URL (authoritative but JS-heavy)",
				"For multi-day analysis (days > 1), scroll through the last " + strconv.Itoa(days) + " trading days on the same page",
				"Flag any day where FII and DII flows exceed ±INR 2000 crore in opposite directions (divergence signal)",
				"Summarize the trend and, if relevant, correlate with index moves on the same dates",
			},
			Disclaimer: "This tool does not fetch live data; it returns a structured pointer for the LLM to fetch via WebFetch/Tavily. All numbers must be verified on the source URL. Not investment advice — flow data is indicative, not predictive.",
		}

		return handler.MarshalResponse(resp, "get_fii_dii_flow")
	}
}

// latestTradingDay returns YYYY-MM-DD for the most recent Indian equity
// trading day as of `now`. Weekends (Saturday/Sunday) roll back to the
// previous Friday. We do NOT account for NSE/BSE holidays (Independence Day,
// Diwali, etc.) — the LLM is expected to surface "no data" if the date is
// a holiday, and the user can then retry with an explicit date.
func latestTradingDay(now time.Time) string {
	d := now
	switch d.Weekday() {
	case time.Saturday:
		d = d.AddDate(0, 0, -1) // back to Friday
	case time.Sunday:
		d = d.AddDate(0, 0, -2) // back to Friday
	}
	return d.Format("2006-01-02")
}

