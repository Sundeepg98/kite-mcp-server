package mcp

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
)

// AnalyzeConcallTool is a "frame the LLM" tool for Indian earnings-call
// (concall) analysis. It does not fetch transcripts itself — scraping BSE /
// broker-research PDFs at scale is brittle and expensive. Instead, it returns
// structured metadata + a well-formed pointer (BSE corporate-announcements
// URL) that the LLM can feed into WebFetch / Tavily in the same chat session.
//
// Why this design:
//   - Zero infrastructure cost. The LLM does the summarization client-side.
//   - Works inside Claude / ChatGPT where users can already fetch PDFs.
//   - Agent 32 identified concall analysis as the #1 AI-native pull for
//     Indian retail (Trendlyne charges Rs 310/mo for it; Dhanarthi built a
//     user base around it).
//
// MVP scope: return the URL + structured guidance. A future enhancement can
// add a transcript-cache + themed summarizer.
type AnalyzeConcallTool struct{}

func (*AnalyzeConcallTool) Tool() mcp.Tool {
	return mcp.NewTool("analyze_concall",
		mcp.WithDescription("Frame an earnings-call (concall) analysis for an Indian listed stock. Returns structured metadata (company name, quarter, BSE corporate-announcements URL) plus a guidance block telling the LLM which transcript-fetching tool to use and which themes to extract (guidance, orders, margins, management commentary, risks). Does not fetch the transcript itself — the LLM is expected to call WebFetch / Tavily on the returned URL. Default quarter is the most recently completed Indian fiscal quarter (Apr–Mar fiscal year)."),
		mcp.WithTitleAnnotation("Analyze Earnings Concall"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(true),
		mcp.WithString("symbol", mcp.Description("Trading symbol of the listed company, e.g. INFY, RELIANCE, TCS. Case-insensitive; uppercased internally."), mcp.Required()),
		mcp.WithString("quarter", mcp.Description("Indian fiscal quarter in QxFYyy form (e.g. Q4FY25 for Jan-Mar 2025). Optional — defaults to the most recently completed quarter inferred from today's date.")),
		mcp.WithString("year", mcp.Description("Calendar year (e.g. 2025) — currently informational only. The quarter string is authoritative.")),
	)
}

// concallResponse is the structured payload returned by analyze_concall.
// The text fallback (via MarshalResponse) contains the same JSON so LLM
// clients without structuredContent parsing still get readable guidance.
type concallResponse struct {
	Symbol         string   `json:"symbol"`
	Exchange       string   `json:"exchange"`
	CompanyName    string   `json:"company_name"`
	Quarter        string   `json:"quarter"`
	Year           string   `json:"year,omitempty"`
	DocumentStatus string   `json:"document_status"` // "pointer_available" | "unknown_symbol"
	TranscriptHint string   `json:"transcript_hint"`
	BSEAnnouncementURL string `json:"bse_announcement_url"`
	NextSteps      []string `json:"next_steps"`
	Themes         []string `json:"themes_to_extract"`
	Disclaimer     string   `json:"disclaimer"`
}

func (*AnalyzeConcallTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "analyze_concall")
		args := request.GetArguments()

		if err := ValidateRequired(args, "symbol"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		p := NewArgParser(args)
		symbol := strings.ToUpper(strings.TrimSpace(p.String("symbol", "")))
		quarter := strings.ToUpper(strings.TrimSpace(p.String("quarter", "")))
		year := strings.TrimSpace(p.String("year", ""))

		if quarter == "" {
			quarter = latestIndianFiscalQuarter(time.Now())
		}

		// Lookup instrument for company name — best effort. Unknown symbols
		// still get a pointer, flagged with document_status=unknown_symbol
		// so the LLM can warn the user or try the URL anyway.
		companyName := ""
		exchange := "NSE" // default assumption for Indian equities
		documentStatus := "pointer_available"
		if manager != nil && manager.Instruments != nil {
			if inst, err := manager.Instruments.GetByTradingsymbol("NSE", symbol); err == nil {
				companyName = inst.Name
				exchange = inst.Exchange
			} else if inst, err := manager.Instruments.GetByTradingsymbol("BSE", symbol); err == nil {
				companyName = inst.Name
				exchange = inst.Exchange
			} else {
				documentStatus = "unknown_symbol"
			}
		} else {
			// No instruments manager available — still return a pointer but
			// flag that we couldn't verify the symbol.
			documentStatus = "unknown_symbol"
		}

		bseURL := fmt.Sprintf("https://www.bseindia.com/stock-share-price/%s/corporate-announcements/", symbol)

		resp := &concallResponse{
			Symbol:             symbol,
			Exchange:           exchange,
			CompanyName:        companyName,
			Quarter:            quarter,
			Year:               year,
			DocumentStatus:     documentStatus,
			BSEAnnouncementURL: bseURL,
			TranscriptHint: fmt.Sprintf(
				"Search the BSE announcements page for a PDF titled 'Earnings Call Transcript' or 'Concall' dated within 30-60 days of %s quarter-end. Broker research (Motilal Oswal, ICICI Direct, Kotak) also publishes concall notes on their research portals.",
				quarter,
			),
			NextSteps: []string{
				fmt.Sprintf("Use WebFetch or Tavily to load %s", bseURL),
				"Search the rendered page for a PDF link containing 'Concall' or 'Earnings Call'",
				"If found, WebFetch the PDF URL and summarize against the themes below",
				"If not found, tell the user the transcript has not yet been published for this quarter",
			},
			Themes: []string{
				"Management guidance for the next 2-4 quarters (revenue, margin, volume)",
				"Order book / deal wins (TCV, geographical / segment mix)",
				"Operating margin trajectory + drivers (wage hikes, utilization, FX)",
				"Commentary on demand environment (BFSI, retail, manufacturing slowdown)",
				"Capex / buyback / dividend announcements",
				"Key risks called out by management (regulatory, competitive, client concentration)",
				"Q&A pushback — what analysts pressed on and how management responded",
			},
			Disclaimer: "This tool does not fetch the transcript itself. All analysis is performed client-side by the LLM after fetching the document. Information is based on publicly disclosed concall transcripts — not investment advice.",
		}

		return handler.MarshalResponse(resp, "analyze_concall")
	}
}

// latestIndianFiscalQuarter returns the QxFYyy string for the most recently
// *completed* Indian fiscal quarter as of `now`. Indian fiscal year runs
// April 1 - March 31; FY25 means April 2024 - March 2025.
//
// Current-quarter → previous-quarter mapping:
//
//	Apr-Jun (Q1 of FYnext) → previous = Q4 of FYcurr  (Jan-Mar yearEnd)
//	Jul-Sep (Q2 of FYnext) → previous = Q1 of FYnext
//	Oct-Dec (Q3 of FYnext) → previous = Q2 of FYnext
//	Jan-Mar (Q4 of FYcurr) → previous = Q3 of FYcurr
//
// We return the quarter whose *results* are most likely available now —
// concalls typically happen 30-60 days after quarter-end, so the just-ended
// quarter is what the user most likely wants to analyse.
func latestIndianFiscalQuarter(now time.Time) string {
	m := int(now.Month())
	y := now.Year()

	var q int
	var fy int
	switch {
	case m >= 1 && m <= 3:
		// Currently in Q4 of FY ending this year. Previous = Q3 of same FY.
		q = 3
		fy = y
	case m >= 4 && m <= 6:
		// Currently in Q1 of FY ending next year. Previous = Q4 of FY that
		// just ended (ends in the current calendar year, so FY = y).
		q = 4
		fy = y
	case m >= 7 && m <= 9:
		// Currently in Q2. Previous = Q1 of same FY (ends next year).
		q = 1
		fy = y + 1
	default: // m 10-12
		// Currently in Q3. Previous = Q2 of same FY.
		q = 2
		fy = y + 1
	}
	return fmt.Sprintf("Q%dFY%02d", q, fy%100)
}
