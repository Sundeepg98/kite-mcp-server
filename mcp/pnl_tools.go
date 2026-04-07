package mcp

import (
	"context"
	"fmt"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// GetPnLJournalTool retrieves historical P&L data with statistics.
type GetPnLJournalTool struct{}

func (*GetPnLJournalTool) Tool() mcp.Tool {
	return mcp.NewTool("get_pnl_journal",
		mcp.WithDescription("Get your daily P&L journal with cumulative returns, best/worst days, and streak analysis. "+
			"Data is captured automatically at 3:40 PM IST each trading day. "+
			"Use 'period' for quick ranges or 'from'/'to' for custom dates."),
		mcp.WithTitleAnnotation("Get P&L Journal"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
		mcp.WithString("period",
			mcp.Description("Quick date range: 'week' (last 7 days), 'month' (last 30 days), 'quarter' (last 90 days), 'year' (last 365 days), or 'all' (all time). Ignored if 'from' is provided."),
			mcp.Enum("week", "month", "quarter", "year", "all"),
		),
		mcp.WithString("from",
			mcp.Description("Start date (YYYY-MM-DD format). Overrides 'period'."),
		),
		mcp.WithString("to",
			mcp.Description("End date (YYYY-MM-DD format). Defaults to today if omitted."),
		),
	)
}

func (*GetPnLJournalTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "get_pnl_journal")

		email := oauth.EmailFromContext(ctx)
		if email == "" {
			return mcp.NewToolResultError("Email required (OAuth must be enabled)"), nil
		}

		pnlService := manager.PnLService()
		if pnlService == nil {
			return mcp.NewToolResultError("P&L journal not available (requires database persistence)"), nil
		}

		args := request.GetArguments()
		p := NewArgParser(args)
		fromDate := p.String("from", "")
		toDate := p.String("to", "")
		period := p.String("period", "month")

		now := time.Now()

		// If no explicit from date, use period
		if fromDate == "" {
			switch period {
			case "week":
				fromDate = now.AddDate(0, 0, -7).Format("2006-01-02")
			case "month":
				fromDate = now.AddDate(0, -1, 0).Format("2006-01-02")
			case "quarter":
				fromDate = now.AddDate(0, -3, 0).Format("2006-01-02")
			case "year":
				fromDate = now.AddDate(-1, 0, 0).Format("2006-01-02")
			case "all":
				fromDate = "2020-01-01" // far enough back
			default:
				fromDate = now.AddDate(0, -1, 0).Format("2006-01-02")
			}
		}

		if toDate == "" {
			toDate = now.Format("2006-01-02")
		}

		// Validate date format
		if _, err := time.Parse("2006-01-02", fromDate); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Invalid 'from' date format: %s (expected YYYY-MM-DD)", fromDate)), nil
		}
		if _, err := time.Parse("2006-01-02", toDate); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Invalid 'to' date format: %s (expected YYYY-MM-DD)", toDate)), nil
		}

		result, err := pnlService.GetJournal(email, fromDate, toDate)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to get P&L journal: %s", err)), nil
		}

		if result.TotalDays == 0 {
			return mcp.NewToolResultText(fmt.Sprintf("No P&L data found for %s to %s. Data is captured daily at 3:40 PM IST.", fromDate, toDate)), nil
		}

		return handler.MarshalResponse(result, "get_pnl_journal")
	}
}
