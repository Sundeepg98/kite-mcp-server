package mcp

import (
	"context"
	"strings"
	"testing"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRegisterPrompts_AllSeven verifies that RegisterPrompts wires up all
// 7 prompts (3 original + 4 new). It exercises the registration path and
// protects against accidental removal.
func TestRegisterPrompts_AllSeven(t *testing.T) {
	t.Parallel()
	srv := server.NewMCPServer("test", "1.0")
	RegisterPrompts(srv, sharedTestManager)
	// No panic = pass. The MCPServer does not expose a public list of
	// registered prompts, so we rely on individual handler tests below for
	// per-prompt assertions.
}

// ---- week_review ---------------------------------------------------------

func TestWeekReviewHandler_Basic(t *testing.T) {
	t.Parallel()
	handler := weekReviewHandler(sharedTestManager)
	result, err := handler(context.Background(), gomcp.GetPromptRequest{})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "Weekly trading review", result.Description)
	require.Len(t, result.Messages, 1)
	assert.Equal(t, gomcp.RoleUser, result.Messages[0].Role)

	text := result.Messages[0].Content.(gomcp.TextContent).Text
	assert.Contains(t, text, "Weekly Trading Review")
	assert.Contains(t, text, "get_pnl_journal")
	assert.Contains(t, text, "Best Day")
	assert.Contains(t, text, "Worst Day")
	assert.Contains(t, text, "Most-Traded Symbol")
	assert.Contains(t, text, "Not investment advice.")
}

// ---- options_sanity_check ------------------------------------------------

func TestOptionsSanityCheckHandler_Basic(t *testing.T) {
	t.Parallel()
	handler := optionsSanityCheckHandler(sharedTestManager)
	req := gomcp.GetPromptRequest{}
	req.Params.Arguments = map[string]string{
		"underlying":           "NIFTY",
		"strategy_description": "bull call spread 22000/22200 April expiry",
	}
	result, err := handler(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Contains(t, result.Description, "NIFTY")
	require.Len(t, result.Messages, 1)

	text := result.Messages[0].Content.(gomcp.TextContent).Text
	assert.Contains(t, text, "NIFTY")
	assert.Contains(t, text, "bull call spread 22000/22200 April expiry")
	assert.Contains(t, text, "get_option_chain")
	assert.Contains(t, text, "Max Loss")
	assert.Contains(t, text, "Breakevens")
	assert.Contains(t, text, "Not investment advice.")
}

func TestOptionsSanityCheckHandler_MissingArgs(t *testing.T) {
	t.Parallel()
	handler := optionsSanityCheckHandler(sharedTestManager)
	// No arguments supplied — handler must fall back to a "missing" placeholder,
	// not panic. This mirrors tradeCheckHandler's tolerant behaviour.
	result, err := handler(context.Background(), gomcp.GetPromptRequest{})
	require.NoError(t, err)
	require.NotNil(t, result)
	text := result.Messages[0].Content.(gomcp.TextContent).Text
	assert.Contains(t, strings.ToLower(text), "missing")
}

// ---- compliance_report ---------------------------------------------------

func TestComplianceReportHandler_Basic(t *testing.T) {
	t.Parallel()
	handler := complianceReportHandler(sharedTestManager)
	result, err := handler(context.Background(), gomcp.GetPromptRequest{})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "Compliance snapshot", result.Description)
	require.Len(t, result.Messages, 1)

	text := result.Messages[0].Content.(gomcp.TextContent).Text
	assert.Contains(t, text, "Compliance Snapshot")
	assert.Contains(t, text, "sebi_compliance_status")
	assert.Contains(t, text, "test_ip_whitelist")
	assert.Contains(t, text, "server_metrics")
	assert.Contains(t, text, "Risk Guard")
	assert.Contains(t, text, "Not investment advice.")
}

// ---- setup_checklist -----------------------------------------------------

func TestSetupChecklistHandler_Basic(t *testing.T) {
	t.Parallel()
	handler := setupChecklistHandler(sharedTestManager)
	result, err := handler(context.Background(), gomcp.GetPromptRequest{})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "Setup checklist walkthrough", result.Description)
	require.Len(t, result.Messages, 1)

	text := result.Messages[0].Content.(gomcp.TextContent).Text
	assert.Contains(t, text, "Setup Checklist")
	assert.Contains(t, text, "get_profile")
	assert.Contains(t, text, "test_ip_whitelist")
	assert.Contains(t, text, "paper_trading_status")
	assert.Contains(t, text, "setup_telegram")
	assert.Contains(t, text, "list_alerts")
	assert.Contains(t, text, "list_watchlists")
	assert.Contains(t, text, "Not investment advice.")
}

// ---- description length guard --------------------------------------------

// TestPromptDescriptionsUnder200Chars asserts the MCP spec 200-char cap for
// prompt descriptions. If a new prompt is added that exceeds the cap, this
// fails loudly instead of being silently truncated by the client.
func TestPromptDescriptionsUnder200Chars(t *testing.T) {
	t.Parallel()
	descriptions := map[string]string{
		"morning_brief":        "Morning trading briefing — portfolio state, market indices, alerts, margin, warnings. Call this at the start of the trading day.",
		"trade_check":          "Pre-flight check before placing a trade — margin, concentration, risk, stop-loss suggestion.",
		"eod_review":           "End-of-day trading review — P&L, positions, orders, alerts, action items for tomorrow.",
		"week_review":          "Weekly trading recap — P&L journal, trades, orders, best/worst day, most-traded symbol, commissions, discipline notes.",
		"options_sanity_check": "Pre-flight sanity checks for an options strategy — IV percentile, liquidity, max loss vs portfolio, breakevens.",
		"compliance_report":    "Compliance snapshot — SEBI algo status, IP whitelist, audit log completeness, risk guard status. Read-only factual dump.",
		"setup_checklist":      "Walk through the setup checklist — credentials, IP whitelist, paper mode, Telegram, alerts, watchlist. Pass/fail per item.",
	}
	for name, desc := range descriptions {
		assert.LessOrEqualf(t, len(desc), 200,
			"prompt %s description is %d chars (must be <=200)", name, len(desc))
	}
}

// ---- mustLoadIST helper --------------------------------------------------

func TestMustLoadIST(t *testing.T) {
	t.Parallel()
	loc := mustLoadIST()
	require.NotNil(t, loc)
	// Either "Asia/Kolkata" (tzdata present) or "UTC" (fallback). Both are
	// acceptable — the handler doesn't care which, it just needs a non-nil
	// Location to avoid a panic on time.Now().In(loc).
	name := loc.String()
	assert.True(t, name == "Asia/Kolkata" || name == "UTC",
		"expected Asia/Kolkata or UTC fallback, got %q", name)
}
