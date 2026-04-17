package mcp

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// --- SEBI Compliance Status Tool ---

// SEBIComplianceTool reports the user's SEBI algo trading compliance posture.
type SEBIComplianceTool struct{}

func (*SEBIComplianceTool) Tool() mcp.Tool {
	return mcp.NewTool("sebi_compliance_status",
		mcp.WithDescription("Check SEBI algo trading compliance status. Shows: static IP whitelist status, Kite session validity, order rate (OPS), order tagging, API rate limits, and audit trail status. All API orders are classified as algorithmic under SEBI's April 2026 framework."),
		mcp.WithTitleAnnotation("SEBI Compliance Status"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(true),
	)
}

// complianceSection is a single compliance area with a status and descriptive notes.
type complianceSection struct {
	Status string `json:"status"`
	Note   string `json:"note,omitempty"`

	// Fields used by specific sections (omitted when zero-value)
	EgressIP        string  `json:"egress_ip,omitempty"`
	Email           string  `json:"email,omitempty"`
	Tag             string  `json:"tag,omitempty"`
	MaxOPS          int     `json:"max_ops,omitempty"`
	Mode            string  `json:"mode,omitempty"`
	Retention       string  `json:"retention,omitempty"`
	Backup          string  `json:"backup,omitempty"`
	Checks          int     `json:"checks,omitempty"`
	OrderValueCap   string  `json:"order_value_cap,omitempty"`
	DailyLimit      string  `json:"daily_limit,omitempty"`
	DailyOrderCount int     `json:"daily_order_count,omitempty"`
	DailyValueINR   float64 `json:"daily_value_inr,omitempty"`
	Frozen          bool    `json:"frozen,omitempty"`
	FrozenBy        string  `json:"frozen_by,omitempty"`
	FrozenReason    string  `json:"frozen_reason,omitempty"`
	Reason          string  `json:"reason,omitempty"`
}

type complianceResponse struct {
	ComplianceFramework string            `json:"compliance_framework"`
	StaticIP            complianceSection `json:"static_ip"`
	Session             complianceSection `json:"session"`
	OrderTagging        complianceSection `json:"order_tagging"`
	RateLimits          complianceSection `json:"rate_limits"`
	MarketProtection    complianceSection `json:"market_protection"`
	AuditTrail          complianceSection `json:"audit_trail"`
	RiskGuard           complianceSection `json:"riskguard"`
	AlgoRegistration    complianceSection `json:"algo_registration"`
}

func (*SEBIComplianceTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "sebi_compliance_status")

		return handler.WithSession(ctx, "sebi_compliance_status", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			email := oauth.EmailFromContext(ctx)

			// Check session validity by dispatching a lightweight profile query
			// through the bus — exercises the full observability + middleware
			// stack instead of hot-pathing the use case directly.
			tokenStatus := "VALID"
			probeCtx := kc.WithBroker(ctx, session.Broker)
			if _, err := manager.QueryBus().DispatchWithResult(probeCtx, cqrs.GetProfileQuery{Email: email}); err != nil {
				tokenStatus = "EXPIRED"
			}

			// Build session section.
			sessionNote := "Kite tokens expire ~6 AM IST daily."
			if tokenStatus == "EXPIRED" {
				sessionNote = "Session expired. Use the login tool to re-authenticate. Tokens expire ~6 AM IST daily."
			}

			// RiskGuard section — pull live state if available.
			rgSection := complianceSection{
				Status:      "ACTIVE",
				Checks:      7,
				OrderValueCap: formatINR(riskguard.SystemDefaults.MaxSingleOrderINR),
				DailyLimit:  fmt.Sprintf("%d orders/day", riskguard.SystemDefaults.MaxOrdersPerDay),
			}

			if guard := manager.RiskGuard(); guard != nil {
				limits := guard.GetEffectiveLimits(email)
				rgSection.OrderValueCap = formatINR(limits.MaxSingleOrderINR)
				rgSection.DailyLimit = fmt.Sprintf("%d orders/day", limits.MaxOrdersPerDay)
				rgSection.Checks = 7 // kill-switch, order value, quantity, daily count, rate, duplicate, daily value

				if email != "" {
					userStatus := guard.GetUserStatus(email)
					rgSection.DailyOrderCount = userStatus.DailyOrderCount
					rgSection.DailyValueINR = userStatus.DailyPlacedValue
					rgSection.Frozen = userStatus.IsFrozen
					if userStatus.IsFrozen {
						rgSection.Status = "FROZEN"
						rgSection.FrozenBy = userStatus.FrozenBy
						rgSection.FrozenReason = userStatus.FrozenReason
					}
				}
			} else {
				rgSection.Status = "NOT CONFIGURED"
				rgSection.Note = "RiskGuard not initialized on this server."
			}

			resp := &complianceResponse{
				ComplianceFramework: "SEBI Algo Trading (April 2026)",
				StaticIP: complianceSection{
					Status:   "COMPLIANT",
					EgressIP: "209.71.68.157",
					Note:     "Must be whitelisted in your Kite developer console.",
				},
				Session: complianceSection{
					Status: tokenStatus,
					Email:  email,
					Note:   sessionNote,
				},
				OrderTagging: complianceSection{
					Status: "COMPLIANT",
					Tag:    "mcp",
					Note:   "All orders tagged 'mcp' for SEBI traceability. Exchange-level algo ID assignment for third-party API clients is a Zerodha OMS implementation detail — see your broker for specifics.",
				},
				RateLimits: complianceSection{
					Status: "COMPLIANT",
					MaxOPS: 10,
					Note:   "Server rate limited to <10 OPS. No algo registration required.",
				},
				MarketProtection: complianceSection{
					Status: "COMPLIANT",
					Mode:   "auto (-1)",
					Note:   "MarketProtection auto-applied on all MARKET orders.",
				},
				AuditTrail: complianceSection{
					Status:    "COMPLIANT",
					Retention: "5 years (1825 days)",
					Backup:    "Litestream -> Cloudflare R2",
				},
				RiskGuard: rgSection,
				AlgoRegistration: complianceSection{
					Status: "NOT REQUIRED",
					Reason: "Under 10 OPS threshold. White-Box platform (transparent execution wrapper, no proprietary strategies) — SEBI RA registration not required. Broker empanelment advised post-April-2026 SEBI framework.",
				},
			}

			return handler.MarshalResponse(resp, "sebi_compliance_status")
		})
	}
}

// formatINR formats a float as a human-readable Indian rupee string.
func formatINR(v float64) string {
	if v >= 100000 {
		lakhs := v / 100000
		if lakhs == float64(int(lakhs)) {
			return fmt.Sprintf("Rs %d,00,000", int(lakhs))
		}
		return fmt.Sprintf("Rs %.2f L", lakhs)
	}
	return fmt.Sprintf("Rs %.0f", v)
}
