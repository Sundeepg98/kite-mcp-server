package ops

import (
	"fmt"
	"net/http"
	"strings"
	htmltemplate "html/template"

	"github.com/zerodha/kite-mcp-server/kc/billing"
	"github.com/zerodha/kite-mcp-server/oauth"
)

func (d *DashboardHandler) serveBillingPage(w http.ResponseWriter, r *http.Request) {
	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		http.Redirect(w, r, "/auth/login", http.StatusFound)
		return
	}

	tier := "Free"
	status := ""
	maxUsers := 1
	memberCount := 0
	adminEmail := ""
	isAdmin := false
	hasStripe := false

	if d.adminCheck != nil {
		isAdmin = d.adminCheck(email)
	}

	if d.billingStore != nil {
		if sub := d.billingStore.GetSubscription(email); sub != nil {
			tier = tierDisplayName(sub.Tier)
			status = sub.Status
			maxUsers = sub.MaxUsers
			hasStripe = sub.StripeCustomerID != ""
		}
	}

	// Check if family member (inherited tier from admin).
	if d.manager != nil {
		if uStore := d.manager.UserStore(); uStore != nil {
			if u, ok := uStore.Get(email); ok && u.AdminEmail != "" {
				adminEmail = u.AdminEmail
				// Get admin's tier if user has no direct subscription.
				if tier == "Free" && d.billingStore != nil {
					if adminSub := d.billingStore.GetSubscription(u.AdminEmail); adminSub != nil {
						tier = tierDisplayName(adminSub.Tier)
						status = adminSub.Status
					}
				}
			}
			// Count family members if admin.
			if isAdmin {
				memberCount = len(uStore.ListByAdminEmail(email))
			}
		}
	}

	// Build feature list per tier.
	type feature struct {
		Name    string
		Enabled bool
	}
	features := []feature{
		{"Read-only market data", true},
		{"Paper trading", true},
		{"Watchlists", true},
		{"Basic portfolio view", true},
		{"Live order execution", tier == "Pro" || tier == "Premium"},
		{"GTT orders", tier == "Pro" || tier == "Premium"},
		{"Price alerts + Telegram", tier == "Pro" || tier == "Premium"},
		{"Trailing stops", tier == "Pro" || tier == "Premium"},
		{"Advanced analytics", tier == "Pro" || tier == "Premium"},
		{"Backtesting", tier == "Premium"},
		{"Options strategies", tier == "Premium"},
		{"Technical indicators", tier == "Premium"},
		{"Tax harvesting", tier == "Premium"},
		{"SEBI compliance", tier == "Premium"},
	}

	// Status badge color.
	statusColor := "#64748b" // gray for unknown/empty
	statusLabel := "—"
	switch status {
	case "active", "trialing":
		statusColor = "#34d399" // green
		statusLabel = strings.ToUpper(status[:1]) + status[1:]
	case "past_due":
		statusColor = "#fbbf24" // amber
		statusLabel = "Past Due"
	case "canceled":
		statusColor = "#f87171" // red
		statusLabel = "Canceled"
	default:
		if tier == "Free" {
			statusLabel = "Active"
			statusColor = "#34d399"
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Account &amp; Billing - Kite MCP</title>
<link rel="stylesheet" href="/static/dashboard-base.css">
<style>
.billing-wrap{max-width:640px;margin:0 auto;padding:40px 20px}
.billing-header{margin-bottom:32px}
.billing-header h1{font-size:1.5rem;font-weight:700;color:var(--text-0,#e2e8f0);margin-bottom:4px}
.billing-header p{color:var(--text-1,#94a3b8);font-size:0.9rem}
.tier-card{border:1px solid var(--border,#1e293b);border-radius:12px;padding:28px 24px;margin-bottom:24px;background:var(--card-bg,rgba(30,41,59,0.3))}
.tier-row{display:flex;align-items:center;gap:12px;margin-bottom:16px}
.tier-name{font-size:1.6rem;font-weight:700;color:var(--text-0,#e2e8f0)}
.tier-badge{display:inline-block;padding:3px 10px;border-radius:20px;font-size:0.75rem;font-weight:600;letter-spacing:0.03em}
.tier-meta{color:var(--text-1,#94a3b8);font-size:0.85rem;line-height:1.5}
.features-card{border:1px solid var(--border,#1e293b);border-radius:12px;padding:24px;margin-bottom:24px;background:var(--card-bg,rgba(30,41,59,0.3))}
.features-card h3{font-size:1rem;font-weight:600;color:var(--text-0,#e2e8f0);margin-bottom:16px}
.feature-list{list-style:none;padding:0;margin:0;columns:2;column-gap:24px}
.feature-list li{padding:6px 0;font-size:0.85rem;break-inside:avoid}
.feature-list li.on{color:var(--text-1,#94a3b8)}
.feature-list li.on::before{content:"\2713 ";color:#34d399;font-weight:700}
.feature-list li.off{color:var(--text-2,#475569)}
.feature-list li.off::before{content:"\2717 ";color:#475569;font-weight:700}
.family-card{border:1px solid var(--border,#1e293b);border-radius:12px;padding:24px;margin-bottom:24px;background:var(--card-bg,rgba(30,41,59,0.3))}
.family-card h3{font-size:1rem;font-weight:600;color:var(--text-0,#e2e8f0);margin-bottom:12px}
.family-card p{color:var(--text-1,#94a3b8);font-size:0.85rem;line-height:1.5}
.actions{display:flex;gap:12px;flex-wrap:wrap}
.btn{display:inline-block;padding:10px 20px;border-radius:6px;font-weight:600;font-size:0.85rem;text-decoration:none;text-align:center;cursor:pointer;border:none}
.btn-primary{background:#22d3ee;color:#0a0c10}
.btn-primary:hover{opacity:0.9}
.btn-secondary{background:transparent;color:#94a3b8;border:1px solid #1e293b}
.btn-secondary:hover{border-color:#334155;color:#e2e8f0}
.back-link{display:inline-block;margin-top:24px;color:var(--accent,#22d3ee);font-size:0.85rem;text-decoration:none}
.back-link:hover{text-decoration:underline}
</style>
</head>
<body>
<div class="billing-wrap">
<div class="billing-header">
<h1>Account &amp; Billing</h1>
<p>%s</p>
</div>
`, htmltemplate.HTMLEscapeString(email))

	// Tier card.
	fmt.Fprintf(w, `<div class="tier-card">
<div class="tier-row">
<span class="tier-name">%s</span>
<span class="tier-badge" style="background:%s22;color:%s">%s</span>
</div>
`, htmltemplate.HTMLEscapeString(tier), statusColor, statusColor, htmltemplate.HTMLEscapeString(statusLabel))

	if adminEmail != "" {
		fmt.Fprintf(w, `<div class="tier-meta">Inherited from admin: <strong>%s</strong></div>
`, htmltemplate.HTMLEscapeString(adminEmail))
	}
	if tier != "Free" && maxUsers > 1 {
		fmt.Fprintf(w, `<div class="tier-meta">Plan includes up to %d family members</div>
`, maxUsers)
	}
	fmt.Fprint(w, `</div>
`)

	// Feature list.
	fmt.Fprint(w, `<div class="features-card">
<h3>Features</h3>
<ul class="feature-list">
`)
	for _, f := range features {
		cls := "off"
		if f.Enabled {
			cls = "on"
		}
		fmt.Fprintf(w, `<li class="%s">%s</li>
`, cls, htmltemplate.HTMLEscapeString(f.Name))
	}
	fmt.Fprint(w, `</ul>
</div>
`)

	// Family section (only if admin or family member).
	if isAdmin || adminEmail != "" {
		fmt.Fprint(w, `<div class="family-card">
<h3>Family Plan</h3>
`)
		if isAdmin {
			fmt.Fprintf(w, `<p><strong>%d</strong> of <strong>%d</strong> family member seats used.</p>
<p style="margin-top:8px;font-size:0.8rem;color:var(--text-2,#475569)">Use the <code>admin_list_family</code> MCP tool to see all members, or <code>admin_invite_family_member</code> to invite new ones.</p>
`, memberCount, maxUsers)
		} else {
			fmt.Fprintf(w, `<p>You are a family member. Your plan is inherited from <strong>%s</strong>.</p>
`, htmltemplate.HTMLEscapeString(adminEmail))
		}
		fmt.Fprint(w, `</div>
`)
	}

	// Action buttons.
	fmt.Fprint(w, `<div class="actions">
`)
	if tier == "Free" {
		fmt.Fprint(w, `<a href="/pricing" class="btn btn-primary">Upgrade Plan</a>
`)
	} else {
		fmt.Fprint(w, `<a href="/pricing" class="btn btn-secondary">Change Plan</a>
`)
	}
	if hasStripe {
		fmt.Fprint(w, `<a href="/stripe-portal" class="btn btn-secondary">Manage in Stripe</a>
<p style="font-size:12px;color:var(--text-2);margin-top:8px;">View billing history, invoices, and update payment methods in the Stripe portal.</p>
`)
	}
	fmt.Fprint(w, `</div>
`)

	fmt.Fprint(w, `<a href="/dashboard" class="back-link">&larr; Back to Dashboard</a>
</div>
</body>
</html>`)
}

// tierDisplayName returns a title-cased display name for a billing tier.
func tierDisplayName(t billing.Tier) string {
	switch t {
	case billing.TierPro:
		return "Pro"
	case billing.TierPremium:
		return "Premium"
	default:
		return "Free"
	}
}
