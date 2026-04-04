package templates

// Embed login_success.html, status.html, and base.html in this package

import (
	"embed"
)

//go:embed login_success.html status.html base.html browser_login.html admin_login.html ops.html dashboard.html activity.html orders.html alerts.html email_prompt.html login_choice.html portfolio_app.html activity_app.html orders_app.html alerts_app.html paper.html paper_app.html safety.html safety_app.html landing.html order_form_app.html legal.html dashboard-base.css
var FS embed.FS
