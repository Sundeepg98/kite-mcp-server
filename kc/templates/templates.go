package templates

// Embed login_success.html, status.html, and base.html in this package

import (
	"embed"
)

//go:embed login_success.html status.html base.html browser_login.html admin_login.html ops.html dashboard.html activity.html orders.html alerts.html email_prompt.html login_choice.html portfolio_app.html activity_app.html orders_app.html alerts_app.html paper.html paper_app.html safety.html safety_app.html landing.html order_form_app.html watchlist_app.html hub_app.html options_chain_app.html chart_app.html setup_app.html credentials_app.html legal.html dashboard-base.css overview_stats.html overview_tools.html admin_sessions.html admin_tickers.html admin_alerts.html admin_users.html admin_metrics.html user_portfolio_stats.html user_portfolio_holdings.html user_portfolio_positions.html user_market_bar.html user_activity_stats.html user_activity_timeline.html user_orders_stats.html user_orders_table.html user_alerts_stats.html user_alerts_active.html user_alerts_triggered.html user_paper_stats.html user_paper_banner.html user_paper_tables.html user_safety_freeze.html user_safety_limits.html user_safety_sebi.html admin_overview_app.html admin_users_app.html admin_metrics_app.html admin_registry_app.html static/*
var FS embed.FS
