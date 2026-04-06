# Handoff

## State
9 MCP App widgets (7 existing + watchlist_app + hub_app), 80 tools on Fly.io. 6 critical bugs fixed (alert delete, order form, GTT confirm, cancel variety, positions merge, tool routing). DEV_MODE mock broker wired. Auth separation live. Kite token valid (logged in today). CI+Security green. Deploy running.

## Next
1. Build options_app.html widget (option chain + Greeks — AppBridge-driven, no pre-injected data, lazy Greeks per row click)
2. Build chart_app.html widget (candlestick + indicators — needs inline TradingView Lightweight Charts ~65KB, 3 AppBridge calls per load)
3. Managed hosting MVP: pricing page + Stripe Checkout + onboarding email (~40h total)

## Context
- Codebase at D:\kite-mcp-temp — ALWAYS tell agents this path explicitly with specific file paths
- Widget pattern: read mcp/ext_apps.go + kc/templates/portfolio_app.html for exact pattern
- Options widget: get_option_chain returns NO greeks — need lazy options_greeks call per row click via AppBridge
- Chart widget: must inline TradingView Lightweight Charts standalone JS (~65KB) — no CDN in widgets
- Chart needs 2-step: search_instruments (get token) → get_historical_data (get candles) → technical_indicators (get scalars)
- Dashboard pages KEPT (decided: don't remove, widgets complement not compete)
- Both new widgets modify ext_apps.go — check for merge conflicts
