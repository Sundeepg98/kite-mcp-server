# Handoff

## State
11 widgets, 80 tools (73 routed), CI green (930d0bb). Activity crash + 5 bugs fixed. Deploy may need retry. Admin MCP (10 tools) fully specced but NOT built. Billing refactor fully designed but NOT built. Commercial model decided: Model A (admin pays for family ₹349/699).

## Next
1. Build billing refactor: admin_email PK in billing table, admin_email FK in users table, GetTierForUser with adminEmailFn, webhook upgrades payer to admin role. 6 files change (billing/store, middleware, webhook, users/store, app.go, interfaces.go)
2. Build 10 admin MCP tools in mcp/admin_tools.go (4 read + 5 reversible + 1 global freeze). Use elicitation, self-action guards, last-admin guards. Add GlobalFreezeStatus() to guard.go
3. Build 4 admin widgets (overview, users, metrics, registry) + pricing page + Stripe Checkout CREATE endpoint

## Context
- Codebase at D:\kite-mcp-temp — ALWAYS tell agents this path with specific file paths
- Family onboarding: dad pays → registers Kite apps → mom joins via Google SSO → registry.RegisteredBy links her to dad → billing inherits dad's tier
- Tier resolution: GetTierForUser checks direct subscription first, then admin's. adminEmailFn closure bridges billing↔user stores without circular deps
- Schema: billing PK rename email→admin_email + max_users col. users table add admin_email col. Migration: existing rows become solo (admin_email="")
- Admin MCP: NO approval workflow — use existing elicitation. Suspend must call Freeze+UpdateStatus+TerminateByEmail (HTTP handler only does UpdateStatus). guard.go globalFrozenBy/At unexported — need GlobalFreezeStatus() getter
- Pricing: Free ₹0/1user, Pro ₹349/5users, Premium ₹699/20users. Stripe flat-rate with metadata not per-seat
- htmx migration left broken getElementById refs — ALWAYS check IDs exist when converting pages to templates
- 7 tools intentionally unmapped (login, open_dashboard, stop_ticker, unsubscribe, delete_account, update_creds, server_metrics)
