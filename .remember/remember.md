# Handoff

## State
91 tools (11 admin), 15 widgets (4 admin), billing refactor, family tier inheritance, Stripe checkout, pricing page — all deployed at kite-mcp-server.fly.dev (commits 29c1a07→a360e76→9bf91f3). Stripe test mode configured. Scores: UX 5.5/10, Architecture 5.8/10, Product clarity 3.7/10. Family invite flow DOES NOT EXIST — Model A is architecturally ready but UX-broken.

## Next
1. Build family invite flow: new `family_invitations` table + `admin_invite_family_member` MCP tool + HTTP endpoints (POST /admin/ops/api/family/invite, GET /members, POST /auth/accept-invite) + max_users enforcement + ListByAdminEmail() on users store. Design doc in research agent output. 2-3 days with parallel agents.
2. Build account/billing page: replace minimal serveBillingPage with proper tier display, renewal date, family count, Stripe Customer Portal link (billingportal/session from stripe-go/v82). 1 day.
3. Admin nav: add conditional "Admin" link to dashboard.html ({{if eq .Role "admin"}}), add "Dashboard" link to ops.html topbar. AppBridge dedup via Go template partial (widgets can't load external scripts — MCP resource protocol requires inline). 1-2 days.

## Context
- User wants PARALLEL BUILD AGENTS — learned this the hard way after 10 rounds of serial research. Always use parallel agents for coding.
- User gets frustrated with over-research — max 1-2 rounds then BUILD
- billing.Subscription field renamed to AdminEmail (not Email) — all callers updated including tests
- stripe.Key set at app.go:536 from STRIPE_SECRET_KEY env var
- Stripe test keys: sk_test_51SnwxS5..., prices: price_1TJFef5... (Pro ₹349), price_1TJFgc5... (Premium ₹699), webhook: whsec_Hxq8PwJ0...
- SAC blocks mcp test binary intermittently — not a code issue
- Product direction UNDECIDED: Option A (family platform) vs Option B (solo trader first). User hasn't committed yet.
