# Handoff

## State
93 tools (13 admin), 15 widgets (4 admin), full billing refactor, family invite flow, Stripe checkout+portal, pricing page, admin nav — all deployed at kite-mcp-server.fly.dev (commit 492c171). Scores: Product 7.2/10, UX 6.8/10, Architecture 7.1/10. Launch-ready.

## Next
1. Polish: Extract AppBridge into Go template partial (14 widgets duplicate ~120 lines each). Use `{{ template "appbridge" }}` — MCP widgets can't load external scripts. Saves 35KB, improves maintainability.
2. Polish: Accessibility — add ARIA labels to interactive elements, focus-visible styles, fix color contrast on light theme. Target 6/10 (currently 3/10).
3. Polish: Add "Invite Family" button to billing page (currently invite is MCP-tool-only). Generate acceptance link visually. Add expired invitation cleanup.
4. Optional: Family member self-service (leave family, view admin info). Solo Pro tier (₹249) for traders who don't need family.

## Context
- User wants PARALLEL BUILD AGENTS for all coding — never serial
- User gets frustrated with over-research — 1 round max then BUILD
- 13 admin tools: list_users, get_user, server_status, get_risk_status, suspend_user, activate_user, change_role, freeze_user, unfreeze_user, freeze_global, unfreeze_global, invite_family_member, list_family
- Stripe test keys in Fly.io secrets (sk_test_51SnwxS5..., whsec_Hxq8PwJ0...)
- billing.Subscription field is AdminEmail (not Email) — renamed in all callers
- InvitationStore wired in manager + app.go, accept endpoint at /auth/accept-invite
- SAC blocks mcp test binary intermittently — not code issue
- Product direction: Option A (family platform) — committed this session
