# Handoff

## State
All 5 phases built and committed at 29c1a07. 90 tools, 15 widgets, billing refactor, family onboarding, pricing page, Stripe checkout. Build clean, vet clean. MCP tests blocked by SAC (Windows Smart App Control) not code. Deploy not yet done.

## Next
1. Deploy to Fly.io: `flyctl deploy -a kite-mcp-server` — set STRIPE_SECRET_KEY, STRIPE_PRICE_PRO, STRIPE_PRICE_PREMIUM env vars first
2. Test E2E: pricing page → checkout → webhook → subscription → family member SSO → tier inheritance
3. Review agent changes: oauth/handlers.go KeyRegistry interface changed (GetByEmail now returns *RegistryEntry), verify all callers work correctly

## Context
- Codebase at D:\kite-mcp-temp — ALWAYS tell agents this path with specific file paths
- 10 admin tools use direct requestConfirmation() calls, NOT confirmableTools map. 3 destructive tools also have confirm:bool param
- admin_suspend_user does Freeze+UpdateStatus+TerminateByEmail (all three, in that order)
- billing.Middleware now takes (store, adminEmailFn) — tests pass nil for adminEmailFn
- WebhookHandler now takes (store, signingSecret, logger, adminUpgrade) — 4th param is func(email string)
- oauth/handlers.go: KeyRegistry.GetByEmail returns (*RegistryEntry, bool) now — was (string, string, bool)
- Phase 3 agent changed the KeyRegistry interface — verify registryAdapter in app.go still works
- SAC blocks mcp test binary intermittently — not a code issue
- globalFrozenReason field added to guard.go — FreezeGlobal now stores reason
