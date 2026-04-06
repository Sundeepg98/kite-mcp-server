# Handoff

## State
94 tools (14 admin), 15 widgets, 25 admin tests, full billing+family+Stripe+pricing deployed at kite-mcp-server.fly.dev (commit 1ebd808). Scores: Product 9.2, UX 9.0, Architecture 9.0 (overall 9.1/10). Solo Pro tier added (₹199). Domain events emitting. Invitation cleanup running. All ARIA done.

## Next
1. Remaining 0.9 to 10/10: manager decomposition (split god object), full keyboard nav on 11 user widgets, more integration tests (billing webhook E2E, Stripe checkout E2E), CSS template dedup (minor — widgets must be self-contained)
2. Create STRIPE_PRICE_SOLO_PRO product in Stripe dashboard (₹199/mo) and set as Fly.io secret
3. Push to origin: `git push origin master` (currently 10+ commits ahead)

## Context
- User wants PARALLEL BUILD AGENTS — never serial, max 1 round research then build
- 14 admin tools: list_users, get_user, server_status, get_risk_status, suspend_user, activate_user, change_role, freeze_user, unfreeze_user, freeze_global, unfreeze_global, invite_family_member, list_family, remove_family_member
- billing.Subscription field is AdminEmail (renamed from Email)
- Stripe test keys in Fly.io secrets. Solo Pro needs STRIPE_PRICE_SOLO_PRO secret (not created yet)
- Product direction committed: Option A (family platform) with Solo Pro for individuals
- SAC blocks mcp test binary intermittently — not code issue
- Domain events: UserSuspendedEvent, GlobalFreezeEvent, FamilyInvitedEvent in kc/domain/events.go
- withAdminCheck helper available for future admin tools (existing 14 use adminCheck directly)
