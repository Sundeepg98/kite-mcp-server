# Handoff

## State
94 tools (14 admin), 15 widgets, 19 use cases, 3 aggregates, 11 domain events, 10 middleware decorators, plugin registry, 900+ tests. All deployed at kite-mcp-server.fly.dev (commit 41f2b1c). CI+security green. Stripe test mode with 4 tiers live (Free/SoloPro/FamilyPro/Premium).

## Next
1. Testing: coverage at ~40% overall. Target 75%. Biggest gaps: mcp tool handlers (30%), kc/ops (6%), kc/telegram (0%). Need per-tool validation tests for 80 non-admin tools. Load testing not started.
2. Hosting: SQLite single-writer limits to ~100 concurrent users. Plan PostgreSQL migration when targeting 200+ DAU. Current Fly.io Connect tier (512MB, ₹500/mo) sufficient for MVP.
3. Admin role rename: "admin" is overloaded (server operator vs billing family head). Rename to operator/family_admin for clarity. Functional code is correct.
4. Remaining Kite-specific tools (MF, margins, pretrade) documented as intentional broker.Client exclusions.

## Context
- User wants PARALLEL BUILD AGENTS — never serial, max 1 round research then build
- "Admin" means TWO things: server operator (ADMIN_EMAILS env) AND paying customer (Stripe webhook upgrades role). Architecture supports both but naming is confusing.
- Per-user OAuth works: each user can bring own Kite credentials. Global KITE_API_KEY optional.
- TierSoloPro (Tier=3) maps to Pro tool access via EffectiveTier(). STRIPE_PRICE_SOLO_PRO secret set on Fly.io.
- CSS injection: dashboard-base.css injected into widgets via /*__INJECTED_CSS__*/ placeholder at serve time
- RetryOnTransient wraps ALL 16 broker adapter methods (2 retries, exponential backoff)
- Plugin registry: RegisterPlugin + HookMiddleware wired in middleware chain
- ArgParser replaces all SafeAssert calls across 27 tool files
- SAC blocks mcp test binary intermittently — not code issue
