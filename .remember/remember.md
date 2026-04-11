# Handoff

## State
94 tools, 15 widgets, 1000+ tests across 24 modules. Deployed at kite-mcp-server.fly.dev. CI+security green. Coverage: 15 modules at 75%+, 19 at 65%+, ~65% overall (up from 31.7%). TDD policy in .claude/CLAUDE.md. t.Parallel() on 329 tests, TestMain shared manager.

## Next
1. Testing ceiling: mcp 56%, broker/zerodha 44%, app 11% — need integration test harness (httptest server) to go higher. Mocking Stripe webhook signatures would unlock billing handler tests.
2. Hosting: SQLite single-writer limits ~100 concurrent users. PostgreSQL migration plan needed before 200+ DAU. Current Fly.io (512MB, ₹500/mo) sufficient for MVP.
3. Admin role rename: "admin" overloaded (server operator vs billing family head). Functionally correct but confusing. Rename to operator/family_admin.
4. Testing approach research incomplete: mocks vs generated mocks (mockgen) vs property testing vs golden files. Start next session with this research.

## Context
- User wants PARALLEL BUILD AGENTS, max 1 round research then build
- TDD enforced via .claude/CLAUDE.md for all NEW features
- Coverage backfill complete — further gains need integration test infrastructure
- All SAC test failures are Windows Smart App Control blocking test binaries, not code issues
- kc/scheduler coverage drops on weekends (tick() returns early) — re-run on weekday for accurate numbers
