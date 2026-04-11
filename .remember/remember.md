# Handoff

## State
94 tools, 15 widgets, 4649 test functions. Build+vet clean. 8 modules at 100% (cqrs, usecases, domain, zerodha, plugins, mock, registry, ticker). 20 at 90%+. Overall ~90%. mcp 81%, app 75%, ops 59%. Test consolidation done for mcp, oauth, kc root, alerts, app. CI race condition fixed (newBotFunc mutex). CI OpenDB path fixed (cross-platform).

## Next
1. Verify CI green: `gh run list -L 2` — should pass now.
2. Remaining consolidation: kc/ops/ has coverage_final_test.go + multiple test files. Consolidate.
3. Remaining coverage: ops 59%, cmd/rotate-key 80%, isttz 75% (panic guard). Push ops with more handler tests.
4. Test architecture: remaining coverage_*_test.go files in subpackages (kc/audit, kc/instruments, kc/eventsourcing, kc/riskguard, kc/papertrading, kc/ticker). These are properly named by concern but could be renamed to match source files.
5. Deploy + verify: flyctl deploy after CI green.
6. Future: PostgreSQL migration, load testing (k6), admin role rename, ARCHITECTURE.md.

## Context
- 4649 test functions total (grep -r "func Test" count)
- REUSE agents via SendMessage — 2-3 iterations per agent max
- One agent per module, verify no file overlap before assigning
- Don't touch files while agent is working on them
- Agent reuse pattern in memory/feedback_agent_reuse.md
- Clock injection pattern for time-dependent tests (scheduler, riskguard)
- DevMode stub Kite client in session_service.go
- newFullDevModeManager in mcp/tools_test_helpers_test.go — all stores wired
- Telegram bot mock: httptest + newBotFunc with sync.Mutex
- Stripe webhook mock: webhook.GenerateTestSignedPayload
- ticker: wireCallbacks refactored into named methods + interfaces
- BrokerDataProvider interface in alerts/briefing.go
- Codebase at D:\kite-mcp-temp — ALWAYS tell agents this path
