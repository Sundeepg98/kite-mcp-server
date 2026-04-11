# Handoff

## State
94 tools, 15 widgets, 2500+ tests. 8 modules at 100% (cqrs, usecases, domain, zerodha, plugins, mock, registry, ticker). 19 at 90%+. Overall ~90%. mcp build fixed. CI race condition fixed (newBotFunc mutex). CI re-running — should be green now.

## Next
1. VERIFY CI: `gh run list -L 2` — both CI and Security Scan should pass.
2. TEST RESTRUCTURE: Consolidate mcp/coverage_push{1-7}_test.go into concern-based files. Same for kc/alerts/ (6 test files) and app/ (4 test files). Use agents, one per package.
3. Remaining coverage: oauth 86%, audit 83%, kc root 82%, isttz 75%, ops 52%. Each needs specific interface extraction or clock injection.
4. Deploy: `flyctl deploy -a kite-mcp-server --remote-only` after CI green.

## Context
- REUSE agents via SendMessage — 2-3 iterations per agent. Don't launch new for same module.
- Agent reuse pattern saved in memory/feedback_agent_reuse.md.
- Clock injection (scheduler, riskguard) for time-dependent tests.
- DevMode stub Kite client (session_service.go) for handler body testing.
- Telegram bot mock: httptest + newBotFunc with sync.Mutex protection.
- Stripe webhook mock: webhook.GenerateTestSignedPayload.
- ticker: wireCallbacks refactored into named methods + interfaces (100%).
- BrokerDataProvider interface in alerts/briefing.go breaks Kite API ceiling.
- Codebase at D:\kite-mcp-temp — ALWAYS tell agents this path.
