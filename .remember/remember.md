# Handoff

## State
94 tools, 15 widgets, 2500+ tests. 8 modules at 100% (cqrs, usecases, domain, zerodha, plugins, mock, registry, ticker). 19 at 90%+. Overall ~90%. CI failing on kc/alerts trailing stop test (race condition). mcp has build conflict (duplicate test function names in coverage_push7_test.go vs coverage_push2/3). App at 75%.

## Next
1. FIX BUILD: mcp/coverage_push7_test.go has 4 duplicate test names (TestSimulateTrades_NoSignals, TestComputeMaxDrawdown_NoTrades, TestInjectData_NilData, TestInjectData_NoPlaceholder). Rename with _V2 suffix or delete duplicates.
2. FIX CI: kc/alerts trailing stop test race condition on Ubuntu. Run `gh run view --log-failed` for exact test name.
3. TEST RESTRUCTURE: Consolidate 7x coverage_push{1-7}_test.go into concern-based files (tools_validation_test.go, tools_devmode_test.go, helpers_test.go). One session.
4. Remaining coverage gaps: oauth 86% (Google redirect), audit 83% (SAC), kc root 82%, isttz 75% (panic guard), ops 52%, cmd/rotate-key 50%.
5. Test architecture: need testdata/ dirs, golden files, proper naming convention, build tags for slow tests.

## Context
- REUSE agents via SendMessage — each handles 2-3 iterations. Don't launch new agents for same module.
- One agent per module, no overlap. Descriptive test file names.
- Clock injection pattern works (scheduler 98%, riskguard 99.7%). Use for any time-dependent code.
- DevMode stub Kite client in session_service.go enables handler body testing.
- Telegram bot mock via httptest + newBotFunc injection (telegram.go 100%).
- Stripe webhook mock via webhook.GenerateTestSignedPayload.
- ticker wireCallbacks refactored into named methods + tickerConn/callbackRegistrar interfaces (100%).
- BrokerDataProvider interface in alerts/briefing.go breaks Kite API ceiling.
- SAC test failures are Windows-only — CI runs Ubuntu.
