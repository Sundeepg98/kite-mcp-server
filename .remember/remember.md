# Handoff

## State
94 tools, 15 widgets, 2000+ tests. Coverage: 7 modules at 100%, 17 at 90%+, overall ~87%. CI failing on kc/alerts trailing stop test (race condition on Ubuntu). Test files need restructuring — 30+ scattered files with generic names (coverage_push*.go).

## Next
1. Fix CI: kc/alerts trailing stop test race condition. Run `gh run view --log-failed` to find exact test.
2. Test restructure: consolidate coverage_push{1-7}_test.go into concern-based files (tools_validation_test.go, tools_devmode_test.go, etc.). One session.
3. Remaining coverage: mcp ~73% (DevMode session handlers), app ~71% (server lifecycle), alerts ~89% (briefing Send*). Agents running on these.
4. Architecture: ARCHITECTURE.md needed. Test naming convention + testdata/ directory.

## Context
- REUSE agents via SendMessage instead of launching new ones. Each agent handles 2-3 iterations.
- One agent per module — no overlap. Descriptive test file names, not generic.
- SAC test failures are Windows-only — CI runs Ubuntu, no SAC issue.
- .claude/CLAUDE.md enforces TDD for new features.
- Clock injection pattern (scheduler, riskguard) enables deterministic time-dependent tests.
- DevMode stub Kite client (session_service.go) enables handler body testing.
- Telegram bot mock via httptest + newBotFunc injection.
- Stripe webhook mock via webhook.GenerateTestSignedPayload.
