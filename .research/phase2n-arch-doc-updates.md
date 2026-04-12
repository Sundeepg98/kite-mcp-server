# Phase 2n: ARCHITECTURE.md corrections

Applied 6 corrections from docs-review + added a "Known Production Issues"
section covering H1/H2/H3 from `.research/resume-error-audit.md`.

Source of truth for current-state metrics going forward:
`.research/resume-phase2-metrics.md`.

## Changes

1. **§3 Known SDK leaks** — rewrote. Production code now has **zero** direct
   `kiteconnect.New()` leaks. The only surviving call sites are the factory
   itself (`kc/manager.go` default factory + `kc/kite_client.go`
   `DefaultKiteClientFactory`). Briefing, Telegram fallback, and OAuth
   exchanger — all formerly listed as leaks — now route through
   `broker.Factory`.

2. **§10 StoreAccessor** — 18 → **20** Provider interfaces, with an honest
   note that only **4** are consumed at call sites today:
   `SessionProvider`, `CredentialResolver`, `MetricsRecorder`,
   `AppConfigProvider`. The other 16 are defined-but-unused (Interface
   Segregation theater).

3. **§4 CQRS** — `kc/usecases/` count 27 → **28**. Added explanation that
   CQRS here is the request-object pattern: typed Command/Query DTOs with
   domain VOs. `kc/cqrs/bus.go` and `kc/cqrs/query_dispatcher.go` exist but
   are **not instantiated** in production wiring. The DTOs themselves are
   the real value, not any runtime bus. Also updated the directory table
   row for `kc/usecases/`.

4. **§13 Large files** — updated stale line counts:
   - `kc/ops/user_render.go`: 986 → **158 lines (split complete)**
   - `mcp/ext_apps.go`: ~900 → **682 lines**
   - `kc/manager.go`: ~1200 → **728 lines**

5. **§14 Further reading** — cited `resume-phase2-metrics.md` as
   authoritative for current-state metrics, with a note that
   `final-arch-verification.md` is stale and kept only for history.

6. **§6 middleware note** — reworded the confusing "outermost first"
   comment. The list is now framed as **execution order**: first item runs
   first on an incoming request, last item runs immediately before the
   tool handler. The `mcp-go` reverse-wrapping quirk is explained
   once, not conflated with the list order.

## New section: §13a Known Production Issues

Three HIGH-severity findings from `.research/resume-error-audit.md`:

- **H1** — audit store init failure leaves `auditMiddleware` nil, silently
  disabling the audit trail (`app/wire.go`).
- **H2** — risk-limit load failure continues startup with in-memory
  defaults (`app/wire.go`), silently clearing user kill switches and caps.
- **H3** — `kc/audit/store.go` `Enqueue` swallows synchronous `Record`
  errors and only `Warn`-logs buffer-full drops.

Remediation status is tracked under phase 2i.

## Files touched

- `ARCHITECTURE.md` — six edits plus one new section.
- `.research/phase2n-arch-doc-updates.md` — this note.
