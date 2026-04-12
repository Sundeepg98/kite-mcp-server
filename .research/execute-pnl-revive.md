# ACTION 1 — pnlService Revival (execute report)

**Status:** COMPLETE. No code changes needed — field was already restored in a prior session.

## Finding

The task brief assumed the `pnlService *alerts.PnLSnapshotService` field on `Manager` still needed to be restored after commit `0ff7334` ("Dead code removal: pnlService field…"). Audit shows it was re-introduced — but on `AlertService` rather than directly on `Manager` — as part of the Clean Architecture decomposition.

## Current wiring (verified)

1. **Field owner:** `kc/alert_service.go:15`
   ```go
   type AlertService struct {
       ...
       pnlService *alerts.PnLSnapshotService
   }
   ```
2. **Accessors on AlertService:** `kc/alert_service.go:57` `PnLService()`, `kc/alert_service.go:62` `SetPnLService(svc)`.
3. **Manager delegators (public API unchanged):**
   - `kc/alert_service.go:81` — `func (m *Manager) PnLService() *alerts.PnLSnapshotService`
   - `kc/alert_service.go:86` — `func (m *Manager) SetPnLService(svc *alerts.PnLSnapshotService)`
4. **Interface contract:** `kc/manager_interfaces.go:161` still exposes `PnLService()`.
5. **Producer:** `app/wire.go:400-403` — `alerts.NewPnLSnapshotService(...)` → `kcManager.SetPnLService(pnlService)`.
6. **Scheduler fire:** `app/wire.go:404-409` — `sched.Add(Task{Name:"pnl_snapshot", Hour:15, Minute:40, Fn: pnlService.TakeSnapshots})`.
7. **Consumers:**
   - `mcp/pnl_tools.go:51` — `pnlService := manager.PnLService()` → feeds `usecases.NewGetPnLJournalUseCase` (the `get_pnl_journal` tool).
   - `mcp/pnl_tools.go:94` — uses the service.
   - Tests cover `SetPnLService`/`PnLService` nil-paths in `kc/manager_test.go:701-706` and `kc/service_test.go:731-749`.
8. **Coverage:** `kc/alerts/briefing_test.go`, `db_test.go`, `alerts_edge_test.go` all construct `NewPnLSnapshotService(...)` — service itself is test-covered.

## Verification commands

```
go vet ./...          # clean, no output
go build ./...        # clean, no output
go test ./kc/alerts/  # ok (cached)
go test ./mcp/        # ok 9.6s
go test ./kc/         # binary blocked by Windows Smart App Control (environment issue, not code — see memory note on SAC gopls block). Compilation succeeds.
```

## Conclusion

- Deletion called out in `0ff7334` was real, but was followed by a proper re-introduction on `AlertService` (Clean Architecture relocation, not dead-code revival).
- All three consumers (pnlChartAPI/dashboard, `get_pnl_journal` MCP tool, `scheduler.TakeSnapshots`) are live.
- SQLite `daily_pnl` persistence path is intact via `alertDB` passed to `NewPnLSnapshotService`.
- **No file edits required for Task #1.** Task #2 is unblocked.
