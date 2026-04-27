package providers

import (
	"log/slog"
	"time"

	"go.uber.org/fx"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/scheduler"
)

// scheduler.go — Wave D Phase 2 Slice P2.4b. Provides the App's
// scheduled-tasks scheduler as an Fx graph node.
//
// LEGACY BEHAVIOUR PRESERVED
//
// The original imperative chain at app/wire.go:initScheduler
// (lines 927-1013) constructed a *scheduler.Scheduler, conditionally
// added 5 tasks (3 Telegram-briefing + audit_cleanup + pnl_snapshot)
// based on which services were available, and called Start() iff
// any tasks were added. BuildScheduler preserves that semantic:
// when no input service is non-nil, the wrapper's Scheduler stays
// nil and no goroutine is started.
//
// CONSTRUCTION OWNERSHIP
//
// The 3 services (BriefingService, PnLSnapshotService, AuditStore)
// are constructed by the composition site (app/wire.go) BEFORE the
// fx.New(...) call. They use unexported app-package adapters
// (briefingTokenAdapter, briefingCredAdapter) that can't move into
// this package without an import cycle. The composition site
// fx.Supply's the constructed services into the graph; this
// provider takes them as inputs and wires them as scheduler tasks.
//
// LIFECYCLE
//
// The returned wrapper's Scheduler is the live, started
// *scheduler.Scheduler. Stop() responsibility stays with the
// composition site (app.scheduler.Stop() at app/wire.go:151,
// app/app.go:583, app/http.go:80) — the multi-call-site shutdown
// pattern predates Wave D and is preserved unchanged.
//
// WRAPPER TYPE
//
// Per the wrapper-type convention (see audit_init.go), we return
// *InitializedScheduler so the Fx type graph distinguishes "raw
// scheduler component" from "post-build wired scheduler". For
// scheduler this is purely the Fx graph-conflict prevention; there
// is no init-failure mode that yields a half-built scheduler.

// InitializedScheduler wraps a *scheduler.Scheduler. The Scheduler
// field is nil when BuildScheduler determined no tasks should be
// added (matches the legacy "no tasks → no Start" path); non-nil
// when at least one conditional task fired and Start() was called.
type InitializedScheduler struct {
	// Scheduler is the live started *scheduler.Scheduler, or nil if
	// BuildScheduler ran with no input services configured.
	Scheduler *scheduler.Scheduler
}

// AuditCleanupConfig captures the retention parameters for the
// daily audit-trail cleanup task. SEBI algo trading audit trail
// requires 5 years (1825 days) per the existing wire.go:967
// constant; exposing this as config makes it overrideable for
// tests + future regulatory adjustments without editing the
// provider.
type AuditCleanupConfig struct {
	// RetentionDays is the rolling cutoff: rows older than this are
	// deleted on the daily cleanup task. Zero defaults to 1825 days
	// (5 years — SEBI mandate) at provider time, matching legacy
	// behaviour at wire.go:967. Negative disables the cleanup task
	// (explicit opt-out for tests / dev-only deployments).
	RetentionDays int
}

// defaultAuditRetentionDays is the SEBI algo trading audit trail
// retention requirement (5 years). Used when RetentionDays==0 to
// preserve legacy const behaviour from wire.go:967.
const defaultAuditRetentionDays = 1825

// buildSchedulerInput is the fx.In struct convention for providers
// with 4+ inputs. Keeps BuildScheduler's call-site readable as a
// single fx.Provide(BuildScheduler) declaration.
type buildSchedulerInput struct {
	fx.In

	// Briefing is the Telegram morning/MIS/daily briefing service.
	// Constructed upstream from kcManager.TelegramNotifier() +
	// adapter shims; nil when TELEGRAM_BOT_TOKEN is not configured
	// or alerts.NewBriefingService returned nil.
	Briefing *alerts.BriefingService `optional:"true"`

	// PnL is the daily P&L snapshot service. Constructed upstream
	// from alertDB + adapters; nil when no AlertDB is wired.
	PnL *alerts.PnLSnapshotService `optional:"true"`

	// AuditStore drives the daily audit_cleanup task. Nil when
	// audit init was skipped (DevMode-no-DB or DevMode-init-failed).
	AuditStore *audit.Store `optional:"true"`

	// AuditConfig parameterizes the cleanup retention window. Zero
	// value treats RetentionDays=0 as "skip cleanup" — matching the
	// existing nil-auditStore early-return.
	AuditConfig AuditCleanupConfig `optional:"true"`

	// Logger is required for scheduler construction and task logs.
	// Nil-tolerant per kc/scheduler's New signature.
	Logger *slog.Logger
}

// BuildScheduler is the Fx provider for the App's task scheduler.
// Returns *InitializedScheduler with a nil-Scheduler signal when no
// conditional inputs are wired (preserves the legacy
// "no-tasks → no-start" semantic at wire.go:1004-1008).
//
// Pure provider: constructs the scheduler and calls Start exactly
// once when at least one task is added. No I/O beyond
// scheduler.Start (which spawns the tick goroutine).
func BuildScheduler(in buildSchedulerInput) (*InitializedScheduler, error) {
	sched := scheduler.New(in.Logger)
	taskCount := 0

	// --- Telegram briefings (3 tasks; nil-Briefing = skip) ---
	if in.Briefing != nil {
		sched.Add(scheduler.Task{
			Name:   "morning_briefing",
			Hour:   9,
			Minute: 0,
			Fn:     in.Briefing.SendMorningBriefings,
		})
		sched.Add(scheduler.Task{
			Name:   "mis_warning",
			Hour:   14,
			Minute: 30,
			Fn:     in.Briefing.SendMISWarnings,
		})
		sched.Add(scheduler.Task{
			Name:   "daily_summary",
			Hour:   15,
			Minute: 35,
			Fn:     in.Briefing.SendDailySummaries,
		})
		taskCount += 3
	}

	// --- Audit cleanup (1 task; gated on audit store; retention
	// defaults to 1825 days when AuditConfig.RetentionDays==0,
	// matching legacy wire.go:967 const. Negative explicitly opts
	// out — tests can pass -1 to skip the task.) ---
	retention := in.AuditConfig.RetentionDays
	if retention == 0 {
		retention = defaultAuditRetentionDays
	}
	if in.AuditStore != nil && retention > 0 {
		store := in.AuditStore
		logger := in.Logger
		sched.Add(scheduler.Task{
			Name:   "audit_cleanup",
			Hour:   3,
			Minute: 0,
			Fn: func() {
				cutoff := time.Now().AddDate(0, 0, -retention)
				deleted, err := store.DeleteOlderThan(cutoff)
				if logger == nil {
					return
				}
				if err != nil {
					logger.Error("Audit cleanup failed", "error", err)
				} else if deleted > 0 {
					logger.Info("Audit cleanup completed", "deleted", deleted, "retention_days", retention)
				}
			},
		})
		taskCount++
	}

	// --- Daily P&L snapshot (1 task; nil-PnL = skip) ---
	if in.PnL != nil {
		sched.Add(scheduler.Task{
			Name:   "pnl_snapshot",
			Hour:   15,
			Minute: 40,
			Fn:     in.PnL.TakeSnapshots,
		})
		taskCount++
	}

	// --- Start only if at least one task was added (legacy
	// behaviour at wire.go:1004-1012). ---
	if taskCount == 0 {
		return &InitializedScheduler{Scheduler: nil}, nil
	}
	sched.Start()
	return &InitializedScheduler{Scheduler: sched}, nil
}
