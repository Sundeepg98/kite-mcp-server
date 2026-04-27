package audit

import (
	"context"
	"strconv"
	"time"
)

// DefaultRetentionDays is the in-package default used by StartRetentionWorker
// and retentionDaysFromEnv when AUDIT_RETENTION_DAYS is unset or invalid.
//
// NOTE: This is a DPDP-compliance-minimum default. Deployments with stricter
// regulatory requirements (e.g. SEBI algo trading audit trail — 5 years) wire
// a larger retention window via AUDIT_RETENTION_DAYS or invoke DeleteOlderThan
// directly from their own scheduler (see app/wire.go). The in-package worker
// is the backstop, not the only line of defence.
const DefaultRetentionDays = 90

// retentionTickInterval is the time between cleanup runs. Daily matches the
// expected data-freshness budget for DPDP 90-day retention (losing up to one
// day of over-retention after cutoff is acceptable).
var retentionTickInterval = 24 * time.Hour

// CleanupOldRecords deletes tool_call rows older than `days` days from now.
// Returns the number of rows deleted.
//
// When days <= 0 retention is treated as DISABLED and the call is a no-op
// returning (0, nil). Operators disable the in-package cleanup worker by
// setting AUDIT_RETENTION_DAYS=0 (useful when an external scheduler already
// owns retention, e.g. app/wire.go).
//
// Internally delegates to DeleteOlderThan so the hash-chain break-marker
// behaviour applies: chain integrity is preserved across retention
// deletions via a recorded __chain_break entry. See VerifyChain for details.
func (s *Store) CleanupOldRecords(days int) (int64, error) {
	if days <= 0 {
		return 0, nil
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -days)
	return s.DeleteOlderThan(cutoff)
}

// ParseRetentionDays parses the effective retention window in days from a
// raw string value (typically AUDIT_RETENTION_DAYS from the environment).
//
// Resolution order:
//  1. raw if a non-empty parseable integer
//     (including 0 or negative — which disable retention).
//  2. Otherwise the provided defaultDays.
//
// Unparseable values (non-numeric garbage) fall back to the default so a
// typo'd env var does not silently disable audit retention.
//
// Pure function — no env read. Callers pass os.Getenv("AUDIT_RETENTION_DAYS")
// explicitly so tests can exercise the parser without t.Setenv.
func ParseRetentionDays(raw string, defaultDays int) int {
	if raw == "" {
		return defaultDays
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return defaultDays
	}
	if n <= 0 {
		return 0 // explicit disable
	}
	return n
}

// StartRetentionWorker launches a background goroutine that runs
// CleanupOldRecords(days) once every retentionTickInterval (default 24h).
//
// When days <= 0 the worker is not started (retention disabled); callers
// can still invoke CleanupOldRecords directly if they want a one-shot cleanup.
//
// This is intended as an in-package backstop that operators can enable when
// no external scheduler owns audit retention. The existing app/wire.go
// scheduler already runs DeleteOlderThan daily at 03:00 IST for production
// deployments; leaving the in-package worker inactive avoids double-deletion.
// Callers that want to drive retention entirely from the audit package
// (e.g. tests, alternative wiring, tooling) should call this method
// explicitly and pair it with StopRetentionWorker on shutdown.
//
// Safe to call multiple times: a second call is a no-op while a worker is
// already running.
//
// ctx is the parent service context — captured by the goroutine for
// log correlation (the goroutine's cleanup-success / cleanup-failure
// log entries flow through it). Shutdown is still driven by the
// stop channel (close via StopRetentionWorker); ctx is currently for
// logging only, but capturing it now positions us to honour
// ctx.Done() without a public-API change.
func (s *Store) StartRetentionWorkerCtx(ctx context.Context, days int) {
	if days <= 0 {
		// Retention disabled — do not spawn the goroutine. StopRetentionWorker
		// will see nil channels and return immediately.
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}

	s.retentionMu.Lock()
	if s.retentionStop != nil {
		// Worker already running.
		s.retentionMu.Unlock()
		return
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	s.retentionStop = stop
	s.retentionDone = done
	s.retentionMu.Unlock()

	go func() {
		defer close(done)
		ticker := time.NewTicker(retentionTickInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				deleted, err := s.CleanupOldRecords(days)
				if err != nil {
					if s.logger != nil {
						s.logger.Error(ctx, "audit retention cleanup failed",
							err, "retention_days", days)
					}
					continue
				}
				if deleted > 0 && s.logger != nil {
					s.logger.Info(ctx, "audit retention cleanup completed",
						"rows_deleted", deleted, "retention_days", days)
				}
			case <-stop:
				return
			}
		}
	}()
}

// StartRetentionWorker is the legacy non-ctx variant, retained as a
// thin shim that calls StartRetentionWorkerCtx with
// context.Background(). Existing test fixtures continue to work
// unchanged; new callers should reach for StartRetentionWorkerCtx
// and pass the parent service context.
//
// Deprecated: use StartRetentionWorkerCtx. This shim exists for the
// migration window only and will be removed once Wave D Phase 3
// Package 8 (cleanup) lands.
func (s *Store) StartRetentionWorker(days int) {
	s.StartRetentionWorkerCtx(context.Background(), days)
}

// StopRetentionWorker signals the retention goroutine to exit and blocks
// until it has finished. Safe to call when the worker was never started
// (no-op) and idempotent if called repeatedly.
func (s *Store) StopRetentionWorker() {
	s.retentionMu.Lock()
	stop := s.retentionStop
	done := s.retentionDone
	// Clear state so a subsequent StartRetentionWorker can launch a new
	// goroutine and a second StopRetentionWorker call becomes a no-op.
	s.retentionStop = nil
	s.retentionDone = nil
	s.retentionMu.Unlock()

	if stop == nil {
		return
	}
	close(stop)
	if done != nil {
		<-done
	}
}
