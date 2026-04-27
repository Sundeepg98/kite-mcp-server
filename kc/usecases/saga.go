package usecases

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	logport "github.com/zerodha/kite-mcp-server/kc/logger"
)

// SagaStep is one unit of a multi-step business operation that may need
// to be rolled back if a later step fails. Each step has a forward Action
// (run during normal execution) and an optional Compensate (run during
// rollback, in reverse order).
//
// Compensate is BEST-EFFORT: it is called for any step whose Action ran
// to completion (with or without success — see ContinueOnError). If
// Compensate itself returns an error, the error is logged and the next
// compensation runs anyway. This matches the BASE-style saga semantics
// described in Garcia-Molina & Salem (1987) and Microsoft's saga pattern
// guidance — full distributed-transaction ACID is NOT a goal here.
//
// Compensate may be nil for steps that are idempotent or whose effects
// are intentionally not rolled back (e.g., audit-log appends — auditors
// want to see the failed attempt).
type SagaStep struct {
	// Name identifies the step in logs and the SagaError. Required.
	Name string
	// Action runs the forward operation. May return an error to
	// trigger rollback of all completed prior steps. Required.
	Action func(ctx context.Context) error
	// Compensate undoes the forward Action. May be nil for steps
	// without a meaningful compensation. Errors are logged but do
	// NOT block subsequent compensations.
	Compensate func(ctx context.Context) error
	// ContinueOnError — if true, an error from Action is logged but
	// does NOT trigger rollback; the saga continues to the next step.
	// Use for steps whose failure is acceptable (best-effort cleanups
	// in DeleteMyAccount: paper-engine reset, watchlist deletion).
	ContinueOnError bool
}

// SagaError aggregates errors from a failed Saga: the original Action
// error that triggered rollback (Cause), and any errors raised during
// Compensate calls (CompensationErrors). Both are surfaced so callers
// can distinguish "rollback succeeded cleanly" from "rollback was
// itself partial".
type SagaError struct {
	// FailedStep is the Name of the step whose Action returned the
	// triggering error.
	FailedStep string
	// Cause is the error returned by FailedStep's Action.
	Cause error
	// CompensationErrors collects any errors raised while running
	// Compensate on the steps that ran before FailedStep. Empty
	// slice when rollback ran cleanly.
	CompensationErrors []error
}

// Error returns a human-readable summary of the saga failure.
func (e *SagaError) Error() string {
	if e == nil || e.Cause == nil {
		return ""
	}
	if len(e.CompensationErrors) == 0 {
		return fmt.Sprintf("saga step %q failed: %v", e.FailedStep, e.Cause)
	}
	return fmt.Sprintf("saga step %q failed: %v (with %d compensation error(s))",
		e.FailedStep, e.Cause, len(e.CompensationErrors))
}

// Unwrap returns the underlying Cause so errors.Is / errors.As work
// against the triggering error.
func (e *SagaError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// RunSaga executes the steps in order. On the first non-ContinueOnError
// failure, it runs Compensate on every prior completed step in reverse
// order, then returns a *SagaError. If all steps run to completion,
// returns nil.
//
// The logger MAY be nil; nil-logger is treated as a no-op for diagnostic
// log lines. The signature accepts *slog.Logger for caller compatibility
// and converts via logport.NewSlog at the boundary so internal log
// statements use the kc/logger.Logger port. The context is threaded
// into both Action and Compensate so cancellation propagates to
// in-flight steps and to compensations.
//
// Compensation runs in REVERSE order: step N-1, N-2, ..., 0. This matches
// LIFO undo semantics — the most recent change is undone first.
func RunSaga(ctx context.Context, logger *slog.Logger, name string, steps []SagaStep) error {
	lg := logport.NewSlog(logger)
	completed := make([]int, 0, len(steps))

	for i, step := range steps {
		if step.Action == nil {
			return &SagaError{FailedStep: step.Name, Cause: errors.New("saga: step has nil Action")}
		}
		if err := step.Action(ctx); err != nil {
			if step.ContinueOnError {
				if lg != nil {
					lg.Warn(ctx, "saga step failed (continuing)",
						"saga", name, "step", step.Name, "error", err)
				}
				completed = append(completed, i)
				continue
			}
			// Triggering failure: roll back completed steps in reverse.
			compErrs := compensateSteps(ctx, lg, name, steps, completed)
			return &SagaError{
				FailedStep:         step.Name,
				Cause:              err,
				CompensationErrors: compErrs,
			}
		}
		completed = append(completed, i)
	}
	return nil
}

// compensateSteps walks the completed step indices in reverse and runs
// each step's Compensate (when non-nil). All errors are collected — a
// failure in one compensation does not abort the others.
func compensateSteps(ctx context.Context, logger logport.Logger, sagaName string, steps []SagaStep, completed []int) []error {
	var errs []error
	for i := len(completed) - 1; i >= 0; i-- {
		idx := completed[i]
		step := steps[idx]
		if step.Compensate == nil {
			continue
		}
		if err := step.Compensate(ctx); err != nil {
			if logger != nil {
				logger.Error(ctx, "saga compensation failed", err,
					"saga", sagaName, "step", step.Name)
			}
			errs = append(errs, fmt.Errorf("compensate %q: %w", step.Name, err))
		}
	}
	return errs
}
