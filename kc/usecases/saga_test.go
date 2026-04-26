package usecases

import (
	"context"
	"errors"
	"testing"
)

// TestRunSaga_AllStepsSucceed verifies the happy path: every Action
// returns nil, no compensations run, RunSaga returns nil.
func TestRunSaga_AllStepsSucceed(t *testing.T) {
	t.Parallel()

	var ranActions []string
	var ranComps []string

	steps := []SagaStep{
		{
			Name:   "step1",
			Action: func(ctx context.Context) error {
				ranActions = append(ranActions, "step1")
				return nil
			},
			Compensate: func(ctx context.Context) error {
				ranComps = append(ranComps, "step1")
				return nil
			},
		},
		{
			Name:   "step2",
			Action: func(ctx context.Context) error {
				ranActions = append(ranActions, "step2")
				return nil
			},
			Compensate: func(ctx context.Context) error {
				ranComps = append(ranComps, "step2")
				return nil
			},
		},
	}

	if err := RunSaga(context.Background(), nil, "happy", steps); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	if len(ranActions) != 2 || ranActions[0] != "step1" || ranActions[1] != "step2" {
		t.Errorf("expected actions [step1 step2], got %v", ranActions)
	}
	if len(ranComps) != 0 {
		t.Errorf("expected no compensations, got %v", ranComps)
	}
}

// TestRunSaga_RollbackOnFailure verifies that when a middle step fails,
// completed prior steps are compensated in REVERSE order, and the
// triggering Cause is preserved on the SagaError.
func TestRunSaga_RollbackOnFailure(t *testing.T) {
	t.Parallel()

	var ranComps []string
	boom := errors.New("step2 boom")

	steps := []SagaStep{
		{
			Name:       "step1",
			Action:     func(ctx context.Context) error { return nil },
			Compensate: func(ctx context.Context) error { ranComps = append(ranComps, "step1"); return nil },
		},
		{
			Name:       "step2",
			Action:     func(ctx context.Context) error { return boom },
			Compensate: func(ctx context.Context) error { ranComps = append(ranComps, "step2"); return nil },
		},
		{
			Name:       "step3",
			Action:     func(ctx context.Context) error { t.Fatalf("step3 should not run"); return nil },
			Compensate: func(ctx context.Context) error { ranComps = append(ranComps, "step3"); return nil },
		},
	}

	err := RunSaga(context.Background(), nil, "rollback", steps)
	if err == nil {
		t.Fatalf("expected SagaError, got nil")
	}
	var sagaErr *SagaError
	if !errors.As(err, &sagaErr) {
		t.Fatalf("expected *SagaError, got %T", err)
	}
	if sagaErr.FailedStep != "step2" {
		t.Errorf("expected FailedStep=step2, got %q", sagaErr.FailedStep)
	}
	if !errors.Is(err, boom) {
		t.Errorf("expected errors.Is(err, boom)=true")
	}
	// step1 is the only completed-before-failure step; step2's Action did NOT
	// complete (it returned the error), so its Compensate should NOT run.
	if len(ranComps) != 1 || ranComps[0] != "step1" {
		t.Errorf("expected compensations [step1], got %v", ranComps)
	}
}

// TestRunSaga_ContinueOnError verifies that a step marked
// ContinueOnError logs and continues without triggering rollback.
func TestRunSaga_ContinueOnError(t *testing.T) {
	t.Parallel()

	var ranActions []string
	steps := []SagaStep{
		{
			Name:            "best-effort",
			ContinueOnError: true,
			Action: func(ctx context.Context) error {
				ranActions = append(ranActions, "best-effort")
				return errors.New("transient")
			},
		},
		{
			Name: "must-succeed",
			Action: func(ctx context.Context) error {
				ranActions = append(ranActions, "must-succeed")
				return nil
			},
		},
	}
	if err := RunSaga(context.Background(), nil, "best-effort", steps); err != nil {
		t.Fatalf("expected nil (best-effort), got %v", err)
	}
	if len(ranActions) != 2 {
		t.Errorf("expected both steps to run, got %v", ranActions)
	}
}

// TestRunSaga_CompensationErrorsCollected verifies that errors raised
// during Compensate are collected into SagaError.CompensationErrors and
// do NOT abort the rollback chain — each Compensate runs even if a
// prior one failed.
func TestRunSaga_CompensationErrorsCollected(t *testing.T) {
	t.Parallel()

	var ranComps []string
	cause := errors.New("step3 boom")
	compErr1 := errors.New("step1 comp boom")
	compErr2 := errors.New("step2 comp boom")

	steps := []SagaStep{
		{
			Name:       "step1",
			Action:     func(ctx context.Context) error { return nil },
			Compensate: func(ctx context.Context) error { ranComps = append(ranComps, "step1"); return compErr1 },
		},
		{
			Name:       "step2",
			Action:     func(ctx context.Context) error { return nil },
			Compensate: func(ctx context.Context) error { ranComps = append(ranComps, "step2"); return compErr2 },
		},
		{
			Name:   "step3",
			Action: func(ctx context.Context) error { return cause },
		},
	}

	err := RunSaga(context.Background(), nil, "comperr", steps)
	var sagaErr *SagaError
	if !errors.As(err, &sagaErr) {
		t.Fatalf("expected *SagaError, got %T", err)
	}
	if len(sagaErr.CompensationErrors) != 2 {
		t.Fatalf("expected 2 compensation errors, got %d", len(sagaErr.CompensationErrors))
	}
	// Reverse order: step2 first (most recent), then step1.
	if ranComps[0] != "step2" || ranComps[1] != "step1" {
		t.Errorf("expected reverse order [step2 step1], got %v", ranComps)
	}
}

// TestRunSaga_NilAction returns SagaError without panicking.
func TestRunSaga_NilAction(t *testing.T) {
	t.Parallel()

	steps := []SagaStep{
		{Name: "broken", Action: nil},
	}
	err := RunSaga(context.Background(), nil, "nil-action", steps)
	if err == nil {
		t.Fatalf("expected error for nil Action")
	}
	var sagaErr *SagaError
	if !errors.As(err, &sagaErr) {
		t.Fatalf("expected *SagaError, got %T", err)
	}
	if sagaErr.FailedStep != "broken" {
		t.Errorf("expected FailedStep=broken, got %q", sagaErr.FailedStep)
	}
}

// TestSagaError_ErrorMessage verifies the formatted error message.
func TestSagaError_ErrorMessage(t *testing.T) {
	t.Parallel()

	cause := errors.New("oops")
	e := &SagaError{FailedStep: "step1", Cause: cause}
	if e.Error() != `saga step "step1" failed: oops` {
		t.Errorf("unexpected message: %q", e.Error())
	}
	e.CompensationErrors = []error{errors.New("comp1")}
	if e.Error() != `saga step "step1" failed: oops (with 1 compensation error(s))` {
		t.Errorf("unexpected message with comp errors: %q", e.Error())
	}
	// Nil-receiver safety.
	var nilErr *SagaError
	if nilErr.Error() != "" {
		t.Errorf("nil receiver should return empty string")
	}
}
