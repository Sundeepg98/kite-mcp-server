package scheduler

import (
	"sync/atomic"
	"testing"
	"time"
)

// TestRegisterTaskProvider_TasksAppearAfterStart verifies that tasks
// returned by a registered provider are collected when Start() runs and
// are subsequently visible to the tick loop via ListTaskNames().
func TestRegisterTaskProvider_TasksAppearAfterStart(t *testing.T) {
	t.Parallel()
	s := New(testLogger())

	// Stub provider that returns two tasks at known IST times.
	p := &stubProvider{
		name: "test_provider",
		tasks: []Task{
			{Name: "stub_task_a", Hour: 10, Minute: 0, Fn: func() {}},
			{Name: "stub_task_b", Hour: 15, Minute: 30, Fn: func() {}},
		},
	}
	s.RegisterTaskProvider(p)

	// Before Start, provider tasks are NOT collected — the contract is
	// "collected once at Start" so repeated Add calls at construction
	// time don't create duplicates.
	if len(s.tasks) != 0 {
		t.Fatalf("expected 0 tasks before Start, got %d", len(s.tasks))
	}

	// Start collects provider tasks synchronously before launching the
	// tick loop goroutine, so ListTaskNames is safe to call immediately
	// after Start returns — no wait needed.
	s.Start()
	defer s.Stop()

	names := s.ListTaskNames()
	if len(names) != 2 {
		t.Fatalf("expected 2 tasks after Start, got %d: %v", len(names), names)
	}
	seen := map[string]bool{}
	for _, n := range names {
		seen[n] = true
	}
	if !seen["stub_task_a"] || !seen["stub_task_b"] {
		t.Fatalf("expected both stub tasks, got %v", names)
	}
}

// TestRegisterTaskProvider_TasksFireOnSchedule confirms provider-registered
// tasks actually execute when the fake clock lands on their scheduled
// IST minute. This is the end-to-end plug-in smoke test: register via
// the new API, Start, tick — the task runs.
func TestRegisterTaskProvider_TasksFireOnSchedule(t *testing.T) {
	t.Parallel()
	s := New(testLogger())

	var calledA atomic.Int32
	var calledB atomic.Int32

	s.RegisterTaskProvider(&stubProvider{
		name: "fire_provider",
		tasks: []Task{
			{Name: "fire_a", Hour: 11, Minute: 15, Fn: func() { calledA.Add(1) }},
			{Name: "fire_b", Hour: 11, Minute: 15, Fn: func() { calledB.Add(1) }},
		},
	})

	// Wednesday 2026-04-08 11:15 IST — a known trading day.
	wed := time.Date(2026, 4, 8, 11, 15, 0, 0, kolkataLoc)
	s.SetClock(func() time.Time { return wed })

	// Start collects provider tasks. We don't need the goroutine for
	// this test — tick() is invoked directly.
	s.Start()
	defer s.Stop()

	s.tick()
	pollCount(t, &calledA, 1, "expected fire_a to run once")
	pollCount(t, &calledB, 1, "expected fire_b to run once")
}

// TestRegisterTaskProvider_CombinesWithAdd verifies that provider tasks
// and tasks added via the pre-existing Add() API coexist peacefully.
// Use case: a plugin adds tasks via a TaskProvider while app/wire.go
// continues to register its built-in briefing tasks via Add().
func TestRegisterTaskProvider_CombinesWithAdd(t *testing.T) {
	t.Parallel()
	s := New(testLogger())

	var calledBuiltin atomic.Int32
	var calledPlugin atomic.Int32

	// Built-in task registered the old way.
	s.Add(Task{Name: "builtin", Hour: 9, Minute: 0, Fn: func() { calledBuiltin.Add(1) }})

	// Plugin task via provider.
	s.RegisterTaskProvider(&stubProvider{
		name: "plugin_provider",
		tasks: []Task{
			{Name: "plugin", Hour: 9, Minute: 0, Fn: func() { calledPlugin.Add(1) }},
		},
	})

	s.Start()
	defer s.Stop()

	// Fire both at 09:00 on a trading day.
	wed := time.Date(2026, 4, 8, 9, 0, 0, 0, kolkataLoc)
	s.SetClock(func() time.Time { return wed })
	s.tick()
	pollCount(t, &calledBuiltin, 1, "builtin task should have fired")
	pollCount(t, &calledPlugin, 1, "plugin task should have fired")

	names := s.ListTaskNames()
	if len(names) != 2 {
		t.Fatalf("expected 2 total tasks (1 Add + 1 provider); got %d: %v", len(names), names)
	}
}

// TestRegisterTaskProvider_MultipleProvidersCollected verifies the
// registration API handles more than one provider. Each provider's
// Tasks() is called exactly once at Start.
func TestRegisterTaskProvider_MultipleProvidersCollected(t *testing.T) {
	t.Parallel()
	s := New(testLogger())

	var pACalls, pBCalls atomic.Int32
	pA := &stubProvider{
		name:     "provider_a",
		countHit: &pACalls,
		tasks: []Task{
			{Name: "pa_task", Hour: 10, Minute: 0, Fn: func() {}},
		},
	}
	pB := &stubProvider{
		name:     "provider_b",
		countHit: &pBCalls,
		tasks: []Task{
			{Name: "pb_task_1", Hour: 10, Minute: 0, Fn: func() {}},
			{Name: "pb_task_2", Hour: 10, Minute: 30, Fn: func() {}},
		},
	}

	s.RegisterTaskProvider(pA)
	s.RegisterTaskProvider(pB)
	// Tasks() is called synchronously inside Start before the goroutine
	// launches, so the counters are correct as soon as Start returns.
	s.Start()
	defer s.Stop()

	if pACalls.Load() != 1 {
		t.Errorf("provider A.Tasks() should be called once at Start; got %d", pACalls.Load())
	}
	if pBCalls.Load() != 1 {
		t.Errorf("provider B.Tasks() should be called once at Start; got %d", pBCalls.Load())
	}
	if got := len(s.ListTaskNames()); got != 3 {
		t.Fatalf("expected 3 collected tasks (1 + 2); got %d (%v)", got, s.ListTaskNames())
	}
}

// TestRegisterTaskProvider_NilProviderIgnored confirms RegisterTaskProvider
// fails-open on a nil argument. A misconfigured plugin should not crash
// scheduler init — it simply contributes no tasks.
func TestRegisterTaskProvider_NilProviderIgnored(t *testing.T) {
	t.Parallel()
	s := New(testLogger())
	// Explicitly pass a typed-nil. This is the realistic shape (e.g.
	// a plugin returns a nil *MyProvider when a feature flag is off).
	var p *stubProvider
	s.RegisterTaskProvider(p)

	// Start collects tasks synchronously — no wait needed.
	s.Start()
	defer s.Stop()

	if len(s.ListTaskNames()) != 0 {
		t.Fatalf("nil provider must contribute 0 tasks")
	}
}

// --- test helpers ---

// stubProvider is a minimal TaskProvider for tests. countHit optionally
// records how many times Tasks() was invoked — used by
// TestRegisterTaskProvider_MultipleProvidersCollected to assert the
// "called exactly once at Start" contract.
type stubProvider struct {
	name     string
	tasks    []Task
	countHit *atomic.Int32
}

func (p *stubProvider) Name() string {
	if p == nil {
		return ""
	}
	return p.name
}
func (p *stubProvider) Tasks() []Task {
	if p == nil {
		return nil
	}
	if p.countHit != nil {
		p.countHit.Add(1)
	}
	return p.tasks
}

// Compile-time assertion: stubProvider is a TaskProvider.
var _ TaskProvider = (*stubProvider)(nil)
