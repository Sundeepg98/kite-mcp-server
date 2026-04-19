package scheduler

import "reflect"

// TaskProvider is the plugin extension point for Scheduler.
//
// A TaskProvider contributes zero or more Tasks at startup. Unlike the
// pre-existing Add(Task) API — which expects callers to know their
// task definitions at construction time — a provider is consulted once
// at Start(): every registered provider has its Tasks() method invoked,
// and the returned tasks are appended to the scheduler's task list before
// the tick loop begins.
//
// Design rationale:
//
//   - Plugins cannot always statically list their tasks at wire-up time.
//     A billing plugin might only emit a "collect_usage_metrics" task if
//     Stripe is configured; a compliance plugin might emit per-exchange
//     holiday-reminder tasks that depend on an instruments manifest
//     loaded after construction. Deferring task enumeration until Start
//     lets providers inspect runtime state that isn't ready at New().
//
//   - Collecting once at Start (as opposed to per-tick) preserves the
//     existing "tasks are fixed once scheduler runs" invariant, which
//     other callers depend on. Dynamic task registration would require
//     re-examining the dedup map (lastRun) on every tick — a tradeoff
//     we explicitly rejected because it makes "did this task run today?"
//     harder to reason about.
//
//   - The TaskProvider interface is intentionally narrow. It carries no
//     lifecycle, config, or teardown hooks. Providers that need their
//     own lifecycle should wire that through their enclosing module
//     (e.g. the plugin's own Init/Shutdown); the scheduler cares only
//     about "give me your tasks".
//
// Typical usage in app wiring:
//
//	sched := scheduler.New(logger)
//	sched.RegisterTaskProvider(myplugin.NewScheduleProvider(deps))
//	// ... sched.Add(Task{...}) for built-in tasks ...
//	sched.Start()
type TaskProvider interface {
	// Name is a stable identifier for logs and duplicate detection.
	// Must be unique across registered providers; a second provider
	// with the same Name replaces the first (last-wins). Use snake_case.
	Name() string

	// Tasks returns the tasks this provider wishes to contribute.
	// Called exactly once at Start(). A provider that wishes to
	// contribute no tasks (e.g. feature-flagged off) should return a
	// nil or empty slice — the provider registration itself is not
	// an error.
	//
	// The returned slice is copied into the scheduler's task list
	// before Start launches the tick goroutine, so callers need not
	// worry about the scheduler retaining or mutating the slice.
	Tasks() []Task
}

// RegisterTaskProvider installs a TaskProvider. Safe to call before
// Start; panic-safe against nil (nil providers are silently dropped so
// a plugin that returns a typed-nil from a feature-flag path doesn't
// crash scheduler init).
//
// Registering the same provider twice is allowed but discouraged —
// both registrations will fire at Start, producing duplicate tasks
// whose Name() collision will cause the tick loop to treat them as
// "already ran today" after the first fires. Use a single provider
// instance per logical source of tasks.
func (s *Scheduler) RegisterTaskProvider(p TaskProvider) {
	if p == nil {
		return
	}
	// Guard against typed-nil (a pointer provider whose underlying
	// value is nil — common when a feature flag is off and the
	// constructor returned (*MyProvider)(nil)).
	if isTypedNil(p) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.providers = append(s.providers, p)
}

// collectProviderTasks drains every registered provider's Tasks() into
// s.tasks. Called once by Start() before the tick goroutine launches.
// Takes the writer lock to synchronise with concurrent Add() calls (the
// contract is "register everything before Start", but we defend against
// misuse rather than data-race at runtime).
//
// Defensive behaviour: a provider whose Tasks() panics is logged and
// skipped rather than crashing the scheduler. This preserves the
// fail-open ethos of the rest of the scheduler (a misbehaving task
// provider should not take down unrelated scheduled work).
func (s *Scheduler) collectProviderTasks() {
	s.mu.Lock()
	providers := make([]TaskProvider, len(s.providers))
	copy(providers, s.providers)
	s.mu.Unlock()

	for _, p := range providers {
		tasks := safeProviderTasks(s, p)
		if len(tasks) == 0 {
			continue
		}
		s.mu.Lock()
		s.tasks = append(s.tasks, tasks...)
		s.mu.Unlock()
	}
}

// safeProviderTasks calls p.Tasks() with panic recovery. A misbehaving
// provider must not take down the scheduler during startup.
func safeProviderTasks(s *Scheduler, p TaskProvider) (tasks []Task) {
	defer func() {
		if r := recover(); r != nil {
			if s.logger != nil {
				s.logger.Error("Scheduler: TaskProvider.Tasks() panicked",
					"provider", safeProviderName(p),
					"panic", r,
				)
			}
			tasks = nil
		}
	}()
	return p.Tasks()
}

// safeProviderName wraps p.Name() with panic recovery so log lines
// remain useful even when a provider's Name() implementation itself
// panics (pathological, but cheap to defend against).
func safeProviderName(p TaskProvider) (name string) {
	defer func() {
		if r := recover(); r != nil {
			name = "<panicked>"
		}
	}()
	return p.Name()
}

// ListTaskNames returns the Name field of every task currently held
// by the scheduler in registration order. Intended for tests, admin
// tooling, and log diagnostics ("what's the active schedule?").
//
// Snapshot: safe for concurrent use; the returned slice is a copy.
func (s *Scheduler) ListTaskNames() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.tasks))
	for i, t := range s.tasks {
		out[i] = t.Name
	}
	return out
}

// isTypedNil reports whether p is a non-nil interface wrapping a nil
// concrete pointer. Without this guard, a plugin that returns a
// typed-nil provider from a feature-flag path would pass the
// `p == nil` check above but blow up later when Tasks() dereferences
// the nil receiver.
//
// We use reflect.ValueOf rather than a panic-recover sniff because
// reflect.IsNil is a well-defined contract: it returns true only for
// pointer, chan, func, interface, map, and slice kinds. The
// recoverable-kinds check prevents a reflect panic on a value-typed
// provider (e.g. if someone ever registers a struct-value TaskProvider —
// rare, but not forbidden by the interface).
func isTypedNil(p TaskProvider) bool {
	v := reflect.ValueOf(p)
	switch v.Kind() {
	case reflect.Ptr, reflect.Map, reflect.Chan, reflect.Slice, reflect.Func, reflect.Interface:
		return v.IsNil()
	}
	return false
}
