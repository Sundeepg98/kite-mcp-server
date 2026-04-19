package mcp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSafeInvoke_PanicRecovered confirms that SafeInvoke swallows a
// panic and returns it as an error. This is the primary safety
// primitive used by every plugin-invocation site.
func TestSafeInvoke_PanicRecovered(t *testing.T) {
	err := SafeInvoke("test_plugin", func() error {
		panic("boom")
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "test_plugin")
	assert.Contains(t, err.Error(), "boom")
}

// TestSafeInvoke_ErrorPassthrough — a non-panicking function that
// returns an error must have that error surfaced unchanged (no
// double-wrap).
func TestSafeInvoke_ErrorPassthrough(t *testing.T) {
	sentinel := errors.New("sentinel")
	err := SafeInvoke("test", func() error { return sentinel })
	assert.ErrorIs(t, err, sentinel)
}

// TestSafeInvoke_SuccessNilErr — a clean path returns nil.
func TestSafeInvoke_SuccessNilErr(t *testing.T) {
	err := SafeInvoke("test", func() error { return nil })
	assert.NoError(t, err)
}

// TestSafeCall_PanicRecovered — the generic two-value variant used
// when a plugin function returns a value plus an error (e.g. widget
// handlers, around-hooks).
func TestSafeCall_PanicRecovered(t *testing.T) {
	result, err := SafeCall("test", func() (int, error) {
		panic("kaboom")
	})
	assert.Equal(t, 0, result, "zero value returned on panic")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kaboom")
}

// TestSafeCall_Passthrough — happy path returns the value.
func TestSafeCall_Passthrough(t *testing.T) {
	result, err := SafeCall("test", func() (int, error) { return 42, nil })
	assert.NoError(t, err)
	assert.Equal(t, 42, result)
}

// TestPluginHealth_RegisterAndRead — a plugin records its health
// via ReportPluginHealth; PluginHealth() returns a snapshot.
func TestPluginHealth_RegisterAndRead(t *testing.T) {
	ClearPluginHealth()
	defer ClearPluginHealth()

	ReportPluginHealth("my_plugin", HealthStatus{
		State:   HealthStateOK,
		Message: "all green",
	})

	health := PluginHealth()
	require.Contains(t, health, "my_plugin")
	assert.Equal(t, HealthStateOK, health["my_plugin"].State)
	assert.Equal(t, "all green", health["my_plugin"].Message)
}

// TestPluginHealth_StateTransitions — a plugin moves through states
// (ok -> degraded -> failed). Each ReportPluginHealth replaces the
// prior entry (last-wins).
func TestPluginHealth_StateTransitions(t *testing.T) {
	ClearPluginHealth()
	defer ClearPluginHealth()

	ReportPluginHealth("p", HealthStatus{State: HealthStateOK})
	ReportPluginHealth("p", HealthStatus{State: HealthStateDegraded, Message: "slow"})
	ReportPluginHealth("p", HealthStatus{State: HealthStateFailed, Message: "crashed"})

	health := PluginHealth()
	assert.Equal(t, HealthStateFailed, health["p"].State)
	assert.Equal(t, "crashed", health["p"].Message)
}

// TestPluginHealth_TimestampAuto — ReportPluginHealth stamps LastChecked
// automatically if caller leaves it zero.
func TestPluginHealth_TimestampAuto(t *testing.T) {
	ClearPluginHealth()
	defer ClearPluginHealth()

	before := time.Now()
	ReportPluginHealth("p", HealthStatus{State: HealthStateOK})
	after := time.Now()

	h := PluginHealth()["p"]
	assert.True(t, !h.LastChecked.Before(before))
	assert.True(t, !h.LastChecked.After(after))
}

// TestInitPluginRegistries_InvokesAll — calling InitPluginRegistries
// triggers Init on each registered PluginLifecycle.
func TestInitPluginRegistries_InvokesAll(t *testing.T) {
	ClearPluginLifecycles()
	defer ClearPluginLifecycles()

	var initCount int
	RegisterPluginLifecycle("a", &stubLifecycle{
		initFn: func(ctx context.Context) error { initCount++; return nil },
	})
	RegisterPluginLifecycle("b", &stubLifecycle{
		initFn: func(ctx context.Context) error { initCount++; return nil },
	})

	err := InitPluginRegistries(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, initCount)
}

// TestInitPluginRegistries_PanicsIsolated — a plugin whose Init
// panics must NOT prevent other plugins from initialising. The
// panicking plugin is marked Failed in health; others stay OK.
func TestInitPluginRegistries_PanicsIsolated(t *testing.T) {
	ClearPluginLifecycles()
	ClearPluginHealth()
	defer ClearPluginLifecycles()
	defer ClearPluginHealth()

	var bothCalled bool
	RegisterPluginLifecycle("panicker", &stubLifecycle{
		initFn: func(ctx context.Context) error {
			panic("init panic")
		},
	})
	RegisterPluginLifecycle("good", &stubLifecycle{
		initFn: func(ctx context.Context) error {
			bothCalled = true
			return nil
		},
	})

	err := InitPluginRegistries(context.Background())
	// Aggregate error is returned; not nil but not a crash.
	require.Error(t, err)
	assert.True(t, bothCalled, "good plugin must still init after sibling panicked")

	health := PluginHealth()
	assert.Equal(t, HealthStateFailed, health["panicker"].State)
	assert.Equal(t, HealthStateOK, health["good"].State)
}

// TestShutdownPluginRegistries_ReverseOrder — Shutdown is called
// in the reverse order of Init so stateful teardown mirrors setup
// (standard for lifecycle managers).
func TestShutdownPluginRegistries_ReverseOrder(t *testing.T) {
	ClearPluginLifecycles()
	defer ClearPluginLifecycles()

	var order []string
	RegisterPluginLifecycle("first", &stubLifecycle{
		shutdownFn: func(ctx context.Context) error {
			order = append(order, "first")
			return nil
		},
	})
	RegisterPluginLifecycle("second", &stubLifecycle{
		shutdownFn: func(ctx context.Context) error {
			order = append(order, "second")
			return nil
		},
	})
	RegisterPluginLifecycle("third", &stubLifecycle{
		shutdownFn: func(ctx context.Context) error {
			order = append(order, "third")
			return nil
		},
	})

	err := ShutdownPluginRegistries(context.Background())
	require.NoError(t, err)
	// Reverse of registration: third, second, first.
	assert.Equal(t, []string{"third", "second", "first"}, order)
}

// TestReloadPluginRegistries_ShutdownThenInit — Reload is a
// coordinated shutdown + init, used by the "edit plugin code, hit
// SIGHUP" dev loop.
func TestReloadPluginRegistries_ShutdownThenInit(t *testing.T) {
	ClearPluginLifecycles()
	defer ClearPluginLifecycles()

	var sequence []string
	RegisterPluginLifecycle("p", &stubLifecycle{
		initFn: func(ctx context.Context) error {
			sequence = append(sequence, "init")
			return nil
		},
		shutdownFn: func(ctx context.Context) error {
			sequence = append(sequence, "shutdown")
			return nil
		},
	})

	err := ReloadPluginRegistries(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"shutdown", "init"}, sequence)
}

// TestPluginManifest_IncludesHealth — GetPluginManifest now carries
// a Health map so one endpoint surfaces everything the admin needs.
func TestPluginManifest_IncludesHealth(t *testing.T) {
	ClearPluginHealth()
	defer ClearPluginHealth()

	ReportPluginHealth("x", HealthStatus{State: HealthStateOK, Message: "alive"})
	m := GetPluginManifest()
	assert.Contains(t, m.Health, "x")
	assert.Equal(t, HealthStateOK, m.Health["x"].State)
}

// --- test helpers ---

// stubLifecycle is a minimal PluginLifecycle for tests — either fn
// can be nil to mean "no-op" for that phase.
type stubLifecycle struct {
	initFn     func(ctx context.Context) error
	shutdownFn func(ctx context.Context) error
}

func (s *stubLifecycle) Init(ctx context.Context) error {
	if s.initFn != nil {
		return s.initFn(ctx)
	}
	return nil
}
func (s *stubLifecycle) Shutdown(ctx context.Context) error {
	if s.shutdownFn != nil {
		return s.shutdownFn(ctx)
	}
	return nil
}

var _ PluginLifecycle = (*stubLifecycle)(nil)
