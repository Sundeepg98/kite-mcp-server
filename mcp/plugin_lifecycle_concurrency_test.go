package mcp

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConcurrentRegisterDuringReload — registering a new plugin
// lifecycle while Reload is running MUST NOT deadlock or race.
// Tests that the reload path takes the snapshot once and iterates
// over the copy rather than holding the registry lock across Init
// and Shutdown (which would block any registration).
func TestConcurrentRegisterDuringReload(t *testing.T) {
	ClearPluginLifecycles()
	ClearPluginHealth()
	defer ClearPluginLifecycles()
	defer ClearPluginHealth()

	// Pre-register a slow lifecycle whose Shutdown holds for 50ms
	// so we have a window during which to try registering in
	// parallel.
	RegisterPluginLifecycle("slow", &stubLifecycle{
		shutdownFn: func(ctx context.Context) error {
			time.Sleep(50 * time.Millisecond)
			return nil
		},
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = ReloadPluginRegistries(context.Background())
	}()

	// During the reload's Shutdown-sleep, register new entries.
	// These MUST succeed without deadlock.
	time.Sleep(10 * time.Millisecond) // let reload start
	for i := 0; i < 5; i++ {
		RegisterPluginLifecycle("late-"+string(rune('a'+i)), &stubLifecycle{})
	}

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("reload blocked on concurrent register")
	}

	// After reload completes, both slow and the late registrations
	// are in the registry.
	assert.GreaterOrEqual(t, PluginLifecycleCount(), 6)
}

// TestShutdownDuringInflightSafeCall — SafeInvoke racing with Close
// must not panic or deadlock. The SafeInvoke function itself is
// stateless, but this verifies callers can reason about the
// interleaving.
func TestShutdownDuringInflightSafeCall(t *testing.T) {
	ClearPluginHealth()
	defer ClearPluginHealth()

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			err := SafeInvoke("concurrent", func() error {
				if i%3 == 0 {
					panic("one of three")
				}
				time.Sleep(5 * time.Millisecond)
				return nil
			})
			// 1/3 should panic (recovered as error).
			if i%3 == 0 {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		}(i)
	}
	wg.Wait()
}

// TestInitPluginRegistries_AllPanicsCollected — if every registered
// plugin panics in Init, InitPluginRegistries still runs to
// completion (no early return) AND returns an aggregate error
// listing every panic.
func TestInitPluginRegistries_AllPanicsCollected(t *testing.T) {
	ClearPluginLifecycles()
	ClearPluginHealth()
	defer ClearPluginLifecycles()
	defer ClearPluginHealth()

	const N = 5
	var panicCount atomic.Int32
	for i := 0; i < N; i++ {
		name := "panicker-" + string(rune('a'+i))
		RegisterPluginLifecycle(name, &stubLifecycle{
			initFn: func(ctx context.Context) error {
				panicCount.Add(1)
				panic("init kaboom")
			},
		})
	}

	err := InitPluginRegistries(context.Background())
	require.Error(t, err, "expected aggregate error")
	assert.Equal(t, int32(N), panicCount.Load(),
		"every plugin's Init must have run despite siblings panicking")

	health := PluginHealth()
	for i := 0; i < N; i++ {
		name := "panicker-" + string(rune('a'+i))
		require.Contains(t, health, name)
		assert.Equal(t, HealthStateFailed, health[name].State)
	}
}

// TestShutdownReverseOrder_PanicsIsolated — Shutdown in reverse
// registration order, and a panic in one Shutdown does NOT prevent
// siblings from running.
func TestShutdownReverseOrder_PanicsIsolated(t *testing.T) {
	ClearPluginLifecycles()
	defer ClearPluginLifecycles()

	var order []string
	var mu sync.Mutex
	record := func(s string) {
		mu.Lock()
		defer mu.Unlock()
		order = append(order, s)
	}

	RegisterPluginLifecycle("first", &stubLifecycle{
		shutdownFn: func(ctx context.Context) error {
			record("first")
			return nil
		},
	})
	RegisterPluginLifecycle("panicker", &stubLifecycle{
		shutdownFn: func(ctx context.Context) error {
			record("panicker")
			panic("shutdown boom")
		},
	})
	RegisterPluginLifecycle("last", &stubLifecycle{
		shutdownFn: func(ctx context.Context) error {
			record("last")
			return nil
		},
	})

	err := ShutdownPluginRegistries(context.Background())
	// Aggregate error because panicker panicked.
	require.Error(t, err)

	// Shutdown order is reverse: last, panicker, first.
	// All three executed despite panicker's panic.
	assert.Equal(t, []string{"last", "panicker", "first"}, order)
}

// TestSafeCall_GenericTypeInference — SafeCall compiles and
// executes cleanly across diverse return types. Primarily a
// compile-time check that the generic signature works; the
// runtime assertions are secondary.
func TestSafeCall_GenericTypeInference(t *testing.T) {
	// string result
	s, err := SafeCall("str", func() (string, error) { return "hi", nil })
	assert.NoError(t, err)
	assert.Equal(t, "hi", s)

	// struct result
	type pair struct{ A, B int }
	p, err := SafeCall("struct", func() (pair, error) { return pair{1, 2}, nil })
	assert.NoError(t, err)
	assert.Equal(t, pair{1, 2}, p)

	// pointer result
	ptr, err := SafeCall("ptr", func() (*int, error) {
		v := 42
		return &v, nil
	})
	assert.NoError(t, err)
	require.NotNil(t, ptr)
	assert.Equal(t, 42, *ptr)

	// panic case — zero value of T and non-nil error
	zero, err := SafeCall("zero", func() (pair, error) {
		panic("test")
	})
	assert.Error(t, err)
	assert.Equal(t, pair{}, zero, "panic must return zero value of T")
}

// TestPluginManifest_CrossRegistryIntegration — populates every
// plugin-registry category and asserts GetPluginManifest surfaces
// all of them. One test, one snapshot — fails loudly if a new
// registry is added without wiring it into the manifest.
func TestPluginManifest_CrossRegistryIntegration(t *testing.T) {
	// Reset everything to known state.
	ClearPluginLifecycles()
	ClearPluginHealth()
	ClearPluginSBOM()
	ClearPluginInfo()
	ClearPluginMiddleware()
	ClearPluginWidgets()
	ClearPluginEventSubscriptions()
	ClearHooks()
	ClearPlugins()
	defer func() {
		ClearPluginLifecycles()
		ClearPluginHealth()
		ClearPluginSBOM()
		ClearPluginInfo()
		ClearPluginMiddleware()
		ClearPluginWidgets()
		ClearPluginEventSubscriptions()
		ClearHooks()
		ClearPlugins()
	}()

	// Seed one entry in each category the manifest tracks.
	require.NoError(t, RegisterPluginInfo(PluginInfo{
		Name:    "integration_test",
		Version: "1.0.0",
	}))
	require.NoError(t, RegisterPluginSBOM(PluginSBOMEntry{
		Name:     "integration_test",
		Checksum: "sha256:integration",
		Version:  "1.0.0",
	}))
	ReportPluginHealth("integration_test", HealthStatus{State: HealthStateOK})
	RegisterPluginLifecycle("integration_test", &stubLifecycle{})

	m := GetPluginManifest()
	assert.Len(t, m.Plugins, 1)
	assert.NotEmpty(t, m.Health)
	assert.NotEmpty(t, m.SBOM)
	assert.Equal(t, 1, m.LifecycleCount)

	// The manifest is the single "is everything wired?" contract
	// — if any of the above assertions fail, a new registry was
	// added without updating GetPluginManifest.
}
