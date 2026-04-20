package app

// anomaly_wiring_test.go — verifies that initializeServices wires the
// anomaly-detection BaselineProvider on the production Guard to the
// audit store. Without this wire the anomaly check silently no-ops in
// production (fail-open), defeating its purpose.

import (
	"reflect"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zerodha/kite-mcp-server/kc/riskguard"
)

// TestAnomalyWiring verifies initializeServices installs a non-nil
// BaselineProvider on the risk guard when an audit store is available,
// and that the wired provider is the audit store itself (not some stub).
func TestAnomalyWiring(t *testing.T) {
	t.Parallel()
	app := newTestAppWithConfig(t, &Config{
		KiteAPIKey:           "test_key",
		KiteAPISecret:        "test_secret",
		AlertDBPath:          ":memory:",
		InstrumentsSkipFetch: true,
	})
	app.DevMode = true

	kcManager, mcpServer, err := app.initializeServices()
	require.NoError(t, err)
	require.NotNil(t, kcManager)
	require.NotNil(t, mcpServer)
	defer cleanupInitializeServices(app, kcManager)

	// Guard must exist on the app.
	require.NotNil(t, app.riskGuard, "riskGuard should be wired")
	require.NotNil(t, app.auditStore, "auditStore should be wired in DevMode with ALERT_DB_PATH")

	// Inspect the private `baseline` field via reflection. We can't add
	// an exported getter without touching guard.go (out of scope), so
	// reflection is the least-invasive way to prove the wire landed.
	provider := readBaselineProvider(t, app.riskGuard)
	require.NotNil(t, provider, "BaselineProvider should be wired to audit store, got nil")

	// The wired provider MUST be the app's audit store itself — if some
	// other concrete type landed here, the wire is wrong.
	assert.Same(t, interface{}(app.auditStore), provider,
		"BaselineProvider should be exactly app.auditStore")

	// Behavioural sanity: the wired provider implements the interface
	// and returns (0,0,0) for an unknown user (the documented sentinel).
	bp, ok := provider.(riskguard.BaselineProvider)
	require.True(t, ok, "wired provider must implement riskguard.BaselineProvider")
	mean, stdev, count := bp.UserOrderStats("unknown@nowhere.test", 30)
	assert.Zero(t, mean)
	assert.Zero(t, stdev)
	assert.Zero(t, count)
}

// readBaselineProvider extracts the private `baseline` field from a
// *riskguard.Guard using reflection. Returns nil when unset.
//
// reflect.Value.Interface() on an unexported field panics, so we use
// reflect.NewAt with the field's unsafe address to read the value —
// a test-only pattern for inspecting private state without touching
// the target package's API.
func readBaselineProvider(t *testing.T, g *riskguard.Guard) interface{} {
	t.Helper()
	v := reflect.ValueOf(g).Elem().FieldByName("baseline")
	if !v.IsValid() {
		t.Fatalf("riskguard.Guard has no field 'baseline' — interface changed?")
	}
	if v.IsNil() {
		return nil
	}
	ptr := unsafe.Pointer(v.UnsafeAddr())
	return reflect.NewAt(v.Type(), ptr).Elem().Interface()
}
