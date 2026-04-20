//go:build integration

package app

// integration_kite_api_test.go — exercises the live Kite instruments-fetch
// path. Guarded by the `integration` build tag so it never runs in the
// default CI pipeline (which must stay isolated from api.kite.trade rate
// limits). Run locally with:
//
//	go test -tags integration ./app/ -run TestInitializeServices_FetchesRealInstruments -v
//
// This is the retained-coverage counterpart to the INSTRUMENTS_SKIP_FETCH
// seam used by newTestApp. It proves the production code path still works
// end-to-end against the real URL — something the unit-test suite can no
// longer cover (by design, to keep CI green).

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInitializeServices_FetchesRealInstruments verifies that the normal
// initialization path (without InstrumentsSkipFetch) successfully loads
// instruments from api.kite.trade. Requires network access and runs only
// under -tags integration.
func TestInitializeServices_FetchesRealInstruments(t *testing.T) {
	// Phase E.2 Task #42: most env reads replaced with a Config literal.
	// DEV_MODE remains a t.Setenv because app.DevMode is derived from the
	// env inside NewApp rather than Config. INSTRUMENTS_SKIP_FETCH is
	// explicitly cleared so the real fetch path is exercised; the build
	// tag `integration` keeps this out of default CI.
	t.Setenv("DEV_MODE", "true")
	os.Unsetenv("INSTRUMENTS_SKIP_FETCH")

	cfg := &Config{
		KiteAPIKey:    "test_key",
		KiteAPISecret: "test_secret",
		AlertDBPath:   ":memory:",
	}
	app := NewAppWithConfig(cfg, testLogger())
	t.Cleanup(func() {
		if app.metrics != nil {
			app.metrics.Shutdown()
		}
	})

	mgr, mcpServer, err := app.initializeServices()
	require.NoError(t, err, "real Kite instruments fetch should succeed under -tags integration")
	require.NotNil(t, mgr)
	require.NotNil(t, mcpServer)
	t.Cleanup(func() { cleanupInitializeServices(app, mgr) })

	// Spot-check: the instruments manager should have loaded *something*.
	instrMgr := mgr.InstrumentsManagerConcrete()
	require.NotNil(t, instrMgr, "instruments manager should be wired")
	// A successful fetch returns tens of thousands of instruments — assert
	// loosely (>1000) so we tolerate weekend vs trading-day variance.
	stats := instrMgr.GetUpdateStats()
	assert.Greater(t, stats.LastUpdateCount, 1000,
		"expected instruments.json fetch to return >1000 rows; got %d",
		stats.LastUpdateCount)
}
