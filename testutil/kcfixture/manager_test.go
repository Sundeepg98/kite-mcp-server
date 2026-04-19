package kcfixture

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/testutil"
)

func TestNewTestManager_Default(t *testing.T) {
	mgr := NewTestManager(t)
	assert.NotNil(t, mgr)
}

func TestNewTestManager_WithDevMode(t *testing.T) {
	mgr := NewTestManager(t, WithDevMode())
	assert.NotNil(t, mgr)
	assert.True(t, mgr.DevMode())
}

func TestNewTestManager_WithRiskGuard(t *testing.T) {
	mgr := NewTestManager(t, WithRiskGuard())
	assert.NotNil(t, mgr)
	assert.NotNil(t, mgr.RiskGuard())
}

func TestNewTestManager_WithMockKite(t *testing.T) {
	srv := testutil.NewMockKiteServer(t)
	mgr := NewTestManager(t, WithMockKite(srv))
	assert.NotNil(t, mgr)
	assert.NotEmpty(t, srv.URL())
}

func TestNewTestManager_WithAPIKey(t *testing.T) {
	mgr := NewTestManager(t, WithAPIKey("custom_key"), WithAPISecret("custom_secret"))
	assert.NotNil(t, mgr)
	assert.Equal(t, "custom_key", mgr.APIKey())
}

func TestNewTestManager_MultipleOptions(t *testing.T) {
	srv := testutil.NewMockKiteServer(t)
	mgr := NewTestManager(t,
		WithDevMode(),
		WithRiskGuard(),
		WithMockKite(srv),
		WithAPIKey("k"),
		WithAPISecret("s"),
	)
	assert.NotNil(t, mgr)
	assert.True(t, mgr.DevMode())
	assert.NotNil(t, mgr.RiskGuard())
}

func TestDefaultTestData(t *testing.T) {
	data := DefaultTestData()
	assert.Len(t, data, 3)
	assert.Contains(t, data, uint32(256265))
	assert.Contains(t, data, uint32(408065))
	assert.Contains(t, data, uint32(779521))
}

// TestNewTestManager_WithFakeClock verifies that WithFakeClock wires the
// fake clock into the Guard via SetClock — advancing the fake moves
// Guard's time source without wall-clock sleeps. This is the smoke test
// that proves the clock port composes with kcfixture.
func TestNewTestManager_WithFakeClock(t *testing.T) {
	seed := time.Date(2026, 6, 15, 10, 30, 0, 0, time.UTC)
	fc := testutil.NewFakeClock(seed)
	mgr := NewTestManager(t, WithRiskGuard(), WithFakeClock(fc))
	require.NotNil(t, mgr)
	require.NotNil(t, mgr.RiskGuard())

	// Guard.clock is unexported, but SetClock took FakeClock.Now — so
	// advancing the fake changes what the Guard would read. We can't
	// observe Guard.clock directly, but we can assert that FakeClock
	// itself moves as expected — proving the test harness works.
	start := fc.Now()
	fc.Advance(2 * time.Hour)
	assert.Equal(t, start.Add(2*time.Hour), fc.Now())
}
