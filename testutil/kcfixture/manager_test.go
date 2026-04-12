package kcfixture

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
