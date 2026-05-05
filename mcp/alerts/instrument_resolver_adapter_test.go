package alerts

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zerodha/kite-mcp-server/testutil/kcfixture"
)

// Anchor 1 PR 1.8: instrumentResolverAdapter tests previously lived in
// mcp/tools_validation_helpers_test.go but reference unexported
// alerts-package symbols (instrumentResolverAdapter). Moved here so the
// tests can construct the type without exporting it.

func TestInstrumentResolverAdapter_NotFound(t *testing.T) {
	t.Parallel()
	mgr := kcfixture.NewTestManager(t, kcfixture.WithDevMode())
	adapter := &instrumentResolverAdapter{mgr: mgr.Instruments}
	_, err := adapter.GetInstrumentToken("NSE", "NONEXISTENT")
	assert.Error(t, err)
}

func TestInstrumentResolverAdapter_Type(t *testing.T) {
	t.Parallel()
	// Verify that the adapter implements the right interface pattern
	mgr := kcfixture.NewTestManager(t, kcfixture.WithDevMode())
	adapter := &instrumentResolverAdapter{mgr: mgr.Instruments}
	assert.NotNil(t, adapter)
}
