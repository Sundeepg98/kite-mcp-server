package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRegisterBuiltinWidgetPack_RegistersExpectedWidgets confirms the
// pack installs each widget that has landed so far. The set grows one
// widget per commit; this test walks whatever RegisterBuiltinWidgetPack
// returns and asserts every URI in expectedWidgetURIs is present. Keeps
// the test honest as widgets are added — each new widget commit appends
// its URI below.
func TestRegisterBuiltinWidgetPack_RegistersExpectedWidgets(t *testing.T) {
	t.Parallel()
	LockDefaultRegistryForTest(t)
	err := RegisterBuiltinWidgetPack(nil, nil, nil)
	require.NoError(t, err)

	widgets := ListPluginWidgets()
	assert.NotEmpty(t, widgets, "pack registration should install at least one widget")

	uris := make(map[string]bool)
	for _, w := range widgets {
		uris[w.URI] = true
	}
	expectedWidgetURIs := []string{
		"ui://kite-mcp/sector-donut",
		"ui://kite-mcp/pnl-sparkline",
		"ui://kite-mcp/margin-gauge",
		"ui://kite-mcp/ip-whitelist-status",
		"ui://kite-mcp/returns-matrix",
	}
	for _, want := range expectedWidgetURIs {
		assert.True(t, uris[want], "expected widget %q to be registered", want)
	}
}

// TestRegisterBuiltinWidgetPack_HandlersReturnValidHTML confirms every
// registered handler returns at least one ResourceContents with
// non-empty HTML on invocation. This is the smoke test the brief
// asks for — "register a fake widget, assert it appears in
// resources/list response" generalised: each real widget must actually
// produce output.
func TestRegisterBuiltinWidgetPack_HandlersReturnValidHTML(t *testing.T) {
	t.Parallel()
	LockDefaultRegistryForTest(t)
	require.NoError(t, RegisterBuiltinWidgetPack(nil, nil, nil))

	for _, w := range ListPluginWidgets() {
		t.Run(w.Name, func(t *testing.T) {
			req := gomcp.ReadResourceRequest{}
			req.Params.URI = w.URI
			contents, err := w.Handler(context.Background(), req)
			require.NoError(t, err, "handler for %s returned error", w.URI)
			require.Len(t, contents, 1)
			tc, ok := contents[0].(gomcp.TextResourceContents)
			require.True(t, ok)
			assert.Equal(t, ResourceMIMEType, tc.MIMEType)
			assert.NotEmpty(t, tc.Text)
			// Every widget HTML should include the injected data marker
			// resolved (placeholder replaced with either JSON or "null").
			assert.NotContains(t, tc.Text, dataPlaceholder,
				"widget %q still has unresolved %s", w.URI, dataPlaceholder)
		})
	}
}

// TestRegisterBuiltinWidgetPack_Idempotent — calling the pack
// registration twice must not duplicate widgets (last-wins per
// RegisterWidget semantics). Guards against double-init bugs during
// app start + test setup.
func TestRegisterBuiltinWidgetPack_Idempotent(t *testing.T) {
	t.Parallel()
	LockDefaultRegistryForTest(t)
	require.NoError(t, RegisterBuiltinWidgetPack(nil, nil, nil))
	countAfterFirst := PluginWidgetCount()
	require.NoError(t, RegisterBuiltinWidgetPack(nil, nil, nil))
	assert.Equal(t, countAfterFirst, PluginWidgetCount(),
		"double-registration should not duplicate widgets (last-wins)")
}

// TestSectorDonutData_HandlesNilManager — a nil manager yields a
// deterministic "not configured" data payload rather than a panic.
// Matches the defensive posture of every other widget DataFunc in
// the codebase (portfolio / activity / orders all handle nil manager
// without crashing).
func TestSectorDonutData_HandlesNilManager(t *testing.T) {
	t.Parallel()
	LockDefaultRegistryForTest(t)
	data := sectorDonutWidgetData(context.Background(), nil, "user@test.com")
	b, err := json.Marshal(data)
	require.NoError(t, err)
	j := string(b)
	// Payload contains an error/unavailable flag but NOT a stack trace.
	assert.True(t,
		strings.Contains(j, "unavailable") || strings.Contains(j, "error"),
		"nil manager should yield an explicit error/unavailable flag; got %s", j)
}

// TestPnLSparklineData_HandlesNilManager — nil-safe like every other
// widget data function; a nil manager yields an error shape rather
// than a panic.
func TestPnLSparklineData_HandlesNilManager(t *testing.T) {
	t.Parallel()
	LockDefaultRegistryForTest(t)
	data := pnlSparklineWidgetData(context.Background(), nil, "user@test.com")
	assert.NotNil(t, data, "even nil manager yields a response object")
}

// TestMarginGaugeData_HandlesNilManager — nil-safe contract.
func TestMarginGaugeData_HandlesNilManager(t *testing.T) {
	t.Parallel()
	LockDefaultRegistryForTest(t)
	data := marginGaugeWidgetData(context.Background(), nil, "user@test.com")
	assert.NotNil(t, data)
}

// TestIPWhitelistData_StaticFields confirms the IP whitelist widget
// emits the deployment's static egress IP (209.71.68.157 by default
// for the Fly.io bom region) and the Kite developer-console URL.
// SEBI Apr 2026 compliance surface.
func TestIPWhitelistData_StaticFields(t *testing.T) {
	t.Parallel()
	LockDefaultRegistryForTest(t)
	data := ipWhitelistWidgetData(context.Background(), nil, "user@test.com")
	b, err := json.Marshal(data)
	require.NoError(t, err)
	j := string(b)
	assert.Contains(t, j, "209.71.68.157", "static egress IP must be present")
	assert.Contains(t, j, "kite.trade", "Kite console URL must be present")
}

// TestReturnsMatrixData_HandlesNilManager — nil-safe contract.
func TestReturnsMatrixData_HandlesNilManager(t *testing.T) {
	t.Parallel()
	LockDefaultRegistryForTest(t)
	data := returnsMatrixWidgetData(context.Background(), nil, "user@test.com")
	assert.NotNil(t, data)
}
