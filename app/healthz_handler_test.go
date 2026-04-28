package app

// healthz_handler_test.go — HTTP integration tests for /healthz and the
// underlying component-status helpers in http.go.
//
// Coverage focus (Sub-commit A of the app/ HTTP integration push):
//   - handleHealthz: the three response shapes (legacy flat / format=json
//     / probe=deep) at the HTTP layer (was 60%).
//   - databaseDeepStatus, brokerFactoryDeepStatus, litestreamDeepStatus,
//     anomalyCacheComponentStatus: the deep/component helpers reachable
//     via /healthz?probe=deep (most were 0% — entirely dark before).
//   - auditComponentStatus: the dropping > 0 branch (40% → higher).
//
// Non-goals: tests for serveLegalPages and renderMarkdown — both already
// well-covered in app/http_privacy_test.go and app/server_edge_test.go.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
)

// ===========================================================================
// /healthz HTTP integration — three response shapes
// ===========================================================================

// TestHandleHealthz_LegacyDefault verifies the no-query-param request
// returns the flat legacy shape (status/uptime/version/tools). This is
// the path used by load balancers and uptime checkers.
func TestHandleHealthz_LegacyDefault(t *testing.T) {
	app := newTestApp(t)
	app.Version = "test-v1.2.3"

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	app.handleHealthz(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var got map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	assert.Equal(t, "ok", got["status"])
	assert.Equal(t, "test-v1.2.3", got["version"])
	// uptime is a duration string like "0s" or "1ms" — just non-empty.
	uptime, ok := got["uptime"].(string)
	require.True(t, ok)
	assert.NotEmpty(t, uptime)
	// tools is a number (count of registered MCP tools).
	_, ok = got["tools"].(float64)
	require.True(t, ok, "tools field must be a JSON number")
}

// TestHandleHealthz_FormatJSON verifies ?format=json returns the rich
// component-level shape (status/uptime_s/version/components map).
func TestHandleHealthz_FormatJSON(t *testing.T) {
	app := newTestApp(t)
	app.Version = "test-v1.2.3"

	// Wire a riskguard so the riskguard component reports something
	// other than the defaults-only fallback.
	app.riskGuard = riskguard.NewGuard(testLogger())
	app.riskLimitsLoaded = true

	req := httptest.NewRequest(http.MethodGet, "/healthz?format=json", nil)
	rec := httptest.NewRecorder()
	app.handleHealthz(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var got healthzReport
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	assert.NotEmpty(t, got.Status, "rich format must include status")
	assert.Equal(t, "test-v1.2.3", got.Version)
	assert.NotNil(t, got.Components, "rich format must include components map")
	// Audit and riskguard are always reported (kite_connectivity +
	// litestream are also present as "unknown" stubs in the cheap probe).
	_, hasAudit := got.Components["audit"]
	_, hasRiskguard := got.Components["riskguard"]
	assert.True(t, hasAudit)
	assert.True(t, hasRiskguard)
}

// TestHandleHealthz_DeepProbe verifies ?probe=deep returns the deep
// shape (cheap components + database/broker_factory/litestream
// runtime probes).
func TestHandleHealthz_DeepProbe(t *testing.T) {
	app := newTestApp(t)
	app.riskGuard = riskguard.NewGuard(testLogger())
	app.riskLimitsLoaded = true

	req := httptest.NewRequest(http.MethodGet, "/healthz?probe=deep", nil)
	rec := httptest.NewRecorder()
	app.handleHealthz(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var got healthzReport
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))

	// Deep probe must surface the three deep components in addition to
	// the cheap ones.
	for _, key := range []string{"database", "broker_factory", "litestream"} {
		comp, ok := got.Components[key]
		require.True(t, ok, "deep probe must include component %q", key)
		assert.NotEmpty(t, comp.Status, "%q component must report status", key)
	}
}

// ===========================================================================
// databaseDeepStatus — the four state branches
// ===========================================================================

// TestDatabaseDeepStatus_NilManager covers the "manager not wired"
// fast-path: app.kcManager == nil → "disabled".
func TestDatabaseDeepStatus_NilManager(t *testing.T) {
	app := newTestApp(t)
	app.kcManager = nil

	got := app.databaseDeepStatus()
	assert.Equal(t, "disabled", got.Status)
	assert.Contains(t, got.Note, "manager not wired")
}

// TestDatabaseDeepStatus_HealthyDB covers the happy path: kcManager
// present, AlertDB pings successfully → "ok".
func TestDatabaseDeepStatus_HealthyDB(t *testing.T) {
	app := newTestApp(t)
	app.kcManager = newTestManagerWithDB(t)

	got := app.databaseDeepStatus()
	assert.Equal(t, "ok", got.Status,
		"in-memory DB should ping successfully; got note=%q", got.Note)
}

// ===========================================================================
// brokerFactoryDeepStatus — three state branches
// ===========================================================================

// TestBrokerFactoryDeepStatus_NilSession covers the "session service
// not wired" fast-path.
func TestBrokerFactoryDeepStatus_NilSession(t *testing.T) {
	app := newTestApp(t)
	app.kcManager = nil

	got := app.brokerFactoryDeepStatus()
	assert.Equal(t, "disabled", got.Status)
	assert.Contains(t, got.Note, "session service not wired")
}

// TestBrokerFactoryDeepStatus_DevModeNoFactory covers the DevMode
// fallback path: in DevMode the session service exists but no
// explicit broker.Factory is wired → "ok" with note about implicit
// Zerodha factory default.
func TestBrokerFactoryDeepStatus_DevModeNoFactory(t *testing.T) {
	app := newTestApp(t)
	app.kcManager = newTestManager(t) // DevMode, no broker.Factory wired
	app.DevMode = true

	got := app.brokerFactoryDeepStatus()
	assert.Equal(t, "ok", got.Status)
	assert.Contains(t, got.Note, "dev mode")
}

// TestBrokerFactoryDeepStatus_DegradedNoFactory covers the production-
// path warning: SessionService present, no factory wired, NOT DevMode
// → "degraded".
func TestBrokerFactoryDeepStatus_DegradedNoFactory(t *testing.T) {
	app := newTestApp(t)
	app.kcManager = newTestManager(t)
	app.DevMode = false

	got := app.brokerFactoryDeepStatus()
	assert.Equal(t, "degraded", got.Status)
	assert.Contains(t, got.Note, "broker.Factory not wired")
}

// ===========================================================================
// litestreamDeepStatus — four state branches
// ===========================================================================

// TestLitestreamDeepStatus_NoConfig covers the "Config nil" path: the
// helper short-circuits to "ok" with "no DB path configured" note.
func TestLitestreamDeepStatus_NoConfig(t *testing.T) {
	app := newTestApp(t)
	app.Config = nil

	got := app.litestreamDeepStatus()
	assert.Equal(t, "ok", got.Status)
	assert.Contains(t, got.Note, "no DB path configured")
}

// TestLitestreamDeepStatus_EmptyAlertDBPath covers the same short-
// circuit when Config is present but AlertDBPath is empty.
func TestLitestreamDeepStatus_EmptyAlertDBPath(t *testing.T) {
	app := newTestApp(t)
	app.Config = &Config{AlertDBPath: ""}

	got := app.litestreamDeepStatus()
	assert.Equal(t, "ok", got.Status)
	assert.Contains(t, got.Note, "replication N/A")
}

// TestLitestreamDeepStatus_MemoryDB covers the special-cased :memory:
// path which is also "no replication".
func TestLitestreamDeepStatus_MemoryDB(t *testing.T) {
	app := newTestApp(t)
	app.Config = &Config{AlertDBPath: ":memory:"}

	got := app.litestreamDeepStatus()
	assert.Equal(t, "ok", got.Status)
	assert.Contains(t, got.Note, "replication N/A")
}

// TestLitestreamDeepStatus_FreshWAL covers the happy path: a
// recently-touched WAL file → "ok" status with no note.
func TestLitestreamDeepStatus_FreshWAL(t *testing.T) {
	app := newTestApp(t)

	// Build a path with a freshly-touched -wal sibling.
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	walPath := dbPath + "-wal"
	require.NoError(t, os.WriteFile(walPath, []byte("wal-data"), 0644))
	app.Config = &Config{AlertDBPath: dbPath}

	got := app.litestreamDeepStatus()
	assert.Equal(t, "ok", got.Status)
}

// TestLitestreamDeepStatus_StaleWAL covers the >1-min mtime path
// reporting "stale". We back-date the WAL file's mtime via os.Chtimes.
func TestLitestreamDeepStatus_StaleWAL(t *testing.T) {
	app := newTestApp(t)

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	walPath := dbPath + "-wal"
	require.NoError(t, os.WriteFile(walPath, []byte("wal-data"), 0644))
	// Make WAL 5 minutes old (well past healthzWALStaleAfter=60s).
	staleTime := time.Now().Add(-5 * time.Minute)
	require.NoError(t, os.Chtimes(walPath, staleTime, staleTime))
	app.Config = &Config{AlertDBPath: dbPath}

	got := app.litestreamDeepStatus()
	assert.Equal(t, "stale", got.Status)
	assert.Contains(t, got.Note, "WAL mtime")
}

// TestLitestreamDeepStatus_MissingWAL covers the "WAL file not
// present" path: AlertDBPath set but no -wal sibling exists yet
// (cold start before first commit) → "unknown".
func TestLitestreamDeepStatus_MissingWAL(t *testing.T) {
	app := newTestApp(t)

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "no-wal.db")
	// Deliberately do NOT create the -wal sibling.
	app.Config = &Config{AlertDBPath: dbPath}

	got := app.litestreamDeepStatus()
	assert.Equal(t, "unknown", got.Status)
	assert.Contains(t, got.Note, "WAL file not present")
}

// ===========================================================================
// auditComponentStatus — the dropping branch
// ===========================================================================

// TestAuditComponentStatus_DroppingNonZero covers the dropping > 0
// branch: an audit store that's failed to record any entries reports
// "dropping" status with the count surfaced. Mirrors the production
// alert path that wakes up ops on an audit-buffer overflow.
func TestAuditComponentStatus_DroppingNonZero(t *testing.T) {
	t.Parallel()
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	// Don't InitTable — EnqueueCtx without a table forces a drop on the
	// sync-fallback path.
	auditStore := audit.New(db)
	auditStore.EnqueueCtx(context.Background(), &audit.ToolCall{CallID: "drop-me", ToolName: "x"})
	require.Greater(t, auditStore.DroppedCount(), int64(0),
		"test setup: EnqueueCtx without a table must drop")

	app := newTestApp(t)
	app.auditStore = auditStore

	got := app.auditComponentStatus()
	assert.Equal(t, "dropping", got.Status)
	assert.Greater(t, got.DroppedCount, int64(0))
	assert.NotEmpty(t, got.Note)
}

// TestAuditComponentStatus_DisabledNilStore covers the nil-store
// branch (disabled / compliance gap path). Provides explicit coverage
// for the if-nil branch which the build tests don't otherwise hit
// directly.
func TestAuditComponentStatus_DisabledNilStore(t *testing.T) {
	t.Parallel()
	app := newTestApp(t)
	app.auditStore = nil

	got := app.auditComponentStatus()
	assert.Equal(t, "disabled", got.Status)
	assert.Contains(t, got.Note, "audit store init failed")
}

// TestAuditComponentStatus_OkHealthy covers the happy path: store is
// wired, no drops → "ok" with no extra fields.
func TestAuditComponentStatus_OkHealthy(t *testing.T) {
	t.Parallel()
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	auditStore := audit.New(db)
	require.NoError(t, auditStore.InitTable())

	app := newTestApp(t)
	app.auditStore = auditStore

	got := app.auditComponentStatus()
	assert.Equal(t, "ok", got.Status)
	assert.Empty(t, got.Note)
	assert.Equal(t, int64(0), got.DroppedCount)
}

// ===========================================================================
// anomalyCacheComponentStatus — three rate buckets
// ===========================================================================

// TestAnomalyCacheComponentStatus_ZeroRateColdStart covers the
// cold-start branch: hit_rate == 0 must NOT trigger a degraded alert
// (otherwise every post-deploy window false-alarms).
func TestAnomalyCacheComponentStatus_ZeroRateColdStart(t *testing.T) {
	t.Parallel()
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	auditStore := audit.New(db)
	require.NoError(t, auditStore.InitTable())

	app := newTestApp(t)
	app.auditStore = auditStore

	// No traffic — hit rate is zero.
	require.InDelta(t, 0.0, auditStore.StatsCacheHitRate(), 0.0001,
		"test setup: fresh store should have hit rate 0")

	got := app.anomalyCacheComponentStatus()
	assert.Equal(t, "ok", got.Status, "cold-start hit_rate=0 must NOT degrade")
	assert.Contains(t, got.Note, "no traffic yet")
	require.NotNil(t, got.HitRate)
	assert.InDelta(t, 0.0, *got.HitRate, 0.0001)
	require.NotNil(t, got.MaxEntries)
}

// ===========================================================================
// /healthz integration — degraded surfacing through the HTTP layer
// ===========================================================================

// TestHandleHealthz_FormatJSON_Degraded covers the end-to-end
// degraded-status surfacing: a dropping audit store at the helper
// level → top-level "degraded" status emitted via the HTTP response
// body. Pins the contract that operators see degraded on the wire.
func TestHandleHealthz_FormatJSON_Degraded(t *testing.T) {
	t.Parallel()
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	auditStore := audit.New(db)
	auditStore.EnqueueCtx(context.Background(), &audit.ToolCall{CallID: "drop", ToolName: "x"})
	require.Greater(t, auditStore.DroppedCount(), int64(0))

	app := newTestApp(t)
	app.auditStore = auditStore
	app.riskGuard = riskguard.NewGuard(testLogger())
	app.riskLimitsLoaded = true

	req := httptest.NewRequest(http.MethodGet, "/healthz?format=json", nil)
	rec := httptest.NewRecorder()
	app.handleHealthz(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code,
		"healthz must always return 200 even when components are degraded")

	var got healthzReport
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	assert.Equal(t, "degraded", got.Status,
		"top-level status must surface 'degraded' when audit is dropping")
	assert.Equal(t, "dropping", got.Components["audit"].Status)
	assert.Greater(t, got.Components["audit"].DroppedCount, int64(0))
}
