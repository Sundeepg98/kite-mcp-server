// order_chain_helpers_test.go — shared scaffolding for the
// `*_full_chain_test.go` integration tests (modify_order, cancel_order,
// place_gtt_order, close_position). Mirrors the setup pattern established
// by TestPlaceOrder_FullChain_AuditAndRiskguard at commit 76e42be while
// keeping that test self-contained (intentional — this file is purely
// additive infrastructure for the 4 sibling tests).
//
// Why a shared helper file:
//
//	The 4 sibling tests share ~50 lines of identical mockClient/factory/
//	auditStore/session-broker-swap setup. Inlining 5 copies (incl. the
//	existing place_order test) is unnecessary duplication. A shared
//	helper file lets each test focus on its own tool-specific request +
//	assertions.
//
// What stays inline in each test:
//
//	- Per-tool mock state seeding (e.g., pre-seed an OPEN LIMIT order for
//	  modify/cancel; pre-seed a position for close_position)
//	- The tool-specific MCP call request shape
//	- The tool-specific broker-state assertion (e.g., orders[i].Price for
//	  modify, orders[i].Status for cancel, len(gtts) for place_gtt_order)
//
// Chain shape per tool — empirically verified before writing the tests
// (see test-file headers for the per-tool chain commentary):
//
//	place_order        : audit + riskguard.CheckOrderCtx + broker.PlaceOrder
//	modify_order       : audit + riskguard.CheckOrderCtx + broker.ModifyOrder
//	cancel_order       : audit + broker.CancelOrder   (riskguard SKIPPED per
//	                     CancelOrderUseCase: "cancelling reduces risk")
//	place_gtt_order    : audit + broker.PlaceGTT      (riskguard SKIPPED;
//	                     PlaceGTTUseCase has no riskguard field)
//	close_position     : audit + riskguard.CheckOrderCtx + broker.PlaceOrder
//	                     (opposite MARKET order against existing position)

package mcp

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	alerts "github.com/algo2go/kite-mcp-alerts"
	"github.com/algo2go/kite-mcp-audit"
	brokermock "github.com/algo2go/kite-mcp-broker/mock"
	"github.com/zerodha/kite-mcp-server/kc"
)

// fullChainHarness bundles the three artefacts each chain test needs
// post-setup:
//
//	mgr        : *kc.Manager with mock broker.Factory + RiskGuard
//	mockClient : the SHARED brokermock.Client routed by the Factory
//	auditStore : SQLite-backed audit.Store; worker NOT started so
//	             EnqueueCtx falls through to synchronous Record
//	             (kite-mcp-audit/store_worker.go:81-97)
//
// Each test builds its own auditMW via audit.Middleware(harness.auditStore)
// so the test-local rawHandler/wrappedHandler bookkeeping reads linearly.
type fullChainHarness struct {
	mgr        *kc.Manager
	mockClient *brokermock.Client
	auditStore *audit.Store
}

// newFullChainHarness builds the shared setup. Each chain test calls
// this then layers its own mock state + tool-specific request.
//
// Setup steps (mirrors TestPlaceOrder_FullChain_AuditAndRiskguard at 76e42be):
//  1. mockClient + fullChainMockFactory (defined in place_order_full_chain_test.go)
//  2. newFactoryManager (in tools_broker_test.go) for instrument/session/
//     credential/RiskGuard seeding
//  3. SessionSvc.SetBrokerFactory(factory) to route GetBrokerForEmail through
//     the mock factory
//  4. OVERWRITE the pre-seeded session.Broker to mockClient — critical
//     because SessionService.GetBrokerForEmail tries session.Broker BEFORE
//     consulting the Factory (kc/session_service.go)
//  5. Construct a real audit.Store backed by an in-test SQLite file;
//     InitTable() but DO NOT StartWorkerCtx — sync-Record fallback path
//     gives us deterministic List() reads with no sleep/poll loop
func newFullChainHarness(t *testing.T) *fullChainHarness {
	t.Helper()

	mockClient := brokermock.New()
	mockClient.SetPrices(map[string]float64{"NSE:INFY": 1620.0})
	factory := &fullChainMockFactory{client: mockClient}

	mockKite := startMockKiteForFactory()
	t.Cleanup(mockKite.Close)
	mgr := newFactoryManager(t, mockKite.URL)
	mgr.SessionSvc.SetBrokerFactory(factory)

	// Critical: overwrite session.Broker (see file-header step 4).
	sm := mgr.SessionManager()
	require.NotNil(t, sm)
	rawKD, err := sm.GetSessionData(factorySessionID)
	require.NoError(t, err)
	kd, ok := rawKD.(*kc.KiteSessionData)
	require.True(t, ok, "factory session data must be *kc.KiteSessionData")
	kd.Broker = mockClient
	require.NoError(t, sm.UpdateSessionData(factorySessionID, kd))

	// Audit store — sync-Record fallback (no worker).
	dbPath := filepath.Join(t.TempDir(), "audit_full_chain.db")
	auditDB, err := alerts.OpenDB(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditDB.Close() })

	auditStore := audit.New(auditDB)
	require.NoError(t, auditStore.InitTable())

	return &fullChainHarness{
		mgr:        mgr,
		mockClient: mockClient,
		auditStore: auditStore,
	}
}

// assertAuditRowExists is the canonical (a) audit assertion across the
// chain tests. Looks for a row with the given tool_name owned by
// factoryEmail; asserts row.IsError=false + non-empty CallID + populated
// timestamps.
func assertAuditRowExists(t *testing.T, store *audit.Store, toolName string) {
	t.Helper()
	rows, total, err := store.List(factoryEmail, audit.ListOptions{Limit: 10})
	require.NoError(t, err, "audit.Store.List must succeed")
	require.GreaterOrEqual(t, total, 1,
		"audit middleware must have written at least one row for the %s call; "+
			"if 0, the middleware was not wired into the handler chain", toolName)
	found := false
	for _, row := range rows {
		if row.ToolName == toolName {
			found = true
			require.False(t, row.IsError,
				"audit row for %s must NOT be marked as error on the allowed path; "+
					"row.ErrorMessage=%q", toolName, row.ErrorMessage)
			require.NotEmpty(t, row.CallID, "audit row must carry a call_id")
			require.NotZero(t, row.StartedAt, "audit row must carry a started_at timestamp")
			require.Greater(t, row.DurationMs, int64(-1),
				"audit row must carry a non-negative duration_ms")
			break
		}
	}
	require.True(t, found,
		"audit row with tool_name=%s must exist; the chain did not reach the audit writer",
		toolName)
}
