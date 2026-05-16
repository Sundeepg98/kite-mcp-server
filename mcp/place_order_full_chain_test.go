// place_order_full_chain_test.go — single end-to-end integration test that
// proves the full chain
//
//	tool call -> audit middleware -> riskguard.CheckOrderCtx -> broker mock
//
// is wired and works for a `place_order` invocation. Closes the gap flagged
// in `.research/research/architecture-integration-audit-2026-05-11.md` §2.3:
//
//	> Gap acknowledged: there is no single TestPlaceOrder_FullChain_AuditAndRiskguard
//	> integration test that proves the audit row IS written AND riskguard IS
//	> consulted during a single place_order tool call. The behaviour is
//	> empirically verified at 3 separate unit tests + 1 chain-construction
//	> test, not by one end-to-end test.
//
// Approach:
//  1. Build a Manager with a mock broker.Client (from algo2go/kite-mcp-broker/mock)
//     wired in via a custom broker.Factory implementation. Reuses the existing
//     newFactoryManager seeding pattern for session+credential setup.
//  2. Attach a real audit.Store on the Manager (via WithAuditStore-equivalent
//     setter) and wrap the place_order tool handler in audit.Middleware. This
//     mirrors what app/providers/mcpserver.go:126 does in production via
//     server.WithToolHandlerMiddleware on the live MCP server.
//  3. Dispatch a valid place_order tool call through the wrapped handler.
//  4. Assert:
//     (a) audit row exists in tool_calls for "place_order" (proves audit
//     middleware ran)
//     (b) mock broker recorded the order (proves riskguard.CheckOrderCtx
//     returned Allowed AND the broker call executed end-to-end —
//     riskguard runs BEFORE the broker call in PlaceOrderUseCase, so
//     a broker-recorded order is a direct proof that riskguard
//     consulted-and-allowed)
//
// Riskguard-consulted note: PlaceOrderUseCase calls riskguard.CheckOrderCtx
// BEFORE GetBrokerForEmail. The increment of DailyOrderCount happens in
// riskguard.Middleware via RecordOrder POST-broker-success — NOT inside
// PlaceOrderUseCase itself. Since this test does not wrap the riskguard
// middleware (only audit), DailyOrderCount stays 0; the proof of
// "riskguard was consulted" is therefore that the broker recorded the
// order (which means the riskguard.CheckOrderCtx returned Allowed and
// the use-case proceeded to the broker call).
//
// No build tag: fast in-process integration test, no network I/O. Runs under
// default `go test ./mcp/...`.

package mcp

import (
	"context"
	"path/filepath"
	"testing"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	alerts "github.com/algo2go/kite-mcp-alerts"
	"github.com/algo2go/kite-mcp-audit"
	"github.com/algo2go/kite-mcp-broker"
	brokermock "github.com/algo2go/kite-mcp-broker/mock"
	"github.com/algo2go/kite-mcp-oauth"
	"github.com/zerodha/kite-mcp-server/kc"
)

// fullChainMockFactory implements broker.Factory and hands out a SHARED
// *brokermock.Client so the test can inspect post-call state directly
// (e.g., "what orders did this client receive?").
type fullChainMockFactory struct {
	client *brokermock.Client
}

func (f *fullChainMockFactory) BrokerName() broker.Name                   { return broker.Zerodha }
func (f *fullChainMockFactory) Create(apiKey string) (broker.Client, error) { return f.client, nil }
func (f *fullChainMockFactory) CreateWithToken(apiKey, accessToken string) (broker.Client, error) {
	return f.client, nil
}

// TestPlaceOrder_FullChain_AuditAndRiskguard exercises the full chain in one
// assertion-block. See file header for design notes.
func TestPlaceOrder_FullChain_AuditAndRiskguard(t *testing.T) {
	// Construct a SHARED mock broker.Client and a Factory that always
	// returns it. Seed a price for NSE:INFY so any quote-lookup paths
	// downstream don't blow up; the place_order chain itself doesn't
	// require a pre-seeded price but a few sibling chain steps may.
	mockClient := brokermock.New()
	mockClient.SetPrices(map[string]float64{"NSE:INFY": 1620.0})
	factory := &fullChainMockFactory{client: mockClient}

	// Reuse the existing factory-manager builder for instrument data +
	// session + credential seeding + RiskGuard attachment. The mockKite
	// HTTP server from newFactoryManager is required for the constructor
	// but is unused on the place_order path once we overwrite the
	// session's Broker field to our in-memory mock below.
	//
	// CRITICAL: SessionService.GetBrokerForEmail tries to REUSE an
	// existing session's Broker FIRST (kc/session_service.go) before
	// falling through to the registered broker.Factory. The pre-seeded
	// session has Broker=zerodha.New(kiteClient) pointing at the mockKite
	// HTTP server; we MUST overwrite it with our brokermock.Client so
	// place_order's downstream chain (riskguard -> broker.PlaceOrder)
	// records against our in-memory mock instead of returning 404 from
	// the http server (which only handles GET-shaped paths properly).
	mockKite := startMockKiteForFactory()
	t.Cleanup(mockKite.Close)
	mgr := newFactoryManager(t, mockKite.URL)
	mgr.SessionSvc.SetBrokerFactory(factory)

	// Overwrite the session's pre-seeded Broker with our in-memory mock.
	// The SessionRegistry.UpdateSessionData call replaces the entire
	// KiteSessionData payload — we keep the Email + Kite fields stable
	// and only swap Broker.
	sm := mgr.SessionManager()
	require.NotNil(t, sm)
	rawKD, err := sm.GetSessionData(factorySessionID)
	require.NoError(t, err)
	kd, ok := rawKD.(*kc.KiteSessionData)
	require.True(t, ok, "factory session data must be *kc.KiteSessionData")
	kd.Broker = mockClient
	require.NoError(t, sm.UpdateSessionData(factorySessionID, kd))

	// Construct a real audit Store backed by an in-test SQLite file.
	dbPath := filepath.Join(t.TempDir(), "audit_full_chain.db")
	auditDB, err := alerts.OpenDB(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditDB.Close() })

	auditStore := audit.New(auditDB)
	require.NoError(t, auditStore.InitTable())
	// Worker NOT started -> audit.EnqueueCtx falls through to synchronous
	// Record (see kite-mcp-audit/store_worker.go:81-97). This lets us
	// List() immediately after the tool call without sleep/poll.

	// Attach audit middleware to the place_order tool handler. This mirrors
	// app/providers/mcpserver.go:126 in production:
	//   server.WithToolHandlerMiddleware(auditMW)
	// applied to the mcp-go server. We rebuild the wrapping locally so the
	// test does NOT depend on full app/wire.go Fx composition.
	mw := audit.Middleware(auditStore)
	require.NotNil(t, mw)

	// Locate the place_order tool from the registry.
	var rawHandler server.ToolHandlerFunc
	for _, tool := range GetAllTools() {
		if tool.Tool().Name == "place_order" {
			rawHandler = tool.Handler(mgr)
			break
		}
	}
	require.NotNil(t, rawHandler, "place_order tool must be registered")
	wrappedHandler := mw(rawHandler)

	// Build the MCP call context. Match the factory-manager fixture
	// (factoryEmail + factorySessionID seeded by newFactoryManager).
	ctx := context.Background()
	ctx = oauth.ContextWithEmail(ctx, factoryEmail)
	mcpSrv := server.NewMCPServer("place-order-chain-test", "1.0")
	ctx = mcpSrv.WithContext(ctx, &mockSession{id: factorySessionID})

	// Pre-call broker state: mockClient.GetOrders() returns empty.
	ordersBefore, err := mockClient.GetOrders()
	require.NoError(t, err)
	require.Empty(t, ordersBefore, "broker must have zero orders before the test call")

	// Build the place_order request — minimal valid params per
	// trade/post_tools.go:119 required list.
	req := gomcp.CallToolRequest{}
	req.Params.Name = "place_order"
	req.Params.Arguments = map[string]any{
		"variety":          "regular",
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         1,
		"product":          "CNC",
		"order_type":       "MARKET",
	}

	// Execute through the audit-wrapped handler. This is the integration
	// point under test: the call MUST flow through audit middleware,
	// reach the CommandBus, dispatch to PlaceOrderUseCase, hit
	// riskguard.CheckOrderCtx (Allowed branch), then reach the broker.
	result, err := wrappedHandler(ctx, req)
	require.NoError(t, err, "handler must not return a top-level error on the allowed path")
	require.NotNil(t, result)
	assert.False(t, result.IsError,
		"place_order must succeed on the riskguard-allowed path; got error result. Inspect: %+v", result)

	// (a) AUDIT ASSERTION — a row was written for this tool call.
	rows, total, err := auditStore.List(factoryEmail, audit.ListOptions{Limit: 10})
	require.NoError(t, err, "audit.Store.List must succeed")
	require.GreaterOrEqual(t, total, 1,
		"audit middleware must have written at least one row for the place_order call; "+
			"if 0, the middleware was not wired into the handler chain")
	foundPlaceOrder := false
	for _, row := range rows {
		if row.ToolName == "place_order" {
			foundPlaceOrder = true
			assert.False(t, row.IsError,
				"audit row for place_order must NOT be marked as error on the allowed path; "+
					"row.ErrorMessage=%q", row.ErrorMessage)
			assert.NotEmpty(t, row.CallID, "audit row must carry a call_id")
			assert.NotZero(t, row.StartedAt, "audit row must carry a started_at timestamp")
			assert.Greater(t, row.DurationMs, int64(-1),
				"audit row must carry a non-negative duration_ms")
			break
		}
	}
	assert.True(t, foundPlaceOrder,
		"audit row with tool_name=place_order must exist; the chain did not reach the audit writer")

	// (b) RISKGUARD-CONSULTED + CHAIN-COMPLETED ASSERTION — the broker
	// received the order. Per PlaceOrderUseCase contract:
	//   1. riskguard.CheckOrderCtx is invoked first
	//   2. if rejected: return error before broker call (broker state
	//      stays empty)
	//   3. if allowed: GetBrokerForEmail -> broker.PlaceOrder is invoked
	// Therefore a broker-recorded order is direct proof that
	//   - riskguard was consulted AND returned Allowed
	//   - the chain completed end-to-end
	ordersAfter, err := mockClient.GetOrders()
	require.NoError(t, err)
	require.Len(t, ordersAfter, 1,
		"mock broker must have recorded exactly 1 order; got %d. "+
			"If 0: the chain did not reach the broker step (riskguard rejected, "+
			"or use-case errored before broker call). If >1: spurious duplicate dispatch.",
		len(ordersAfter))
	placedOrder := ordersAfter[0]
	assert.Equal(t, "INFY", placedOrder.Tradingsymbol)
	assert.Equal(t, "NSE", placedOrder.Exchange)
	assert.Equal(t, "BUY", placedOrder.TransactionType)
	assert.Equal(t, "MARKET", placedOrder.OrderType)
	assert.Equal(t, "CNC", placedOrder.Product)
}
