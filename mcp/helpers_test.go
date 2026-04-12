package mcp

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/kc/papertrading"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
	"github.com/zerodha/kite-mcp-server/kc/users"
	"github.com/zerodha/kite-mcp-server/oauth"
	"github.com/zerodha/kite-mcp-server/testutil/kcfixture"
)

// Shared test helpers used by multiple test files.
//
// Coverage ceiling: ~85%. Uncovered code is primarily:
//   - Kite API success paths behind WithSession (~60% of gaps)
//   - Token refresh/expiry detection with real API
//   - GTT/ATO order creation
//   - Admin tool success paths with specific store state
//   - Backtest strategy signals with specific data patterns
// A mock Kite HTTP backend (testutil.NewMockKiteServer) covers some of these.

type mockSession struct {
	id string
}

func (m *mockSession) Initialize()                                       {}

func (m *mockSession) Initialized() bool                                 { return true }

func (m *mockSession) NotificationChannel() chan<- gomcp.JSONRPCNotification { return make(chan gomcp.JSONRPCNotification, 1) }

func (m *mockSession) SessionID() string                                 { return m.id }

func callToolAdmin(t *testing.T, mgr *kc.Manager, toolName string, email string, args map[string]any) *gomcp.CallToolResult {
	t.Helper()
	ctx := context.Background()
	if email != "" {
		ctx = oauth.ContextWithEmail(ctx, email)
	}

	for _, tool := range GetAllTools() {
		if tool.Tool().Name == toolName {
			req := gomcp.CallToolRequest{}
			req.Params.Name = toolName
			req.Params.Arguments = args
			result, err := tool.Handler(mgr)(ctx, req)
			require.NoError(t, err)
			return result
		}
	}
	t.Fatalf("tool %q not found in GetAllTools()", toolName)
	return nil
}

func callToolDevMode(t *testing.T, mgr *kc.Manager, toolName string, email string, args map[string]any) *gomcp.CallToolResult {
	t.Helper()
	ctx := context.Background()
	if email != "" {
		ctx = oauth.ContextWithEmail(ctx, email)
	}
	mcpSrv := server.NewMCPServer("test", "1.0")
	// Use a valid UUID as session ID so SessionRegistry accepts it
	ctx = mcpSrv.WithContext(ctx, &mockSession{id: "a1b2c3d4-e5f6-7890-abcd-ef1234567890"})

	for _, tool := range GetAllTools() {
		if tool.Tool().Name == toolName {
			req := gomcp.CallToolRequest{}
			req.Params.Name = toolName
			req.Params.Arguments = args
			result, err := tool.Handler(mgr)(ctx, req)
			require.NoError(t, err)
			return result
		}
	}
	t.Fatalf("tool %q not found in GetAllTools()", toolName)
	return nil
}

func callToolWithSession(t *testing.T, mgr *kc.Manager, toolName string, email string, args map[string]any) *gomcp.CallToolResult {
	t.Helper()
	ctx := context.Background()
	if email != "" {
		ctx = oauth.ContextWithEmail(ctx, email)
	}
	// Create a minimal MCP server to inject a session context
	mcpSrv := server.NewMCPServer("test", "1.0")
	ctx = mcpSrv.WithContext(ctx, &mockSession{id: "test-session-id"})

	for _, tool := range GetAllTools() {
		if tool.Tool().Name == toolName {
			req := gomcp.CallToolRequest{}
			req.Params.Name = toolName
			req.Params.Arguments = args
			result, err := tool.Handler(mgr)(ctx, req)
			require.NoError(t, err)
			return result
		}
	}
	t.Fatalf("tool %q not found in GetAllTools()", toolName)
	return nil
}

func newDevModeManager(t *testing.T) *kc.Manager {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	testData := map[uint32]*instruments.Instrument{
		256265: {InstrumentToken: 256265, Tradingsymbol: "INFY", Name: "INFOSYS", Exchange: "NSE", Segment: "NSE", InstrumentType: "EQ"},
		408065: {InstrumentToken: 408065, Tradingsymbol: "RELIANCE", Name: "RELIANCE INDUSTRIES", Exchange: "NSE", Segment: "NSE", InstrumentType: "EQ"},
	}

	instMgr, err := instruments.New(instruments.Config{
		UpdateConfig: func() *instruments.UpdateConfig {
			c := instruments.DefaultUpdateConfig()
			c.EnableScheduler = false
			return c
		}(),
		Logger:   logger,
		TestData: testData,
	})
	require.NoError(t, err)

	mgr, err := kc.New(kc.Config{
		APIKey:             "test_key",
		APISecret:          "test_secret",
		Logger:             logger,
		InstrumentsManager: instMgr,
		DevMode:            true,
	})
	require.NoError(t, err)

	mgr.SetRiskGuard(riskguard.NewGuard(logger))
	return mgr
}

func newRichDevModeManager(t *testing.T) (*kc.Manager, *audit.Store) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	testData := map[uint32]*instruments.Instrument{
		256265: {InstrumentToken: 256265, Tradingsymbol: "INFY", Name: "INFOSYS", Exchange: "NSE", Segment: "NSE", InstrumentType: "EQ"},
		408065: {InstrumentToken: 408065, Tradingsymbol: "RELIANCE", Name: "RELIANCE INDUSTRIES", Exchange: "NSE", Segment: "NSE", InstrumentType: "EQ"},
	}

	instMgr, err := instruments.New(instruments.Config{
		UpdateConfig: func() *instruments.UpdateConfig {
			c := instruments.DefaultUpdateConfig()
			c.EnableScheduler = false
			return c
		}(),
		Logger:   logger,
		TestData: testData,
	})
	require.NoError(t, err)

	mgr, err := kc.New(kc.Config{
		APIKey:             "test_key",
		APISecret:          "test_secret",
		Logger:             logger,
		InstrumentsManager: instMgr,
		DevMode:            true,
	})
	require.NoError(t, err)
	mgr.SetRiskGuard(riskguard.NewGuard(logger))

	// Wire up audit store (in-memory SQLite)
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	auditStore := audit.New(db)
	require.NoError(t, auditStore.InitTable())
	mgr.SetAuditStore(auditStore)

	// Create admin user
	uStore := mgr.UserStoreConcrete()
	require.NotNil(t, uStore)
	require.NoError(t, uStore.Create(&users.User{
		ID:     "u_admin",
		Email:  "admin@example.com",
		Role:   users.RoleAdmin,
		Status: users.StatusActive,
	}))

	t.Cleanup(func() { db.Close() })

	return mgr, auditStore
}

// newFullDevModeManager creates a DevMode Manager with ALL stores wired up:
// AuditStore, PaperEngine, PnLService, admin user, and test credentials+tokens.
// This enables testing handlers that depend on PaperEngine, PnLService,
// or ext_apps data functions that need brokerClientForEmail to return non-nil.
func newFullDevModeManager(t *testing.T) (*kc.Manager, *audit.Store) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	testData := map[uint32]*instruments.Instrument{
		256265: {InstrumentToken: 256265, ID: "NSE:INFY", Tradingsymbol: "INFY", Name: "INFOSYS", Exchange: "NSE", Segment: "NSE", InstrumentType: "EQ"},
		408065: {InstrumentToken: 408065, ID: "NSE:RELIANCE", Tradingsymbol: "RELIANCE", Name: "RELIANCE INDUSTRIES", Exchange: "NSE", Segment: "NSE", InstrumentType: "EQ"},
	}

	instMgr, err := instruments.New(instruments.Config{
		UpdateConfig: func() *instruments.UpdateConfig {
			c := instruments.DefaultUpdateConfig()
			c.EnableScheduler = false
			return c
		}(),
		Logger:   logger,
		TestData: testData,
	})
	require.NoError(t, err)

	mgr, err := kc.New(kc.Config{
		APIKey:             "test_key",
		APISecret:          "test_secret",
		Logger:             logger,
		InstrumentsManager: instMgr,
		DevMode:            true,
	})
	require.NoError(t, err)
	mgr.SetRiskGuard(riskguard.NewGuard(logger))

	// SQLite-backed stores
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)

	auditStore := audit.New(db)
	require.NoError(t, auditStore.InitTable())
	mgr.SetAuditStore(auditStore)

	// PaperEngine
	paperStore := papertrading.NewStore(db, logger)
	require.NoError(t, paperStore.InitTables())
	paperEngine := papertrading.NewEngine(paperStore, logger)
	mgr.SetPaperEngine(paperEngine)

	// PnLService (tokens/creds nil is fine -- GetJournal only needs the DB)
	pnlSvc := alerts.NewPnLSnapshotService(db, nil, nil, logger)
	mgr.SetPnLService(pnlSvc)

	// Admin user
	uStore := mgr.UserStoreConcrete()
	require.NotNil(t, uStore)
	require.NoError(t, uStore.Create(&users.User{
		ID: "u_admin", Email: "admin@example.com",
		Role: users.RoleAdmin, Status: users.StatusActive,
	}))

	// Seed test credentials + token so brokerClientForEmail returns non-nil
	mgr.CredentialStore().Set("cred@example.com", &kc.KiteCredentialEntry{
		APIKey:    "test_api_key",
		APISecret: "test_api_secret",
		StoredAt:  time.Now(),
	})
	mgr.TokenStore().Set("cred@example.com", &kc.KiteTokenEntry{
		AccessToken: "test_access_token",
		StoredAt:    time.Now(),
	})

	t.Cleanup(func() { db.Close() })
	return mgr, auditStore
}

// resultText extracts the text from the first content item of a CallToolResult.
func resultText(t *testing.T, result *gomcp.CallToolResult) string {
	t.Helper()
	if result == nil || len(result.Content) == 0 {
		return ""
	}
	tc, ok := result.Content[0].(gomcp.TextContent)
	if !ok {
		return ""
	}
	return tc.Text
}

// assertResultContains asserts the first text content of a result contains substr.
func assertResultContains(t *testing.T, result *gomcp.CallToolResult, substr string) {
	t.Helper()
	if len(result.Content) == 0 {
		t.Fatalf("result has no content to check for %q", substr)
	}
	text := result.Content[0].(gomcp.TextContent).Text
	assert.Contains(t, text, substr)
}

// assertResultNotContains asserts the first text content does NOT contain substr.
func assertResultNotContains(t *testing.T, result *gomcp.CallToolResult, substr string) {
	t.Helper()
	if len(result.Content) == 0 {
		return // no content to check
	}
	text := result.Content[0].(gomcp.TextContent).Text
	assert.NotContains(t, text, substr)
}

// newTestManager creates a minimal Manager that never makes HTTP calls.
// It delegates to kcfixture.NewTestManager (the shared factory) and attaches
// a RiskGuard so tool handlers that gate on it have one.
func newTestManager(t *testing.T) *kc.Manager {
	t.Helper()
	return kcfixture.NewTestManager(t, kcfixture.WithRiskGuard())
}

// callToolWithManager invokes a tool handler with the given manager and context params.
// Includes a minimal MCP session context to prevent panics in WithSession.
func callToolWithManager(t *testing.T, mgr *kc.Manager, toolName string, email string, args map[string]any) *gomcp.CallToolResult {
	t.Helper()
	ctx := context.Background()
	if email != "" {
		ctx = oauth.ContextWithEmail(ctx, email)
	}
	mcpSrv := server.NewMCPServer("test", "1.0")
	ctx = mcpSrv.WithContext(ctx, &mockSession{id: "d0e1f2a3-b4c5-6789-abcd-ef0123456789"})
	for _, tool := range GetAllTools() {
		if tool.Tool().Name == toolName {
			req := gomcp.CallToolRequest{}
			req.Params.Name = toolName
			req.Params.Arguments = args
			result, err := tool.Handler(mgr)(ctx, req)
			require.NoError(t, err)
			return result
		}
	}
	t.Fatalf("tool %q not found in GetAllTools()", toolName)
	return nil
}

// callToolNFODevMode calls a tool in DevMode with NFO instrument data.
func callToolNFODevMode(t *testing.T, mgr *kc.Manager, toolName string, email string, args map[string]any) *gomcp.CallToolResult {
	t.Helper()
	ctx := context.Background()
	if email != "" {
		ctx = oauth.ContextWithEmail(ctx, email)
	}
	mcpSrv := server.NewMCPServer("test", "1.0")
	ctx = mcpSrv.WithContext(ctx, &mockSession{id: "b2c3d4e5-f6a7-8901-bcde-f23456789012"})

	for _, tool := range GetAllTools() {
		if tool.Tool().Name == toolName {
			req := gomcp.CallToolRequest{}
			req.Params.Name = toolName
			req.Params.Arguments = args
			result, err := tool.Handler(mgr)(ctx, req)
			require.NoError(t, err)
			return result
		}
	}
	t.Fatalf("tool %q not found", toolName)
	return nil
}

// newNFODevModeManager creates a DevMode manager with both NSE equities and
// NFO options instruments loaded for options/strategy tests.
func newNFODevModeManager(t *testing.T) *kc.Manager {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	futureExpiry := time.Now().AddDate(0, 0, 14).Format("2006-01-02")

	testData := map[uint32]*instruments.Instrument{
		256265: {InstrumentToken: 256265, Tradingsymbol: "INFY", Name: "INFOSYS", Exchange: "NSE", Segment: "NSE", InstrumentType: "EQ"},
		408065: {InstrumentToken: 408065, Tradingsymbol: "RELIANCE", Name: "RELIANCE INDUSTRIES", Exchange: "NSE", Segment: "NSE", InstrumentType: "EQ"},
		// NIFTY options — CE
		100001: {InstrumentToken: 100001, Tradingsymbol: "NIFTY2641017500CE", Name: "NIFTY", Exchange: "NFO", Segment: "NFO-OPT", InstrumentType: "CE", Strike: 17500, ExpiryDate: futureExpiry, LotSize: 50},
		100002: {InstrumentToken: 100002, Tradingsymbol: "NIFTY2641017600CE", Name: "NIFTY", Exchange: "NFO", Segment: "NFO-OPT", InstrumentType: "CE", Strike: 17600, ExpiryDate: futureExpiry, LotSize: 50},
		100003: {InstrumentToken: 100003, Tradingsymbol: "NIFTY2641017700CE", Name: "NIFTY", Exchange: "NFO", Segment: "NFO-OPT", InstrumentType: "CE", Strike: 17700, ExpiryDate: futureExpiry, LotSize: 50},
		100004: {InstrumentToken: 100004, Tradingsymbol: "NIFTY2641017800CE", Name: "NIFTY", Exchange: "NFO", Segment: "NFO-OPT", InstrumentType: "CE", Strike: 17800, ExpiryDate: futureExpiry, LotSize: 50},
		100005: {InstrumentToken: 100005, Tradingsymbol: "NIFTY2641017900CE", Name: "NIFTY", Exchange: "NFO", Segment: "NFO-OPT", InstrumentType: "CE", Strike: 17900, ExpiryDate: futureExpiry, LotSize: 50},
		100006: {InstrumentToken: 100006, Tradingsymbol: "NIFTY2641018000CE", Name: "NIFTY", Exchange: "NFO", Segment: "NFO-OPT", InstrumentType: "CE", Strike: 18000, ExpiryDate: futureExpiry, LotSize: 50},
		100007: {InstrumentToken: 100007, Tradingsymbol: "NIFTY2641018100CE", Name: "NIFTY", Exchange: "NFO", Segment: "NFO-OPT", InstrumentType: "CE", Strike: 18100, ExpiryDate: futureExpiry, LotSize: 50},
		100008: {InstrumentToken: 100008, Tradingsymbol: "NIFTY2641018200CE", Name: "NIFTY", Exchange: "NFO", Segment: "NFO-OPT", InstrumentType: "CE", Strike: 18200, ExpiryDate: futureExpiry, LotSize: 50},
		100009: {InstrumentToken: 100009, Tradingsymbol: "NIFTY2641018300CE", Name: "NIFTY", Exchange: "NFO", Segment: "NFO-OPT", InstrumentType: "CE", Strike: 18300, ExpiryDate: futureExpiry, LotSize: 50},
		100010: {InstrumentToken: 100010, Tradingsymbol: "NIFTY2641018400CE", Name: "NIFTY", Exchange: "NFO", Segment: "NFO-OPT", InstrumentType: "CE", Strike: 18400, ExpiryDate: futureExpiry, LotSize: 50},
		100011: {InstrumentToken: 100011, Tradingsymbol: "NIFTY2641018500CE", Name: "NIFTY", Exchange: "NFO", Segment: "NFO-OPT", InstrumentType: "CE", Strike: 18500, ExpiryDate: futureExpiry, LotSize: 50},
		// NIFTY options — PE
		200001: {InstrumentToken: 200001, Tradingsymbol: "NIFTY2641017500PE", Name: "NIFTY", Exchange: "NFO", Segment: "NFO-OPT", InstrumentType: "PE", Strike: 17500, ExpiryDate: futureExpiry, LotSize: 50},
		200002: {InstrumentToken: 200002, Tradingsymbol: "NIFTY2641017600PE", Name: "NIFTY", Exchange: "NFO", Segment: "NFO-OPT", InstrumentType: "PE", Strike: 17600, ExpiryDate: futureExpiry, LotSize: 50},
		200003: {InstrumentToken: 200003, Tradingsymbol: "NIFTY2641017700PE", Name: "NIFTY", Exchange: "NFO", Segment: "NFO-OPT", InstrumentType: "PE", Strike: 17700, ExpiryDate: futureExpiry, LotSize: 50},
		200004: {InstrumentToken: 200004, Tradingsymbol: "NIFTY2641017800PE", Name: "NIFTY", Exchange: "NFO", Segment: "NFO-OPT", InstrumentType: "PE", Strike: 17800, ExpiryDate: futureExpiry, LotSize: 50},
		200005: {InstrumentToken: 200005, Tradingsymbol: "NIFTY2641017900PE", Name: "NIFTY", Exchange: "NFO", Segment: "NFO-OPT", InstrumentType: "PE", Strike: 17900, ExpiryDate: futureExpiry, LotSize: 50},
		200006: {InstrumentToken: 200006, Tradingsymbol: "NIFTY2641018000PE", Name: "NIFTY", Exchange: "NFO", Segment: "NFO-OPT", InstrumentType: "PE", Strike: 18000, ExpiryDate: futureExpiry, LotSize: 50},
		200007: {InstrumentToken: 200007, Tradingsymbol: "NIFTY2641018100PE", Name: "NIFTY", Exchange: "NFO", Segment: "NFO-OPT", InstrumentType: "PE", Strike: 18100, ExpiryDate: futureExpiry, LotSize: 50},
		200008: {InstrumentToken: 200008, Tradingsymbol: "NIFTY2641018200PE", Name: "NIFTY", Exchange: "NFO", Segment: "NFO-OPT", InstrumentType: "PE", Strike: 18200, ExpiryDate: futureExpiry, LotSize: 50},
		200009: {InstrumentToken: 200009, Tradingsymbol: "NIFTY2641018300PE", Name: "NIFTY", Exchange: "NFO", Segment: "NFO-OPT", InstrumentType: "PE", Strike: 18300, ExpiryDate: futureExpiry, LotSize: 50},
		200010: {InstrumentToken: 200010, Tradingsymbol: "NIFTY2641018400PE", Name: "NIFTY", Exchange: "NFO", Segment: "NFO-OPT", InstrumentType: "PE", Strike: 18400, ExpiryDate: futureExpiry, LotSize: 50},
		200011: {InstrumentToken: 200011, Tradingsymbol: "NIFTY2641018500PE", Name: "NIFTY", Exchange: "NFO", Segment: "NFO-OPT", InstrumentType: "PE", Strike: 18500, ExpiryDate: futureExpiry, LotSize: 50},
	}

	instMgr, err := instruments.New(instruments.Config{
		UpdateConfig: func() *instruments.UpdateConfig {
			c := instruments.DefaultUpdateConfig()
			c.EnableScheduler = false
			return c
		}(),
		Logger:   logger,
		TestData: testData,
	})
	require.NoError(t, err)

	mgr, err := kc.New(kc.Config{
		APIKey:             "test_key",
		APISecret:          "test_secret",
		Logger:             logger,
		InstrumentsManager: instMgr,
		DevMode:            true,
	})
	require.NoError(t, err)
	mgr.SetRiskGuard(riskguard.NewGuard(logger))
	return mgr
}

// newTestAuditStore creates an in-memory audit store for tests.
func newTestAuditStore(t *testing.T) *audit.Store {
	t.Helper()
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	store := audit.New(db)
	require.NoError(t, store.InitTable())
	store.StartWorker()
	t.Cleanup(func() {
		store.Stop()
		db.Close()
	})
	return store
}
