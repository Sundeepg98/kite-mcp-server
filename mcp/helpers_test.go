package mcp

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/kc/papertrading"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
	"github.com/zerodha/kite-mcp-server/kc/users"
	"github.com/zerodha/kite-mcp-server/oauth"
	gomcp "github.com/mark3labs/mcp-go/mcp"
)

// Shared test helpers used by multiple test files.

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
