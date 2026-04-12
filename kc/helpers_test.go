package kc

// helpers_test.go — shared test helpers used across manager_edge_test.go,
// session_edge_test.go, and other kc package test files.

import (
	"net/http/httptest"
	"testing"

	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/kite-mcp-server/testutil"
)

// newMockKiteServer returns an httptest.Server that handles the Kite session
// lifecycle routes (POST/DELETE /session/token, GET /user/profile) plus all
// default read-only Kite API routes. It delegates to the shared
// testutil.NewSessionKiteServer so every package exercising the Kite session
// flow uses the same fixture.
func newMockKiteServer(t *testing.T) *httptest.Server {
	t.Helper()
	return testutil.NewSessionKiteServer(t)
}

// newKiteClientWithMock creates a *kiteconnect.Client pointed at the mock server.
func newKiteClientWithMock(ts *httptest.Server, apiKey string) *kiteconnect.Client {
	c := kiteconnect.New(apiKey)
	c.SetBaseURI(ts.URL)
	return c
}

// newTestManagerWithDB creates a Manager backed by an in-memory SQLite DB.
func newTestManagerWithDB(t *testing.T) *Manager {
	t.Helper()
	m, err := New(Config{
		APIKey:             "test_key",
		APISecret:          "test_secret",
		InstrumentsManager: newTestInstrumentsManager(),
		Logger:             testLogger(),
		AlertDBPath:        ":memory:",
	})
	if err != nil {
		t.Fatalf("newTestManagerWithDB: %v", err)
	}
	t.Cleanup(func() { m.Shutdown() })
	return m
}
