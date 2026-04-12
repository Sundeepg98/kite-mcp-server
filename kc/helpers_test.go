package kc

// helpers_test.go — shared test helpers used across manager_edge_test.go,
// session_edge_test.go, and other kc package test files.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	kiteconnect "github.com/zerodha/gokiteconnect/v4"
)

// kiteEnvelope wraps data in the Kite API JSON envelope format.
func kiteEnvelope(t *testing.T, data interface{}) string {
	t.Helper()
	b, err := json.Marshal(map[string]interface{}{"data": data, "status": "success"})
	if err != nil {
		t.Fatalf("kiteEnvelope marshal: %v", err)
	}
	return string(b)
}

// newMockKiteServer returns an httptest.Server that handles:
//   - POST /session/token  (GenerateSession)
//   - GET  /user/profile   (GetUserProfile)
//   - DELETE /session/token (InvalidateAccessToken)
func newMockKiteServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/session/token" && r.Method == http.MethodPost:
			fmt.Fprint(w, kiteEnvelope(t, map[string]interface{}{
				"user_id":       "XY1234",
				"user_name":     "Test User",
				"email":         "test@example.com",
				"access_token":  "mock-access-token",
				"public_token":  "mock-public-token",
				"refresh_token": "mock-refresh-token",
			}))
		case r.URL.Path == "/user/profile" && r.Method == http.MethodGet:
			fmt.Fprint(w, kiteEnvelope(t, map[string]interface{}{
				"user_id":   "XY1234",
				"user_name": "Test User",
				"email":     "test@example.com",
			}))
		case r.URL.Path == "/session/token" && r.Method == http.MethodDelete:
			fmt.Fprint(w, kiteEnvelope(t, true))
		default:
			http.Error(w, `{"status":"error","message":"not found"}`, http.StatusNotFound)
		}
	}))
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
