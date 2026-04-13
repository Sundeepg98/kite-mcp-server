package kc

import (
	"context"
	"strings"
	"testing"

	"github.com/zerodha/kite-mcp-server/kc/cqrs"
)

// TestCommandBus_Login_ReachesManagerPort proves the batch-F setup handler
// wires LoginCommand through to the real LoginUseCase, which in turn calls
// the Manager's SessionLoginURL method as its SessionLoginURLProvider port.
//
// SessionLoginURL requires a pre-registered MCP session; without one, it
// returns a well-defined 'session not found' error. We assert on that exact
// error string — which only surfaces if the dispatch reached the Manager
// port — and use it as a positive wiring signal. Any earlier failure
// (missing handler, wrong type, nil port) would produce a different error.
func TestCommandBus_Login_ReachesManagerPort(t *testing.T) {
	mgr, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager: %v", err)
	}

	_, err = mgr.CommandBus().DispatchWithResult(context.Background(), cqrs.LoginCommand{
		Email:        "user@example.com",
		MCPSessionID: "session-abc",
	})
	if err == nil {
		t.Fatal("expected session-not-found error, got nil")
	}
	// Wrapper prefix proves the handler routed through LoginUseCase.Execute
	// and the use case reached SessionLoginURL on the Manager port.
	if !strings.Contains(err.Error(), "generate kite login url") {
		t.Errorf("expected 'generate kite login url' wrap, got: %v", err)
	}
}

// TestCommandBus_Login_MissingSessionID asserts the LoginUseCase's
// "mcp_session_id is required" validation surfaces through the CommandBus.
// Without MCPSessionID, Execute returns the error before ever touching the
// Manager port, so this test proves the handler returns use case errors
// verbatim (no swallowing, no wrapping).
func TestCommandBus_Login_MissingSessionID(t *testing.T) {
	mgr, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager: %v", err)
	}

	_, err = mgr.CommandBus().DispatchWithResult(context.Background(), cqrs.LoginCommand{
		Email: "user@example.com",
	})
	if err == nil {
		t.Fatal("expected mcp_session_id error, got nil")
	}
	if !strings.Contains(err.Error(), "mcp_session_id") {
		t.Errorf("expected mcp_session_id error, got: %v", err)
	}
}

// TestCommandBus_Login_InvalidAPIKey asserts invalid characters in the
// API key are rejected by the use case's Validate step — proving the
// command travels through the handler without pre-validation that could
// mask this check.
func TestCommandBus_Login_InvalidAPIKey(t *testing.T) {
	mgr, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager: %v", err)
	}

	_, err = mgr.CommandBus().DispatchWithResult(context.Background(), cqrs.LoginCommand{
		Email:        "user@example.com",
		MCPSessionID: "session-abc",
		APIKey:       "bad-key!",
		APISecret:    "validsecret1",
	})
	if err == nil {
		t.Fatal("expected invalid api_key error, got nil")
	}
	if !strings.Contains(err.Error(), "api_key") {
		t.Errorf("expected api_key validation error, got: %v", err)
	}
}
