package app

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zerodha/kite-mcp-server/kc"
)

// TestClientHintedResolver_WiresThroughToRegistry verifies the app-level
// adapter forwards the User-Agent-derived hint down to the underlying
// SessionRegistry. This guards against regression in the two-hop
// adapter chain (app → kc → SessionRegistry).
func TestClientHintedResolver_WiresThroughToRegistry(t *testing.T) {
	t.Parallel()
	reg := kc.NewSessionRegistry(testLogger())
	resolver := newClientHintedResolver(reg)

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("User-Agent", "Cursor/1.0 (darwin)")

	mgr := resolver.ResolveSessionIdManager(req)
	sid := mgr.Generate()
	if sid == "" {
		t.Fatal("Generate returned empty session ID")
	}
	s, err := reg.GetSession(sid)
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if s.ClientHint != kc.HintCursor {
		t.Errorf("s.ClientHint = %q, want %q", s.ClientHint, kc.HintCursor)
	}
}

// TestClientHintedResolver_ValidateDelegates verifies Validate is forwarded
// to the underlying registry without mutation.
func TestClientHintedResolver_ValidateDelegates(t *testing.T) {
	t.Parallel()
	reg := kc.NewSessionRegistry(testLogger())
	resolver := newClientHintedResolver(reg)

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("User-Agent", "Claude/1.0")
	mgr := resolver.ResolveSessionIdManager(req)
	sid := mgr.Generate()

	terminated, err := mgr.Validate(sid)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if terminated {
		t.Error("fresh session reported terminated")
	}
}

// TestClientHintedResolver_NilRequest verifies the idle-sweeper path
// (mcp-go passes nil request to ResolveSessionIdManager).
func TestClientHintedResolver_NilRequest(t *testing.T) {
	t.Parallel()
	reg := kc.NewSessionRegistry(testLogger())
	resolver := newClientHintedResolver(reg)

	mgr := resolver.ResolveSessionIdManager(nil)
	sid := mgr.Generate()
	if sid == "" {
		t.Fatal("Generate returned empty session ID on nil-request path")
	}
}

// TestClientHintedResolver_TerminateDelegates verifies Terminate forwards
// through the two-hop adapter chain to the SessionRegistry.
func TestClientHintedResolver_TerminateDelegates(t *testing.T) {
	t.Parallel()
	reg := kc.NewSessionRegistry(testLogger())
	resolver := newClientHintedResolver(reg)

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("User-Agent", "Claude/1.0")
	mgr := resolver.ResolveSessionIdManager(req)

	sid := mgr.Generate()
	notAllowed, err := mgr.Terminate(sid)
	if err != nil {
		t.Fatalf("Terminate: %v", err)
	}
	if notAllowed {
		t.Error("Terminate reported not-allowed on a fresh session")
	}
}
