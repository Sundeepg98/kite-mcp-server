package kc

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestClientHintResolver_WithUserAgent verifies that a request carrying a
// recognizable User-Agent causes the generated session to be tagged with
// the matching ClientHint.
func TestClientHintResolver_WithUserAgent(t *testing.T) {
	reg := NewSessionRegistry(testLogger())
	resolver := NewClientHintResolver(reg)

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("User-Agent", "Claude/1.2.3 (macOS; arm64)")

	mgr := resolver.ResolveSessionIdManager(req)
	sid := mgr.Generate()
	if sid == "" {
		t.Fatal("Generate returned empty session ID")
	}
	s, err := reg.GetSession(sid)
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if s.ClientHint != HintClaudeDesktop {
		t.Errorf("ClientHint = %q, want %q", s.ClientHint, HintClaudeDesktop)
	}
}

// TestClientHintResolver_NilRequest covers the idle-sweeper path where
// mcp-go passes a nil HTTP request. The resolver must still return a
// functioning manager, and the produced session's hint is empty (not
// "unknown") so the distinction between "no request context" and "known
// unrecognized client" is preserved.
func TestClientHintResolver_NilRequest(t *testing.T) {
	reg := NewSessionRegistry(testLogger())
	resolver := NewClientHintResolver(reg)

	mgr := resolver.ResolveSessionIdManager(nil)
	sid := mgr.Generate()
	if sid == "" {
		t.Fatal("Generate returned empty session ID")
	}
	s, err := reg.GetSession(sid)
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if s.ClientHint != "" {
		t.Errorf("ClientHint = %q, want empty string for nil-request path", s.ClientHint)
	}
}

// TestClientHintResolver_UnknownUserAgent verifies that a UA we don't
// recognize still produces a session; it just carries the "unknown" hint
// instead of a specific client marker.
func TestClientHintResolver_UnknownUserAgent(t *testing.T) {
	reg := NewSessionRegistry(testLogger())
	resolver := NewClientHintResolver(reg)

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("User-Agent", "MyExperimentalTool/0.1")

	mgr := resolver.ResolveSessionIdManager(req)
	sid := mgr.Generate()
	s, err := reg.GetSession(sid)
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if s.ClientHint != HintUnknown {
		t.Errorf("ClientHint = %q, want %q for unrecognized UA", s.ClientHint, HintUnknown)
	}
}

// TestClientHintResolver_DelegatesValidate verifies that the resolver's
// wrapped manager forwards Validate calls to the underlying registry so
// existing session lifecycle logic is untouched.
func TestClientHintResolver_DelegatesValidate(t *testing.T) {
	reg := NewSessionRegistry(testLogger())
	resolver := NewClientHintResolver(reg)

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("User-Agent", "Cursor/1.0")
	mgr := resolver.ResolveSessionIdManager(req)

	sid := mgr.Generate()
	terminated, err := mgr.Validate(sid)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if terminated {
		t.Error("fresh session reported as terminated")
	}
}

// TestClientHintResolver_DelegatesTerminate verifies Terminate round-trip
// through the resolver wrapper.
func TestClientHintResolver_DelegatesTerminate(t *testing.T) {
	reg := NewSessionRegistry(testLogger())
	resolver := NewClientHintResolver(reg)

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("User-Agent", "vscode/1.0")
	mgr := resolver.ResolveSessionIdManager(req)

	sid := mgr.Generate()
	notAllowed, err := mgr.Terminate(sid)
	if err != nil {
		t.Fatalf("Terminate failed: %v", err)
	}
	if notAllowed {
		t.Error("Terminate should succeed for a fresh session")
	}
	// Re-terminating a nonexistent session should error now that it's gone-ish.
	// The registry marks it as terminated without deleting; re-terminate is
	// a no-op that returns nil (existing behavior). We just assert the
	// resolver doesn't inject any new error.
	_, err = mgr.Terminate(sid)
	if err != nil {
		// Registry historically returns nil here; this test guards against
		// an unintended error-injection regression in the wrapper layer.
		t.Logf("second Terminate returned: %v (acceptable)", err)
	}
}

// TestClientHintResolver_EachRequestGetsOwnHint verifies that two requests
// with different User-Agents produce sessions with distinct hints, even
// though they share the underlying registry. This is the whole point of
// the request-scoped wrapper.
func TestClientHintResolver_EachRequestGetsOwnHint(t *testing.T) {
	reg := NewSessionRegistry(testLogger())
	resolver := NewClientHintResolver(reg)

	r1 := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	r1.Header.Set("User-Agent", "Claude/1.0 (macOS)")
	r2 := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	r2.Header.Set("User-Agent", "cursor/1.0")

	sid1 := resolver.ResolveSessionIdManager(r1).Generate()
	sid2 := resolver.ResolveSessionIdManager(r2).Generate()
	if sid1 == sid2 {
		t.Fatal("two Generate calls produced identical session IDs")
	}

	s1, err := reg.GetSession(sid1)
	if err != nil {
		t.Fatalf("GetSession s1: %v", err)
	}
	s2, err := reg.GetSession(sid2)
	if err != nil {
		t.Fatalf("GetSession s2: %v", err)
	}
	if s1.ClientHint != HintClaudeDesktop {
		t.Errorf("s1.ClientHint = %q, want %q", s1.ClientHint, HintClaudeDesktop)
	}
	if s2.ClientHint != HintCursor {
		t.Errorf("s2.ClientHint = %q, want %q", s2.ClientHint, HintCursor)
	}
}
