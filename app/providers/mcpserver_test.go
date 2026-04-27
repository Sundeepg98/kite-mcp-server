package providers

import (
	"testing"

	"github.com/mark3labs/mcp-go/server"
)

// mcpserver_test.go covers BuildMiddlewareChain and BuildMCPServer.
// Wave D Phase 2 Slice P2.4d+e (Batch 3 Commit α).
//
// Two providers in this file:
//   - BuildMiddlewareChain(deps) []server.ServerOption — pure
//     function, assembles the 10-layer middleware chain in canonical
//     order (per .claude/CLAUDE.md §"Middleware Chain"). Skips nil
//     layers (matches the legacy `if mw != nil` gate at wire.go).
//   - BuildMCPServer(in) *server.MCPServer — calls server.NewMCPServer
//     with the supplied options + version + name. Pure passthrough.
//
// The fan-in via MiddlewareDeps avoids Fx's
// "type already provided" graph conflict for 10 same-typed fields:
// instead of 10 separate fx.Supply(server.ToolHandlerMiddleware) calls
// (which Fx can't disambiguate without name tags), the composition
// site assembles ONE MiddlewareDeps struct and supplies it.

// dummyMiddleware returns a non-nil server.ToolHandlerMiddleware that
// passes through to its `next` handler. Used in tests to verify
// BuildMiddlewareChain preserves the layer ordering.
func dummyMiddleware() server.ToolHandlerMiddleware {
	return func(next server.ToolHandlerFunc) server.ToolHandlerFunc {
		return next
	}
}

// TestBuildMiddlewareChain_AllNil_ReturnsEmpty verifies that a fully
// empty MiddlewareDeps produces zero ServerOptions. No middleware to
// register = empty options slice. Fx graph that wires no middlewares
// must still produce a usable MCP server (no panics, no unused
// imports).
func TestBuildMiddlewareChain_AllNil_ReturnsEmpty(t *testing.T) {
	t.Parallel()

	got := BuildMiddlewareChain(MiddlewareDeps{})
	if len(got) != 0 {
		t.Errorf("expected zero options for empty deps; got %d", len(got))
	}
}

// TestBuildMiddlewareChain_AllPresent_ReturnsTen verifies that
// supplying all 10 middleware layers produces 10 ServerOptions in the
// canonical order. We can't easily inspect the order from
// ServerOption opaque values; instead we verify the count + that the
// chain assembly does not panic, then exercise the legacy ordering
// via existing TestInitializeServices_* tests on the integration side.
func TestBuildMiddlewareChain_AllPresent_ReturnsTen(t *testing.T) {
	t.Parallel()

	mw := dummyMiddleware()
	deps := MiddlewareDeps{
		Correlation:    mw,
		Timeout:        mw,
		Audit:          mw,
		Hooks:          mw,
		CircuitBreaker: mw,
		RiskGuard:      mw,
		RateLimiter:    mw,
		Billing:        mw,
		PaperTrading:   mw,
		DashboardURL:   mw,
	}
	got := BuildMiddlewareChain(deps)
	if len(got) != 10 {
		t.Errorf("expected 10 options; got %d", len(got))
	}
}

// TestBuildMiddlewareChain_PartialPresence_SkipsNils verifies that
// only the non-nil layers are emitted as ServerOptions. This pins the
// "nil = skip layer" contract that matches wire.go's legacy
// `if auditMiddleware != nil` / `if paperEngine != nil` gates.
func TestBuildMiddlewareChain_PartialPresence_SkipsNils(t *testing.T) {
	t.Parallel()

	mw := dummyMiddleware()
	tests := []struct {
		name string
		deps MiddlewareDeps
		want int
	}{
		{
			name: "only required core (Correlation+Timeout+Hooks+CB+RG+RL+Dashboard = 7)",
			deps: MiddlewareDeps{
				Correlation:    mw,
				Timeout:        mw,
				Hooks:          mw,
				CircuitBreaker: mw,
				RiskGuard:      mw,
				RateLimiter:    mw,
				DashboardURL:   mw,
			},
			want: 7,
		},
		{
			name: "core + audit (DevMode-init-failed path drops audit, this is the audit-enabled path)",
			deps: MiddlewareDeps{
				Correlation:    mw,
				Timeout:        mw,
				Audit:          mw,
				Hooks:          mw,
				CircuitBreaker: mw,
				RiskGuard:      mw,
				RateLimiter:    mw,
				DashboardURL:   mw,
			},
			want: 8,
		},
		{
			name: "core + billing (production with Stripe)",
			deps: MiddlewareDeps{
				Correlation:    mw,
				Timeout:        mw,
				Audit:          mw,
				Hooks:          mw,
				CircuitBreaker: mw,
				RiskGuard:      mw,
				RateLimiter:    mw,
				Billing:        mw,
				DashboardURL:   mw,
			},
			want: 9,
		},
		{
			name: "core + paper trading (DevMode with paper enabled)",
			deps: MiddlewareDeps{
				Correlation:    mw,
				Timeout:        mw,
				Audit:          mw,
				Hooks:          mw,
				CircuitBreaker: mw,
				RiskGuard:      mw,
				RateLimiter:    mw,
				PaperTrading:   mw,
				DashboardURL:   mw,
			},
			want: 9,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := BuildMiddlewareChain(tt.deps)
			if len(got) != tt.want {
				t.Errorf("expected %d options; got %d", tt.want, len(got))
			}
		})
	}
}

// TestBuildMCPServer_ConstructsServer verifies that the provider
// produces a non-nil *server.MCPServer when given valid name +
// version + ServerOptions. This is the primary contract — composition
// sites get a usable server back.
func TestBuildMCPServer_ConstructsServer(t *testing.T) {
	t.Parallel()

	in := MCPServerInput{
		Name:    "test-server",
		Version: "v1.0.0",
		Options: nil, // empty options is valid — server starts with no middleware
	}
	got := BuildMCPServer(in)
	if got == nil {
		t.Fatal("expected non-nil *server.MCPServer")
	}
}

// TestBuildMCPServer_AppendsElicitationAndUIHooks verifies that the
// provider appends the elicitation + UI extension hooks to the
// supplied options. We can't inspect the Hooks field directly (it's
// private inside server.MCPServer), so we just verify construction
// succeeds with a non-empty options input — the legacy behaviour is
// covered by integration tests in app/.
func TestBuildMCPServer_AppendsElicitationAndUIHooks(t *testing.T) {
	t.Parallel()

	in := MCPServerInput{
		Name:    "ui-test",
		Version: "v0.0.0",
		Options: []server.ServerOption{
			server.WithToolHandlerMiddleware(dummyMiddleware()),
		},
	}
	got := BuildMCPServer(in)
	if got == nil {
		t.Fatal("expected non-nil server with options + UI hooks appended")
	}
}
