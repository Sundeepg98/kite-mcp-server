package providers

import (
	"context"

	"github.com/mark3labs/mcp-go/server"

	gomcp "github.com/mark3labs/mcp-go/mcp"

	"github.com/zerodha/kite-mcp-server/mcp"
)

// mcpserver.go — Wave D Phase 2 Slice P2.4d+e (Batch 3 Commit α).
// Provides the 10-layer middleware chain assembly + the
// *server.MCPServer construction as Fx graph nodes.
//
// LEGACY BEHAVIOUR PRESERVED
//
// The original imperative chain at app/wire.go:591-770 walked through
// 10 conditional middleware appends + elicitation + MCP Apps UI
// extension hooks before calling server.NewMCPServer. The provider
// pair below preserves the canonical layer ordering documented in
// .claude/CLAUDE.md §"Middleware Chain (order matters)" and the
// nil-skip semantics that wire.go used via inline `if mw != nil`
// checks.
//
// SCOPE
//
// In:
//   - 10 named middleware fields (some optional/nullable — Audit,
//     Billing, PaperTrading; the rest are always-present).
//   - Server name + version + the assembled chain as ServerOptions.
//
// Not in scope (stays at composition site):
//   - Plugin hook registrations (rolegate, telegramnotify) — these
//     register handlers on app.registry as side-effects BEFORE the
//     HookMiddlewareFor middleware is built; can't be Fx providers.
//   - SIGHUP rate-limit hot-reload goroutine — depends on
//     app.rateLimitReloadStop (App field) and the hot-loop pattern
//     doesn't fit the Fx graph cleanly.
//   - Billing-tier wiring (`toolRateLimiter.WithTierMultiplier(...)`)
//     — runs AFTER the middleware is constructed, mutates the
//     limiter in-place. Stays at composition.
//   - Tool registration (`mcp.RegisterToolsForRegistry`) — happens
//     after server.NewMCPServer; not part of the construction
//     contract.
//   - kcManager.SetMCPServer — backward write into Manager state
//     after the server is constructed; stays at composition.
//
// CHAIN ORDER (canonical, preserved from wire.go:594-745)
//
//   1. Correlation     — X-Request-ID injection
//   2. Timeout         — 30s tool-handler timeout
//   3. Audit           — tool-call logging (optional; nil iff init failed)
//   4. Hooks           — plugin before/after-execution dispatch
//   5. CircuitBreaker  — Kite API outage protection
//   6. RiskGuard       — pre-trade safety checks
//   7. RateLimiter     — per-tool per-user throttling
//   8. Billing         — tier-based tool gating (optional; nil iff
//                        StripeSecretKey unset / DevMode)
//   9. PaperTrading    — virtual-trade interception (optional; nil
//                        iff paper engine disabled)
//   10. DashboardURL   — auto-append dashboard hint to responses
//
// Changing this order changes runtime behaviour (e.g., RiskGuard
// before Audit means rejected orders aren't logged; Hooks after
// CircuitBreaker means hooks fire on broken-circuit responses too).
// Tests asserting on specific orderings live in app/wire_test.go.

// MiddlewareDeps bundles the 10 named middleware layers as a single
// Fx-graph value. Avoids the "type already provided" graph conflict
// that would arise from 10 separate fx.Supply(server.ToolHandlerMiddleware)
// calls — Fx can't disambiguate same-typed values without
// fx.Annotate name tags, and the tag ceremony is uglier than the
// struct.
//
// Each field is the constructed middleware (NOT the underlying
// service that produces it — composition site does that). Optional
// fields are nil when the corresponding feature is disabled
// (DevMode, no Stripe key, no paper engine).
type MiddlewareDeps struct {
	Correlation    server.ToolHandlerMiddleware
	Timeout        server.ToolHandlerMiddleware
	Audit          server.ToolHandlerMiddleware // optional
	Hooks          server.ToolHandlerMiddleware
	CircuitBreaker server.ToolHandlerMiddleware
	RiskGuard      server.ToolHandlerMiddleware
	RateLimiter    server.ToolHandlerMiddleware
	Billing        server.ToolHandlerMiddleware // optional
	PaperTrading   server.ToolHandlerMiddleware // optional
	DashboardURL   server.ToolHandlerMiddleware
}

// BuildMiddlewareChain assembles the 10-layer middleware chain as a
// []server.ServerOption slice in canonical order. Nil layers are
// skipped (matches wire.go:597's `if auditMiddleware != nil` gate).
//
// Pure function — no I/O, no goroutines. Deterministic output for
// any given MiddlewareDeps input.
//
// Internally routes through mcp.BuildChainFromSpec (the declarative
// DSL) so the chain order lives in mcp.DefaultBuiltInOrder as data,
// NOT in this function as a sequence of add() calls. Reordering the
// production chain is now a single edit to DefaultBuiltInOrder; both
// the operator-override path (mcp.BuildMiddlewareChain) and the
// production wire-up (this function) pick up the change without
// parallel edits. Validation errors are intentionally swallowed —
// MiddlewareDeps' typed fields make startup-time misconfiguration
// impossible (you can't have a duplicate field, you can't typo a
// field name without a Go-compile error). The operator-override path
// retains fail-fast validation via mcp.ValidateSpec.
func BuildMiddlewareChain(deps MiddlewareDeps) []server.ServerOption {
	chain, err := mcp.BuildChainFromSpec(mcp.DefaultBuiltInSpec(deps.toRegistry()))
	if err != nil {
		// Defensive: the typed-field MiddlewareDeps cannot construct an
		// invalid Spec (no duplicates possible — fields are nominal; no
		// missing names possible — toRegistry maps every canonical name).
		// If this branch ever fires it's a programmer error in the
		// translation; surface as an empty chain rather than panicking
		// (mirrors the legacy "nil = skip" graceful-degrade contract).
		return nil
	}

	opts := make([]server.ServerOption, 0, len(chain))
	for _, mw := range chain {
		opts = append(opts, server.WithToolHandlerMiddleware(mw))
	}
	return opts
}

// toRegistry projects MiddlewareDeps's typed fields into the
// canonical-name MiddlewareRegistry shape consumed by
// mcp.BuildChainFromSpec. This is the bridge between the typed
// fan-in struct (compile-time safety; can't have duplicate or typo'd
// names) and the data-driven DSL (Order is data; same Spec validates
// for both production wire-up and operator overrides).
//
// Each entry wraps the corresponding deps field in a closure-builder
// so mcp.BuildChainFromSpec sees the MiddlewareBuilder type. Builders
// for nil deps fields are themselves nil — preserving the
// "nil = skip layer" contract that mcp.BuildMiddlewareChain honours.
func (deps MiddlewareDeps) toRegistry() mcp.MiddlewareRegistry {
	mk := func(mw server.ToolHandlerMiddleware) mcp.MiddlewareBuilder {
		if mw == nil {
			return nil
		}
		// The middleware is already constructed at this point (the
		// composition site built it before the fan-in). The builder
		// just returns the held value; the Spec resolver doesn't care
		// whether construction is lazy or eager.
		return func() server.ToolHandlerMiddleware { return mw }
	}
	return mcp.MiddlewareRegistry{
		"correlation":    mk(deps.Correlation),
		"timeout":        mk(deps.Timeout),
		"audit":          mk(deps.Audit),
		"hooks":          mk(deps.Hooks),
		"circuitbreaker": mk(deps.CircuitBreaker),
		"riskguard":      mk(deps.RiskGuard),
		"ratelimit":      mk(deps.RateLimiter),
		"billing":        mk(deps.Billing),
		"papertrading":   mk(deps.PaperTrading),
		"dashboardurl":   mk(deps.DashboardURL),
	}
}

// MCPServerInput carries the inputs BuildMCPServer consumes via the
// Fx graph. Single-arg-struct convention per audit_init.go. Exported
// because composition sites (app/wire.go) construct it directly via
// closure capture (the Name / Version come from the App, not from
// other fx.Provide values).
type MCPServerInput struct {
	// Name is the MCP server identifier ("Kite MCP Server" in
	// production). Surfaces in the InitializeResult sent to clients.
	Name string

	// Version is the build version string (app.Version). Same
	// surface — clients use it for debugging / capability negotiation.
	Version string

	// Options is the pre-assembled middleware chain plus any other
	// ServerOptions the caller wants to thread in. Typically built
	// by BuildMiddlewareChain. The provider appends Elicitation +
	// MCP Apps UI extension hooks AFTER the supplied options so
	// those production-required defaults always land.
	Options []server.ServerOption
}

// BuildMCPServer constructs the *server.MCPServer with the supplied
// options + the production-required Elicitation and MCP Apps UI
// extension hooks. Pure passthrough — no I/O beyond the underlying
// mcp-go constructor.
//
// MCP Apps UI extension hook
//
// Declares the io.modelcontextprotocol/ui capability so MCP App
// hosts (Cowork, claude.ai) know this server supports inline
// rendering of ui:// resources. mcp-go does not yet expose a
// WithExtensions option, so the capability is injected via an
// OnAfterInitialize hook that mutates the InitializeResult before
// it returns to the client.
func BuildMCPServer(in MCPServerInput) *server.MCPServer {
	opts := append([]server.ServerOption{}, in.Options...)

	// Production-required: enable elicitation so tool handlers can
	// request user confirmation before placing orders. Clients that
	// don't support elicitation will gracefully degrade (fail open
	// — orders proceed without confirmation).
	opts = append(opts, server.WithElicitation())

	// Production-required: declare the MCP Apps UI extension.
	uiHooks := &server.Hooks{}
	uiHooks.AddAfterInitialize(func(_ context.Context, _ any, _ *gomcp.InitializeRequest, result *gomcp.InitializeResult) {
		if result.Capabilities.Extensions == nil {
			result.Capabilities.Extensions = make(map[string]any)
		}
		result.Capabilities.Extensions["io.modelcontextprotocol/ui"] = map[string]any{}
	})
	opts = append(opts, server.WithHooks(uiHooks))

	return server.NewMCPServer(in.Name, in.Version, opts...)
}
