package mcp

import (
	"fmt"
	"sort"
	"strings"

	"github.com/mark3labs/mcp-go/server"
)

// middleware_dsl.go — declarative middleware-chain DSL.
//
// PROBLEM
//
// The pre-DSL chain assembly in app/wire.go + app/providers/mcpserver.go
// expressed the middleware order via TWO sources of truth:
//
//   1. mcp.DefaultBuiltInOrder — a []string with names ("correlation",
//      "timeout", "audit", …) used by mcp.BuildMiddlewareChain when an
//      operator-supplied override was present.
//   2. app/providers/mcpserver.go:BuildMiddlewareChain(deps) — fan-in
//      struct over MiddlewareDeps with HARD-CODED order in code (the
//      sequence of add(deps.Correlation), add(deps.Timeout), … calls).
//      The struct fields' position in the source file IS the order;
//      reordering means editing Go.
//
// The production wire.go path (line 542 onward) consumed source #2;
// the operator-override path consumed #1. The two could drift —
// reordering #1 without reordering #2 produced no behavioural change
// in production.
//
// This file makes the order data-not-code by defining ONE schema —
// MiddlewareSpec — that both surfaces consume. The production wire-up
// builds a MiddlewareSpec at startup, validates it (fail-fast on
// missing/duplicate/typo'd entries), and feeds the resolved
// []server.ToolHandlerMiddleware into the existing
// providers.BuildMCPServer. Reordering the chain is now a single edit
// to a slice literal that the test suite enforces.
//
// SCOPE
//
// In:
//   - MiddlewareSpec struct: the declarative config schema (named
//     entries + ordered list).
//   - ValidateSpec: startup validation that fails fast on duplicates
//     in the order list, references to unregistered names, and empty
//     names. Caller is expected to log + exit on error.
//   - BuildChainFromSpec: pure data-to-runtime resolver. Returns
//     []server.ToolHandlerMiddleware ready for
//     server.WithToolHandlerMiddleware. Wraps existing
//     BuildMiddlewareChain.
//   - DefaultBuiltInSpec: factory for the canonical 10-layer order
//     using DefaultBuiltInOrder. Operators pass a MiddlewareRegistry
//     keyed by the canonical names to obtain a production spec.
//
// Out (intentionally separate from this file):
//   - YAML/JSON deserialisation. Operators today reorder the chain
//     in code; switching to file-based config trades the safety net
//     of the test suite for runtime-config flexibility we have no
//     consumer for. If a Tier-3 operator ships their own deployment
//     and wants file-based ordering, they deserialise into
//     MiddlewareSpec and feed it through ValidateSpec — the schema
//     IS the contract.
//   - Per-tool middleware overrides. The chain is uniform across
//     tools (per ADR 0005). Tool-level filtering happens inside
//     individual middlewares (e.g. riskguard.Middleware skips
//     non-order tools).
//
// CONTRACT
//
// 1. Order is a []string. Slice index 0 is OUTERMOST (matches
//    DefaultBuiltInOrder convention; matches mcp-go's
//    WithToolHandlerMiddleware semantics — first-registered wraps
//    later-registered).
// 2. Registry is a map[string]MiddlewareBuilder. Keys MUST appear in
//    Order to take effect; entries not referenced from Order are
//    DROPPED (operator pruning is supported via Order-list edit).
// 3. A registered name with a nil builder is "optional middleware
//    disabled in this build" (e.g. billing without STRIPE_SECRET_KEY).
//    BuildChainFromSpec skips it silently. ValidateSpec accepts it.
// 4. Order MAY contain a name that is NOT in Registry → ValidateSpec
//    surfaces this as an error at startup. Production must not start
//    with a typo'd middleware name.
// 5. Order MUST NOT contain duplicates → ValidateSpec rejects.
// 6. Order MAY be empty → BuildChainFromSpec returns an empty chain.
//    Test/dev configurations may want this.
//
// CONSEQUENCE
//
// The production app/wire.go middleware assembly becomes:
//
//   spec := mcp.MiddlewareSpec{
//       Registry: mcp.MiddlewareRegistry{
//           "correlation":    func() server.ToolHandlerMiddleware { return mcp.CorrelationMiddleware() },
//           "timeout":        ...,
//           …
//       },
//       Order: mcp.DefaultBuiltInOrder,
//   }
//   if err := mcp.ValidateSpec(spec); err != nil { return err }
//   chain, err := mcp.BuildChainFromSpec(spec)
//
// Reordering the chain = editing the DefaultBuiltInOrder slice (one
// line in mcp/middleware_chain.go). All call sites pick it up
// automatically; no parallel file edits required.

// MiddlewareRegistry maps a canonical name to its constructor.
// A nil value is legal — see MiddlewareBuilder for the semantics.
//
// Why a defined type over map[string]MiddlewareBuilder: callers can
// declare `var reg mcp.MiddlewareRegistry` and add entries
// incrementally without each addition needing a `map[…]…{}` literal.
// Nominal typing also surfaces "wrong map shape" errors at compile
// time when a caller (e.g. test) passes the wrong-shaped map.
type MiddlewareRegistry map[string]MiddlewareBuilder

// MiddlewareSpec is the declarative DSL for a middleware chain. The
// pair (Registry, Order) is the entire wire-format — anything that
// can produce a valid Spec (Go struct literal, YAML deser, env
// var-driven generator) goes through the same ValidateSpec +
// BuildChainFromSpec path.
//
// Spec is INTENTIONALLY a value type: a Spec passed to BuildChainFromSpec
// is not mutated. Tests that compare two Specs use assert.Equal
// directly.
type MiddlewareSpec struct {
	// Registry holds the named middleware builders. The map is
	// consulted once per Order entry; a missing key is a startup
	// error (see ValidateSpec). Nil-value entries are skipped at
	// build time.
	Registry MiddlewareRegistry

	// Order lists the registered names in outer-to-inner sequence
	// (slice index 0 wraps slice index 1 wraps the real handler).
	// Duplicates and references to names absent from Registry are
	// startup errors. Empty Order is a valid (no-middleware) chain.
	Order []string
}

// ValidateSpec is the fail-fast validator. Run at startup before
// constructing the MCP server; on error, log the returned message
// and exit non-zero. The runtime cost is O(len(Order) +
// len(Registry)) — a single pass per side, suitable for hot startup.
//
// Errors surfaced (in detection order):
//   - empty name in Order: "middleware spec: empty name at order index N"
//   - duplicate in Order: "middleware spec: duplicate name %q at order index N (also at M)"
//   - Order references missing Registry key: "middleware spec: name %q in order is not registered"
//
// Nil Registry / nil Order are valid (the empty-chain configuration
// is legal — useful for tests or DevMode bypass paths). The
// validator is generous on shape and strict on content.
//
// Multiple errors in a single spec are reported as a SINGLE error
// with newline-joined messages so operators can fix everything at
// once rather than running through a fix-deploy-fix loop.
func ValidateSpec(spec MiddlewareSpec) error {
	if len(spec.Order) == 0 {
		// Empty Order is valid; no checks needed (Registry can hold
		// anything — unreferenced entries are dropped at build).
		return nil
	}

	var problems []string

	// Track each Order entry's first-seen index for duplicate-detection.
	// Sorted output makes the validator deterministic across runs;
	// helpful when grepping CI logs or diffing failed builds.
	seen := make(map[string]int, len(spec.Order))

	for i, name := range spec.Order {
		if name == "" {
			problems = append(problems, fmt.Sprintf("empty name at order index %d", i))
			continue
		}
		if firstIdx, dup := seen[name]; dup {
			problems = append(problems, fmt.Sprintf("duplicate name %q at order index %d (also at %d)", name, i, firstIdx))
			continue
		}
		seen[name] = i

		if _, ok := spec.Registry[name]; !ok {
			problems = append(problems, fmt.Sprintf("name %q in order is not registered", name))
		}
	}

	if len(problems) == 0 {
		return nil
	}

	// Sort for deterministic error output. The first error message
	// encountered varies with map-iteration order downstream
	// otherwise; sorted output makes ValidateSpec easy to pin in
	// table-driven tests without flaky assertions.
	sort.Strings(problems)
	return fmt.Errorf("middleware spec: %s", strings.Join(problems, "; "))
}

// BuildChainFromSpec resolves the spec into a runtime chain. Validates
// first via ValidateSpec; on validation failure returns the error
// without constructing any middleware (callers must not silently
// ignore the validator). On success returns the chain ready for
// server.WithToolHandlerMiddleware — same shape as the legacy
// BuildMiddlewareChain.
//
// The single round-trip through ValidateSpec keeps this function
// single-responsibility for callers who want validate+build in one
// call (the common case at startup). Callers that want validate-only
// (e.g. a config-lint subcommand) should call ValidateSpec directly.
func BuildChainFromSpec(spec MiddlewareSpec) ([]server.ToolHandlerMiddleware, error) {
	if err := ValidateSpec(spec); err != nil {
		return nil, err
	}
	return BuildMiddlewareChain(spec.Registry, spec.Order)
}

// DefaultBuiltInSpec returns a MiddlewareSpec with the canonical
// 10-layer Order populated from DefaultBuiltInOrder and the supplied
// Registry. Convenience constructor for the production wire-up; the
// registry is supplied by the caller because middleware constructors
// close over runtime-only values (audit store, circuit breaker,
// billing store, etc.) that the mcp package does not own.
//
// The returned Spec is a value; modifying it does not affect any
// shared state. DefaultBuiltInOrder is shared by reference (it's a
// package-level slice); callers MUST NOT mutate the returned
// Spec.Order.
func DefaultBuiltInSpec(registry MiddlewareRegistry) MiddlewareSpec {
	return MiddlewareSpec{
		Registry: registry,
		Order:    DefaultBuiltInOrder,
	}
}
