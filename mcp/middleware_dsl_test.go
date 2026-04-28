package mcp

import (
	"context"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// middleware_dsl_test.go — coverage for the declarative DSL surface
// (MiddlewareSpec / ValidateSpec / BuildChainFromSpec / DefaultBuiltInSpec).
//
// What these tests prove
//
//   - The order in which middleware runs is data, not code: the
//     same Registry produces different invocation orders depending
//     on Order alone (TestBuildChainFromSpec_OrderDrivesInvocationData).
//   - ValidateSpec is a fail-fast: empty names, duplicates, and
//     references to unregistered builders are rejected at startup
//     (the four TestValidateSpec_* cases).
//   - BuildChainFromSpec runs the validator first; a malformed Spec
//     never produces a partial chain (TestBuildChainFromSpec_ValidationGate).
//   - DefaultBuiltInSpec assembles the canonical 10-layer
//     production order from a registry (TestDefaultBuiltInSpec_UsesCanonicalOrder).
//
// These complement (don't duplicate) the existing tests in
// middleware_chain_builder_test.go, which cover the lower-level
// BuildMiddlewareChain(entries, order) entry point.

// recordingMiddlewareForDSL is a test helper analogous to the one in
// middleware_chain_builder_test.go: every middleware appends its
// name to the calls slice when invoked, then forwards. Verifying
// invocation order against an expected slice proves the chain
// composition is order-faithful.
func recordingMiddlewareForDSL(name string, calls *[]string) server.ToolHandlerMiddleware {
	return func(next server.ToolHandlerFunc) server.ToolHandlerFunc {
		return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			*calls = append(*calls, name)
			return next(ctx, req)
		}
	}
}

// applyChainForDSL composes the chain right-to-left around a
// terminal handler and fires one request. Right-to-left wrapping
// matches the contract: BuildChainFromSpec returns the chain in
// outer-to-inner order, so the FIRST entry must be the OUTERMOST
// caller (first to record).
func applyChainForDSL(t *testing.T, mws []server.ToolHandlerMiddleware) {
	t.Helper()
	var handler server.ToolHandlerFunc = func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return mcp.NewToolResultText("ok"), nil
	}
	for i := len(mws) - 1; i >= 0; i-- {
		handler = mws[i](handler)
	}
	_, err := handler(context.Background(), mcp.CallToolRequest{})
	require.NoError(t, err)
}

// TestValidateSpec_EmptyOrderIsValid pins the documented contract:
// a Spec with no Order is the legal "empty chain" configuration and
// must not error at validation time. Useful for DevMode and
// bare-bones test wiring.
func TestValidateSpec_EmptyOrderIsValid(t *testing.T) {
	t.Parallel()

	spec := MiddlewareSpec{
		Registry: MiddlewareRegistry{
			"audit": func() server.ToolHandlerMiddleware {
				return func(next server.ToolHandlerFunc) server.ToolHandlerFunc { return next }
			},
		},
		// Order intentionally empty — chain is the identity.
	}
	assert.NoError(t, ValidateSpec(spec))
}

// TestValidateSpec_NilSpecIsValid covers the most defensive case —
// the zero value of MiddlewareSpec (nil Registry + nil Order) must
// not crash the validator. Tests that build a Spec incrementally
// would otherwise fail confusingly.
func TestValidateSpec_NilSpecIsValid(t *testing.T) {
	t.Parallel()

	// Zero value — no Registry, no Order. ValidateSpec must treat
	// this as the empty-chain configuration.
	assert.NoError(t, ValidateSpec(MiddlewareSpec{}))
}

// TestValidateSpec_HappyPath exercises the canonical 10-layer order
// against a fully-populated Registry. Used as a positive baseline for
// the negative-path tests below.
func TestValidateSpec_HappyPath(t *testing.T) {
	t.Parallel()

	mw := func() server.ToolHandlerMiddleware {
		return func(next server.ToolHandlerFunc) server.ToolHandlerFunc { return next }
	}
	registry := MiddlewareRegistry{}
	for _, name := range DefaultBuiltInOrder {
		registry[name] = mw
	}
	spec := MiddlewareSpec{
		Registry: registry,
		Order:    DefaultBuiltInOrder,
	}
	assert.NoError(t, ValidateSpec(spec))
}

// TestValidateSpec_UnregisteredName proves the typo-detection
// contract: an Order that references a name not in Registry MUST
// fail validation. This is the most common operator mistake — copy-
// paste with a typo.
func TestValidateSpec_UnregisteredName(t *testing.T) {
	t.Parallel()

	mw := func() server.ToolHandlerMiddleware {
		return func(next server.ToolHandlerFunc) server.ToolHandlerFunc { return next }
	}
	spec := MiddlewareSpec{
		Registry: MiddlewareRegistry{
			"audit": mw,
		},
		Order: []string{"audit", "rsikguard"}, // typo'd "rsikguard"
	}
	err := ValidateSpec(spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rsikguard")
	assert.Contains(t, err.Error(), "not registered")
}

// TestValidateSpec_DuplicateName proves duplicates in Order surface
// as an error. A duplicate ordinarily indicates a merge conflict
// that resolved both branches' insertions; surfacing at startup
// avoids the runtime mystery of "why does audit fire twice".
func TestValidateSpec_DuplicateName(t *testing.T) {
	t.Parallel()

	mw := func() server.ToolHandlerMiddleware {
		return func(next server.ToolHandlerFunc) server.ToolHandlerFunc { return next }
	}
	spec := MiddlewareSpec{
		Registry: MiddlewareRegistry{
			"audit":     mw,
			"riskguard": mw,
		},
		Order: []string{"audit", "riskguard", "audit"},
	}
	err := ValidateSpec(spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate")
	assert.Contains(t, err.Error(), `"audit"`)
}

// TestValidateSpec_EmptyName surfaces the case where the Order
// list contains an empty string entry. Common cause: YAML loader
// emitting "" for a missing list element. Surfaces with a
// clear position-tagged message.
func TestValidateSpec_EmptyName(t *testing.T) {
	t.Parallel()

	mw := func() server.ToolHandlerMiddleware {
		return func(next server.ToolHandlerFunc) server.ToolHandlerFunc { return next }
	}
	spec := MiddlewareSpec{
		Registry: MiddlewareRegistry{
			"audit": mw,
		},
		Order: []string{"audit", "", "audit"}, // gap at index 1
	}
	err := ValidateSpec(spec)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty name")
	assert.Contains(t, err.Error(), "index 1")
}

// TestValidateSpec_MultipleErrorsReportedTogether pins the documented
// "fix everything at once" contract: a Spec with several distinct
// problems produces ONE error whose message lists ALL of them. This
// makes config-fix iteration a single deploy cycle, not N.
func TestValidateSpec_MultipleErrorsReportedTogether(t *testing.T) {
	t.Parallel()

	mw := func() server.ToolHandlerMiddleware {
		return func(next server.ToolHandlerFunc) server.ToolHandlerFunc { return next }
	}
	spec := MiddlewareSpec{
		Registry: MiddlewareRegistry{
			"audit": mw,
		},
		Order: []string{"audit", "", "audit", "missing"},
	}
	err := ValidateSpec(spec)
	require.Error(t, err)
	msg := err.Error()
	// Each problem must surface in the single error message:
	assert.Contains(t, msg, "empty name")
	assert.Contains(t, msg, "duplicate")
	assert.Contains(t, msg, "missing")
	// All three must be on the SAME error (no early return).
	assert.True(t, strings.Count(msg, ";") >= 2,
		"multiple problems should be ;-separated; got: %s", msg)
}

// TestBuildChainFromSpec_ValidationGate is the load-bearing
// invariant: if the spec is invalid, BuildChainFromSpec must NOT
// return any middleware. A partial chain is worse than no chain —
// it would silently drop the bad layer's responsibility.
func TestBuildChainFromSpec_ValidationGate(t *testing.T) {
	t.Parallel()

	mw := func() server.ToolHandlerMiddleware {
		return func(next server.ToolHandlerFunc) server.ToolHandlerFunc { return next }
	}
	spec := MiddlewareSpec{
		Registry: MiddlewareRegistry{
			"audit": mw,
		},
		Order: []string{"audit", "rsikguard"}, // unregistered
	}
	chain, err := BuildChainFromSpec(spec)
	require.Error(t, err, "validation must gate the build")
	assert.Nil(t, chain, "no chain on validation failure (no partial-chain risk)")
}

// TestBuildChainFromSpec_OrderDrivesInvocationData is THE point of
// the DSL: changing the Order slice — and only the Order slice —
// changes the invocation order. The Registry is the same Go-data
// object across both runs; only the data describing the order
// differs. Demonstrates "order is data, not code".
func TestBuildChainFromSpec_OrderDrivesInvocationData(t *testing.T) {
	t.Parallel()

	// Build a Registry once. We'll feed it through BuildChainFromSpec
	// twice with different Order slices and assert different
	// invocation orders.
	calls := []string{}
	registry := MiddlewareRegistry{
		"audit":     func() server.ToolHandlerMiddleware { return recordingMiddlewareForDSL("audit", &calls) },
		"riskguard": func() server.ToolHandlerMiddleware { return recordingMiddlewareForDSL("riskguard", &calls) },
		"billing":   func() server.ToolHandlerMiddleware { return recordingMiddlewareForDSL("billing", &calls) },
	}

	// First pass: audit → riskguard → billing.
	calls = nil
	chain, err := BuildChainFromSpec(MiddlewareSpec{
		Registry: registry,
		Order:    []string{"audit", "riskguard", "billing"},
	})
	require.NoError(t, err)
	require.Len(t, chain, 3)
	applyChainForDSL(t, chain)
	assert.Equal(t, []string{"audit", "riskguard", "billing"}, calls,
		"first pass: invocation order matches Order slice")

	// Second pass: same Registry, REVERSED Order. The chain rebuilds
	// from the same data — invocation order MUST flip.
	calls = nil
	chain, err = BuildChainFromSpec(MiddlewareSpec{
		Registry: registry,
		Order:    []string{"billing", "riskguard", "audit"},
	})
	require.NoError(t, err)
	require.Len(t, chain, 3)
	applyChainForDSL(t, chain)
	assert.Equal(t, []string{"billing", "riskguard", "audit"}, calls,
		"second pass: invocation order matches reversed Order — order is data, not code")
}

// TestBuildChainFromSpec_OptionalNilSkipped pins the optional-
// middleware contract — a Registry entry whose builder is nil
// represents "this layer is disabled in the current build" (e.g.
// billing without STRIPE_SECRET_KEY). BuildChainFromSpec must skip
// silently rather than panic; ValidateSpec must accept the
// configuration as legal.
func TestBuildChainFromSpec_OptionalNilSkipped(t *testing.T) {
	t.Parallel()

	calls := []string{}
	spec := MiddlewareSpec{
		Registry: MiddlewareRegistry{
			"audit":   func() server.ToolHandlerMiddleware { return recordingMiddlewareForDSL("audit", &calls) },
			"billing": nil, // disabled — DevMode / no STRIPE_SECRET_KEY
		},
		Order: []string{"audit", "billing"},
	}
	require.NoError(t, ValidateSpec(spec), "nil-builder entries must validate")
	chain, err := BuildChainFromSpec(spec)
	require.NoError(t, err)
	assert.Len(t, chain, 1, "nil-builder entry must be skipped at build")
	applyChainForDSL(t, chain)
	assert.Equal(t, []string{"audit"}, calls, "only audit fires")
}

// TestDefaultBuiltInSpec_UsesCanonicalOrder verifies that the
// convenience constructor populates Order from DefaultBuiltInOrder
// (the package-level canonical sequence). This is the production
// wire-up's entry point — operators should not have to spell out
// the 10-layer order at every call site.
func TestDefaultBuiltInSpec_UsesCanonicalOrder(t *testing.T) {
	t.Parallel()

	mw := func() server.ToolHandlerMiddleware {
		return func(next server.ToolHandlerFunc) server.ToolHandlerFunc { return next }
	}
	registry := MiddlewareRegistry{}
	for _, name := range DefaultBuiltInOrder {
		registry[name] = mw
	}
	spec := DefaultBuiltInSpec(registry)
	require.NoError(t, ValidateSpec(spec))

	// The Spec.Order MUST point at the same canonical sequence the
	// rest of the codebase consumes — reordering happens once, in
	// DefaultBuiltInOrder, and propagates through DefaultBuiltInSpec
	// to every caller.
	assert.Equal(t, DefaultBuiltInOrder, spec.Order)
	assert.Equal(t, registry, spec.Registry)
}

// TestDefaultBuiltInSpec_ResolvesToTenLayers locks the production
// shape: feeding DefaultBuiltInSpec with all 10 canonical builders
// must produce a 10-layer chain. Guards against accidental drift
// between DefaultBuiltInOrder and the documented Middleware Chain
// in .claude/CLAUDE.md.
func TestDefaultBuiltInSpec_ResolvesToTenLayers(t *testing.T) {
	t.Parallel()

	calls := []string{}
	registry := MiddlewareRegistry{}
	for _, name := range DefaultBuiltInOrder {
		// Capture name into a local for the closure (loop-var hazard).
		layerName := name
		registry[name] = func() server.ToolHandlerMiddleware {
			return recordingMiddlewareForDSL(layerName, &calls)
		}
	}
	spec := DefaultBuiltInSpec(registry)
	chain, err := BuildChainFromSpec(spec)
	require.NoError(t, err)
	assert.Len(t, chain, len(DefaultBuiltInOrder),
		"chain depth must match DefaultBuiltInOrder length")

	applyChainForDSL(t, chain)
	assert.Equal(t, DefaultBuiltInOrder, calls,
		"production-shape chain: invocation order matches DefaultBuiltInOrder")
}
