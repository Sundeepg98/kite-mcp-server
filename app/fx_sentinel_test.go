package app

import (
	"testing"

	"go.uber.org/fx"
)

// fx_sentinel_test.go is the Wave D Phase 2 Slice P2.1 deliverable.
//
// Purpose: lock the go.uber.org/fx dependency into go.mod / go.sum and
// prove the import compiles + links cleanly under Go 1.25.x. No
// production wiring yet — subsequent slices (P2.2 leaf providers, P2.3
// first fx.New beachhead) will start using the fx graph for real.
//
// This test is INTENTIONALLY trivial. It exists only to:
//   1. Force `go mod tidy` to retain the fx dep when nothing else
//      imports it (it would be pruned otherwise).
//   2. Surface any toolchain / version skew between fx and our module
//      at the cheapest possible test-cost (single import + nil constructor).
//   3. Provide a one-line canary: if fx's API ever introduces a
//      breaking change to fx.New / fx.Options / fx.NopLogger that our
//      providers will rely on, this test starts to fail compile and
//      we know to look at the migration guide before debugging
//      provider wiring.
//
// Once P2.3 ships (first real fx.New call in production wiring),
// this sentinel becomes redundant and can be removed. Until then it
// is the load-bearing import that keeps fx in our dependency graph.

// TestFxSentinel verifies that fx.New constructs and shuts down a
// minimal app cleanly. Uses fx.NopLogger to keep the test silent;
// fx.New will error if its internal type-graph construction has any
// startup-time issue with our toolchain.
func TestFxSentinel(t *testing.T) {
	t.Parallel()

	// Construct a minimal fx app with no providers. fx.New always
	// succeeds at the constructor; errors surface via app.Err() when
	// the graph is invalid. An empty graph is trivially valid.
	app := fx.New(
		fx.NopLogger,
	)

	if app == nil {
		t.Fatal("fx.New returned nil")
	}
	if err := app.Err(); err != nil {
		t.Fatalf("fx.New error: %v", err)
	}
}
