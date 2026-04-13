package cqrs

import (
	"context"
	"testing"
)

// TestNativeAlertClientContext verifies that the context-carrier helpers
// introduced for the batch-D QueryBus migration round-trip a value
// unchanged and return nil when nothing is attached.
func TestNativeAlertClientContext(t *testing.T) {
	t.Parallel()

	// Empty context -> nil.
	if got := NativeAlertClientFromContext(context.Background()); got != nil {
		t.Fatalf("expected nil client from empty context, got %T", got)
	}

	// Attach a sentinel and pull it back.
	type sentinel struct{ name string }
	want := &sentinel{name: "batch-d"}
	ctx := WithNativeAlertClient(context.Background(), want)

	got := NativeAlertClientFromContext(ctx)
	if got == nil {
		t.Fatalf("expected non-nil client from attached context")
	}
	gotSentinel, ok := got.(*sentinel)
	if !ok {
		t.Fatalf("expected *sentinel, got %T", got)
	}
	if gotSentinel != want {
		t.Fatalf("round-tripped pointer mismatch: got %p want %p", gotSentinel, want)
	}
	if gotSentinel.name != "batch-d" {
		t.Fatalf("unexpected sentinel name %q", gotSentinel.name)
	}
}

// TestNativeAlertClientContext_Nesting verifies that a later WithNativeAlertClient
// shadows an earlier one, matching context.WithValue semantics.
func TestNativeAlertClientContext_Nesting(t *testing.T) {
	t.Parallel()

	type sentinel struct{ id int }
	outer := &sentinel{id: 1}
	inner := &sentinel{id: 2}

	outerCtx := WithNativeAlertClient(context.Background(), outer)
	innerCtx := WithNativeAlertClient(outerCtx, inner)

	if got := NativeAlertClientFromContext(innerCtx).(*sentinel); got.id != 2 {
		t.Fatalf("inner ctx should resolve to inner sentinel, got id=%d", got.id)
	}
	if got := NativeAlertClientFromContext(outerCtx).(*sentinel); got.id != 1 {
		t.Fatalf("outer ctx should still resolve to outer sentinel, got id=%d", got.id)
	}
}
