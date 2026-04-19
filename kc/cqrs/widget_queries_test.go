package cqrs

import (
	"context"
	"testing"
)

// TestWidgetAuditStoreContext verifies the context-carrier helpers used by
// the ext_apps widget DataFuncs round-trip an audit-store sentinel
// unchanged and return nil when nothing is attached.
func TestWidgetAuditStoreContext(t *testing.T) {
	t.Parallel()

	// Empty context -> nil.
	if got := WidgetAuditStoreFromContext(context.Background()); got != nil {
		t.Fatalf("expected nil audit store from empty context, got %T", got)
	}

	// Attach a sentinel and pull it back.
	type sentinel struct{ name string }
	want := &sentinel{name: "widget-batch"}
	ctx := WithWidgetAuditStore(context.Background(), want)

	got := WidgetAuditStoreFromContext(ctx)
	if got == nil {
		t.Fatalf("expected non-nil audit store from attached context")
	}
	gotSentinel, ok := got.(*sentinel)
	if !ok {
		t.Fatalf("expected *sentinel, got %T", got)
	}
	if gotSentinel != want {
		t.Fatalf("round-tripped pointer mismatch: got %p want %p", gotSentinel, want)
	}
}

// TestWithWidgetAuditStore_NilInputs verifies the nil-guard on
// WithWidgetAuditStore — nil ctx or nil store return the input ctx
// unchanged rather than panicking.
func TestWithWidgetAuditStore_NilInputs(t *testing.T) {
	t.Parallel()

	// nil store -> ctx unchanged, FromContext still nil.
	ctx := WithWidgetAuditStore(context.Background(), nil)
	if got := WidgetAuditStoreFromContext(ctx); got != nil {
		t.Fatalf("nil store should not attach; got %T", got)
	}

	// nil ctx -> return as-is (no panic).
	got := WithWidgetAuditStore(nil, "anything") //nolint:staticcheck // intentionally nil
	if got != nil {
		t.Fatalf("nil ctx should round-trip as nil, got %T", got)
	}
}
