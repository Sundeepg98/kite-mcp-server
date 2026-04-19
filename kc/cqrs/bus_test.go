package cqrs

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"reflect"
	"testing"
)

func TestInMemoryBus_DispatchWithResult(t *testing.T) {
	t.Parallel()
	bus := NewInMemoryBus()

	// Register a handler for GetProfileQuery
	if err := bus.Register(reflect.TypeFor[GetProfileQuery](), func(ctx context.Context, msg any) (any, error) {
		q := msg.(GetProfileQuery)
		return "profile-for-" + q.Email, nil
	}); err != nil {
		t.Fatalf("unexpected register error: %v", err)
	}

	result, err := bus.DispatchWithResult(context.Background(), GetProfileQuery{Email: "test@example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "profile-for-test@example.com" {
		t.Fatalf("unexpected result: %v", result)
	}
}

func TestInMemoryBus_Dispatch(t *testing.T) {
	t.Parallel()
	bus := NewInMemoryBus()

	called := false
	if err := bus.Register(reflect.TypeFor[PlaceOrderCommand](), func(ctx context.Context, msg any) (any, error) {
		called = true
		return nil, nil
	}); err != nil {
		t.Fatalf("unexpected register error: %v", err)
	}

	err := bus.Dispatch(context.Background(), PlaceOrderCommand{Email: "test@example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Fatal("handler was not called")
	}
}

func TestInMemoryBus_UnregisteredType(t *testing.T) {
	t.Parallel()
	bus := NewInMemoryBus()

	_, err := bus.DispatchWithResult(context.Background(), GetProfileQuery{Email: "test@example.com"})
	if err == nil {
		t.Fatal("expected error for unregistered type")
	}
	if err.Error() != "cqrs: no handler registered for cqrs.GetProfileQuery" {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestInMemoryBus_DuplicateRegistrationReturnsError(t *testing.T) {
	t.Parallel()
	bus := NewInMemoryBus()

	handler := func(ctx context.Context, msg any) (any, error) { return nil, nil }
	if err := bus.Register(reflect.TypeFor[GetProfileQuery](), handler); err != nil {
		t.Fatalf("first register should succeed: %v", err)
	}

	// Duplicate registration must return a descriptive error, not panic —
	// startup code can now surface programmer mistakes cleanly instead of
	// crashing the process.
	err := bus.Register(reflect.TypeFor[GetProfileQuery](), handler)
	if err == nil {
		t.Fatal("expected error on duplicate registration")
	}
	if got, want := err.Error(), "cqrs: duplicate handler for cqrs.GetProfileQuery"; got != want {
		t.Fatalf("unexpected error message: got %q, want %q", got, want)
	}
}

func TestInMemoryBus_MiddlewareChain(t *testing.T) {
	t.Parallel()
	var order []string

	mw1 := func(next HandlerFunc) HandlerFunc {
		return func(ctx context.Context, msg any) (any, error) {
			order = append(order, "mw1-before")
			result, err := next(ctx, msg)
			order = append(order, "mw1-after")
			return result, err
		}
	}

	mw2 := func(next HandlerFunc) HandlerFunc {
		return func(ctx context.Context, msg any) (any, error) {
			order = append(order, "mw2-before")
			result, err := next(ctx, msg)
			order = append(order, "mw2-after")
			return result, err
		}
	}

	bus := NewInMemoryBus(mw1, mw2)

	if err := bus.Register(reflect.TypeFor[GetProfileQuery](), func(ctx context.Context, msg any) (any, error) {
		order = append(order, "handler")
		return "ok", nil
	}); err != nil {
		t.Fatalf("unexpected register error: %v", err)
	}

	result, err := bus.DispatchWithResult(context.Background(), GetProfileQuery{Email: "test@example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "ok" {
		t.Fatalf("unexpected result: %v", result)
	}

	// Middleware should wrap: mw1 -> mw2 -> handler -> mw2 -> mw1
	expected := []string{"mw1-before", "mw2-before", "handler", "mw2-after", "mw1-after"}
	if len(order) != len(expected) {
		t.Fatalf("expected %d calls, got %d: %v", len(expected), len(order), order)
	}
	for i, v := range expected {
		if order[i] != v {
			t.Fatalf("call %d: expected %q, got %q", i, v, order[i])
		}
	}
}

func TestInMemoryBus_HandlerError(t *testing.T) {
	t.Parallel()
	bus := NewInMemoryBus()

	if err := bus.Register(reflect.TypeFor[GetProfileQuery](), func(ctx context.Context, msg any) (any, error) {
		return nil, errors.New("something went wrong")
	}); err != nil {
		t.Fatalf("unexpected register error: %v", err)
	}

	_, err := bus.DispatchWithResult(context.Background(), GetProfileQuery{Email: "test@example.com"})
	if err == nil {
		t.Fatal("expected error from handler")
	}
	if err.Error() != "something went wrong" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoggingMiddleware(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	bus := NewInMemoryBus(LoggingMiddleware(logger))

	if err := bus.Register(reflect.TypeFor[GetProfileQuery](), func(ctx context.Context, msg any) (any, error) {
		return "ok", nil
	}); err != nil {
		t.Fatalf("unexpected register error: %v", err)
	}

	result, err := bus.DispatchWithResult(context.Background(), GetProfileQuery{Email: "test@example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "ok" {
		t.Fatalf("unexpected result: %v", result)
	}
}

func TestLoggingMiddleware_ErrorPath(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	bus := NewInMemoryBus(LoggingMiddleware(logger))

	if err := bus.Register(reflect.TypeFor[PlaceOrderCommand](), func(ctx context.Context, msg any) (any, error) {
		return nil, errors.New("order failed")
	}); err != nil {
		t.Fatalf("unexpected register error: %v", err)
	}

	_, err := bus.DispatchWithResult(context.Background(), PlaceOrderCommand{Email: "test@example.com"})
	if err == nil {
		t.Fatal("expected error from handler")
	}
	if err.Error() != "order failed" {
		t.Fatalf("unexpected error: %v", err)
	}
}
