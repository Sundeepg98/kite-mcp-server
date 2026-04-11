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
	bus := NewInMemoryBus()

	// Register a handler for GetProfileQuery
	bus.Register(reflect.TypeOf(GetProfileQuery{}), func(ctx context.Context, msg any) (any, error) {
		q := msg.(GetProfileQuery)
		return "profile-for-" + q.Email, nil
	})

	result, err := bus.DispatchWithResult(context.Background(), GetProfileQuery{Email: "test@example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "profile-for-test@example.com" {
		t.Fatalf("unexpected result: %v", result)
	}
}

func TestInMemoryBus_Dispatch(t *testing.T) {
	bus := NewInMemoryBus()

	called := false
	bus.Register(reflect.TypeOf(PlaceOrderCommand{}), func(ctx context.Context, msg any) (any, error) {
		called = true
		return nil, nil
	})

	err := bus.Dispatch(context.Background(), PlaceOrderCommand{Email: "test@example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Fatal("handler was not called")
	}
}

func TestInMemoryBus_UnregisteredType(t *testing.T) {
	bus := NewInMemoryBus()

	_, err := bus.DispatchWithResult(context.Background(), GetProfileQuery{Email: "test@example.com"})
	if err == nil {
		t.Fatal("expected error for unregistered type")
	}
	if err.Error() != "cqrs: no handler registered for cqrs.GetProfileQuery" {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestInMemoryBus_DuplicateRegistrationPanics(t *testing.T) {
	bus := NewInMemoryBus()

	handler := func(ctx context.Context, msg any) (any, error) { return nil, nil }
	bus.Register(reflect.TypeOf(GetProfileQuery{}), handler)

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic on duplicate registration")
		}
	}()

	bus.Register(reflect.TypeOf(GetProfileQuery{}), handler) // should panic
}

func TestInMemoryBus_MiddlewareChain(t *testing.T) {
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

	bus.Register(reflect.TypeOf(GetProfileQuery{}), func(ctx context.Context, msg any) (any, error) {
		order = append(order, "handler")
		return "ok", nil
	})

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
	bus := NewInMemoryBus()

	bus.Register(reflect.TypeOf(GetProfileQuery{}), func(ctx context.Context, msg any) (any, error) {
		return nil, errors.New("something went wrong")
	})

	_, err := bus.DispatchWithResult(context.Background(), GetProfileQuery{Email: "test@example.com"})
	if err == nil {
		t.Fatal("expected error from handler")
	}
	if err.Error() != "something went wrong" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoggingMiddleware(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	bus := NewInMemoryBus(LoggingMiddleware(logger))

	bus.Register(reflect.TypeOf(GetProfileQuery{}), func(ctx context.Context, msg any) (any, error) {
		return "ok", nil
	})

	result, err := bus.DispatchWithResult(context.Background(), GetProfileQuery{Email: "test@example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "ok" {
		t.Fatalf("unexpected result: %v", result)
	}
}
