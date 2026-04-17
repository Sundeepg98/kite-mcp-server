package cqrs

import (
	"context"
	"fmt"
	"log/slog"
	"reflect"
	"sync"
	"time"
)

// CommandBus dispatches commands to their registered handlers.
// All write operations flow through this single entry point.
type CommandBus interface {
	// Dispatch sends a command to its handler. Returns error if handler not found
	// or execution fails.
	Dispatch(ctx context.Context, cmd any) error

	// DispatchWithResult sends a command that returns a result (e.g., order ID).
	DispatchWithResult(ctx context.Context, cmd any) (any, error)
}

// QueryBus dispatches queries to their registered handlers.
// All read operations flow through this single entry point.
type QueryBus interface {
	// Dispatch sends a query to its handler and returns the result.
	Dispatch(ctx context.Context, query any) (any, error)
}

// Middleware wraps a handler with cross-cutting concerns.
type Middleware func(next HandlerFunc) HandlerFunc

// HandlerFunc is the generic signature for command/query handlers.
type HandlerFunc func(ctx context.Context, msg any) (any, error)

// InMemoryBus is a synchronous in-process bus that routes commands/queries
// by Go type to registered handler functions. It implements both CommandBus
// and QueryBus interfaces.
type InMemoryBus struct {
	mu       sync.RWMutex
	handlers map[reflect.Type]HandlerFunc
	mw       []Middleware
}

// NewInMemoryBus creates a new bus with optional middleware applied to all dispatches.
func NewInMemoryBus(middlewares ...Middleware) *InMemoryBus {
	return &InMemoryBus{
		handlers: make(map[reflect.Type]HandlerFunc),
		mw:       middlewares,
	}
}

// Register associates a message type with a handler function.
// Returns an error on duplicate registration so startup code can surface
// the programmer mistake cleanly instead of crashing the process mid-init.
func (b *InMemoryBus) Register(msgType reflect.Type, handler HandlerFunc) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, exists := b.handlers[msgType]; exists {
		return fmt.Errorf("cqrs: duplicate handler for %s", msgType)
	}
	b.handlers[msgType] = handler
	return nil
}

// Dispatch routes a message to its handler, applying middleware. Ignores return value.
func (b *InMemoryBus) Dispatch(ctx context.Context, msg any) error {
	_, err := b.DispatchWithResult(ctx, msg)
	return err
}

// DispatchWithResult routes a message and returns the handler's result.
func (b *InMemoryBus) DispatchWithResult(ctx context.Context, msg any) (any, error) {
	b.mu.RLock()
	msgType := reflect.TypeOf(msg)
	handler, ok := b.handlers[msgType]
	b.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("cqrs: no handler registered for %s", msgType)
	}

	// Apply middleware chain (outermost first).
	final := handler
	for i := len(b.mw) - 1; i >= 0; i-- {
		final = b.mw[i](final)
	}

	return final(ctx, msg)
}

// LoggingMiddleware logs every dispatch with duration and error status.
func LoggingMiddleware(logger *slog.Logger) Middleware {
	return func(next HandlerFunc) HandlerFunc {
		return func(ctx context.Context, msg any) (any, error) {
			msgType := reflect.TypeOf(msg).Name()
			start := time.Now()
			result, err := next(ctx, msg)
			duration := time.Since(start)
			if err != nil {
				logger.Error("Bus dispatch failed",
					"type", msgType,
					"duration_ms", duration.Milliseconds(),
					"error", err,
				)
			} else {
				logger.Debug("Bus dispatch OK",
					"type", msgType,
					"duration_ms", duration.Milliseconds(),
				)
			}
			return result, err
		}
	}
}
