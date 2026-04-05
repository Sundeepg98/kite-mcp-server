package cqrs

import "context"

// CommandHandler processes a command of type C and returns an error if the
// operation fails. Commands are write operations that mutate system state.
//
// Example usage:
//
//	type PlaceOrderHandler struct { ... }
//	func (h *PlaceOrderHandler) Handle(ctx context.Context, cmd PlaceOrderCommand) error { ... }
type CommandHandler[C any] interface {
	Handle(ctx context.Context, cmd C) error
}

// CommandHandlerWithResult processes a command and returns both a result and error.
// Use this for commands that produce a meaningful return value (e.g., order ID).
//
// Example usage:
//
//	type PlaceOrderHandler struct { ... }
//	func (h *PlaceOrderHandler) Handle(ctx context.Context, cmd PlaceOrderCommand) (string, error) { ... }
type CommandHandlerWithResult[C any, R any] interface {
	Handle(ctx context.Context, cmd C) (R, error)
}

// QueryHandler processes a query of type Q and returns a result of type R.
// Queries are read operations that never mutate system state.
//
// Example usage:
//
//	type GetPortfolioHandler struct { ... }
//	func (h *GetPortfolioHandler) Handle(ctx context.Context, q GetPortfolioQuery) (*Portfolio, error) { ... }
type QueryHandler[Q any, R any] interface {
	Handle(ctx context.Context, query Q) (R, error)
}
