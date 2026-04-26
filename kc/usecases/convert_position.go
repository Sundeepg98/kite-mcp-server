package usecases

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// ConvertPositionUseCase converts a position from one product type to another.
type ConvertPositionUseCase struct {
	brokerResolver BrokerResolver
	eventStore     EventAppender
	events         *domain.EventDispatcher
	logger         *slog.Logger
}

// NewConvertPositionUseCase creates a ConvertPositionUseCase with all dependencies injected.
func NewConvertPositionUseCase(resolver BrokerResolver, logger *slog.Logger) *ConvertPositionUseCase {
	return &ConvertPositionUseCase{
		brokerResolver: resolver,
		logger:         logger,
	}
}

// SetEventStore opts the use case into event-sourced audit. nil disables.
func (uc *ConvertPositionUseCase) SetEventStore(s EventAppender) { uc.eventStore = s }

// SetEventDispatcher wires the typed domain event dispatcher so the use
// case emits a domain.PositionConvertedEvent on success — replacing the
// prior untyped appendAuxEvent payload with a stable typed schema for
// projector consumers. Nil-safe: when unset, only the legacy aux-event
// path runs (preserves backward compatibility for tests / bootstrap
// configurations that don't wire the dispatcher). Both paths fire on
// success during the migration window so audit consumers depending on
// the historical untyped row aren't broken.
func (uc *ConvertPositionUseCase) SetEventDispatcher(d *domain.EventDispatcher) {
	uc.events = d
}

// Execute converts a position from one product type to another.
func (uc *ConvertPositionUseCase) Execute(ctx context.Context, cmd cqrs.ConvertPositionCommand) (bool, error) {
	if cmd.Email == "" {
		return false, fmt.Errorf("usecases: email is required")
	}
	if cmd.Tradingsymbol == "" {
		return false, fmt.Errorf("usecases: tradingsymbol is required")
	}
	if cmd.Quantity <= 0 {
		return false, fmt.Errorf("usecases: quantity must be positive, got %d", cmd.Quantity)
	}

	client, err := uc.brokerResolver.GetBrokerForEmail(cmd.Email)
	if err != nil {
		return false, fmt.Errorf("usecases: resolve broker: %w", err)
	}

	ok, err := client.ConvertPosition(broker.ConvertPositionParams{
		Exchange:        cmd.Exchange,
		Tradingsymbol:   cmd.Tradingsymbol,
		TransactionType: cmd.TransactionType,
		Quantity:        cmd.Quantity,
		OldProduct:      cmd.OldProduct,
		NewProduct:      cmd.NewProduct,
		PositionType:    cmd.PositionType,
	})
	if err != nil {
		uc.logger.Error("Failed to convert position",
			"email", cmd.Email,
			"tradingsymbol", cmd.Tradingsymbol,
			"error", err,
		)
		return false, fmt.Errorf("usecases: convert position: %w", err)
	}

	uc.logger.Info("Position converted",
		"email", cmd.Email,
		"tradingsymbol", cmd.Tradingsymbol,
		"old_product", cmd.OldProduct,
		"new_product", cmd.NewProduct,
	)

	now := time.Now().UTC()

	// Typed domain event — preferred path for new projector consumers.
	// Replaces the prior untyped map[string]any payload with a stable
	// schema. Nil-safe: dispatcher is optional in bootstrap / tests.
	if uc.events != nil {
		uc.events.Dispatch(domain.PositionConvertedEvent{
			Email:           cmd.Email,
			Instrument:      domain.NewInstrumentKey(cmd.Exchange, cmd.Tradingsymbol),
			TransactionType: cmd.TransactionType,
			Quantity:        cmd.Quantity,
			OldProduct:      cmd.OldProduct,
			NewProduct:      cmd.NewProduct,
			PositionType:    cmd.PositionType,
			Timestamp:       now,
		})
	}

	// Legacy untyped audit path retained for backward compatibility —
	// existing audit-trail readers may already consume the
	// "position.converted" StoredEvent rows under the historical
	// map[string]any payload. Aggregate key composed of
	// email+exchange+symbol+old_product so a CNC→MIS→CNC sequence
	// replays cleanly under stable IDs (matches
	// domain.PositionConvertedAggregateID).
	aggregateID := domain.PositionConvertedAggregateID(cmd.Email, cmd.Exchange, cmd.Tradingsymbol, cmd.OldProduct)
	appendAuxEvent(uc.eventStore, uc.logger, "Position", aggregateID, "position.converted", map[string]any{
		"email":            cmd.Email,
		"exchange":         cmd.Exchange,
		"tradingsymbol":    cmd.Tradingsymbol,
		"transaction_type": cmd.TransactionType,
		"quantity":         cmd.Quantity,
		"old_product":      cmd.OldProduct,
		"new_product":      cmd.NewProduct,
		"position_type":    cmd.PositionType,
	})

	return ok, nil
}
