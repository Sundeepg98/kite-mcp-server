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

	// ES post-migration: typed event only. Persister in app/wire.go
	// subscribes "position.converted" to makeEventPersister and writes
	// the audit row from this dispatch (with EmailHash for PII
	// correlation, an improvement over the prior aux-event row which
	// lacked it). Follow-up to commit 9a36681 which migrated the
	// other 15 dual-emit sites; position.converted was deferred to
	// avoid cross-batch overlap with the Money VO Wave A slices.
	//
	// Aggregate-ID derivation lives in app/adapters.go's
	// deriveAggregateID, routed through
	// domain.PositionConvertedAggregateID.
	if uc.events != nil {
		uc.events.Dispatch(domain.PositionConvertedEvent{
			Email:           cmd.Email,
			Instrument:      domain.NewInstrumentKey(cmd.Exchange, cmd.Tradingsymbol),
			TransactionType: cmd.TransactionType,
			Quantity:        cmd.Quantity,
			OldProduct:      cmd.OldProduct,
			NewProduct:      cmd.NewProduct,
			PositionType:    cmd.PositionType,
			Timestamp:       time.Now().UTC(),
		})
	}

	return ok, nil
}
