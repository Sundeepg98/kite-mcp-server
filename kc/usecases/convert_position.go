package usecases

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
)

// ConvertPositionUseCase converts a position from one product type to another.
type ConvertPositionUseCase struct {
	brokerResolver BrokerResolver
	eventStore     EventAppender
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

	// Audit-trail event. Aggregate key composed of email+symbol+old_product
	// so a position-conversion sequence (CNC→MIS→CNC) replays cleanly.
	aggregateID := cmd.Email + "|" + cmd.Exchange + "|" + cmd.Tradingsymbol + "|" + cmd.OldProduct
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
