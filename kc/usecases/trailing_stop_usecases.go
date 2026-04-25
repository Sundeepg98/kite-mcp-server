package usecases

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
)

// TrailingStopManager abstracts trailing stop persistence for use cases.
type TrailingStopManager interface {
	Add(ts *alerts.TrailingStop) (string, error)
	List(email string) []*alerts.TrailingStop
	Cancel(email, id string) error
	CancelByEmail(email string)
}

// --- Set Trailing Stop ---

// SetTrailingStopUseCase creates a new trailing stop-loss.
type SetTrailingStopUseCase struct {
	manager    TrailingStopManager
	eventStore EventAppender
	logger     *slog.Logger
}

// NewSetTrailingStopUseCase creates a SetTrailingStopUseCase with dependencies injected.
func NewSetTrailingStopUseCase(manager TrailingStopManager, logger *slog.Logger) *SetTrailingStopUseCase {
	return &SetTrailingStopUseCase{manager: manager, logger: logger}
}

// SetEventStore opts the use case into event-sourced audit. nil disables.
func (uc *SetTrailingStopUseCase) SetEventStore(s EventAppender) { uc.eventStore = s }

// Execute creates a trailing stop and returns the ID.
func (uc *SetTrailingStopUseCase) Execute(ctx context.Context, cmd cqrs.SetTrailingStopCommand) (string, error) {
	if cmd.Email == "" {
		return "", fmt.Errorf("usecases: email is required")
	}
	if cmd.OrderID == "" {
		return "", fmt.Errorf("usecases: order_id is required")
	}
	if cmd.CurrentStop <= 0 {
		return "", fmt.Errorf("usecases: current_stop must be positive")
	}
	if cmd.ReferencePrice <= 0 {
		return "", fmt.Errorf("usecases: reference_price must be positive")
	}

	ts := &alerts.TrailingStop{
		Email:           cmd.Email,
		Exchange:        cmd.Exchange,
		Tradingsymbol:   cmd.Tradingsymbol,
		InstrumentToken: cmd.InstrumentToken,
		OrderID:         cmd.OrderID,
		Variety:         cmd.Variety,
		TrailAmount:     cmd.TrailAmount,
		TrailPct:        cmd.TrailPct,
		Direction:       cmd.Direction,
		HighWaterMark:   cmd.ReferencePrice,
		CurrentStop:     cmd.CurrentStop,
	}

	id, err := uc.manager.Add(ts)
	if err != nil {
		uc.logger.Error("Failed to set trailing stop", "email", cmd.Email, "error", err)
		return "", fmt.Errorf("usecases: set trailing stop: %w", err)
	}

	appendAuxEvent(uc.eventStore, uc.logger, "TrailingStop", id, "trailing_stop.set", map[string]any{
		"email":            cmd.Email,
		"trailing_stop_id": id,
		"exchange":         cmd.Exchange,
		"tradingsymbol":    cmd.Tradingsymbol,
		"order_id":         cmd.OrderID,
		"variety":          cmd.Variety,
		"direction":        cmd.Direction,
		"trail_amount":     cmd.TrailAmount,
		"trail_pct":        cmd.TrailPct,
		"current_stop":     cmd.CurrentStop,
		"reference_price":  cmd.ReferencePrice,
	})

	return id, nil
}

// --- List Trailing Stops ---

// ListTrailingStopsUseCase retrieves all trailing stops for a user.
type ListTrailingStopsUseCase struct {
	manager TrailingStopManager
	logger  *slog.Logger
}

// NewListTrailingStopsUseCase creates a ListTrailingStopsUseCase with dependencies injected.
func NewListTrailingStopsUseCase(manager TrailingStopManager, logger *slog.Logger) *ListTrailingStopsUseCase {
	return &ListTrailingStopsUseCase{manager: manager, logger: logger}
}

// Execute retrieves all trailing stops for the user.
func (uc *ListTrailingStopsUseCase) Execute(ctx context.Context, query cqrs.ListTrailingStopsQuery) ([]*alerts.TrailingStop, error) {
	if query.Email == "" {
		return nil, fmt.Errorf("usecases: email is required")
	}

	return uc.manager.List(query.Email), nil
}

// --- Cancel Trailing Stop ---

// CancelTrailingStopUseCase deactivates a trailing stop.
type CancelTrailingStopUseCase struct {
	manager    TrailingStopManager
	eventStore EventAppender
	logger     *slog.Logger
}

// NewCancelTrailingStopUseCase creates a CancelTrailingStopUseCase with dependencies injected.
func NewCancelTrailingStopUseCase(manager TrailingStopManager, logger *slog.Logger) *CancelTrailingStopUseCase {
	return &CancelTrailingStopUseCase{manager: manager, logger: logger}
}

// SetEventStore opts the use case into event-sourced audit. nil disables.
func (uc *CancelTrailingStopUseCase) SetEventStore(s EventAppender) { uc.eventStore = s }

// Execute cancels a trailing stop.
func (uc *CancelTrailingStopUseCase) Execute(ctx context.Context, cmd cqrs.CancelTrailingStopCommand) error {
	if cmd.Email == "" {
		return fmt.Errorf("usecases: email is required")
	}
	if cmd.TrailingStopID == "" {
		return fmt.Errorf("usecases: trailing_stop_id is required")
	}

	if err := uc.manager.Cancel(cmd.Email, cmd.TrailingStopID); err != nil {
		uc.logger.Error("Failed to cancel trailing stop", "email", cmd.Email, "id", cmd.TrailingStopID, "error", err)
		return fmt.Errorf("usecases: cancel trailing stop: %w", err)
	}

	appendAuxEvent(uc.eventStore, uc.logger, "TrailingStop", cmd.TrailingStopID, "trailing_stop.cancelled", map[string]any{
		"email":            cmd.Email,
		"trailing_stop_id": cmd.TrailingStopID,
	})

	return nil
}
