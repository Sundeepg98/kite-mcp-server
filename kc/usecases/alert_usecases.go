package usecases

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
)

// AlertReader abstracts alert read/delete operations for use cases.
type AlertReader interface {
	List(email string) []*alerts.Alert
	Delete(email, alertID string) error
}

// --- List Alerts ---

// ListAlertsUseCase retrieves all alerts for a user.
type ListAlertsUseCase struct {
	store  AlertReader
	logger *slog.Logger
}

// NewListAlertsUseCase creates a ListAlertsUseCase with dependencies injected.
func NewListAlertsUseCase(store AlertReader, logger *slog.Logger) *ListAlertsUseCase {
	return &ListAlertsUseCase{store: store, logger: logger}
}

// Execute retrieves all alerts for the given user.
func (uc *ListAlertsUseCase) Execute(ctx context.Context, query cqrs.GetAlertsQuery) ([]*alerts.Alert, error) {
	if query.Email == "" {
		return nil, fmt.Errorf("usecases: email is required")
	}
	return uc.store.List(query.Email), nil
}

// --- Delete Alert ---

// DeleteAlertUseCase deletes a specific alert.
type DeleteAlertUseCase struct {
	store  AlertReader
	logger *slog.Logger
}

// NewDeleteAlertUseCase creates a DeleteAlertUseCase with dependencies injected.
func NewDeleteAlertUseCase(store AlertReader, logger *slog.Logger) *DeleteAlertUseCase {
	return &DeleteAlertUseCase{store: store, logger: logger}
}

// Execute deletes an alert by ID.
func (uc *DeleteAlertUseCase) Execute(ctx context.Context, cmd cqrs.DeleteAlertCommand) error {
	if cmd.Email == "" {
		return fmt.Errorf("usecases: email is required")
	}
	if cmd.AlertID == "" {
		return fmt.Errorf("usecases: alert_id is required")
	}
	if err := uc.store.Delete(cmd.Email, cmd.AlertID); err != nil {
		uc.logger.Error("Failed to delete alert", "email", cmd.Email, "alert_id", cmd.AlertID, "error", err)
		return fmt.Errorf("usecases: delete alert: %w", err)
	}
	return nil
}
