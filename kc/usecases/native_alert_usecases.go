package usecases

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/zerodha/kite-mcp-server/kc/cqrs"
)

// NativeAlertClient abstracts the Kite alert API for use cases.
type NativeAlertClient interface {
	CreateAlert(params any) (any, error)
	ModifyAlert(uuid string, params any) (any, error)
	DeleteAlerts(uuids ...string) error
	GetAlerts(filters map[string]string) (any, error)
	GetAlertHistory(uuid string) (any, error)
}

// --- Place Native Alert ---

// PlaceNativeAlertUseCase creates a server-side alert at Zerodha.
type PlaceNativeAlertUseCase struct {
	eventStore EventAppender
	logger     *slog.Logger
}

// NewPlaceNativeAlertUseCase creates a PlaceNativeAlertUseCase with dependencies injected.
func NewPlaceNativeAlertUseCase(logger *slog.Logger) *PlaceNativeAlertUseCase {
	return &PlaceNativeAlertUseCase{logger: logger}
}

// SetEventStore opts the use case into event-sourced audit. nil disables.
func (uc *PlaceNativeAlertUseCase) SetEventStore(s EventAppender) { uc.eventStore = s }

// Execute creates a native alert via the provided client.
func (uc *PlaceNativeAlertUseCase) Execute(ctx context.Context, client NativeAlertClient, cmd cqrs.PlaceNativeAlertCommand) (any, error) {
	if cmd.Email == "" {
		return nil, fmt.Errorf("usecases: email is required")
	}

	result, err := client.CreateAlert(cmd.Params)
	if err != nil {
		uc.logger.Error("Failed to create native alert", "email", cmd.Email, "error", err)
		return nil, fmt.Errorf("usecases: create native alert: %w", err)
	}

	// Aggregate ID is the email (the broker assigns the alert UUID lazily;
	// we don't always see it in the immediate response). Multiple
	// native_alert.placed events for one user is normal.
	appendAuxEvent(uc.eventStore, uc.logger, "NativeAlert", cmd.Email, "native_alert.placed", map[string]any{
		"email": cmd.Email,
	})

	return result, nil
}

// --- List Native Alerts ---

// ListNativeAlertsUseCase lists all native alerts.
type ListNativeAlertsUseCase struct {
	logger *slog.Logger
}

// NewListNativeAlertsUseCase creates a ListNativeAlertsUseCase with dependencies injected.
func NewListNativeAlertsUseCase(logger *slog.Logger) *ListNativeAlertsUseCase {
	return &ListNativeAlertsUseCase{logger: logger}
}

// Execute lists native alerts.
func (uc *ListNativeAlertsUseCase) Execute(ctx context.Context, client NativeAlertClient, query cqrs.ListNativeAlertsQuery) (any, error) {
	if query.Email == "" {
		return nil, fmt.Errorf("usecases: email is required")
	}

	alerts, err := client.GetAlerts(query.Filters)
	if err != nil {
		uc.logger.Error("Failed to list native alerts", "email", query.Email, "error", err)
		return nil, fmt.Errorf("usecases: list native alerts: %w", err)
	}

	return alerts, nil
}

// --- Modify Native Alert ---

// ModifyNativeAlertUseCase modifies an existing native alert.
type ModifyNativeAlertUseCase struct {
	eventStore EventAppender
	logger     *slog.Logger
}

// NewModifyNativeAlertUseCase creates a ModifyNativeAlertUseCase with dependencies injected.
func NewModifyNativeAlertUseCase(logger *slog.Logger) *ModifyNativeAlertUseCase {
	return &ModifyNativeAlertUseCase{logger: logger}
}

// SetEventStore opts the use case into event-sourced audit. nil disables.
func (uc *ModifyNativeAlertUseCase) SetEventStore(s EventAppender) { uc.eventStore = s }

// Execute modifies a native alert.
func (uc *ModifyNativeAlertUseCase) Execute(ctx context.Context, client NativeAlertClient, cmd cqrs.ModifyNativeAlertCommand) (any, error) {
	if cmd.Email == "" {
		return nil, fmt.Errorf("usecases: email is required")
	}
	if cmd.UUID == "" {
		return nil, fmt.Errorf("usecases: uuid is required")
	}

	result, err := client.ModifyAlert(cmd.UUID, cmd.Params)
	if err != nil {
		uc.logger.Error("Failed to modify native alert", "email", cmd.Email, "uuid", cmd.UUID, "error", err)
		return nil, fmt.Errorf("usecases: modify native alert: %w", err)
	}

	appendAuxEvent(uc.eventStore, uc.logger, "NativeAlert", cmd.UUID, "native_alert.modified", map[string]any{
		"email": cmd.Email,
		"uuid":  cmd.UUID,
	})

	return result, nil
}

// --- Delete Native Alert ---

// DeleteNativeAlertUseCase deletes one or more native alerts.
type DeleteNativeAlertUseCase struct {
	eventStore EventAppender
	logger     *slog.Logger
}

// NewDeleteNativeAlertUseCase creates a DeleteNativeAlertUseCase with dependencies injected.
func NewDeleteNativeAlertUseCase(logger *slog.Logger) *DeleteNativeAlertUseCase {
	return &DeleteNativeAlertUseCase{logger: logger}
}

// SetEventStore opts the use case into event-sourced audit. nil disables.
func (uc *DeleteNativeAlertUseCase) SetEventStore(s EventAppender) { uc.eventStore = s }

// Execute deletes native alert(s).
func (uc *DeleteNativeAlertUseCase) Execute(ctx context.Context, client NativeAlertClient, cmd cqrs.DeleteNativeAlertCommand) error {
	if cmd.Email == "" {
		return fmt.Errorf("usecases: email is required")
	}
	if len(cmd.UUIDs) == 0 {
		return fmt.Errorf("usecases: at least one uuid is required")
	}

	if err := client.DeleteAlerts(cmd.UUIDs...); err != nil {
		uc.logger.Error("Failed to delete native alert(s)", "email", cmd.Email, "uuids", cmd.UUIDs, "error", err)
		return fmt.Errorf("usecases: delete native alert: %w", err)
	}

	// One event per UUID so the per-aggregate replay stream stays clean.
	for _, uuid := range cmd.UUIDs {
		appendAuxEvent(uc.eventStore, uc.logger, "NativeAlert", uuid, "native_alert.deleted", map[string]any{
			"email": cmd.Email,
			"uuid":  uuid,
		})
	}

	return nil
}

// --- Get Native Alert History ---

// GetNativeAlertHistoryUseCase retrieves trigger history for a native alert.
type GetNativeAlertHistoryUseCase struct {
	logger *slog.Logger
}

// NewGetNativeAlertHistoryUseCase creates a GetNativeAlertHistoryUseCase with dependencies injected.
func NewGetNativeAlertHistoryUseCase(logger *slog.Logger) *GetNativeAlertHistoryUseCase {
	return &GetNativeAlertHistoryUseCase{logger: logger}
}

// Execute retrieves alert history.
func (uc *GetNativeAlertHistoryUseCase) Execute(ctx context.Context, client NativeAlertClient, query cqrs.GetNativeAlertHistoryQuery) (any, error) {
	if query.Email == "" {
		return nil, fmt.Errorf("usecases: email is required")
	}
	if query.UUID == "" {
		return nil, fmt.Errorf("usecases: uuid is required")
	}

	history, err := client.GetAlertHistory(query.UUID)
	if err != nil {
		uc.logger.Error("Failed to get native alert history", "email", query.Email, "uuid", query.UUID, "error", err)
		return nil, fmt.Errorf("usecases: get native alert history: %w", err)
	}

	return history, nil
}
