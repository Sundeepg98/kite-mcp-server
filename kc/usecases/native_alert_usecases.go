package usecases

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	logport "github.com/zerodha/kite-mcp-server/kc/logger"
)

// Wave D Phase 3 Package 5 (Logger sweep): use cases in this file
// type their logger field as the kc/logger.Logger port; constructors
// retain *slog.Logger and convert via logport.NewSlog.

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
	events     *domain.EventDispatcher
	logger     logport.Logger
}

// NewPlaceNativeAlertUseCase creates a PlaceNativeAlertUseCase with dependencies injected.
func NewPlaceNativeAlertUseCase(logger *slog.Logger) *PlaceNativeAlertUseCase {
	return &PlaceNativeAlertUseCase{logger: logport.NewSlog(logger)}
}

// SetEventStore opts the use case into event-sourced audit. nil disables.
func (uc *PlaceNativeAlertUseCase) SetEventStore(s EventAppender) { uc.eventStore = s }

// SetEventDispatcher wires the typed domain event dispatcher so
// successful placement emits NativeAlertPlacedEvent. Nil-safe.
func (uc *PlaceNativeAlertUseCase) SetEventDispatcher(d *domain.EventDispatcher) { uc.events = d }

// Execute creates a native alert via the provided client.
func (uc *PlaceNativeAlertUseCase) Execute(ctx context.Context, client NativeAlertClient, cmd cqrs.PlaceNativeAlertCommand) (any, error) {
	if cmd.Email == "" {
		return nil, fmt.Errorf("usecases: email is required")
	}

	result, err := client.CreateAlert(cmd.Params)
	if err != nil {
		uc.logger.Error(ctx, "Failed to create native alert", err, "email", cmd.Email)
		return nil, fmt.Errorf("usecases: create native alert: %w", err)
	}

	// ES post-migration: typed event only. Persister in wire.go
	// handles audit-row write. UUID is empty here — the broker
	// assigns it lazily and the use case doesn't always see it in
	// the immediate response. Multiple native_alert.placed events
	// for one user is normal — aggregate ID falls back to email
	// when UUID is empty (NativeAlertAggregateID).
	if uc.events != nil {
		uc.events.Dispatch(domain.NativeAlertPlacedEvent{
			Email:     cmd.Email,
			Timestamp: time.Now().UTC(),
		})
	}

	return result, nil
}

// --- List Native Alerts ---

// ListNativeAlertsUseCase lists all native alerts.
type ListNativeAlertsUseCase struct {
	logger logport.Logger
}

// NewListNativeAlertsUseCase creates a ListNativeAlertsUseCase with dependencies injected.
func NewListNativeAlertsUseCase(logger *slog.Logger) *ListNativeAlertsUseCase {
	return &ListNativeAlertsUseCase{logger: logport.NewSlog(logger)}
}

// Execute lists native alerts.
func (uc *ListNativeAlertsUseCase) Execute(ctx context.Context, client NativeAlertClient, query cqrs.ListNativeAlertsQuery) (any, error) {
	if query.Email == "" {
		return nil, fmt.Errorf("usecases: email is required")
	}

	alerts, err := client.GetAlerts(query.Filters)
	if err != nil {
		uc.logger.Error(ctx, "Failed to list native alerts", err, "email", query.Email)
		return nil, fmt.Errorf("usecases: list native alerts: %w", err)
	}

	return alerts, nil
}

// --- Modify Native Alert ---

// ModifyNativeAlertUseCase modifies an existing native alert.
type ModifyNativeAlertUseCase struct {
	eventStore EventAppender
	events     *domain.EventDispatcher
	logger     logport.Logger
}

// NewModifyNativeAlertUseCase creates a ModifyNativeAlertUseCase with dependencies injected.
func NewModifyNativeAlertUseCase(logger *slog.Logger) *ModifyNativeAlertUseCase {
	return &ModifyNativeAlertUseCase{logger: logport.NewSlog(logger)}
}

// SetEventStore opts the use case into event-sourced audit. nil disables.
func (uc *ModifyNativeAlertUseCase) SetEventStore(s EventAppender) { uc.eventStore = s }

// SetEventDispatcher wires the typed domain event dispatcher so
// successful modification emits NativeAlertModifiedEvent. Nil-safe.
func (uc *ModifyNativeAlertUseCase) SetEventDispatcher(d *domain.EventDispatcher) { uc.events = d }

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
		uc.logger.Error(ctx, "Failed to modify native alert", err, "email", cmd.Email, "uuid", cmd.UUID)
		return nil, fmt.Errorf("usecases: modify native alert: %w", err)
	}

	// ES post-migration: typed event only. Persister in wire.go
	// handles audit-row write.
	if uc.events != nil {
		uc.events.Dispatch(domain.NativeAlertModifiedEvent{
			Email:     cmd.Email,
			UUID:      cmd.UUID,
			Timestamp: time.Now().UTC(),
		})
	}

	return result, nil
}

// --- Delete Native Alert ---

// DeleteNativeAlertUseCase deletes one or more native alerts.
type DeleteNativeAlertUseCase struct {
	eventStore EventAppender
	events     *domain.EventDispatcher
	logger     logport.Logger
}

// NewDeleteNativeAlertUseCase creates a DeleteNativeAlertUseCase with dependencies injected.
func NewDeleteNativeAlertUseCase(logger *slog.Logger) *DeleteNativeAlertUseCase {
	return &DeleteNativeAlertUseCase{logger: logport.NewSlog(logger)}
}

// SetEventStore opts the use case into event-sourced audit. nil disables.
func (uc *DeleteNativeAlertUseCase) SetEventStore(s EventAppender) { uc.eventStore = s }

// SetEventDispatcher wires the typed domain event dispatcher so
// successful deletion emits NativeAlertDeletedEvent (one per UUID).
// Nil-safe.
func (uc *DeleteNativeAlertUseCase) SetEventDispatcher(d *domain.EventDispatcher) { uc.events = d }

// Execute deletes native alert(s).
func (uc *DeleteNativeAlertUseCase) Execute(ctx context.Context, client NativeAlertClient, cmd cqrs.DeleteNativeAlertCommand) error {
	if cmd.Email == "" {
		return fmt.Errorf("usecases: email is required")
	}
	if len(cmd.UUIDs) == 0 {
		return fmt.Errorf("usecases: at least one uuid is required")
	}

	if err := client.DeleteAlerts(cmd.UUIDs...); err != nil {
		uc.logger.Error(ctx, "Failed to delete native alert(s)", err, "email", cmd.Email, "uuids", cmd.UUIDs)
		return fmt.Errorf("usecases: delete native alert: %w", err)
	}

	// One event per UUID so the per-aggregate replay stream stays
	// clean. ES post-migration: typed event only. Persister in
	// wire.go handles audit-row write.
	now := time.Now().UTC()
	for _, uuid := range cmd.UUIDs {
		if uc.events != nil {
			uc.events.Dispatch(domain.NativeAlertDeletedEvent{
				Email:     cmd.Email,
				UUID:      uuid,
				Timestamp: now,
			})
		}
	}

	return nil
}

// --- Get Native Alert History ---

// GetNativeAlertHistoryUseCase retrieves trigger history for a native alert.
type GetNativeAlertHistoryUseCase struct {
	logger logport.Logger
}

// NewGetNativeAlertHistoryUseCase creates a GetNativeAlertHistoryUseCase with dependencies injected.
func NewGetNativeAlertHistoryUseCase(logger *slog.Logger) *GetNativeAlertHistoryUseCase {
	return &GetNativeAlertHistoryUseCase{logger: logport.NewSlog(logger)}
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
		uc.logger.Error(ctx, "Failed to get native alert history", err, "email", query.Email, "uuid", query.UUID)
		return nil, fmt.Errorf("usecases: get native alert history: %w", err)
	}

	return history, nil
}
