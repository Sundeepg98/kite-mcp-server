package usecases

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	logport "github.com/zerodha/kite-mcp-server/kc/logger"
)

// Wave D Phase 3 Package 5c (Logger sweep): GTT use cases in this
// file type their logger field as the kc/logger.Logger port;
// constructors retain *slog.Logger and convert via logport.NewSlog.

// dispatchGTTRejection emits a typed GTTRejectedEvent for the three
// GTT mutation surfaces (place, modify, delete). Centralised so the
// payload shape stays consistent across call sites; nil-safe.
func dispatchGTTRejection(events *domain.EventDispatcher, email string, triggerID int, source, reason string) {
	if events == nil {
		return
	}
	events.Dispatch(domain.GTTRejectedEvent{
		Email:     email,
		TriggerID: triggerID,
		Source:    source,
		Reason:    reason,
		Timestamp: time.Now().UTC(),
	})
}

// --- GTT query ---

// GetGTTsUseCase retrieves all GTT orders for a user.
type GetGTTsUseCase struct {
	brokerResolver BrokerResolver
	logger         logport.Logger
}

// NewGetGTTsUseCase creates a GetGTTsUseCase with all dependencies injected.
func NewGetGTTsUseCase(resolver BrokerResolver, logger *slog.Logger) *GetGTTsUseCase {
	return &GetGTTsUseCase{
		brokerResolver: resolver,
		logger:         logport.NewSlog(logger),
	}
}

// Execute retrieves all GTT orders for the user.
func (uc *GetGTTsUseCase) Execute(ctx context.Context, query cqrs.GetGTTsQuery) ([]broker.GTTOrder, error) {
	if query.Email == "" {
		return nil, fmt.Errorf("usecases: email is required")
	}

	client, err := uc.brokerResolver.GetBrokerForEmail(query.Email)
	if err != nil {
		return nil, fmt.Errorf("usecases: resolve broker: %w", err)
	}

	gtts, err := client.GetGTTs()
	if err != nil {
		uc.logger.Error(ctx, "Failed to get GTTs", err, "email", query.Email)
		return nil, fmt.Errorf("usecases: get gtts: %w", err)
	}

	return gtts, nil
}

// --- GTT commands ---

// PlaceGTTUseCase orchestrates GTT order placement.
type PlaceGTTUseCase struct {
	brokerResolver BrokerResolver
	eventStore     EventAppender
	events         *domain.EventDispatcher
	logger         logport.Logger
}

// NewPlaceGTTUseCase creates a PlaceGTTUseCase with all dependencies injected.
func NewPlaceGTTUseCase(resolver BrokerResolver, logger *slog.Logger) *PlaceGTTUseCase {
	return &PlaceGTTUseCase{
		brokerResolver: resolver,
		logger:         logport.NewSlog(logger),
	}
}

// SetEventStore opts the use case into event-sourced audit. nil disables.
func (uc *PlaceGTTUseCase) SetEventStore(s EventAppender) { uc.eventStore = s }

// SetEventDispatcher wires the typed domain event dispatcher so broker
// failures emit GTTRejectedEvent. Nil-safe.
func (uc *PlaceGTTUseCase) SetEventDispatcher(d *domain.EventDispatcher) { uc.events = d }

// Execute places a GTT order and returns the trigger ID.
func (uc *PlaceGTTUseCase) Execute(ctx context.Context, cmd cqrs.PlaceGTTCommand) (broker.GTTResponse, error) {
	if cmd.Email == "" {
		return broker.GTTResponse{}, fmt.Errorf("usecases: email is required")
	}
	if cmd.Instrument.Tradingsymbol == "" {
		return broker.GTTResponse{}, fmt.Errorf("usecases: tradingsymbol is required")
	}
	if cmd.Type != "single" && cmd.Type != "two-leg" {
		return broker.GTTResponse{}, fmt.Errorf("usecases: invalid GTT type: %q", cmd.Type)
	}

	if cmd.Type == "single" {
		if _, qerr := domain.NewQuantity(int(cmd.Quantity)); qerr != nil {
			return broker.GTTResponse{}, fmt.Errorf("usecases: gtt quantity: %w", qerr)
		}
	} else {
		if _, qerr := domain.NewQuantity(int(cmd.UpperQuantity)); qerr != nil {
			return broker.GTTResponse{}, fmt.Errorf("usecases: gtt upper quantity: %w", qerr)
		}
		if _, qerr := domain.NewQuantity(int(cmd.LowerQuantity)); qerr != nil {
			return broker.GTTResponse{}, fmt.Errorf("usecases: gtt lower quantity: %w", qerr)
		}
	}

	client, err := uc.brokerResolver.GetBrokerForEmail(cmd.Email)
	if err != nil {
		return broker.GTTResponse{}, fmt.Errorf("usecases: resolve broker: %w", err)
	}

	params := broker.GTTParams{
		Exchange:          cmd.Instrument.Exchange,
		Tradingsymbol:     cmd.Instrument.Tradingsymbol,
		LastPrice:         cmd.LastPrice.Amount,
		TransactionType:   cmd.TransactionType,
		Product:           cmd.Product,
		Type:              cmd.Type,
		TriggerValue:      cmd.TriggerValue,
		Quantity:          cmd.Quantity,
		LimitPrice:        cmd.LimitPrice.Amount,
		UpperTriggerValue: cmd.UpperTriggerValue,
		UpperQuantity:     cmd.UpperQuantity,
		UpperLimitPrice:   cmd.UpperLimitPrice.Amount,
		LowerTriggerValue: cmd.LowerTriggerValue,
		LowerQuantity:     cmd.LowerQuantity,
		LowerLimitPrice:   cmd.LowerLimitPrice.Amount,
	}

	resp, err := client.PlaceGTT(params)
	if err != nil {
		uc.logger.Error(ctx, "Failed to place GTT order", err, "email", cmd.Email)
		// ES: typed rejection event. TriggerID=0 since broker never
		// assigned one; aggregate ID falls back to synthetic key.
		dispatchGTTRejection(uc.events, cmd.Email, 0, "place", err.Error())
		return broker.GTTResponse{}, fmt.Errorf("usecases: place gtt: %w", err)
	}

	uc.logger.Info(ctx, "GTT order placed",
		"email", cmd.Email,
		"trigger_id", resp.TriggerID,
		"tradingsymbol", cmd.Instrument.Tradingsymbol,
		"type", cmd.Type,
	)

	// ES post-migration: typed event only. Persister in wire.go
	// handles audit-row write (with EmailHash for PII correlation).
	if uc.events != nil {
		uc.events.Dispatch(domain.GTTPlacedEvent{
			Email:             cmd.Email,
			TriggerID:         resp.TriggerID,
			Instrument:        cmd.Instrument,
			TransactionType:   cmd.TransactionType,
			Product:           cmd.Product,
			Type:              cmd.Type,
			TriggerValue:      cmd.TriggerValue,
			Quantity:          cmd.Quantity,
			LimitPrice:        cmd.LimitPrice.Amount,
			UpperTriggerValue: cmd.UpperTriggerValue,
			UpperQuantity:     cmd.UpperQuantity,
			UpperLimitPrice:   cmd.UpperLimitPrice.Amount,
			LowerTriggerValue: cmd.LowerTriggerValue,
			LowerQuantity:     cmd.LowerQuantity,
			LowerLimitPrice:   cmd.LowerLimitPrice.Amount,
			Timestamp:         time.Now().UTC(),
		})
	}

	return resp, nil
}

// ModifyGTTUseCase orchestrates GTT order modification.
type ModifyGTTUseCase struct {
	brokerResolver BrokerResolver
	eventStore     EventAppender
	events         *domain.EventDispatcher
	logger         logport.Logger
}

// NewModifyGTTUseCase creates a ModifyGTTUseCase with all dependencies injected.
func NewModifyGTTUseCase(resolver BrokerResolver, logger *slog.Logger) *ModifyGTTUseCase {
	return &ModifyGTTUseCase{
		brokerResolver: resolver,
		logger:         logport.NewSlog(logger),
	}
}

// SetEventStore opts the use case into event-sourced audit. nil disables.
func (uc *ModifyGTTUseCase) SetEventStore(s EventAppender) { uc.eventStore = s }

// SetEventDispatcher wires the typed domain event dispatcher so broker
// failures emit GTTRejectedEvent. Nil-safe.
func (uc *ModifyGTTUseCase) SetEventDispatcher(d *domain.EventDispatcher) { uc.events = d }

// Execute modifies a GTT order and returns the trigger ID.
func (uc *ModifyGTTUseCase) Execute(ctx context.Context, cmd cqrs.ModifyGTTCommand) (broker.GTTResponse, error) {
	if cmd.Email == "" {
		return broker.GTTResponse{}, fmt.Errorf("usecases: email is required")
	}
	if cmd.TriggerID == 0 {
		return broker.GTTResponse{}, fmt.Errorf("usecases: trigger_id is required")
	}
	if cmd.Type != "single" && cmd.Type != "two-leg" {
		return broker.GTTResponse{}, fmt.Errorf("usecases: invalid GTT type: %q", cmd.Type)
	}

	if cmd.Type == "single" {
		if _, qerr := domain.NewQuantity(int(cmd.Quantity)); qerr != nil {
			return broker.GTTResponse{}, fmt.Errorf("usecases: gtt quantity: %w", qerr)
		}
	} else {
		if _, qerr := domain.NewQuantity(int(cmd.UpperQuantity)); qerr != nil {
			return broker.GTTResponse{}, fmt.Errorf("usecases: gtt upper quantity: %w", qerr)
		}
		if _, qerr := domain.NewQuantity(int(cmd.LowerQuantity)); qerr != nil {
			return broker.GTTResponse{}, fmt.Errorf("usecases: gtt lower quantity: %w", qerr)
		}
	}

	client, err := uc.brokerResolver.GetBrokerForEmail(cmd.Email)
	if err != nil {
		return broker.GTTResponse{}, fmt.Errorf("usecases: resolve broker: %w", err)
	}

	params := broker.GTTParams{
		Exchange:          cmd.Instrument.Exchange,
		Tradingsymbol:     cmd.Instrument.Tradingsymbol,
		LastPrice:         cmd.LastPrice.Amount,
		TransactionType:   cmd.TransactionType,
		Product:           cmd.Product,
		Type:              cmd.Type,
		TriggerValue:      cmd.TriggerValue,
		Quantity:          cmd.Quantity,
		LimitPrice:        cmd.LimitPrice.Amount,
		UpperTriggerValue: cmd.UpperTriggerValue,
		UpperQuantity:     cmd.UpperQuantity,
		UpperLimitPrice:   cmd.UpperLimitPrice.Amount,
		LowerTriggerValue: cmd.LowerTriggerValue,
		LowerQuantity:     cmd.LowerQuantity,
		LowerLimitPrice:   cmd.LowerLimitPrice.Amount,
	}

	resp, err := client.ModifyGTT(cmd.TriggerID, params)
	if err != nil {
		uc.logger.Error(ctx, "Failed to modify GTT order", err, "email", cmd.Email, "trigger_id", cmd.TriggerID)
		// ES: rejection joins the existing GTT aggregate stream via TriggerID.
		dispatchGTTRejection(uc.events, cmd.Email, cmd.TriggerID, "modify", err.Error())
		return broker.GTTResponse{}, fmt.Errorf("usecases: modify gtt: %w", err)
	}

	uc.logger.Info(ctx, "GTT order modified",
		"email", cmd.Email,
		"trigger_id", cmd.TriggerID,
		"tradingsymbol", cmd.Instrument.Tradingsymbol,
	)

	// ES post-migration: typed event only. Persister in wire.go
	// handles audit-row write.
	if uc.events != nil {
		uc.events.Dispatch(domain.GTTModifiedEvent{
			Email:             cmd.Email,
			TriggerID:         cmd.TriggerID,
			Instrument:        cmd.Instrument,
			TransactionType:   cmd.TransactionType,
			Product:           cmd.Product,
			Type:              cmd.Type,
			TriggerValue:      cmd.TriggerValue,
			Quantity:          cmd.Quantity,
			LimitPrice:        cmd.LimitPrice.Amount,
			UpperTriggerValue: cmd.UpperTriggerValue,
			UpperQuantity:     cmd.UpperQuantity,
			UpperLimitPrice:   cmd.UpperLimitPrice.Amount,
			LowerTriggerValue: cmd.LowerTriggerValue,
			LowerQuantity:     cmd.LowerQuantity,
			LowerLimitPrice:   cmd.LowerLimitPrice.Amount,
			Timestamp:         time.Now().UTC(),
		})
	}

	return resp, nil
}

// DeleteGTTUseCase orchestrates GTT order deletion.
type DeleteGTTUseCase struct {
	brokerResolver BrokerResolver
	eventStore     EventAppender
	events         *domain.EventDispatcher
	logger         logport.Logger
}

// NewDeleteGTTUseCase creates a DeleteGTTUseCase with all dependencies injected.
func NewDeleteGTTUseCase(resolver BrokerResolver, logger *slog.Logger) *DeleteGTTUseCase {
	return &DeleteGTTUseCase{
		brokerResolver: resolver,
		logger:         logport.NewSlog(logger),
	}
}

// SetEventStore opts the use case into event-sourced audit. nil disables.
func (uc *DeleteGTTUseCase) SetEventStore(s EventAppender) { uc.eventStore = s }

// SetEventDispatcher wires the typed domain event dispatcher so broker
// failures emit GTTRejectedEvent. Nil-safe.
func (uc *DeleteGTTUseCase) SetEventDispatcher(d *domain.EventDispatcher) { uc.events = d }

// Execute deletes a GTT order.
func (uc *DeleteGTTUseCase) Execute(ctx context.Context, cmd cqrs.DeleteGTTCommand) (broker.GTTResponse, error) {
	if cmd.Email == "" {
		return broker.GTTResponse{}, fmt.Errorf("usecases: email is required")
	}
	if cmd.TriggerID == 0 {
		return broker.GTTResponse{}, fmt.Errorf("usecases: trigger_id is required")
	}

	client, err := uc.brokerResolver.GetBrokerForEmail(cmd.Email)
	if err != nil {
		return broker.GTTResponse{}, fmt.Errorf("usecases: resolve broker: %w", err)
	}

	resp, err := client.DeleteGTT(cmd.TriggerID)
	if err != nil {
		uc.logger.Error(ctx, "Failed to delete GTT order", err, "email", cmd.Email, "trigger_id", cmd.TriggerID)
		// ES: rejection joins the existing GTT aggregate stream via TriggerID.
		dispatchGTTRejection(uc.events, cmd.Email, cmd.TriggerID, "delete", err.Error())
		return broker.GTTResponse{}, fmt.Errorf("usecases: delete gtt: %w", err)
	}

	uc.logger.Info(ctx, "GTT order deleted",
		"email", cmd.Email,
		"trigger_id", cmd.TriggerID,
	)

	// ES post-migration: typed event only. Persister in wire.go
	// handles audit-row write.
	if uc.events != nil {
		uc.events.Dispatch(domain.GTTDeletedEvent{
			Email:     cmd.Email,
			TriggerID: cmd.TriggerID,
			Timestamp: time.Now().UTC(),
		})
	}

	return resp, nil
}
