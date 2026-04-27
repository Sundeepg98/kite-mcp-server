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

// dispatchMFRejection emits a typed MFOrderRejectedEvent for the four
// MF mutation surfaces (place_order, cancel_order, place_sip,
// cancel_sip). Centralised so payload shape stays consistent across
// call sites; nil-safe — bootstrap / tests without a wired dispatcher
// skip silently.
func dispatchMFRejection(events *domain.EventDispatcher, email, orderID, source, reason string) {
	if events == nil {
		return
	}
	events.Dispatch(domain.MFOrderRejectedEvent{
		Email:     email,
		OrderID:   orderID,
		Source:    source,
		Reason:    reason,
		Timestamp: time.Now().UTC(),
	})
}

// --- MF Query Use Cases ---

// GetMFOrdersUseCase retrieves all mutual fund orders.
type GetMFOrdersUseCase struct {
	brokerResolver BrokerResolver
	logger         *slog.Logger
}

func NewGetMFOrdersUseCase(resolver BrokerResolver, logger *slog.Logger) *GetMFOrdersUseCase {
	return &GetMFOrdersUseCase{brokerResolver: resolver, logger: logger}
}

func (uc *GetMFOrdersUseCase) Execute(ctx context.Context, query cqrs.GetMFOrdersQuery) ([]broker.MFOrder, error) {
	if query.Email == "" {
		return nil, fmt.Errorf("usecases: email is required")
	}

	client, err := uc.brokerResolver.GetBrokerForEmail(query.Email)
	if err != nil {
		return nil, fmt.Errorf("usecases: resolve broker: %w", err)
	}

	orders, err := client.GetMFOrders()
	if err != nil {
		uc.logger.Error("Failed to get MF orders", "email", query.Email, "error", err)
		return nil, fmt.Errorf("usecases: get mf orders: %w", err)
	}

	return orders, nil
}

// GetMFSIPsUseCase retrieves all mutual fund SIPs.
type GetMFSIPsUseCase struct {
	brokerResolver BrokerResolver
	logger         *slog.Logger
}

func NewGetMFSIPsUseCase(resolver BrokerResolver, logger *slog.Logger) *GetMFSIPsUseCase {
	return &GetMFSIPsUseCase{brokerResolver: resolver, logger: logger}
}

func (uc *GetMFSIPsUseCase) Execute(ctx context.Context, query cqrs.GetMFSIPsQuery) ([]broker.MFSIP, error) {
	if query.Email == "" {
		return nil, fmt.Errorf("usecases: email is required")
	}

	client, err := uc.brokerResolver.GetBrokerForEmail(query.Email)
	if err != nil {
		return nil, fmt.Errorf("usecases: resolve broker: %w", err)
	}

	sips, err := client.GetMFSIPs()
	if err != nil {
		uc.logger.Error("Failed to get MF SIPs", "email", query.Email, "error", err)
		return nil, fmt.Errorf("usecases: get mf sips: %w", err)
	}

	return sips, nil
}

// GetMFHoldingsUseCase retrieves all mutual fund holdings.
type GetMFHoldingsUseCase struct {
	brokerResolver BrokerResolver
	logger         *slog.Logger
}

func NewGetMFHoldingsUseCase(resolver BrokerResolver, logger *slog.Logger) *GetMFHoldingsUseCase {
	return &GetMFHoldingsUseCase{brokerResolver: resolver, logger: logger}
}

func (uc *GetMFHoldingsUseCase) Execute(ctx context.Context, query cqrs.GetMFHoldingsQuery) ([]broker.MFHolding, error) {
	if query.Email == "" {
		return nil, fmt.Errorf("usecases: email is required")
	}

	client, err := uc.brokerResolver.GetBrokerForEmail(query.Email)
	if err != nil {
		return nil, fmt.Errorf("usecases: resolve broker: %w", err)
	}

	holdings, err := client.GetMFHoldings()
	if err != nil {
		uc.logger.Error("Failed to get MF holdings", "email", query.Email, "error", err)
		return nil, fmt.Errorf("usecases: get mf holdings: %w", err)
	}

	return holdings, nil
}

// --- MF Command Use Cases ---

// PlaceMFOrderUseCase places a mutual fund order.
type PlaceMFOrderUseCase struct {
	brokerResolver BrokerResolver
	eventStore     EventAppender
	events         *domain.EventDispatcher
	logger         *slog.Logger
}

func NewPlaceMFOrderUseCase(resolver BrokerResolver, logger *slog.Logger) *PlaceMFOrderUseCase {
	return &PlaceMFOrderUseCase{brokerResolver: resolver, logger: logger}
}

// SetEventStore opts the use case into event-sourced audit. nil disables.
func (uc *PlaceMFOrderUseCase) SetEventStore(s EventAppender) { uc.eventStore = s }

// SetEventDispatcher wires the typed domain event dispatcher so broker
// failures emit MFOrderRejectedEvent. Nil-safe.
func (uc *PlaceMFOrderUseCase) SetEventDispatcher(d *domain.EventDispatcher) { uc.events = d }

func (uc *PlaceMFOrderUseCase) Execute(ctx context.Context, cmd cqrs.PlaceMFOrderCommand) (broker.MFOrderResponse, error) {
	if cmd.Email == "" {
		return broker.MFOrderResponse{}, fmt.Errorf("usecases: email is required")
	}
	if cmd.Tradingsymbol == "" {
		return broker.MFOrderResponse{}, fmt.Errorf("usecases: tradingsymbol is required")
	}

	client, err := uc.brokerResolver.GetBrokerForEmail(cmd.Email)
	if err != nil {
		return broker.MFOrderResponse{}, fmt.Errorf("usecases: resolve broker: %w", err)
	}

	resp, err := client.PlaceMFOrder(broker.MFOrderParams{
		Tradingsymbol:   cmd.Tradingsymbol,
		TransactionType: cmd.TransactionType,
		Amount:          cmd.Amount,
		Quantity:        cmd.Quantity,
		Tag:             cmd.Tag,
	})
	if err != nil {
		uc.logger.Error("Failed to place MF order", "email", cmd.Email, "error", err)
		// ES: typed rejection event so the MF audit stream surfaces the
		// failure path. OrderID is empty — broker never assigned one.
		dispatchMFRejection(uc.events, cmd.Email, "", "place_order", err.Error())
		return broker.MFOrderResponse{}, fmt.Errorf("usecases: place mf order: %w", err)
	}

	uc.logger.Info("MF order placed",
		"email", cmd.Email,
		"tradingsymbol", cmd.Tradingsymbol,
		"transaction_type", cmd.TransactionType,
		"order_id", resp.OrderID,
	)

	// ES post-migration: typed event only. The legacy
	// appendAuxEvent dual-emit was removed in the post-migration
	// cleanup — the persister Subscribe in app/wire.go writes the
	// audit row from this dispatch (with EmailHash for PII
	// correlation, an improvement over the prior aux-event row).
	if uc.events != nil {
		uc.events.Dispatch(domain.MFOrderPlacedEvent{
			Email:           cmd.Email,
			OrderID:         resp.OrderID,
			Tradingsymbol:   cmd.Tradingsymbol,
			TransactionType: cmd.TransactionType,
			Amount:          cmd.Amount,
			Quantity:        cmd.Quantity,
			Tag:             cmd.Tag,
			Timestamp:       time.Now().UTC(),
		})
	}

	return resp, nil
}

// CancelMFOrderUseCase cancels a pending mutual fund order.
type CancelMFOrderUseCase struct {
	brokerResolver BrokerResolver
	eventStore     EventAppender
	events         *domain.EventDispatcher
	logger         *slog.Logger
}

func NewCancelMFOrderUseCase(resolver BrokerResolver, logger *slog.Logger) *CancelMFOrderUseCase {
	return &CancelMFOrderUseCase{brokerResolver: resolver, logger: logger}
}

// SetEventStore opts the use case into event-sourced audit. nil disables.
func (uc *CancelMFOrderUseCase) SetEventStore(s EventAppender) { uc.eventStore = s }

// SetEventDispatcher wires the typed domain event dispatcher so broker
// failures emit MFOrderRejectedEvent. Nil-safe.
func (uc *CancelMFOrderUseCase) SetEventDispatcher(d *domain.EventDispatcher) { uc.events = d }

func (uc *CancelMFOrderUseCase) Execute(ctx context.Context, cmd cqrs.CancelMFOrderCommand) (broker.MFOrderResponse, error) {
	if cmd.Email == "" {
		return broker.MFOrderResponse{}, fmt.Errorf("usecases: email is required")
	}
	if cmd.OrderID == "" {
		return broker.MFOrderResponse{}, fmt.Errorf("usecases: order_id is required")
	}

	client, err := uc.brokerResolver.GetBrokerForEmail(cmd.Email)
	if err != nil {
		return broker.MFOrderResponse{}, fmt.Errorf("usecases: resolve broker: %w", err)
	}

	resp, err := client.CancelMFOrder(cmd.OrderID)
	if err != nil {
		uc.logger.Error("Failed to cancel MF order", "email", cmd.Email, "order_id", cmd.OrderID, "error", err)
		// ES: rejection joins existing MF order aggregate stream via OrderID.
		dispatchMFRejection(uc.events, cmd.Email, cmd.OrderID, "cancel_order", err.Error())
		return broker.MFOrderResponse{}, fmt.Errorf("usecases: cancel mf order: %w", err)
	}

	uc.logger.Info("MF order cancelled", "email", cmd.Email, "order_id", cmd.OrderID)

	// ES post-migration: typed event only. Persister in wire.go
	// handles audit-row write.
	if uc.events != nil {
		uc.events.Dispatch(domain.MFOrderCancelledEvent{
			Email:     cmd.Email,
			OrderID:   cmd.OrderID,
			Timestamp: time.Now().UTC(),
		})
	}

	return resp, nil
}

// PlaceMFSIPUseCase places a new mutual fund SIP.
type PlaceMFSIPUseCase struct {
	brokerResolver BrokerResolver
	eventStore     EventAppender
	events         *domain.EventDispatcher
	logger         *slog.Logger
}

func NewPlaceMFSIPUseCase(resolver BrokerResolver, logger *slog.Logger) *PlaceMFSIPUseCase {
	return &PlaceMFSIPUseCase{brokerResolver: resolver, logger: logger}
}

// SetEventStore opts the use case into event-sourced audit. nil disables.
func (uc *PlaceMFSIPUseCase) SetEventStore(s EventAppender) { uc.eventStore = s }

// SetEventDispatcher wires the typed domain event dispatcher so broker
// failures emit MFOrderRejectedEvent. Nil-safe.
func (uc *PlaceMFSIPUseCase) SetEventDispatcher(d *domain.EventDispatcher) { uc.events = d }

func (uc *PlaceMFSIPUseCase) Execute(ctx context.Context, cmd cqrs.PlaceMFSIPCommand) (broker.MFSIPResponse, error) {
	if cmd.Email == "" {
		return broker.MFSIPResponse{}, fmt.Errorf("usecases: email is required")
	}
	if cmd.Tradingsymbol == "" {
		return broker.MFSIPResponse{}, fmt.Errorf("usecases: tradingsymbol is required")
	}
	if cmd.Amount <= 0 {
		return broker.MFSIPResponse{}, fmt.Errorf("usecases: amount must be positive")
	}

	client, err := uc.brokerResolver.GetBrokerForEmail(cmd.Email)
	if err != nil {
		return broker.MFSIPResponse{}, fmt.Errorf("usecases: resolve broker: %w", err)
	}

	resp, err := client.PlaceMFSIP(broker.MFSIPParams{
		Tradingsymbol: cmd.Tradingsymbol,
		Amount:        cmd.Amount,
		Frequency:     cmd.Frequency,
		Instalments:   cmd.Instalments,
		InitialAmount: cmd.InitialAmount,
		InstalmentDay: cmd.InstalmentDay,
		Tag:           cmd.Tag,
	})
	if err != nil {
		uc.logger.Error("Failed to place MF SIP", "email", cmd.Email, "error", err)
		// ES: SIP rejection — empty OrderID, broker never assigned one.
		dispatchMFRejection(uc.events, cmd.Email, "", "place_sip", err.Error())
		return broker.MFSIPResponse{}, fmt.Errorf("usecases: place mf sip: %w", err)
	}

	uc.logger.Info("MF SIP placed",
		"email", cmd.Email,
		"tradingsymbol", cmd.Tradingsymbol,
		"sip_id", resp.SIPID,
	)

	// ES post-migration: typed event only. Persister in wire.go
	// handles audit-row write.
	if uc.events != nil {
		uc.events.Dispatch(domain.MFSIPPlacedEvent{
			Email:         cmd.Email,
			SIPID:         resp.SIPID,
			Tradingsymbol: cmd.Tradingsymbol,
			Amount:        cmd.Amount,
			Frequency:     cmd.Frequency,
			Instalments:   cmd.Instalments,
			InitialAmount: cmd.InitialAmount,
			InstalmentDay: cmd.InstalmentDay,
			Tag:           cmd.Tag,
			Timestamp:     time.Now().UTC(),
		})
	}

	return resp, nil
}

// CancelMFSIPUseCase cancels an existing mutual fund SIP.
type CancelMFSIPUseCase struct {
	brokerResolver BrokerResolver
	eventStore     EventAppender
	events         *domain.EventDispatcher
	logger         *slog.Logger
}

func NewCancelMFSIPUseCase(resolver BrokerResolver, logger *slog.Logger) *CancelMFSIPUseCase {
	return &CancelMFSIPUseCase{brokerResolver: resolver, logger: logger}
}

// SetEventStore opts the use case into event-sourced audit. nil disables.
func (uc *CancelMFSIPUseCase) SetEventStore(s EventAppender) { uc.eventStore = s }

// SetEventDispatcher wires the typed domain event dispatcher so broker
// failures emit MFOrderRejectedEvent. Nil-safe.
func (uc *CancelMFSIPUseCase) SetEventDispatcher(d *domain.EventDispatcher) { uc.events = d }

func (uc *CancelMFSIPUseCase) Execute(ctx context.Context, cmd cqrs.CancelMFSIPCommand) (broker.MFSIPResponse, error) {
	if cmd.Email == "" {
		return broker.MFSIPResponse{}, fmt.Errorf("usecases: email is required")
	}
	if cmd.SIPID == "" {
		return broker.MFSIPResponse{}, fmt.Errorf("usecases: sip_id is required")
	}

	client, err := uc.brokerResolver.GetBrokerForEmail(cmd.Email)
	if err != nil {
		return broker.MFSIPResponse{}, fmt.Errorf("usecases: resolve broker: %w", err)
	}

	resp, err := client.CancelMFSIP(cmd.SIPID)
	if err != nil {
		uc.logger.Error("Failed to cancel MF SIP", "email", cmd.Email, "sip_id", cmd.SIPID, "error", err)
		// ES: SIPID acts as OrderID for aggregate-stream join.
		dispatchMFRejection(uc.events, cmd.Email, cmd.SIPID, "cancel_sip", err.Error())
		return broker.MFSIPResponse{}, fmt.Errorf("usecases: cancel mf sip: %w", err)
	}

	uc.logger.Info("MF SIP cancelled", "email", cmd.Email, "sip_id", cmd.SIPID)

	// ES post-migration: typed event only. Persister in wire.go
	// handles audit-row write.
	if uc.events != nil {
		uc.events.Dispatch(domain.MFSIPCancelledEvent{
			Email:     cmd.Email,
			SIPID:     cmd.SIPID,
			Timestamp: time.Now().UTC(),
		})
	}

	return resp, nil
}
