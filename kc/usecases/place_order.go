// Package usecases contains application use cases that orchestrate domain
// logic, infrastructure services, and cross-cutting concerns (riskguard, events).
//
// Each use case is a single-purpose struct with an Execute method, following
// Clean Architecture principles. Use cases depend on interfaces, not concrete
// implementations, making them fully testable with mocks.
package usecases

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	"github.com/zerodha/kite-mcp-server/kc/eventsourcing"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
)

// BrokerResolver resolves a broker.Client for a given user email.
// This abstracts the session/credential lookup so use cases don't depend on
// the full SessionService.
type BrokerResolver interface {
	GetBrokerForEmail(email string) (broker.Client, error)
}

// InstrumentLookup looks up lot size and tick size for an instrument. Narrow
// port so the use case does not pull in the full instruments.Manager surface
// just to check divisibility and tick alignment. Returning ok=false means
// "metadata unavailable" — the use case treats that as a silent skip rather
// than a failure, so off-hours or bootstrap paths where instruments aren't
// loaded keep working.
type InstrumentLookup interface {
	Get(exchange, tradingsymbol string) (lotSize int, tickSize float64, ok bool)
}

// PlaceOrderUseCase orchestrates the full order placement pipeline:
// riskguard check -> broker API call -> domain event dispatch.
type PlaceOrderUseCase struct {
	brokerResolver BrokerResolver
	riskguard      *riskguard.Guard
	events         *domain.EventDispatcher
	eventStore     EventAppender
	instruments    InstrumentLookup
	logger         *slog.Logger
}

// NewPlaceOrderUseCase creates a PlaceOrderUseCase with all dependencies injected.
func NewPlaceOrderUseCase(
	resolver BrokerResolver,
	guard *riskguard.Guard,
	events *domain.EventDispatcher,
	logger *slog.Logger,
) *PlaceOrderUseCase {
	return &PlaceOrderUseCase{
		brokerResolver: resolver,
		riskguard:      guard,
		events:         events,
		logger:         logger,
	}
}

// SetEventStore wires the domain audit-log appender. When set, Execute
// appends an order.placed StoredEvent directly after broker success.
// Phase C event sourcing — avoids double-emit with the dispatcher→persister
// path (wire.go drops order.placed persister subscription). The dispatcher
// path still drives fill_watcher and the Projector. Nil-safe.
func (uc *PlaceOrderUseCase) SetEventStore(s EventAppender) {
	uc.eventStore = s
}

// SetInstrumentLookup wires the instrument metadata lookup so Execute can
// enforce lot-size divisibility and tick-size alignment at the domain
// boundary via domain.InstrumentRules. Nil-safe — when unset, the use case
// skips lot/tick checks. Optional to avoid breaking callers that construct
// the use case without instrument metadata (bootstrap, tests).
func (uc *PlaceOrderUseCase) SetInstrumentLookup(l InstrumentLookup) {
	uc.instruments = l
}

// Execute runs the PlaceOrder pipeline and returns the broker-assigned order ID.
func (uc *PlaceOrderUseCase) Execute(ctx context.Context, cmd cqrs.PlaceOrderCommand) (string, error) {
	// 1. Validate basic inputs.
	if cmd.Email == "" {
		return "", fmt.Errorf("usecases: email is required")
	}

	// Construct the domain OrderPlacement aggregate root — single entry point
	// for the {instrument, qty, price, txType, orderType} invariants. This
	// replaces the previous OrderSpec/QuantitySpec/PriceSpec composition so
	// all order-placement rules live on one domain aggregate.
	if _, err := domain.NewOrderPlacement(
		cmd.Instrument, cmd.Qty, cmd.Price, cmd.TransactionType, cmd.OrderType,
	); err != nil {
		return "", fmt.Errorf("usecases: %w", err)
	}

	// Extract raw values from VOs for downstream use.
	qty := cmd.Qty.Int()
	price := cmd.Price.Amount
	exchange := cmd.Instrument.Exchange
	symbol := cmd.Instrument.Tradingsymbol

	// Enforce per-instrument lot-size + tick-size invariants when the
	// lookup port is wired. InstrumentRules routes through the same
	// domain.ValidateLotSize / ValidateTickSize helpers that kc/domain
	// already tests. Nil-safe: if no lookup, skip (matches pre-#35
	// behaviour). Metadata-miss is treated as "don't enforce" rather than
	// "reject" so off-hours tests / bootstrap don't break.
	if uc.instruments != nil {
		if lotSize, tickSize, ok := uc.instruments.Get(exchange, symbol); ok {
			rules := domain.NewInstrumentRules(exchange, symbol, lotSize, tickSize)
			if err := rules.CheckQuantity(qty); err != nil {
				return "", fmt.Errorf("usecases: %w", err)
			}
			// Price alignment only matters for non-MARKET/SL-M orders
			// where the caller supplied a concrete price. MARKET/SL-M
			// carry price=0 by convention — skip alignment check for
			// those to preserve the domain's "zero tick = no rule"
			// semantics consistently.
			if price > 0 && cmd.OrderType != "MARKET" && cmd.OrderType != "SL-M" {
				if err := rules.CheckPrice(price); err != nil {
					return "", fmt.Errorf("usecases: %w", err)
				}
			}
		}
	}

	// 2. Run riskguard checks (if configured).
	// Confirmed is threaded through PlaceOrderCommand from the MCP handler
	// (where elicitation + `confirm: true` arg already satisfied the gate).
	if uc.riskguard != nil {
		result := uc.riskguard.CheckOrder(riskguard.OrderCheckRequest{
			Email:           cmd.Email,
			ToolName:        "place_order",
			Exchange:        exchange,
			Tradingsymbol:   symbol,
			TransactionType: cmd.TransactionType,
			Quantity:        qty,
			Price:           price,
			OrderType:       cmd.OrderType,
			Confirmed:       cmd.Confirmed,
		})
		if !result.Allowed {
			uc.logger.Warn("Order blocked by riskguard",
				"email", cmd.Email,
				"reason", result.Reason,
				"message", result.Message,
			)
			if uc.events != nil {
				uc.events.Dispatch(domain.RiskLimitBreachedEvent{
					Email:     cmd.Email,
					Reason:    string(result.Reason),
					Message:   result.Message,
					ToolName:  "place_order",
					Timestamp: time.Now().UTC(),
				})
			}
			return "", fmt.Errorf("usecases: order blocked by riskguard: %s", result.Message)
		}
	}

	// 3. Resolve broker client.
	client, err := uc.brokerResolver.GetBrokerForEmail(cmd.Email)
	if err != nil {
		return "", fmt.Errorf("usecases: resolve broker: %w", err)
	}

	// 4. Place order via broker API.
	params := broker.OrderParams{
		Exchange:        exchange,
		Tradingsymbol:   symbol,
		TransactionType: cmd.TransactionType,
		OrderType:       cmd.OrderType,
		Product:         cmd.Product,
		Quantity:        qty,
		Price:           price,
		TriggerPrice:    cmd.TriggerPrice,
		Validity:        cmd.Validity,
		Variety:         cmd.Variety,
		Tag:             cmd.Tag,
	}

	resp, err := client.PlaceOrder(params)
	if err != nil {
		uc.logger.Error("Order placement failed",
			"email", cmd.Email,
			"tradingsymbol", symbol,
			"error", err,
		)
		return "", fmt.Errorf("usecases: place order: %w", err)
	}

	// 5. Dispatch domain events.
	// OrderPlacedEvent drives the order projection (via Projector) and the
	// fill-watcher bridge that polls the broker until the order reaches
	// COMPLETE. PositionOpenedEvent activates the position projection: each
	// new order is treated as opening a position candidate keyed by the
	// order ID. Once close_position / close_all_positions dispatches
	// PositionClosedEvent with the same-or-related order ID, the projection
	// reflects the full open → close lifecycle. Position ID is the broker
	// order ID because that's the only stable identifier at placement time.
	now := time.Now().UTC()
	if uc.events != nil {
		uc.events.Dispatch(domain.OrderPlacedEvent{
			Email:           cmd.Email,
			OrderID:         resp.OrderID,
			Instrument:      cmd.Instrument,
			Qty:             cmd.Qty,
			Price:           cmd.Price,
			TransactionType: cmd.TransactionType,
			Timestamp:       now,
		})
		uc.events.Dispatch(domain.PositionOpenedEvent{
			Email:           cmd.Email,
			PositionID:      resp.OrderID,
			Instrument:      cmd.Instrument,
			Product:         cmd.Product,
			Qty:             cmd.Qty,
			AvgPrice:        cmd.Price,
			TransactionType: cmd.TransactionType,
			Timestamp:       now,
		})
	}

	// Phase C ES: append order.placed to the audit log. Direct path avoids
	// double-emit with the dispatcher→persister subscription (dropped in
	// wire.go when this landed).
	uc.appendPlacedEvent(resp.OrderID, cmd, symbol, exchange, qty, price, now)

	uc.logger.Info("Order placed",
		"email", cmd.Email,
		"order_id", resp.OrderID,
		"tradingsymbol", symbol,
		"transaction_type", cmd.TransactionType,
	)

	return resp.OrderID, nil
}

// appendPlacedEvent writes an order.placed StoredEvent to the audit log.
//
// Routes through the OUTBOX (AppendToOutbox) rather than Append directly:
// the broker has already placed the order, so the audit-loss window
// between the synchronous Append and a process crash is the worst-case
// path here. The outbox shrinks the window to a single SQLite INSERT;
// the async pump in kc/eventsourcing/outbox.go drains pending entries
// into domain_events. Startup-recovery picks up rows from a previous
// crashed process automatically.
//
// Payload matches OrderPlacedPayload in kc/eventsourcing/order_aggregate.go
// for replay compatibility.
func (uc *PlaceOrderUseCase) appendPlacedEvent(orderID string, cmd cqrs.PlaceOrderCommand, symbol, exchange string, qty int, price float64, occurredAt time.Time) {
	if uc.eventStore == nil {
		return
	}
	seq, err := uc.eventStore.NextSequence(orderID)
	if err != nil {
		uc.logger.Warn("event store NextSequence failed on order.placed", "order_id", orderID, "error", err)
		return
	}
	payload, err := eventsourcing.MarshalPayload(eventsourcing.OrderPlacedPayload{
		Email:           cmd.Email,
		Exchange:        exchange,
		Tradingsymbol:   symbol,
		TransactionType: cmd.TransactionType,
		OrderType:       cmd.OrderType,
		Product:         cmd.Product,
		Quantity:        qty,
		Price:           price,
	})
	if err != nil { // COVERAGE: unreachable — struct marshals cleanly
		return
	}
	evt := eventsourcing.StoredEvent{
		AggregateID:   orderID,
		AggregateType: "Order",
		EventType:     "order.placed",
		Payload:       payload,
		OccurredAt:    occurredAt,
		Sequence:      seq,
	}
	if err := uc.eventStore.AppendToOutbox(evt); err != nil {
		uc.logger.Warn("outbox append failed on order.placed; trying direct path", "order_id", orderID, "error", err)
		// Fallback to direct append so a transient outbox-table issue
		// (rare) doesn't lose the audit entry on a single attempt.
		if err := uc.eventStore.Append(evt); err != nil {
			uc.logger.Warn("event store Append failed on order.placed", "order_id", orderID, "error", err)
		}
	}
}

