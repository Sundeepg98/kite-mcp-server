package kc

import (
	"strings"

	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/eventsourcing"
)

// orderAggregateToBrokerOrder flattens an event-sourced OrderAggregate into
// the broker.Order read shape that downstream tools expect. This is the
// conversion layer for the optimistic-projection-fallback path: when Kite
// is rate-limited or unavailable, we serve orders from the in-memory
// aggregate projection built up from domain events, and callers get the
// same shape they'd get from a successful broker call.
//
// Fields that live only on the broker side (OrderTimestamp, Tag,
// StatusMessage, TriggerPrice) are populated best-effort from aggregate
// state; they are nil/zero when the projection hasn't seen them yet.
// AveragePrice is the filled price when we have it, else the placed price.
func orderAggregateToBrokerOrder(agg *eventsourcing.OrderAggregate) broker.Order {
	o := broker.Order{
		OrderID:         agg.AggregateID(),
		Exchange:        agg.Instrument.Exchange,
		Tradingsymbol:   agg.Instrument.Tradingsymbol,
		TransactionType: agg.TransactionType,
		OrderType:       agg.OrderType,
		Product:         agg.Product,
		Quantity:        agg.Quantity.Int(),
		Price:           agg.Price.Amount,
		Status:          agg.Status,
		FilledQuantity:  agg.FilledQuantity.Int(),
		AveragePrice:    agg.FilledPrice.Amount,
		OrderTimestamp:  agg.PlacedAt,
	}
	if o.AveragePrice == 0 && agg.Status != eventsourcing.OrderStatusFilled {
		o.AveragePrice = agg.Price.Amount
	}
	return o
}

// projectionOrdersForEmail returns the aggregate-projection view of a
// user's orders as a []broker.Order, ready to substitute for a failed
// broker.GetOrders() call.
func (m *Manager) projectionOrdersForEmail(email string) []broker.Order {
	if m.projector == nil {
		return nil
	}
	aggs := m.projector.ListOrdersForEmail(email)
	out := make([]broker.Order, 0, len(aggs))
	for _, agg := range aggs {
		out = append(out, orderAggregateToBrokerOrder(agg))
	}
	return out
}

// isBrokerUnavailable reports whether err looks like a Kite API outage
// (rate limit, 503, connection refused, timeout). Used by the GetOrders
// fallback to decide whether to substitute projection data for a failed
// broker call.
//
// Intentionally conservative: matches on substrings so new Kite error
// messages that wrap these keywords still trigger the fallback. Does
// not match auth errors (expired token, forbidden) — those should
// propagate because the projection can't help with them.
func isBrokerUnavailable(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	triggers := []string{
		"rate limit",
		"rate_limit",
		"too many requests",
		"429",
		"503",
		"service unavailable",
		"timeout",
		"connection refused",
		"connection reset",
		"eof",
		"no such host",
		"gateway",
	}
	for _, k := range triggers {
		if strings.Contains(msg, k) {
			return true
		}
	}
	return false
}
