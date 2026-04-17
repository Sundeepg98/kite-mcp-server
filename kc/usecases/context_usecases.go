package usecases

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
)

// AlertLister abstracts reading active alerts for a user.
type AlertLister interface {
	ListActive(email string) []AlertSummary
}

// AlertSummary is a minimal alert representation for the trading context.
type AlertSummary struct {
	Tradingsymbol string
	Exchange      string
	Direction     string
	TargetPrice   float64
	Triggered     bool
}

// TradingContextResult holds the unified trading context snapshot.
type TradingContextResult struct {
	Margins   *broker.Margins   `json:"margins,omitempty"`
	Positions *broker.Positions `json:"positions,omitempty"`
	Orders    []broker.Order    `json:"orders,omitempty"`
	Holdings  []broker.Holding  `json:"holdings,omitempty"`
	Errors    map[string]string `json:"errors,omitempty"`
}

// --- Trading Context ---

// TradingContextUseCase retrieves a unified trading context snapshot.
type TradingContextUseCase struct {
	brokerResolver BrokerResolver
	logger         *slog.Logger
}

// NewTradingContextUseCase creates a TradingContextUseCase with dependencies injected.
func NewTradingContextUseCase(resolver BrokerResolver, logger *slog.Logger) *TradingContextUseCase {
	return &TradingContextUseCase{brokerResolver: resolver, logger: logger}
}

// Execute retrieves margins, positions, orders, and holdings in parallel.
func (uc *TradingContextUseCase) Execute(ctx context.Context, query cqrs.TradingContextQuery) (*TradingContextResult, error) {
	if query.Email == "" {
		return nil, fmt.Errorf("usecases: email is required")
	}

	client, err := uc.brokerResolver.GetBrokerForEmail(query.Email)
	if err != nil {
		return nil, fmt.Errorf("usecases: resolve broker: %w", err)
	}

	result := &TradingContextResult{
		Errors: make(map[string]string),
	}

	type apiResult struct {
		key string
		val any
		err error
	}

	ch := make(chan apiResult, 4)

	go func() {
		m, err := client.GetMargins()
		ch <- apiResult{"margins", m, err}
	}()
	go func() {
		p, err := client.GetPositions()
		ch <- apiResult{"positions", p, err}
	}()
	go func() {
		o, err := client.GetOrders()
		ch <- apiResult{"orders", o, err}
	}()
	go func() {
		h, err := client.GetHoldings()
		ch <- apiResult{"holdings", h, err}
	}()

	for range 4 {
		r := <-ch
		if r.err != nil {
			result.Errors[r.key] = r.err.Error()
			uc.logger.Error("Trading context API call failed", "key", r.key, "email", query.Email, "error", r.err)
			continue
		}
		switch r.key {
		case "margins":
			m := r.val.(broker.Margins)
			result.Margins = &m
		case "positions":
			p := r.val.(broker.Positions)
			result.Positions = &p
		case "orders":
			result.Orders = r.val.([]broker.Order)
		case "holdings":
			result.Holdings = r.val.([]broker.Holding)
		}
	}

	if len(result.Errors) == 0 {
		result.Errors = nil
	}

	return result, nil
}
