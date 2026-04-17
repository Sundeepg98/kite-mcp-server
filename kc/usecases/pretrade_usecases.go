package usecases

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
)

// PreTradeData holds the raw data collected from parallel API calls.
type PreTradeData struct {
	LTP          map[string]broker.LTP `json:"ltp,omitempty"`
	Margins      *broker.Margins       `json:"margins,omitempty"`
	Positions    *broker.Positions     `json:"positions,omitempty"`
	Holdings     []broker.Holding      `json:"holdings,omitempty"`
	OrderMargins any                   `json:"order_margins,omitempty"`
	Errors       map[string]string     `json:"errors,omitempty"`
}

// --- Pre-Trade Check ---

// PreTradeCheckUseCase performs pre-trade validation by gathering data from the broker.
type PreTradeCheckUseCase struct {
	brokerResolver BrokerResolver
	logger         *slog.Logger
}

// NewPreTradeCheckUseCase creates a PreTradeCheckUseCase with dependencies injected.
func NewPreTradeCheckUseCase(resolver BrokerResolver, logger *slog.Logger) *PreTradeCheckUseCase {
	return &PreTradeCheckUseCase{brokerResolver: resolver, logger: logger}
}

// Execute gathers LTP, margins, positions, holdings, and order margins in parallel.
func (uc *PreTradeCheckUseCase) Execute(ctx context.Context, query cqrs.PreTradeCheckQuery) (*PreTradeData, error) {
	if query.Email == "" {
		return nil, fmt.Errorf("usecases: email is required")
	}

	client, err := uc.brokerResolver.GetBrokerForEmail(query.Email)
	if err != nil {
		return nil, fmt.Errorf("usecases: resolve broker: %w", err)
	}

	instrumentKey := query.Exchange + ":" + query.Tradingsymbol
	result := &PreTradeData{
		Errors: make(map[string]string),
	}

	type apiResult struct {
		key string
		val any
		err error
	}

	ch := make(chan apiResult, 5)

	go func() {
		ltp, err := client.GetLTP(instrumentKey)
		ch <- apiResult{"ltp", ltp, err}
	}()
	go func() {
		m, err := client.GetMargins()
		ch <- apiResult{"margins", m, err}
	}()
	go func() {
		p, err := client.GetPositions()
		ch <- apiResult{"positions", p, err}
	}()
	go func() {
		h, err := client.GetHoldings()
		ch <- apiResult{"holdings", h, err}
	}()
	go func() {
		om, err := client.GetOrderMargins([]broker.OrderMarginParam{{
			Exchange:        query.Exchange,
			Tradingsymbol:   query.Tradingsymbol,
			TransactionType: query.TransactionType,
			Variety:         "regular",
			Product:         query.Product,
			OrderType:       query.OrderType,
			Quantity:        query.Quantity,
			Price:           query.Price,
		}})
		ch <- apiResult{"order_margins", om, err}
	}()

	for range 5 {
		r := <-ch
		if r.err != nil {
			result.Errors[r.key] = r.err.Error()
			uc.logger.Error("Pre-trade API call failed", "key", r.key, "email", query.Email, "error", r.err)
			continue
		}
		switch r.key {
		case "ltp":
			result.LTP = r.val.(map[string]broker.LTP)
		case "margins":
			m := r.val.(broker.Margins)
			result.Margins = &m
		case "positions":
			p := r.val.(broker.Positions)
			result.Positions = &p
		case "holdings":
			result.Holdings = r.val.([]broker.Holding)
		case "order_margins":
			result.OrderMargins = r.val
		}
	}

	if len(result.Errors) == 0 {
		result.Errors = nil
	}

	return result, nil
}
