package papertrading

import (
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// orderSeq is a package-scope monotonic counter backing nextOrderID.
// Paper-trading IDs are process-local (paper trades don't need to survive
// restarts as a globally-unique namespace), so a single atomic counter
// is the cheapest correct implementation.
//
// Atomic ensures concurrent PlaceOrder / ModifyOrder calls get distinct
// IDs with no mutex overhead. Replaces the prior time.Now().UnixNano()
// scheme which collided on Windows (100ns tick resolution) and forced
// ~57 sites in the test suite to sleep 1ms between successive calls.
var orderSeq atomic.Uint64

// nextOrderID returns the next unique paper-trading order ID in the
// format "PAPER_<decimal>". Monotonic, collision-free, no wall-clock
// dependency.
func nextOrderID() string {
	return fmt.Sprintf("PAPER_%d", orderSeq.Add(1))
}

// LTPProvider fetches last-traded prices for instruments.
// Instrument format: "EXCHANGE:TRADINGSYMBOL" (e.g. "NSE:RELIANCE").
type LTPProvider interface {
	GetLTP(instruments ...string) (map[string]float64, error)
}

// PaperEngine orchestrates virtual trading logic against a Store.
type PaperEngine struct {
	store       *Store
	ltpProvider LTPProvider
	dispatcher  *domain.EventDispatcher
	logger      *slog.Logger
}

// NewEngine creates a new PaperEngine.
func NewEngine(store *Store, logger *slog.Logger) *PaperEngine {
	return &PaperEngine{store: store, logger: logger}
}

// SetLTPProvider sets the LTP provider used for market price lookups.
func (e *PaperEngine) SetLTPProvider(p LTPProvider) {
	e.ltpProvider = p
}

// SetDispatcher wires the paper engine to the shared domain event dispatcher
// so paper fills emit OrderPlacedEvent + OrderFilledEvent + PositionOpenedEvent
// into the same pipeline as live trades. Safe to leave nil in tests that don't
// need the audit trail.
func (e *PaperEngine) SetDispatcher(d *domain.EventDispatcher) {
	e.dispatcher = d
}

// dispatchRejection emits a PaperOrderRejectedEvent for the given order
// rejection. Centralised so the four rejection branches (place_market,
// place_limit, fill_immediate, fill_monitor) stay in lock-step on the
// event payload shape. Nil-safe — callers without a wired dispatcher
// (tests, bootstrap) skip silently.
//
// Source values are constrained to the documented PaperOrderRejectedEvent
// vocabulary so projector consumers can rely on stable strings:
//
//   - "place_market"   — MARKET order, LTP unavailable at place time.
//   - "place_limit"    — LIMIT BUY, cash short at place time (pre-OPEN).
//   - "fill_immediate" — fillOrder cash check failed (BUY notional > cash).
//   - "fill_monitor"   — background monitor cash check failed at fill.
func (e *PaperEngine) dispatchRejection(email, orderID, reason, source string) {
	if e.dispatcher == nil {
		return
	}
	e.dispatcher.Dispatch(domain.PaperOrderRejectedEvent{
		Email:     email,
		OrderID:   orderID,
		Reason:    reason,
		Source:    source,
		Timestamp: time.Now().UTC(),
	})
}

// IsEnabled returns whether paper trading is enabled for the given email.
func (e *PaperEngine) IsEnabled(email string) bool {
	acct, err := e.store.GetAccount(email)
	if err != nil || acct == nil {
		return false
	}
	return acct.Enabled
}

// Enable activates paper trading for the given email with the specified initial cash.
func (e *PaperEngine) Enable(email string, initialCash float64) error {
	if initialCash <= 0 {
		return fmt.Errorf("initial cash must be positive")
	}
	if err := e.store.EnableAccount(email, initialCash); err != nil {
		return fmt.Errorf("enable paper trading: %w", err)
	}
	e.logger.Info("paper trading enabled", "email", email, "initial_cash", initialCash)
	return nil
}

// Disable deactivates paper trading for the given email.
func (e *PaperEngine) Disable(email string) error {
	if err := e.store.DisableAccount(email); err != nil {
		return fmt.Errorf("disable paper trading: %w", err)
	}
	e.logger.Info("paper trading disabled", "email", email)
	return nil
}

// Reset clears all paper trading data and resets cash to the initial amount.
func (e *PaperEngine) Reset(email string) error {
	if err := e.store.ResetAccount(email); err != nil {
		return fmt.Errorf("reset paper account: %w", err)
	}
	e.logger.Info("paper trading reset", "email", email)
	return nil
}

// Status returns a summary of the paper trading account.
func (e *PaperEngine) Status(email string) (map[string]any, error) {
	acct, err := e.store.GetAccount(email)
	if err != nil {
		return nil, fmt.Errorf("get account: %w", err)
	}
	if acct == nil {
		return map[string]any{
			"enabled": false,
			"message": "Paper trading not configured. Use enable to start.",
		}, nil
	}

	positions, err := e.store.GetPositions(email)
	if err != nil {
		return nil, fmt.Errorf("get positions: %w", err)
	}
	holdings, err := e.store.GetHoldings(email)
	if err != nil {
		return nil, fmt.Errorf("get holdings: %w", err)
	}
	openOrders, err := e.store.GetOpenOrders(email)
	if err != nil {
		return nil, fmt.Errorf("get open orders: %w", err)
	}

	return map[string]any{
		"enabled": acct.Enabled,
		// JSON boundary: Money → float64 so the dashboard SSR + JSON
		// marshal path see the same wire shape as before Slice 5.
		"initial_cash":  acct.InitialCash.Float64(),
		"cash_balance":  acct.CashBalance.Float64(),
		"positions":     len(positions),
		"holdings":      len(holdings),
		"open_orders":   len(openOrders),
		"created_at":    acct.CreatedAt.Format(time.RFC3339),
		"last_reset_at": acct.ResetAt.Format(time.RFC3339),
	}, nil
}

// PlaceOrder places a paper order. Returns a Kite-compatible response map.
func (e *PaperEngine) PlaceOrder(email string, params map[string]any) (map[string]any, error) {
	acct, err := e.store.GetAccount(email)
	if err != nil {
		return nil, fmt.Errorf("get account: %w", err)
	}
	if acct == nil || !acct.Enabled {
		return nil, fmt.Errorf("paper trading is not enabled for %s", email)
	}

	// Extract parameters.
	exchange := getString(params, "exchange")
	tradingsymbol := getString(params, "tradingsymbol")
	txnType := strings.ToUpper(getString(params, "transaction_type"))
	orderType := strings.ToUpper(getString(params, "order_type"))
	product := strings.ToUpper(getString(params, "product"))
	variety := getString(params, "variety")
	quantity := getInt(params, "quantity")
	price := getFloat(params, "price")
	triggerPrice := getFloat(params, "trigger_price")
	tag := getString(params, "tag")

	if variety == "" {
		variety = "regular"
	}
	if exchange == "" || tradingsymbol == "" {
		return nil, fmt.Errorf("exchange and tradingsymbol are required")
	}
	if txnType != "BUY" && txnType != "SELL" {
		return nil, fmt.Errorf("transaction_type must be BUY or SELL, got %q", txnType)
	}
	if quantity <= 0 {
		return nil, fmt.Errorf("quantity must be positive")
	}

	orderID := nextOrderID()
	now := time.Now().UTC()

	order := &Order{
		OrderID:         orderID,
		Email:           email,
		Exchange:        exchange,
		Tradingsymbol:   tradingsymbol,
		TransactionType: txnType,
		OrderType:       orderType,
		Product:         product,
		Variety:         variety,
		Quantity:        quantity,
		Price:           price,
		TriggerPrice:    triggerPrice,
		Tag:             tag,
		PlacedAt:        now,
	}

	// Determine fill price.
	instrument := exchange + ":" + tradingsymbol
	ltp, ltpErr := e.fetchLTP(instrument)

	switch orderType {
	case "MARKET":
		if ltpErr != nil {
			order.Status = "REJECTED"
			order.Tag = "LTP unavailable: " + ltpErr.Error()
			if err := e.store.InsertOrder(order); err != nil {
				return nil, fmt.Errorf("insert rejected order: %w", err)
			}
			// ES: typed rejection event for projector consumers — distinct
			// from the live-broker order.rejected so virtual-vs-real can
			// be filtered without parsing OrderID prefixes.
			e.dispatchRejection(email, orderID, order.Tag, "place_market")
			return map[string]any{"order_id": orderID, "status": "REJECTED", "reason": order.Tag}, nil
		}
		return e.fillOrder(acct, order, ltp)

	case "LIMIT":
		if ltpErr == nil {
			// Check if the limit order is immediately marketable.
			marketable := false
			if txnType == "BUY" && price >= ltp {
				marketable = true
			} else if txnType == "SELL" && price <= ltp {
				marketable = true
			}
			if marketable {
				return e.fillOrder(acct, order, ltp)
			}
		}
		// Store as OPEN for later fill.
		if txnType == "BUY" {
			cost := domain.NewINR(float64(quantity) * price)
			// Currency-aware cash check: GreaterThan refuses cross-currency
			// comparisons (Money.Currency mismatch returns an error rather
			// than silent coercion). Treat the error as "unable to verify"
			// → fail-closed for BUY (reject) since cost cannot be confirmed
			// against cash balance.
			over, cmpErr := cost.GreaterThan(acct.CashBalance)
			if cmpErr != nil || over {
				order.Status = "REJECTED"
				order.Tag = fmt.Sprintf("insufficient cash: need %.2f, have %.2f", cost.Float64(), acct.CashBalance.Float64())
				if err := e.store.InsertOrder(order); err != nil {
					return nil, fmt.Errorf("insert rejected order: %w", err)
				}
				// ES: typed rejection event for projector consumers.
				e.dispatchRejection(email, orderID, order.Tag, "place_limit")
				return map[string]any{"order_id": orderID, "status": "REJECTED", "reason": order.Tag}, nil
			}
		}
		order.Status = "OPEN"
		if err := e.store.InsertOrder(order); err != nil {
			return nil, fmt.Errorf("insert open order: %w", err)
		}
		return map[string]any{"order_id": orderID, "status": "OPEN"}, nil

	case "SL", "SL-M":
		// Store as OPEN — these require trigger price monitoring.
		order.Status = "OPEN"
		if err := e.store.InsertOrder(order); err != nil {
			return nil, fmt.Errorf("insert SL order: %w", err)
		}
		return map[string]any{"order_id": orderID, "status": "OPEN"}, nil

	default:
		return nil, fmt.Errorf("unsupported order_type %q", orderType)
	}
}

// fillOrder executes an immediate fill at the given price.
func (e *PaperEngine) fillOrder(acct *Account, order *Order, fillPrice float64) (map[string]any, error) {
	cost := domain.NewINR(float64(order.Quantity) * fillPrice)

	// Cash check for BUY orders.
	if order.TransactionType == "BUY" {
		// Currency-aware cash check via Money.GreaterThan — silent
		// INR↔USD coercion impossible. Fail-closed on currency mismatch
		// (treat as "cannot verify" → reject), same pattern as
		// kc/riskguard/internal_checks.go checkOrderValue.
		over, cmpErr := cost.GreaterThan(acct.CashBalance)
		if cmpErr != nil || over {
			order.Status = "REJECTED"
			order.Tag = fmt.Sprintf("insufficient cash: need %.2f, have %.2f", cost.Float64(), acct.CashBalance.Float64())
			if err := e.store.InsertOrder(order); err != nil {
				return nil, fmt.Errorf("insert rejected order: %w", err)
			}
			// ES: typed rejection event — fillOrder rejection branch
			// (covers MARKET path snap-to-LTP and marketable-LIMIT path
			// where cash dropped between place and fill).
			e.dispatchRejection(acct.Email, order.OrderID, order.Tag, "fill_immediate")
			return map[string]any{"order_id": order.OrderID, "status": "REJECTED", "reason": order.Tag}, nil
		}
	}

	// Fill the order.
	now := time.Now().UTC()
	order.Status = "COMPLETE"
	order.FilledQuantity = order.Quantity
	order.AveragePrice = fillPrice
	order.FilledAt = now

	if err := e.store.InsertOrder(order); err != nil {
		return nil, fmt.Errorf("insert filled order: %w", err)
	}

	// Update cash balance via Money arithmetic. Both Cash and cost are
	// INR by construction (cost was just built with NewINR; CashBalance
	// is INR after EnableAccount). The error path on Add/Sub is the
	// "unreachable defence" branch — log and bail rather than silently
	// continue with stale balance.
	var newBalance domain.Money
	var arithErr error
	if order.TransactionType == "BUY" {
		newBalance, arithErr = acct.CashBalance.Sub(cost)
	} else {
		newBalance, arithErr = acct.CashBalance.Add(cost)
	}
	if arithErr != nil {
		return nil, fmt.Errorf("update cash arithmetic: %w", arithErr)
	}
	acct.CashBalance = newBalance
	// Store boundary: drop to float64 — SQLite REAL column.
	if err := e.store.UpdateCashBalance(acct.Email, acct.CashBalance.Float64()); err != nil {
		return nil, fmt.Errorf("update cash: %w", err)
	}

	// Update position.
	if err := e.updatePosition(acct.Email, order, fillPrice); err != nil {
		return nil, fmt.Errorf("update position: %w", err)
	}

	// For CNC products, also update holdings.
	if order.Product == "CNC" {
		if err := e.updateHolding(acct.Email, order, fillPrice); err != nil {
			return nil, fmt.Errorf("update holding: %w", err)
		}
	}

	e.logger.Info("paper order filled",
		"order_id", order.OrderID,
		"symbol", order.Tradingsymbol,
		"type", order.TransactionType,
		"qty", order.Quantity,
		"price", fillPrice)

	// Emit domain events so paper fills flow through the same audit trail,
	// projection, and dashboard pipeline as live trades. Dispatcher is optional
	// for tests; nil-guard skips the fan-out entirely.
	if e.dispatcher != nil {
		qty, qerr := domain.NewQuantity(order.Quantity)
		if qerr == nil {
			inst := domain.NewInstrumentKey(order.Exchange, order.Tradingsymbol)
			price := domain.NewINR(fillPrice)
			now := order.FilledAt
			e.dispatcher.Dispatch(domain.OrderPlacedEvent{
				Email:           acct.Email,
				OrderID:         order.OrderID,
				Instrument:      inst,
				Qty:             qty,
				Price:           price,
				TransactionType: order.TransactionType,
				Timestamp:       now,
			})
			e.dispatcher.Dispatch(domain.OrderFilledEvent{
				Email:       acct.Email,
				OrderID:     order.OrderID,
				FilledQty:   qty,
				FilledPrice: price,
				// T4: paper-engine fills are always full-quantity and
				// instantaneous (no exchange tranching), so Status is
				// always COMPLETE. Aligns with the live fill-watcher
				// emission so projections don't need to special-case
				// paper trades.
				Status:    "COMPLETE",
				Timestamp: now,
			})
			e.dispatcher.Dispatch(domain.PositionOpenedEvent{
				Email:           acct.Email,
				PositionID:      order.OrderID,
				Instrument:      inst,
				Product:         order.Product,
				Qty:             qty,
				AvgPrice:        price,
				TransactionType: order.TransactionType,
				Timestamp:       now,
			})
		}
	}

	return map[string]any{"order_id": order.OrderID, "status": "COMPLETE"}, nil
}

// updatePosition updates the position for a filled order.
func (e *PaperEngine) updatePosition(email string, order *Order, fillPrice float64) error {
	positions, err := e.store.GetPositions(email)
	if err != nil {
		return err
	}

	// Find existing position.
	var existing *Position
	for _, p := range positions {
		if p.Exchange == order.Exchange && p.Tradingsymbol == order.Tradingsymbol && p.Product == order.Product {
			existing = p
			break
		}
	}

	if existing == nil {
		// Create new position.
		qty := order.Quantity
		if order.TransactionType == "SELL" {
			qty = -qty
		}
		return e.store.UpsertPosition(&Position{
			Email:         email,
			Exchange:      order.Exchange,
			Tradingsymbol: order.Tradingsymbol,
			Product:       order.Product,
			Quantity:      qty,
			AveragePrice:  fillPrice,
			LastPrice:     domain.NewINR(fillPrice),
			PnL:           0,
		})
	}

	// Update existing position.
	if order.TransactionType == "BUY" {
		if existing.Quantity >= 0 {
			// Adding to long: weighted average.
			totalCost := existing.AveragePrice*float64(existing.Quantity) + fillPrice*float64(order.Quantity)
			existing.Quantity += order.Quantity
			if existing.Quantity != 0 {
				existing.AveragePrice = totalCost / float64(existing.Quantity)
			}
		} else {
			// Covering short position.
			existing.Quantity += order.Quantity
			if existing.Quantity > 0 {
				// Flipped to long — new average is the fill price for the remaining.
				existing.AveragePrice = fillPrice
			}
			// If exactly zero, will be deleted below.
		}
	} else { // SELL
		if existing.Quantity <= 0 {
			// Adding to short: weighted average.
			totalCost := existing.AveragePrice*float64(-existing.Quantity) + fillPrice*float64(order.Quantity)
			existing.Quantity -= order.Quantity
			if existing.Quantity != 0 {
				existing.AveragePrice = totalCost / float64(-existing.Quantity)
			}
		} else {
			// Reducing long position.
			existing.Quantity -= order.Quantity
			if existing.Quantity < 0 {
				// Flipped to short — new average is the fill price for the remaining.
				existing.AveragePrice = fillPrice
			}
			// If exactly zero, will be deleted below.
		}
	}

	existing.LastPrice = domain.NewINR(fillPrice)
	if existing.Quantity != 0 {
		existing.PnL = float64(existing.Quantity) * (fillPrice - existing.AveragePrice)
	}

	// Remove the position if quantity is zero.
	if existing.Quantity == 0 {
		return e.store.DeletePosition(email, existing.Exchange, existing.Tradingsymbol, existing.Product)
	}

	return e.store.UpsertPosition(existing)
}

// updateHolding updates holdings for CNC orders.
func (e *PaperEngine) updateHolding(email string, order *Order, fillPrice float64) error {
	holdings, err := e.store.GetHoldings(email)
	if err != nil {
		return err
	}

	var existing *Holding
	for _, h := range holdings {
		if h.Exchange == order.Exchange && h.Tradingsymbol == order.Tradingsymbol {
			existing = h
			break
		}
	}

	if order.TransactionType == "BUY" {
		if existing == nil {
			return e.store.UpsertHolding(&Holding{
				Email:         email,
				Exchange:      order.Exchange,
				Tradingsymbol: order.Tradingsymbol,
				Quantity:      order.Quantity,
				AveragePrice:  fillPrice,
				LastPrice:     domain.NewINR(fillPrice),
				PnL:           0,
			})
		}
		// Weighted average for additional buys.
		totalCost := existing.AveragePrice*float64(existing.Quantity) + fillPrice*float64(order.Quantity)
		existing.Quantity += order.Quantity
		existing.AveragePrice = totalCost / float64(existing.Quantity)
		existing.LastPrice = domain.NewINR(fillPrice)
		existing.PnL = float64(existing.Quantity) * (fillPrice - existing.AveragePrice)
		return e.store.UpsertHolding(existing)
	}

	// SELL from holdings.
	if existing == nil {
		return fmt.Errorf("no holding for %s:%s to sell", order.Exchange, order.Tradingsymbol)
	}
	existing.Quantity -= order.Quantity
	if existing.Quantity < 0 {
		return fmt.Errorf("cannot sell %d of %s:%s, only hold %d",
			order.Quantity, order.Exchange, order.Tradingsymbol, existing.Quantity+order.Quantity)
	}
	if existing.Quantity == 0 {
		// Remove holding — use ExecInsert to delete.
		return e.store.db.ExecInsert(
			`DELETE FROM paper_holdings WHERE email = ? AND exchange = ? AND tradingsymbol = ?`,
			email, order.Exchange, order.Tradingsymbol)
	}
	existing.LastPrice = domain.NewINR(fillPrice)
	existing.PnL = float64(existing.Quantity) * (fillPrice - existing.AveragePrice)
	return e.store.UpsertHolding(existing)
}

// ModifyOrder modifies an open paper order's price, quantity, or order type.
func (e *PaperEngine) ModifyOrder(email, orderID string, params map[string]any) (map[string]any, error) {
	order, err := e.store.GetOrder(orderID)
	if err != nil {
		return nil, err
	}
	if order.Email != email {
		return nil, fmt.Errorf("order %s does not belong to %s", orderID, email)
	}
	if order.Status != "OPEN" {
		return nil, fmt.Errorf("cannot modify order %s with status %s", orderID, order.Status)
	}

	// Apply modifications.
	if v, ok := params["price"]; ok {
		order.Price = toFloat(v)
	}
	if v, ok := params["quantity"]; ok {
		order.Quantity = toInt(v)
	}
	if v, ok := params["order_type"]; ok {
		order.OrderType = strings.ToUpper(fmt.Sprint(v))
	}
	if v, ok := params["trigger_price"]; ok {
		order.TriggerPrice = toFloat(v)
	}

	// Check if the modified LIMIT order is now marketable.
	if order.OrderType == "LIMIT" {
		instrument := order.Exchange + ":" + order.Tradingsymbol
		if ltp, err := e.fetchLTP(instrument); err == nil {
			marketable := false
			if order.TransactionType == "BUY" && order.Price >= ltp {
				marketable = true
			} else if order.TransactionType == "SELL" && order.Price <= ltp {
				marketable = true
			}
			if marketable {
				acct, err := e.store.GetAccount(email)
				if err != nil {
					return nil, fmt.Errorf("get account for fill: %w", err)
				}
				// Remove the old OPEN order and fill it.
				if err := e.store.UpdateOrderStatus(orderID, "CANCELLED", 0, 0); err != nil {
					return nil, fmt.Errorf("cancel old order: %w", err)
				}
				order.OrderID = nextOrderID()
				return e.fillOrder(acct, order, ltp)
			}
		}
	}

	// Update the order in place.
	if err := e.store.db.ExecInsert(
		`UPDATE paper_orders SET price = ?, quantity = ?, order_type = ?, trigger_price = ?
		 WHERE order_id = ?`,
		order.Price, order.Quantity, order.OrderType, order.TriggerPrice, orderID); err != nil {
		return nil, fmt.Errorf("modify order: %w", err)
	}

	return map[string]any{"order_id": orderID, "status": "OPEN"}, nil
}

// CancelOrder cancels an open paper order.
func (e *PaperEngine) CancelOrder(email, orderID string) (map[string]any, error) {
	order, err := e.store.GetOrder(orderID)
	if err != nil {
		return nil, err
	}
	if order.Email != email {
		return nil, fmt.Errorf("order %s does not belong to %s", orderID, email)
	}
	if order.Status != "OPEN" {
		return nil, fmt.Errorf("cannot cancel order %s with status %s", orderID, order.Status)
	}
	if err := e.store.UpdateOrderStatus(orderID, "CANCELLED", 0, 0); err != nil {
		return nil, fmt.Errorf("cancel order: %w", err)
	}
	e.logger.Info("paper order cancelled", "order_id", orderID)
	return map[string]any{"order_id": orderID, "status": "CANCELLED"}, nil
}

// GetOrders returns all paper orders in Kite API format.
func (e *PaperEngine) GetOrders(email string) (any, error) {
	orders, err := e.store.GetOrders(email)
	if err != nil {
		return nil, err
	}
	result := make([]map[string]any, 0, len(orders))
	for _, o := range orders {
		result = append(result, orderToMap(o))
	}
	return result, nil
}

// GetPositions returns all paper positions in Kite API format.
func (e *PaperEngine) GetPositions(email string) (any, error) {
	positions, err := e.store.GetPositions(email)
	if err != nil {
		return nil, err
	}

	// Refresh LTP for each position. LTPProvider returns float64 (raw
	// exchange data); wrap with domain.NewINR at this boundary so the
	// in-domain LastPrice field stays Money. PnL math uses .Float64()
	// because PnL itself is still float64 in this slice (commit 3 will
	// elevate it).
	if e.ltpProvider != nil && len(positions) > 0 {
		instruments := make([]string, len(positions))
		for i, p := range positions {
			instruments[i] = p.Exchange + ":" + p.Tradingsymbol
		}
		if ltps, err := e.ltpProvider.GetLTP(instruments...); err == nil {
			for _, p := range positions {
				key := p.Exchange + ":" + p.Tradingsymbol
				if ltp, ok := ltps[key]; ok {
					p.LastPrice = domain.NewINR(ltp)
					p.PnL = float64(p.Quantity) * (ltp - p.AveragePrice)
				}
			}
		}
	}

	day := make([]map[string]any, 0, len(positions))
	for _, p := range positions {
		day = append(day, map[string]any{
			"tradingsymbol": p.Tradingsymbol,
			"exchange":      p.Exchange,
			"product":       p.Product,
			"quantity":      p.Quantity,
			"average_price": p.AveragePrice,
			// JSON boundary: Money → float64 so the Kite-API-shaped
			// response keeps last_price as a number (matches GetMargins
			// pattern from Slice 5).
			"last_price":       p.LastPrice.Float64(),
			"pnl":              p.PnL,
			"m2m":              p.PnL,
			"buy_quantity":     0,
			"sell_quantity":    0,
			"instrument_token": 0,
		})
	}
	return map[string]any{
		"net": day,
		"day": day,
	}, nil
}

// GetHoldings returns all paper holdings in Kite API format.
func (e *PaperEngine) GetHoldings(email string) (any, error) {
	holdings, err := e.store.GetHoldings(email)
	if err != nil {
		return nil, err
	}

	// Refresh LTP for each holding. Same Money boundary as GetPositions:
	// LTPProvider gives float64; wrap with domain.NewINR for storage.
	if e.ltpProvider != nil && len(holdings) > 0 {
		instruments := make([]string, len(holdings))
		for i, h := range holdings {
			instruments[i] = h.Exchange + ":" + h.Tradingsymbol
		}
		if ltps, err := e.ltpProvider.GetLTP(instruments...); err == nil {
			for _, h := range holdings {
				key := h.Exchange + ":" + h.Tradingsymbol
				if ltp, ok := ltps[key]; ok {
					h.LastPrice = domain.NewINR(ltp)
					h.PnL = float64(h.Quantity) * (ltp - h.AveragePrice)
				}
			}
		}
	}

	result := make([]map[string]any, 0, len(holdings))
	for _, h := range holdings {
		result = append(result, map[string]any{
			"tradingsymbol": h.Tradingsymbol,
			"exchange":      h.Exchange,
			"quantity":      h.Quantity,
			"average_price": h.AveragePrice,
			// JSON boundary: Money → float64.
			"last_price":       h.LastPrice.Float64(),
			"pnl":              h.PnL,
			"t1_quantity":      0,
			"instrument_token": 0,
			"product":          "CNC",
		})
	}
	return result, nil
}

// GetMargins returns paper margin info in Kite API format.
func (e *PaperEngine) GetMargins(email string) (any, error) {
	acct, err := e.store.GetAccount(email)
	if err != nil {
		return nil, fmt.Errorf("get account: %w", err)
	}
	if acct == nil {
		return nil, fmt.Errorf("paper trading not enabled for %s", email)
	}
	// JSON boundary: Money → float64 so the Kite-API-shaped response
	// matches the original wire format. utilised.debits is computed via
	// Money.Sub for currency-aware arithmetic; the cross-currency error
	// path is unreachable here (both fields are INR after EnableAccount)
	// but the Sub call defends in depth.
	debits, _ := acct.InitialCash.Sub(acct.CashBalance)
	return map[string]any{
		"equity": map[string]any{
			"available": map[string]any{
				"cash": acct.CashBalance.Float64(),
			},
			"utilised": map[string]any{
				"debits": debits.Float64(),
			},
			"net": acct.InitialCash.Float64(),
		},
	}, nil
}

// fetchLTP retrieves the LTP for an instrument via the configured provider.
func (e *PaperEngine) fetchLTP(instrument string) (float64, error) {
	if e.ltpProvider == nil {
		return 0, fmt.Errorf("no LTP provider configured")
	}
	ltps, err := e.ltpProvider.GetLTP(instrument)
	if err != nil {
		return 0, fmt.Errorf("fetch LTP for %s: %w", instrument, err)
	}
	ltp, ok := ltps[instrument]
	if !ok {
		return 0, fmt.Errorf("LTP not found for %s", instrument)
	}
	return ltp, nil
}

// orderToMap converts an Order to a Kite API-compatible map.
func orderToMap(o *Order) map[string]any {
	m := map[string]any{
		"order_id":         o.OrderID,
		"exchange":         o.Exchange,
		"tradingsymbol":    o.Tradingsymbol,
		"transaction_type": o.TransactionType,
		"order_type":       o.OrderType,
		"product":          o.Product,
		"variety":          o.Variety,
		"quantity":         o.Quantity,
		"price":            o.Price,
		"trigger_price":    o.TriggerPrice,
		"status":           o.Status,
		"filled_quantity":  o.FilledQuantity,
		"average_price":    o.AveragePrice,
		"placed_at":        o.PlacedAt.Format(time.RFC3339),
		"tag":              o.Tag,
	}
	if !o.FilledAt.IsZero() {
		m["filled_at"] = o.FilledAt.Format(time.RFC3339)
	}
	return m
}

// --- Helper functions for extracting typed values from params ---

func getString(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		return fmt.Sprint(v)
	}
	return ""
}

func getInt(m map[string]any, key string) int {
	return toInt(m[key])
}

func getFloat(m map[string]any, key string) float64 {
	return toFloat(m[key])
}

func toInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	case string:
		var i int
		_, _ = fmt.Sscanf(n, "%d", &i)
		return i
	default:
		return 0
	}
}

func toFloat(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case float32:
		return float64(n)
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case string:
		var f float64
		_, _ = fmt.Sscanf(n, "%f", &f)
		return f
	default:
		return 0
	}
}
