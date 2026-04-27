package papertrading

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/domain"
	logport "github.com/zerodha/kite-mcp-server/kc/logger"
)

// Monitor polls for OPEN paper orders and fills them when the LTP crosses
// the limit/trigger price. It runs as a background goroutine.
//
// Wave D Phase 3 Package 3 (Logger sweep): logger is typed as the
// kc/logger.Logger port. The goroutine uses context.Background() at
// each log call site — Monitor is a long-lived service with no
// request ctx; future ctx threading would tie it to a parent app ctx
// captured by Start.
type Monitor struct {
	engine   *PaperEngine
	interval time.Duration
	stopCh   chan struct{}
	doneCh   chan struct{}
	stopOnce sync.Once
	started  bool
	logger   logport.Logger
}

// NewMonitor creates a new background monitor for the paper trading engine.
// Accepts *slog.Logger for caller compatibility (app/wire.go:712); the
// logger is converted to the kc/logger.Logger port at the boundary.
func NewMonitor(engine *PaperEngine, interval time.Duration, logger *slog.Logger) *Monitor {
	return &Monitor{
		engine:   engine,
		interval: interval,
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
		logger:   logport.NewSlog(logger),
	}
}

// Start launches the monitor goroutine. Calling Start more than once is a
// programming error; the redundant goroutine leaks. Callers should create a
// new Monitor instead.
func (m *Monitor) Start() {
	m.started = true
	go m.loop()
	m.logger.Info(context.Background(), "paper trading monitor started", "interval", m.interval)
}

// Stop signals the monitor goroutine to exit and waits for it to terminate.
// It is safe to call Stop multiple times — only the first call closes the
// stop channel and waits for the loop; subsequent calls are no-ops (sync.Once guard).
//
// If Start was never called, Stop is a pure no-op and returns immediately.
func (m *Monitor) Stop() {
	m.stopOnce.Do(func() {
		close(m.stopCh)
		// Only wait for the loop goroutine when Start was actually called;
		// otherwise doneCh is never closed and we'd block forever.
		if m.started {
			<-m.doneCh
		}
		m.logger.Info(context.Background(), "paper trading monitor stopped")
	})
}

func (m *Monitor) loop() {
	defer close(m.doneCh)
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.tick()
		}
	}
}

func (m *Monitor) tick() {
	orders, err := m.engine.store.GetAllOpenOrders()
	if err != nil {
		m.logger.Error(context.Background(), "monitor: get open orders", err)
		return
	}
	if len(orders) == 0 {
		return
	}

	// Collect unique instruments for a batch LTP lookup.
	instrSet := make(map[string]struct{})
	for _, o := range orders {
		instrSet[o.Exchange+":"+o.Tradingsymbol] = struct{}{}
	}
	instruments := make([]string, 0, len(instrSet))
	for inst := range instrSet {
		instruments = append(instruments, inst)
	}

	ltps, err := m.engine.ltpProvider.GetLTP(instruments...)
	if err != nil {
		m.logger.Error(context.Background(), "monitor: fetch LTPs", err)
		return
	}

	for _, o := range orders {
		inst := o.Exchange + ":" + o.Tradingsymbol
		ltp, ok := ltps[inst]
		if !ok {
			continue
		}

		if !shouldFill(o, ltp) {
			continue
		}

		fillPrice := determineFillPrice(o, ltp)
		m.fill(o, fillPrice)
	}
}

// shouldFill checks whether an open order should be filled at the given LTP.
//
// Money boundary: o.Price is domain.Money (Slice 6b); for the LIMIT
// comparisons we drop to .Float64() because the LTP is a raw float
// from the broker and the comparison is by value within the same INR
// scope. Cross-currency mismatch is impossible in practice
// (LTPProvider only emits INR prices, Order.Price was constructed
// via NewINR), so the simpler float comparison preserves the original
// fill semantics without an unreachable error branch.
func shouldFill(o *Order, ltp float64) bool {
	switch o.OrderType {
	case "LIMIT":
		if o.TransactionType == "BUY" && ltp <= o.Price.Float64() {
			return true
		}
		if o.TransactionType == "SELL" && ltp >= o.Price.Float64() {
			return true
		}
	case "SL":
		// Stop-loss: trigger when LTP crosses the trigger price.
		// Money boundary: drop to .Float64() at the comparison seam —
		// LTP is raw float, TriggerPrice is INR Money by construction;
		// cross-currency mismatch is structurally impossible.
		if o.TransactionType == "BUY" && ltp >= o.TriggerPrice.Float64() {
			return true
		}
		if o.TransactionType == "SELL" && ltp <= o.TriggerPrice.Float64() {
			return true
		}
	case "SL-M":
		// Stop-loss market: same trigger logic, fill at LTP.
		if o.TransactionType == "BUY" && ltp >= o.TriggerPrice.Float64() {
			return true
		}
		if o.TransactionType == "SELL" && ltp <= o.TriggerPrice.Float64() {
			return true
		}
	}
	return false
}

// determineFillPrice returns the price at which to fill the order.
// Returns float64 (not Money) because callers downstream pass the
// fillPrice into fillOrder / updatePosition which work in float at the
// fill seam — Money construction happens inside fillOrder via NewINR.
func determineFillPrice(o *Order, ltp float64) float64 {
	switch o.OrderType {
	case "LIMIT":
		// Limit orders fill at the limit price.
		return o.Price.Float64()
	case "SL":
		// SL orders have a limit price after trigger — fill at the limit price
		// if it's still favorable (positive Money), otherwise at LTP. Use
		// IsPositive sentinel rather than > 0 — same Slice 2 pattern.
		if o.Price.IsPositive() {
			return o.Price.Float64()
		}
		return ltp
	case "SL-M":
		// SL-M orders fill at market (LTP) once triggered.
		return ltp
	default:
		return ltp
	}
}

// fill executes the fill for a single order.
func (m *Monitor) fill(o *Order, fillPrice float64) {
	acct, err := m.engine.store.GetAccount(o.Email)
	if err != nil || acct == nil {
		m.logger.Error(context.Background(), "monitor: get account for fill", err, "email", o.Email)
		return
	}

	cost := domain.NewINR(float64(o.Quantity) * fillPrice)

	// Cash check for BUY orders.
	if o.TransactionType == "BUY" {
		// Currency-aware: GreaterThan refuses cross-currency comparison;
		// fail-closed on error (treat as "cannot verify" → reject).
		over, cmpErr := cost.GreaterThan(acct.CashBalance)
		if cmpErr != nil || over {
			if err := m.engine.store.UpdateOrderStatus(o.OrderID, "REJECTED", 0, 0); err != nil {
				m.logger.Error(context.Background(), "monitor: reject order", err, "order_id", o.OrderID)
			}
			m.logger.Warn(context.Background(), "monitor: order rejected, insufficient cash",
				"order_id", o.OrderID, "needed", cost.Float64(), "available", acct.CashBalance.Float64())
			// ES: typed rejection event — monitor branch (place passed,
			// fill failed because cash dropped between place and fill).
			// Source "fill_monitor" lets projector consumers identify
			// the time-delayed rejection branch for forensic timeline
			// reconstruction.
			m.engine.dispatchRejection(o.Email, o.OrderID,
				fmt.Sprintf("insufficient cash: need %.2f, have %.2f", cost.Float64(), acct.CashBalance.Float64()),
				"fill_monitor")
			return
		}
	}

	// Update order status.
	if err := m.engine.store.UpdateOrderStatus(o.OrderID, "COMPLETE", o.Quantity, fillPrice); err != nil {
		m.logger.Error(context.Background(), "monitor: update order status", err, "order_id", o.OrderID)
		return
	}

	// Update cash balance via Money arithmetic. Cross-currency error path
	// is unreachable in practice (both INR after EnableAccount) but the
	// typed Add/Sub defends in depth.
	var newBalance domain.Money
	var arithErr error
	if o.TransactionType == "BUY" {
		newBalance, arithErr = acct.CashBalance.Sub(cost)
	} else {
		newBalance, arithErr = acct.CashBalance.Add(cost)
	}
	if arithErr != nil {
		m.logger.Error(context.Background(), "monitor: cash arithmetic", arithErr, "order_id", o.OrderID)
		return
	}
	acct.CashBalance = newBalance
	// Store boundary: drop to float64 for SQLite REAL.
	if err := m.engine.store.UpdateCashBalance(o.Email, acct.CashBalance.Float64()); err != nil {
		m.logger.Error(context.Background(), "monitor: update cash", err, "order_id", o.OrderID)
		return
	}

	// Update position. AveragePrice on the Order aggregate is Money
	// (Slice 6b); wrap fillPrice with NewINR at this boundary.
	o.FilledQuantity = o.Quantity
	o.AveragePrice = domain.NewINR(fillPrice)
	if err := m.engine.updatePosition(o.Email, o, fillPrice); err != nil {
		m.logger.Error(context.Background(), "monitor: update position", err, "order_id", o.OrderID)
		return
	}

	// For CNC products, also update holdings.
	if o.Product == "CNC" {
		if err := m.engine.updateHolding(o.Email, o, fillPrice); err != nil {
			m.logger.Error(context.Background(), "monitor: update holding", err, "order_id", o.OrderID)
			return
		}
	}

	m.logger.Info(context.Background(), "monitor: paper order filled",
		"order_id", o.OrderID,
		"symbol", o.Tradingsymbol,
		"type", o.TransactionType,
		"order_type", o.OrderType,
		"qty", o.Quantity,
		"price", fillPrice)
}
