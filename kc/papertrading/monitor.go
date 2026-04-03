package papertrading

import (
	"log/slog"
	"time"
)

// Monitor polls for OPEN paper orders and fills them when the LTP crosses
// the limit/trigger price. It runs as a background goroutine.
type Monitor struct {
	engine   *PaperEngine
	interval time.Duration
	stopCh   chan struct{}
	logger   *slog.Logger
}

// NewMonitor creates a new background monitor for the paper trading engine.
func NewMonitor(engine *PaperEngine, interval time.Duration, logger *slog.Logger) *Monitor {
	return &Monitor{
		engine:   engine,
		interval: interval,
		stopCh:   make(chan struct{}),
		logger:   logger,
	}
}

// Start launches the monitor goroutine.
func (m *Monitor) Start() {
	go m.loop()
	m.logger.Info("paper trading monitor started", "interval", m.interval)
}

// Stop signals the monitor goroutine to exit.
func (m *Monitor) Stop() {
	close(m.stopCh)
	m.logger.Info("paper trading monitor stopped")
}

func (m *Monitor) loop() {
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
		m.logger.Error("monitor: get open orders", "error", err)
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
		m.logger.Error("monitor: fetch LTPs", "error", err)
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
func shouldFill(o *Order, ltp float64) bool {
	switch o.OrderType {
	case "LIMIT":
		if o.TransactionType == "BUY" && ltp <= o.Price {
			return true
		}
		if o.TransactionType == "SELL" && ltp >= o.Price {
			return true
		}
	case "SL":
		// Stop-loss: trigger when LTP crosses the trigger price.
		if o.TransactionType == "BUY" && ltp >= o.TriggerPrice {
			return true
		}
		if o.TransactionType == "SELL" && ltp <= o.TriggerPrice {
			return true
		}
	case "SL-M":
		// Stop-loss market: same trigger logic, fill at LTP.
		if o.TransactionType == "BUY" && ltp >= o.TriggerPrice {
			return true
		}
		if o.TransactionType == "SELL" && ltp <= o.TriggerPrice {
			return true
		}
	}
	return false
}

// determineFillPrice returns the price at which to fill the order.
func determineFillPrice(o *Order, ltp float64) float64 {
	switch o.OrderType {
	case "LIMIT":
		// Limit orders fill at the limit price.
		return o.Price
	case "SL":
		// SL orders have a limit price after trigger — fill at the limit price
		// if it's still favorable, otherwise at LTP.
		if o.Price > 0 {
			return o.Price
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
		m.logger.Error("monitor: get account for fill", "email", o.Email, "error", err)
		return
	}

	cost := float64(o.Quantity) * fillPrice

	// Cash check for BUY orders.
	if o.TransactionType == "BUY" {
		if cost > acct.CashBalance {
			if err := m.engine.store.UpdateOrderStatus(o.OrderID, "REJECTED", 0, 0); err != nil {
				m.logger.Error("monitor: reject order", "order_id", o.OrderID, "error", err)
			}
			m.logger.Warn("monitor: order rejected, insufficient cash",
				"order_id", o.OrderID, "needed", cost, "available", acct.CashBalance)
			return
		}
	}

	// Update order status.
	if err := m.engine.store.UpdateOrderStatus(o.OrderID, "COMPLETE", o.Quantity, fillPrice); err != nil {
		m.logger.Error("monitor: update order status", "order_id", o.OrderID, "error", err)
		return
	}

	// Update cash balance.
	if o.TransactionType == "BUY" {
		acct.CashBalance -= cost
	} else {
		acct.CashBalance += cost
	}
	if err := m.engine.store.UpdateCashBalance(o.Email, acct.CashBalance); err != nil {
		m.logger.Error("monitor: update cash", "order_id", o.OrderID, "error", err)
		return
	}

	// Update position.
	o.FilledQuantity = o.Quantity
	o.AveragePrice = fillPrice
	if err := m.engine.updatePosition(o.Email, o, fillPrice); err != nil {
		m.logger.Error("monitor: update position", "order_id", o.OrderID, "error", err)
		return
	}

	// For CNC products, also update holdings.
	if o.Product == "CNC" {
		if err := m.engine.updateHolding(o.Email, o, fillPrice); err != nil {
			m.logger.Error("monitor: update holding", "order_id", o.OrderID, "error", err)
			return
		}
	}

	m.logger.Info("monitor: paper order filled",
		"order_id", o.OrderID,
		"symbol", o.Tradingsymbol,
		"type", o.TransactionType,
		"order_type", o.OrderType,
		"qty", o.Quantity,
		"price", fillPrice)
}
