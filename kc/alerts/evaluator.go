package alerts

import (
	"log/slog"

	"github.com/zerodha/gokiteconnect/v4/models"
)

// Evaluator checks incoming ticks against active alerts.
type Evaluator struct {
	store  *Store
	logger *slog.Logger
}

// NewEvaluator creates a new alert evaluator.
func NewEvaluator(store *Store, logger *slog.Logger) *Evaluator {
	return &Evaluator{
		store:  store,
		logger: logger,
	}
}

// Evaluate checks if a tick triggers any active alerts for the given instrument.
func (e *Evaluator) Evaluate(email string, tick models.Tick) {
	alerts := e.store.GetByToken(tick.InstrumentToken)
	if len(alerts) == 0 {
		return
	}

	for _, alert := range alerts {
		if shouldTrigger(alert, tick.LastPrice) {
			if !e.store.MarkTriggered(alert.ID, tick.LastPrice) {
				continue
			}

			e.logger.Info("Alert triggered",
				"alert_id", alert.ID,
				"email", alert.Email,
				"instrument", alert.Exchange+":"+alert.Tradingsymbol,
				"target", alert.TargetPrice,
				"current", tick.LastPrice,
				"direction", alert.Direction,
			)

			if e.store.onNotify != nil {
				e.store.onNotify(alert, tick.LastPrice)
			}
		}
	}
}

// shouldTrigger checks if the current price meets the alert condition.
func shouldTrigger(alert *Alert, currentPrice float64) bool {
	switch alert.Direction {
	case DirectionAbove:
		return currentPrice >= alert.TargetPrice
	case DirectionBelow:
		return currentPrice <= alert.TargetPrice
	default:
		return false
	}
}
