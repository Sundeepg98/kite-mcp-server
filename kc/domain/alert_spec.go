package domain

import "fmt"

// maxPercentageThreshold caps the magnitude of drop_pct / rise_pct alert
// thresholds. A 100% drop means the price went to zero — anything larger
// is logically impossible. Rises of >100% are rare enough that we treat
// them as user error too; if a legitimate use case emerges we can widen.
const maxPercentageThreshold = 100.0

// ValidateAlertSpec enforces construction invariants for a single-leg
// price alert. Rules:
//
//   - Direction must be in ValidDirections.
//   - TargetPrice must be strictly positive (a zero / negative threshold
//     is never a valid trigger).
//   - For percentage directions (drop_pct / rise_pct): ReferencePrice
//     must be positive AND TargetPrice must be ≤ 100 (percent).
//
// Called from CreateAlertUseCase.Execute and the telegram /setalert
// handler so the rule lives in one place. Previously duplicated at
// kc/usecases/create_alert.go:75, kc/eventsourcing/alert_aggregate.go:76,
// and kc/telegram/trading_commands.go:349.
func ValidateAlertSpec(direction Direction, targetPrice, referencePrice float64) error {
	if !ValidDirections[direction] {
		return fmt.Errorf("domain: unknown alert direction %q", direction)
	}
	if targetPrice <= 0 {
		return fmt.Errorf("domain: alert target price must be positive, got %v", targetPrice)
	}
	if IsPercentageDirection(direction) {
		if referencePrice <= 0 {
			return fmt.Errorf("domain: %s alert requires a positive reference_price", direction)
		}
		if targetPrice > maxPercentageThreshold {
			return fmt.Errorf("domain: %s alert threshold %v%% exceeds max %v%%",
				direction, targetPrice, maxPercentageThreshold)
		}
	}
	return nil
}

// NewCompositeConditionStrict constructs a CompositeCondition with its
// invariants enforced: non-empty exchange + symbol, valid direction, and
// the same threshold / reference-price rules as ValidateAlertSpec. Returns
// a zero-value CompositeCondition on error so callers can't accidentally
// persist a half-valid leg.
//
// instrumentToken is optional — it may be 0 when the caller hasn't
// resolved the token yet (composite-creation flow looks up tokens per
// leg after validation).
func NewCompositeConditionStrict(
	exchange, tradingsymbol string,
	operator Direction,
	value, referencePrice float64,
) (CompositeCondition, error) {
	if exchange == "" {
		return CompositeCondition{}, fmt.Errorf("domain: composite leg requires exchange")
	}
	if tradingsymbol == "" {
		return CompositeCondition{}, fmt.Errorf("domain: composite leg requires tradingsymbol")
	}
	if err := ValidateAlertSpec(operator, value, referencePrice); err != nil {
		return CompositeCondition{}, err
	}
	return CompositeCondition{
		Exchange:       exchange,
		Tradingsymbol:  tradingsymbol,
		Operator:       operator,
		Value:          value,
		ReferencePrice: referencePrice,
	}, nil
}
