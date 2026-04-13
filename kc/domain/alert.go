package domain

import "time"

// This file holds the Alert domain entity. It was previously collocated with
// the alerts-package persistence code in kc/alerts/store.go — a layering
// miss, because the logic below (trigger conditions, lifecycle transitions,
// instrument matching) has no dependency on storage and is the canonical
// business definition of an alert. Moved here to sit alongside the other
// domain entities (Money, Quantity, InstrumentKey, OrderSpec).
//
// kc/alerts still exports Alert and Direction via type aliases so every
// existing consumer keeps working unchanged. The alias pattern makes this a
// pure layering refactor, not an API break.

// Direction specifies the alert trigger direction.
type Direction string

// Alert direction constants. Percentage directions use ReferencePrice as
// the baseline and TargetPrice as the percentage threshold.
const (
	DirectionAbove   Direction = "above"
	DirectionBelow   Direction = "below"
	DirectionDropPct Direction = "drop_pct"
	DirectionRisePct Direction = "rise_pct"
)

// ValidDirections is the set of all supported alert directions.
var ValidDirections = map[Direction]bool{
	DirectionAbove:   true,
	DirectionBelow:   true,
	DirectionDropPct: true,
	DirectionRisePct: true,
}

// IsPercentageDirection returns true if the direction is a percentage-change type.
func IsPercentageDirection(d Direction) bool {
	return d == DirectionDropPct || d == DirectionRisePct
}

// Alert represents a price alert for a specific instrument. Rich domain
// entity with lifecycle behavior — the 8 methods below are the canonical
// definition of "what it means for an alert to trigger / fire / need
// notification". Persistence is handled by kc/alerts.Store which wraps
// this entity.
type Alert struct {
	ID                 string    `json:"id"`
	Email              string    `json:"email"`
	Tradingsymbol      string    `json:"tradingsymbol"`
	Exchange           string    `json:"exchange"`
	InstrumentToken    uint32    `json:"instrument_token"`
	TargetPrice        float64   `json:"target_price"`
	Direction          Direction `json:"direction"`
	ReferencePrice     float64   `json:"reference_price,omitempty"`
	Triggered          bool      `json:"triggered"`
	CreatedAt          time.Time `json:"created_at"`
	TriggeredAt        time.Time `json:"triggered_at,omitempty"`
	TriggeredPrice     float64   `json:"triggered_price,omitempty"`
	NotificationSentAt time.Time `json:"notification_sent_at,omitempty"`
}

// ShouldTrigger checks if the current price meets this alert's trigger condition.
func (a *Alert) ShouldTrigger(currentPrice float64) bool {
	switch a.Direction {
	case DirectionAbove:
		return currentPrice >= a.TargetPrice
	case DirectionBelow:
		return currentPrice <= a.TargetPrice
	case DirectionDropPct:
		if a.ReferencePrice <= 0 {
			return false
		}
		pctChange := (a.ReferencePrice - currentPrice) / a.ReferencePrice * 100
		return pctChange >= a.TargetPrice
	case DirectionRisePct:
		if a.ReferencePrice <= 0 {
			return false
		}
		pctChange := (currentPrice - a.ReferencePrice) / a.ReferencePrice * 100
		return pctChange >= a.TargetPrice
	default:
		return false
	}
}

// MarkTriggered transitions the alert to triggered state with the given price.
// Returns true if newly triggered, false if already triggered.
func (a *Alert) MarkTriggered(currentPrice float64) bool {
	if a.Triggered {
		return false
	}
	a.Triggered = true
	a.TriggeredAt = time.Now()
	a.TriggeredPrice = currentPrice
	return true
}

// IsPercentageAlert returns true if this alert uses a percentage-change direction.
func (a *Alert) IsPercentageAlert() bool {
	return a.Direction == DirectionDropPct || a.Direction == DirectionRisePct
}

// IsActive returns true if the alert has not yet fired.
func (a *Alert) IsActive() bool {
	return !a.Triggered
}

// MatchesInstrument returns true if the alert is for the given instrument token.
func (a *Alert) MatchesInstrument(instrumentToken uint32) bool {
	return a.InstrumentToken == instrumentToken
}

// NeedsNotification returns true if the alert has fired but no notification has been sent.
func (a *Alert) NeedsNotification() bool {
	return a.Triggered && a.NotificationSentAt.IsZero()
}

// InstrumentKey returns the "exchange:tradingsymbol" identifier for the alerted instrument.
func (a *Alert) InstrumentKey() string {
	return a.Exchange + ":" + a.Tradingsymbol
}

// PercentageChange returns the signed percentage change of currentPrice from ReferencePrice.
// Returns 0 if ReferencePrice is not set (<= 0).
func (a *Alert) PercentageChange(currentPrice float64) float64 {
	if a.ReferencePrice <= 0 {
		return 0
	}
	return (currentPrice - a.ReferencePrice) / a.ReferencePrice * 100
}
