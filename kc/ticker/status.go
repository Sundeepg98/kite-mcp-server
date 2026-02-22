package ticker

import "time"

// Status represents the current state of a user's ticker connection.
type Status struct {
	Running       bool               `json:"running"`
	Connected     bool               `json:"connected"`
	StartedAt     time.Time          `json:"started_at,omitempty"`
	Uptime        string             `json:"uptime,omitempty"`
	Subscriptions []SubscriptionInfo `json:"subscriptions,omitempty"`
}

// SubscriptionInfo represents a subscribed instrument.
type SubscriptionInfo struct {
	InstrumentToken uint32 `json:"instrument_token"`
	Mode            string `json:"mode"`
}
