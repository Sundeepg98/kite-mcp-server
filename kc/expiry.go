package kc

import "time"

// IsKiteTokenExpired checks if a Kite token stored at the given time has likely expired.
// Kite tokens expire daily around 6 AM IST.
func IsKiteTokenExpired(storedAt time.Time) bool {
	now := time.Now().In(KolkataLocation)
	stored := storedAt.In(KolkataLocation)
	expiry := time.Date(now.Year(), now.Month(), now.Day(), 6, 0, 0, 0, KolkataLocation)
	if now.Before(expiry) {
		expiry = expiry.AddDate(0, 0, -1)
	}
	return stored.Before(expiry)
}
