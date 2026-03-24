package kc

import "time"

// kolkataLoc is the cached Asia/Kolkata timezone for Kite token expiry checks.
var kolkataLoc = func() *time.Location {
	loc, err := time.LoadLocation("Asia/Kolkata")
	if err != nil {
		panic("failed to load Asia/Kolkata timezone: " + err.Error())
	}
	return loc
}()

// IsKiteTokenExpired checks if a Kite token stored at the given time has likely expired.
// Kite tokens expire daily around 6 AM IST.
func IsKiteTokenExpired(storedAt time.Time) bool {
	now := time.Now().In(kolkataLoc)
	stored := storedAt.In(kolkataLoc)
	expiry := time.Date(now.Year(), now.Month(), now.Day(), 6, 0, 0, 0, kolkataLoc)
	if now.Before(expiry) {
		expiry = expiry.AddDate(0, 0, -1)
	}
	return stored.Before(expiry)
}
