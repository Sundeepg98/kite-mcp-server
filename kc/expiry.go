package kc

import (
	"time"

	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// IsKiteTokenExpired checks if a Kite token stored at the given time has likely expired.
// Kite tokens expire daily around 6 AM IST.
//
// Retained as the free-standing helper for callers that only have a storedAt
// timestamp (no email/token fields). For callers with a full KiteTokenEntry,
// prefer ToDomainSession(email, entry).IsExpired().
func IsKiteTokenExpired(storedAt time.Time) bool {
	now := time.Now().In(KolkataLocation)
	stored := storedAt.In(KolkataLocation)
	expiry := time.Date(now.Year(), now.Month(), now.Day(), 6, 0, 0, 0, KolkataLocation)
	if now.Before(expiry) {
		expiry = expiry.AddDate(0, 0, -1)
	}
	return stored.Before(expiry)
}

// ToDomainSession converts a KiteTokenEntry (+ email) into the rich domain
// Session entity. Converter boundary between the kc infrastructure type and
// the domain entity — kc retains zero knowledge of domain method bodies.
func ToDomainSession(email string, entry *KiteTokenEntry) domain.Session {
	if entry == nil {
		return domain.NewSessionFromData(domain.SessionData{Email: email})
	}
	return domain.NewSessionFromData(domain.SessionData{
		Email:       email,
		AccessToken: entry.AccessToken,
		IssuedAt:    entry.StoredAt,
	})
}
