package domain

import (
	"time"

	"github.com/zerodha/kite-mcp-server/kc/isttz"
)

// Session is the rich domain entity representing a user's Kite broker
// session — specifically, the authenticated access token and the metadata
// needed to reason about its validity.
//
// Kite access tokens expire once per trading day at 06:00 IST, regardless of
// when they were issued. A token issued at 09:15 IST will therefore live for
// ~20h 45m, while a token issued at 05:59 IST will live for just 1 minute.
// The IsExpired / TokenAgeHours methods encapsulate this broker-specific rule
// so that callers (middleware, scheduled jobs, briefing, dashboards) do not
// need to re-derive the expiry calendar themselves.
//
// This entity intentionally wraps a flat DTO (SessionData) rather than the
// kc.KiteTokenEntry struct, so that kc/domain retains zero upward deps.
// Converters live in kc (see kc.ToDomainSession) to map between the two.
type Session struct {
	dto SessionData
}

// SessionData is the flat DTO view of a Kite session. Matches the relevant
// subset of kc.KiteTokenEntry; additional fields (UserID, UserName) are
// irrelevant to expiry reasoning and are omitted here.
type SessionData struct {
	// Email is the OAuth-authenticated email that owns the session.
	Email string
	// AccessToken is the Kite Connect access token value. The domain entity
	// does not use it directly — included so callers that need to pass the
	// session through to a broker client retain one-stop access.
	AccessToken string
	// IssuedAt is the wall-clock time the token was obtained / stored.
	// Must be in a timezone that can be normalised to IST for the 06:00 rule.
	IssuedAt time.Time
}

// NewSessionFromData constructs a Session from its flat DTO.
func NewSessionFromData(d SessionData) Session {
	return Session{dto: d}
}

// ToDomainSession is a converter alias — identical to NewSessionFromData,
// named for ergonomic use at adapter boundaries.
func ToDomainSession(d SessionData) Session {
	return NewSessionFromData(d)
}

// DTO returns the underlying session DTO for passthrough.
func (s Session) DTO() SessionData {
	return s.dto
}

// Email returns the OAuth email that owns the session.
func (s Session) Email() string {
	return s.dto.Email
}

// AccessToken returns the underlying Kite access token value.
func (s Session) AccessToken() string {
	return s.dto.AccessToken
}

// IssuedAt returns the wall-clock time the token was issued.
func (s Session) IssuedAt() time.Time {
	return s.dto.IssuedAt
}

// IsExpired reports whether the session has passed the daily 06:00 IST
// refresh boundary. Compared against time.Now.
//
// Rule: a token is expired if it was issued before today's 06:00 IST (or
// before yesterday's 06:00 IST if the current time is itself before today's
// 06:00 IST — in that case the "last expiry tick" was yesterday).
//
// Mirrors kc.IsKiteTokenExpired but lives on the rich entity so consumers
// can write `session.IsExpired()` instead of threading the StoredAt timestamp
// through a package-level function.
func (s Session) IsExpired() bool {
	return s.IsExpiredAt(time.Now())
}

// IsExpiredAt is the testable variant of IsExpired — takes "now" explicitly
// so unit tests don't need to monkey-patch time.Now. Production callers
// should prefer IsExpired().
func (s Session) IsExpiredAt(now time.Time) bool {
	loc := isttz.Location
	nowIST := now.In(loc)
	stored := s.dto.IssuedAt.In(loc)
	// Today's 06:00 IST is the next expiry tick.
	expiry := time.Date(nowIST.Year(), nowIST.Month(), nowIST.Day(), 6, 0, 0, 0, loc)
	// If we're before today's tick, the *last* tick was yesterday's.
	if nowIST.Before(expiry) {
		expiry = expiry.AddDate(0, 0, -1)
	}
	// A token stored strictly before the most recent 06:00 IST tick is expired.
	return stored.Before(expiry)
}

// TokenAgeHours returns how many hours have elapsed since IssuedAt,
// computed against time.Now. Negative values (IssuedAt in the future) are
// clamped to 0. Used for display ("token is 3.2 hours old") and for alerting
// on unusually fresh/stale tokens in admin tools.
func (s Session) TokenAgeHours() float64 {
	return s.TokenAgeHoursAt(time.Now())
}

// TokenAgeHoursAt is the testable variant of TokenAgeHours.
func (s Session) TokenAgeHoursAt(now time.Time) float64 {
	if s.dto.IssuedAt.IsZero() {
		return 0
	}
	h := now.Sub(s.dto.IssuedAt).Hours()
	if h < 0 {
		return 0
	}
	return h
}
