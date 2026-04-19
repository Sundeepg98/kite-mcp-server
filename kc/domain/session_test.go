package domain

// session_test.go — unit tests for the rich Session domain entity.
//
// These tests mirror the IST-boundary cases in kc/manager_edge_test.go's
// TestIsKiteTokenExpired_* suite — the rich entity must reproduce the
// same calendar rules as the pre-existing package-level function.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/zerodha/kite-mcp-server/kc/isttz"
)

func TestSession_Email_AccessToken_IssuedAt(t *testing.T) {
	t.Parallel()

	issued := time.Date(2026, 4, 19, 10, 0, 0, 0, time.UTC)
	s := NewSessionFromData(SessionData{
		Email:       "trader@example.com",
		AccessToken: "TOK123",
		IssuedAt:    issued,
	})
	assert.Equal(t, "trader@example.com", s.Email())
	assert.Equal(t, "TOK123", s.AccessToken())
	assert.Equal(t, issued, s.IssuedAt())
}

func TestSession_IsExpiredAt_Yesterday(t *testing.T) {
	t.Parallel()

	// Token issued 48 hours ago — definitely past the most recent 06:00 IST tick.
	issued := time.Now().Add(-48 * time.Hour)
	s := NewSessionFromData(SessionData{IssuedAt: issued})
	assert.True(t, s.IsExpired())
}

func TestSession_IsExpiredAt_FreshToken(t *testing.T) {
	t.Parallel()

	// Token issued a second ago — not expired.
	issued := time.Now().Add(-time.Second)
	s := NewSessionFromData(SessionData{IssuedAt: issued})
	assert.False(t, s.IsExpired())
}

func TestSession_IsExpiredAt_BeforeSixAM(t *testing.T) {
	t.Parallel()

	// Now = 04:30 IST on Apr 19. The most recent expiry tick was
	// yesterday (Apr 18) at 06:00 IST. A token stored yesterday at
	// 22:00 IST is still valid (stored AFTER yesterday's tick).
	loc := isttz.Location
	now := time.Date(2026, 4, 19, 4, 30, 0, 0, loc)
	yesterday10PM := time.Date(2026, 4, 18, 22, 0, 0, 0, loc)

	s := NewSessionFromData(SessionData{IssuedAt: yesterday10PM})
	assert.False(t, s.IsExpiredAt(now),
		"token issued after yesterday 06:00 IST should still be valid before today 06:00 IST")
}

func TestSession_IsExpiredAt_AfterSixAM(t *testing.T) {
	t.Parallel()

	// Now = 08:00 IST on Apr 19. Expiry tick = today 06:00 IST.
	// Token stored yesterday at 22:00 IST is EXPIRED (stored before today's tick).
	loc := isttz.Location
	now := time.Date(2026, 4, 19, 8, 0, 0, 0, loc)
	yesterday10PM := time.Date(2026, 4, 18, 22, 0, 0, 0, loc)

	s := NewSessionFromData(SessionData{IssuedAt: yesterday10PM})
	assert.True(t, s.IsExpiredAt(now),
		"token issued before today's 06:00 IST should be expired after 06:00")
}

func TestSession_IsExpiredAt_SameDayFreshLogin(t *testing.T) {
	t.Parallel()

	// Token issued today at 09:15 IST, now is 15:30 IST same day. Valid.
	loc := isttz.Location
	issued := time.Date(2026, 4, 19, 9, 15, 0, 0, loc)
	now := time.Date(2026, 4, 19, 15, 30, 0, 0, loc)

	s := NewSessionFromData(SessionData{IssuedAt: issued})
	assert.False(t, s.IsExpiredAt(now))
}

func TestSession_TokenAgeHours(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		issuedAt time.Time
		now      time.Time
		want     float64
	}{
		{
			name:     "2 hours old",
			issuedAt: time.Date(2026, 4, 19, 10, 0, 0, 0, time.UTC),
			now:      time.Date(2026, 4, 19, 12, 0, 0, 0, time.UTC),
			want:     2,
		},
		{
			name:     "12.5 hours old",
			issuedAt: time.Date(2026, 4, 19, 6, 0, 0, 0, time.UTC),
			now:      time.Date(2026, 4, 19, 18, 30, 0, 0, time.UTC),
			want:     12.5,
		},
		{
			name:     "future issuedAt clamps to 0",
			issuedAt: time.Date(2026, 4, 19, 15, 0, 0, 0, time.UTC),
			now:      time.Date(2026, 4, 19, 12, 0, 0, 0, time.UTC),
			want:     0,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := NewSessionFromData(SessionData{IssuedAt: tc.issuedAt})
			assert.InDelta(t, tc.want, s.TokenAgeHoursAt(tc.now), 0.001)
		})
	}
}

func TestSession_TokenAgeHours_ZeroIssuedAt(t *testing.T) {
	t.Parallel()

	// Zero-value IssuedAt means no session has been recorded yet; age is 0
	// rather than "58 years" (Unix epoch - now).
	s := NewSessionFromData(SessionData{})
	assert.Equal(t, 0.0, s.TokenAgeHours())
	assert.Equal(t, 0.0, s.TokenAgeHoursAt(time.Now()))
}

func TestSession_DTO(t *testing.T) {
	t.Parallel()

	d := SessionData{
		Email:       "a@b.com",
		AccessToken: "TOK",
		IssuedAt:    time.Date(2026, 4, 19, 10, 0, 0, 0, time.UTC),
	}
	s := NewSessionFromData(d)
	assert.Equal(t, d, s.DTO())
}

func TestToDomainSession(t *testing.T) {
	t.Parallel()

	loc := isttz.Location
	now := time.Date(2026, 4, 19, 12, 0, 0, 0, loc)
	issued := time.Date(2026, 4, 19, 9, 15, 0, 0, loc)

	d := ToDomainSession(SessionData{
		Email:       "trader@example.com",
		AccessToken: "TOK",
		IssuedAt:    issued,
	})
	assert.Equal(t, "trader@example.com", d.Email())
	assert.False(t, d.IsExpiredAt(now))
	assert.InDelta(t, 2.75, d.TokenAgeHoursAt(now), 0.01)
}
