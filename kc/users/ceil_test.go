package users

// ceil_test.go — coverage ceiling tests + documentation for kc/users.
// Before: 96.3%. Target: ~99.1%.

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ===========================================================================
// store.go:50 — IsActive (was 0% coverage)
// ===========================================================================

func TestUser_IsActive(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		status string
		want   bool
	}{
		{"active user", StatusActive, true},
		{"suspended user", StatusSuspended, false},
		{"empty status", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u := &User{Status: tc.status}
			assert.Equal(t, tc.want, u.IsActive())
		})
	}
}

// ===========================================================================
// store.go:55 — CanTrade (was 0% coverage)
// ===========================================================================

func TestUser_CanTrade(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		role   string
		status string
		want   bool
	}{
		{"admin active", RoleAdmin, StatusActive, true},
		{"trader active", RoleTrader, StatusActive, true},
		{"viewer active", RoleViewer, StatusActive, false},
		{"admin suspended", RoleAdmin, StatusSuspended, false},
		{"trader suspended", RoleTrader, StatusSuspended, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u := &User{Role: tc.role, Status: tc.status}
			assert.Equal(t, tc.want, u.CanTrade())
		})
	}
}

// ===========================================================================
// Unreachable lines — documented ceilings
// ===========================================================================
//
// invitations.go:64 — rows.Scan error in LoadFromDB.
//   The SELECT names 7 columns from family_invitations. If the query succeeds
//   (which requires all columns to exist), SQLite's dynamic typing ensures the
//   scan always succeeds. Unreachable without schema change mid-query.
//   (Also documented in push100_test.go.)
//
// store.go:140 — rows.Scan error in LoadFromDB.
//   The SELECT names 12 columns from users. Same reasoning: if the query
//   succeeds, SQLite's type coercion means scan cannot fail. Unreachable.
//   (Also documented in push100_test.go.)
//
// store.go:458 — EnsureAdmin Create error path.
//   Requires a race between the RLock check and Create. The Create call
//   fails, then UpdateRole is attempted. Tested in push100_test.go via
//   concurrent goroutine hammering. The error-log path (line 461) requires
//   BOTH Create AND UpdateRole to fail, which needs DB failure after the
//   in-memory race. Tested in push100_test.go (DB closed before race).
//
// store.go:460 — EnsureAdmin UpdateRole error after Create race.
//   Same as above — tested in push100_test.go.
//
// store.go:504 — EnsureUser return nil.
//   Defensive guard for impossible race: Create fails AND the user is not
//   found in the in-memory map on subsequent lookup. Would require a
//   concurrent Delete between Create failure and the fallback map read.
//   Unreachable. (Documented in push100_test.go.)
//
// ===========================================================================
// Summary
// ===========================================================================
//
// New tests: IsActive (3 cases), CanTrade (5 cases) — covering 2 methods
// that were at 0%.
//
// Remaining uncovered: 3 lines (scan errors + impossible race guard).
// Ceiling: ~99.1%.
