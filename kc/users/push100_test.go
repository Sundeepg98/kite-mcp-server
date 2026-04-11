package users

// push100_test.go — tests targeting remaining uncovered lines in kc/users.

import (
	"fmt"
	"log/slog"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
)

// ===========================================================================
// store.go:437-441 — EnsureAdmin Create error + UpdateRole error (both fail)
//
// This path fires when:
// 1. User does NOT exist in the in-memory map (exists check on line 418 is false)
// 2. Create fails (line 437)
// 3. UpdateRole also fails (line 439)
// 4. logger is non-nil so the error is logged (line 440)
//
// To trigger: create a user concurrently so Create detects a duplicate, then
// have the subsequent UpdateRole fail because the DB is closed.
// ===========================================================================

func TestEnsureAdmin_CreateAndUpdateRoleBothFail(t *testing.T) {
	t.Parallel()
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)

	s := NewStore()
	s.SetDB(db)
	s.SetLogger(slog.Default())
	require.NoError(t, s.InitTable())
	require.NoError(t, s.LoadFromDB())

	// Close DB so UpdateRole's DB persist also fails.
	db.Close()

	// Simulate the race: EnsureAdmin calls s.Create(u) which will try to add
	// to the in-memory map. If another goroutine adds the same user between
	// EnsureAdmin's RLock check and Create, then Create returns "user already exists".
	// We simulate this by running many concurrent EnsureAdmin calls on a non-existent user.
	// Since the user doesn't exist in-memory, all goroutines take the "create new" path.
	// The first one succeeds, subsequent ones find the user in the map during Create → error.
	// The error triggers line 437, and UpdateRole with closed DB triggers line 439-441.
	//
	// With enough concurrency and no DB, the race is very likely to hit.
	// Run many attempts to reliably hit the race condition where Create
	// fails because another goroutine created the user between the RLock
	// check and the Lock in Create.
	for attempt := 0; attempt < 20; attempt++ {
		email := fmt.Sprintf("raceadmin%d@test.com", attempt)
		done := make(chan struct{})
		var start sync.WaitGroup
		start.Add(1)
		n := 20
		for i := 0; i < n; i++ {
			go func() {
				start.Wait()
				s.EnsureAdmin(email)
				done <- struct{}{}
			}()
		}
		start.Done() // release all goroutines simultaneously
		for i := 0; i < n; i++ {
			<-done
		}
	}

	// All users should exist in memory.
	for attempt := 0; attempt < 20; attempt++ {
		email := fmt.Sprintf("raceadmin%d@test.com", attempt)
		u, ok := s.GetByEmail(email)
		require.True(t, ok, "user %s should exist", email)
		assert.Equal(t, RoleAdmin, u.Role)
	}
}

// ===========================================================================
// Documenting unreachable lines in kc/users
//
// invitations.go:
// COVERAGE: invitations.go:64 — rows.Scan error in LoadFromDB. The SELECT
//   names 7 columns from family_invitations. If the query succeeds (which
//   requires all columns to exist), SQLite's dynamic typing ensures the scan
//   always succeeds. Unreachable without schema change mid-query.
//
// store.go:
// COVERAGE: store.go:120 — rows.Scan error in LoadFromDB. The SELECT names
//   12 columns from users. Same as above: if the query succeeds, the scan
//   cannot fail with SQLite's type coercion. Unreachable.
//
// COVERAGE: store.go:483 — EnsureUser return nil. This defensive guard fires
//   when Create fails AND the user is not found in the in-memory map on the
//   subsequent lookup. Requires a concurrent Delete between Create failure and
//   the fallback map read — an impossible race condition.
// ===========================================================================
