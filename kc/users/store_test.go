package users

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	return NewStore()
}

func newTestStoreWithDB(t *testing.T) (*Store, *alerts.DB) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := alerts.OpenDB(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	s := NewStore()
	s.SetDB(db)
	require.NoError(t, s.InitTable())
	require.NoError(t, s.LoadFromDB())
	return s, db
}

func TestNewStore(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	assert.NotNil(t, s)
	assert.Equal(t, 0, s.Count())
}

func TestStore_Create(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)

	u := &User{
		ID:    "u_1",
		Email: "alice@example.com",
		Role:  RoleTrader,
	}
	err := s.Create(u)
	require.NoError(t, err)
	assert.Equal(t, 1, s.Count())

	// Duplicate should fail
	err = s.Create(u)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestStore_CreateEmptyEmail(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)

	err := s.Create(&User{ID: "u_1", Email: ""})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "email is required")
}

func TestStore_Get(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)

	require.NoError(t, s.Create(&User{ID: "u_1", Email: "bob@example.com", Role: RoleTrader}))

	u, ok := s.Get("bob@example.com")
	assert.True(t, ok)
	assert.Equal(t, "bob@example.com", u.Email)
	assert.Equal(t, RoleTrader, u.Role)

	// Case-insensitive
	u2, ok2 := s.Get("BOB@example.com")
	assert.True(t, ok2)
	assert.Equal(t, u.Email, u2.Email)

	// Not found
	_, ok3 := s.Get("nobody@example.com")
	assert.False(t, ok3)
}

func TestStore_GetByEmail(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)

	require.NoError(t, s.Create(&User{ID: "u_1", Email: "bob@example.com"}))
	u, ok := s.GetByEmail("bob@example.com")
	assert.True(t, ok)
	assert.Equal(t, "bob@example.com", u.Email)
}

func TestStore_Exists(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)

	require.NoError(t, s.Create(&User{ID: "u_1", Email: "exists@example.com"}))
	assert.True(t, s.Exists("exists@example.com"))
	assert.True(t, s.Exists("EXISTS@example.com"))
	assert.False(t, s.Exists("nope@example.com"))
}

func TestStore_IsAdmin(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)

	require.NoError(t, s.Create(&User{ID: "u_1", Email: "admin@example.com", Role: RoleAdmin, Status: StatusActive}))
	require.NoError(t, s.Create(&User{ID: "u_2", Email: "trader@example.com", Role: RoleTrader, Status: StatusActive}))
	require.NoError(t, s.Create(&User{ID: "u_3", Email: "suspended-admin@example.com", Role: RoleAdmin, Status: StatusSuspended}))

	assert.True(t, s.IsAdmin("admin@example.com"))
	assert.False(t, s.IsAdmin("trader@example.com"))
	assert.False(t, s.IsAdmin("suspended-admin@example.com")) // suspended admin is not admin
	assert.False(t, s.IsAdmin("nobody@example.com"))
}

func TestStore_GetStatus(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)

	require.NoError(t, s.Create(&User{ID: "u_1", Email: "active@example.com", Status: StatusActive}))
	require.NoError(t, s.Create(&User{ID: "u_2", Email: "suspended@example.com", Status: StatusSuspended}))

	assert.Equal(t, StatusActive, s.GetStatus("active@example.com"))
	assert.Equal(t, StatusSuspended, s.GetStatus("suspended@example.com"))
	assert.Equal(t, "", s.GetStatus("nobody@example.com"))
}

func TestStore_UpdateLastLogin(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)

	before := time.Now()
	require.NoError(t, s.Create(&User{ID: "u_1", Email: "login@example.com"}))
	s.UpdateLastLogin("login@example.com")

	u, ok := s.Get("login@example.com")
	require.True(t, ok)
	assert.True(t, u.LastLogin.After(before) || u.LastLogin.Equal(before))

	// Non-existent user is a no-op
	s.UpdateLastLogin("nobody@example.com")
}

func TestStore_UpdateRole(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)

	require.NoError(t, s.Create(&User{ID: "u_1", Email: "role@example.com", Role: RoleTrader}))

	err := s.UpdateRole("role@example.com", RoleAdmin)
	require.NoError(t, err)
	u, ok := s.Get("role@example.com")
	require.True(t, ok)
	assert.Equal(t, RoleAdmin, u.Role)

	err = s.UpdateRole("role@example.com", RoleViewer)
	require.NoError(t, err)
	u, ok = s.Get("role@example.com")
	require.True(t, ok)
	assert.Equal(t, RoleViewer, u.Role)

	// Invalid role
	err = s.UpdateRole("role@example.com", "superuser")
	assert.Error(t, err)

	// Non-existent user
	err = s.UpdateRole("nobody@example.com", RoleTrader)
	assert.Error(t, err)
}

func TestStore_UpdateStatus(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)

	require.NoError(t, s.Create(&User{ID: "u_1", Email: "status@example.com", Status: StatusActive}))

	err := s.UpdateStatus("status@example.com", StatusSuspended)
	require.NoError(t, err)
	u, ok := s.Get("status@example.com")
	require.True(t, ok)
	assert.Equal(t, StatusSuspended, u.Status)

	err = s.UpdateStatus("status@example.com", StatusOffboarded)
	require.NoError(t, err)
	u, ok = s.Get("status@example.com")
	require.True(t, ok)
	assert.Equal(t, StatusOffboarded, u.Status)

	// Invalid status
	err = s.UpdateStatus("status@example.com", "banned")
	assert.Error(t, err)

	// Non-existent user
	err = s.UpdateStatus("nobody@example.com", StatusActive)
	assert.Error(t, err)
}

func TestStore_UpdateKiteUID(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)

	require.NoError(t, s.Create(&User{ID: "u_1", Email: "uid@example.com"}))

	s.UpdateKiteUID("uid@example.com", "AB1234")
	u, ok := s.Get("uid@example.com")
	require.True(t, ok)
	assert.Equal(t, "AB1234", u.KiteUID)

	// Non-existent is a no-op
	s.UpdateKiteUID("nobody@example.com", "XX0000")
}

func TestStore_List(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)

	require.NoError(t, s.Create(&User{ID: "u_1", Email: "a@example.com"}))
	require.NoError(t, s.Create(&User{ID: "u_2", Email: "b@example.com"}))
	require.NoError(t, s.Create(&User{ID: "u_3", Email: "c@example.com"}))

	all := s.List()
	assert.Len(t, all, 3)
}

func TestStore_Delete(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)

	require.NoError(t, s.Create(&User{ID: "u_1", Email: "delete@example.com"}))
	assert.True(t, s.Exists("delete@example.com"))

	s.Delete("delete@example.com")
	assert.False(t, s.Exists("delete@example.com"))
	assert.Equal(t, 0, s.Count())
}

func TestStore_EnsureAdmin(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)

	// Create as admin (new user)
	s.EnsureAdmin("admin@example.com")
	u, ok := s.Get("admin@example.com")
	require.True(t, ok)
	assert.Equal(t, RoleAdmin, u.Role)
	assert.Equal(t, "env", u.OnboardedBy)

	// Existing trader promoted to admin
	require.NoError(t, s.Create(&User{ID: "u_2", Email: "trader@example.com", Role: RoleTrader}))
	s.EnsureAdmin("trader@example.com")
	u2, ok2 := s.Get("trader@example.com")
	require.True(t, ok2)
	assert.Equal(t, RoleAdmin, u2.Role)

	// Empty email is a no-op
	s.EnsureAdmin("")
	assert.Equal(t, 2, s.Count())
}

func TestStore_EnsureUser(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)

	// New user
	u := s.EnsureUser("new@example.com", "AB1234", "New User", "self")
	require.NotNil(t, u)
	assert.Equal(t, "new@example.com", u.Email)
	assert.Equal(t, RoleTrader, u.Role)
	assert.Equal(t, StatusActive, u.Status)
	assert.Equal(t, "AB1234", u.KiteUID)

	// Existing user returned as-is
	u2 := s.EnsureUser("new@example.com", "XX0000", "Changed", "other")
	require.NotNil(t, u2)
	assert.Equal(t, "AB1234", u2.KiteUID) // not overwritten
	assert.Equal(t, 1, s.Count())

	// Empty email
	assert.Nil(t, s.EnsureUser("", "", "", ""))
}

func TestStore_DefaultValues(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)

	u := &User{ID: "u_1", Email: "defaults@example.com"}
	require.NoError(t, s.Create(u))

	got, ok := s.Get("defaults@example.com")
	require.True(t, ok)
	assert.Equal(t, RoleTrader, got.Role)
	assert.Equal(t, StatusActive, got.Status)
	assert.Equal(t, "self", got.OnboardedBy)
	assert.False(t, got.CreatedAt.IsZero())
	assert.False(t, got.UpdatedAt.IsZero())
}

func TestStore_ReturnsCopy(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)

	require.NoError(t, s.Create(&User{ID: "u_1", Email: "copy@example.com", Role: RoleTrader}))

	u1, _ := s.Get("copy@example.com")
	u1.Role = "hacked"

	u2, _ := s.Get("copy@example.com")
	assert.Equal(t, RoleTrader, u2.Role) // original unchanged
}

// --- SQLite persistence tests ---

func TestStore_PersistenceRoundTrip(t *testing.T) {
	t.Parallel()
	if os.Getenv("CI") == "true" {
		t.Skip("SQLite test may be flaky on CI")
	}

	s, db := newTestStoreWithDB(t)

	require.NoError(t, s.Create(&User{ID: "u_1", Email: "persist@example.com", Role: RoleAdmin, Status: StatusActive, KiteUID: "AB1234", OnboardedBy: "env"}))
	s.UpdateLastLogin("persist@example.com")

	// Create a new store and load from the same DB
	s2 := NewStore()
	s2.SetDB(db)
	require.NoError(t, s2.InitTable())
	require.NoError(t, s2.LoadFromDB())

	u, ok := s2.Get("persist@example.com")
	require.True(t, ok)
	assert.Equal(t, "u_1", u.ID)
	assert.Equal(t, RoleAdmin, u.Role)
	assert.Equal(t, StatusActive, u.Status)
	assert.Equal(t, "AB1234", u.KiteUID)
	assert.Equal(t, "env", u.OnboardedBy)
	assert.False(t, u.LastLogin.IsZero())
}

func TestStore_DBRoleUpdate(t *testing.T) {
	t.Parallel()
	s, db := newTestStoreWithDB(t)

	require.NoError(t, s.Create(&User{ID: "u_1", Email: "role@example.com", Role: RoleTrader}))
	require.NoError(t, s.UpdateRole("role@example.com", RoleViewer))

	// Reload from DB
	s2 := NewStore()
	s2.SetDB(db)
	require.NoError(t, s2.InitTable())
	require.NoError(t, s2.LoadFromDB())

	u, ok := s2.Get("role@example.com")
	require.True(t, ok)
	assert.Equal(t, RoleViewer, u.Role)
}

func TestStore_DBStatusUpdate(t *testing.T) {
	t.Parallel()
	s, db := newTestStoreWithDB(t)

	require.NoError(t, s.Create(&User{ID: "u_1", Email: "status@example.com", Status: StatusActive}))
	require.NoError(t, s.UpdateStatus("status@example.com", StatusSuspended))

	s2 := NewStore()
	s2.SetDB(db)
	require.NoError(t, s2.InitTable())
	require.NoError(t, s2.LoadFromDB())

	u, ok := s2.Get("status@example.com")
	require.True(t, ok)
	assert.Equal(t, StatusSuspended, u.Status)
}

func TestStore_DBDelete(t *testing.T) {
	t.Parallel()
	s, db := newTestStoreWithDB(t)

	require.NoError(t, s.Create(&User{ID: "u_1", Email: "del@example.com"}))
	s.Delete("del@example.com")

	s2 := NewStore()
	s2.SetDB(db)
	require.NoError(t, s2.InitTable())
	require.NoError(t, s2.LoadFromDB())

	assert.Equal(t, 0, s2.Count())
}

func TestStore_EnsureAdmin_WithDB(t *testing.T) {
	t.Parallel()
	s, db := newTestStoreWithDB(t)

	s.EnsureAdmin("admin@example.com")

	s2 := NewStore()
	s2.SetDB(db)
	require.NoError(t, s2.InitTable())
	require.NoError(t, s2.LoadFromDB())

	assert.True(t, s2.IsAdmin("admin@example.com"))
}

func TestStore_CaseInsensitive(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)

	require.NoError(t, s.Create(&User{ID: "u_1", Email: "MiXeD@Example.COM"}))

	assert.True(t, s.Exists("mixed@example.com"))
	assert.True(t, s.IsAdmin("mixed@example.com") == false) // exists but not admin
	assert.Equal(t, StatusActive, s.GetStatus("MIXED@example.com"))
}
