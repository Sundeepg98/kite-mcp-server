package users

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
)

// newTestStoreWithKey returns a Store with DB + a deterministic encryption
// key wired so MFA secrets are encrypted at rest. Used by tests that
// exercise the encrypted-column round-trip.
func newTestStoreWithKey(t *testing.T) (*Store, *alerts.DB) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "mfa.db")
	db, err := alerts.OpenDB(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	// Deterministic 32-byte key (AES-256). Real production derives via HKDF
	// from OAUTH_JWT_SECRET; tests don't need that — they just need a stable
	// key the round-trip can use.
	key, err := alerts.DeriveEncryptionKey("test-key-deterministic-do-not-use-in-prod")
	require.NoError(t, err)

	s := NewStore()
	s.SetDB(db)
	s.SetEncryptionKey(key)
	require.NoError(t, s.InitTable())
	require.NoError(t, s.LoadFromDB())
	return s, db
}

// TestStore_HasTOTP_NotEnrolled — fresh user without MFA returns false.
func TestStore_HasTOTP_NotEnrolled(t *testing.T) {
	t.Parallel()
	s, _ := newTestStoreWithKey(t)
	require.NoError(t, s.Create(&User{ID: "u_1", Email: "noenroll@example.com"}))
	assert.False(t, s.HasTOTP("noenroll@example.com"))
}

// TestStore_HasTOTP_UnknownUser — unknown email returns false (no error).
func TestStore_HasTOTP_UnknownUser(t *testing.T) {
	t.Parallel()
	s, _ := newTestStoreWithKey(t)
	assert.False(t, s.HasTOTP("nobody@example.com"))
}

// TestStore_SetTOTPSecret_HappyPath — Set persists, Has returns true,
// Get returns the same plaintext we stored.
func TestStore_SetTOTPSecret_HappyPath(t *testing.T) {
	t.Parallel()
	s, _ := newTestStoreWithKey(t)
	require.NoError(t, s.Create(&User{ID: "u_1", Email: "a@example.com", Role: RoleAdmin}))

	secret, err := GenerateTOTPSecret()
	require.NoError(t, err)
	require.NoError(t, s.SetTOTPSecret("a@example.com", secret))

	assert.True(t, s.HasTOTP("a@example.com"))
	got, ok := s.GetTOTPSecret("a@example.com")
	require.True(t, ok)
	assert.Equal(t, secret, got)
}

// TestStore_SetTOTPSecret_PersistsAcrossReload — encryption survives a
// full LoadFromDB cycle. Confirms the secret is being persisted, not just
// kept in RAM.
func TestStore_SetTOTPSecret_PersistsAcrossReload(t *testing.T) {
	t.Parallel()
	dbPath := filepath.Join(t.TempDir(), "persist.db")
	db, err := alerts.OpenDB(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	key, err := alerts.DeriveEncryptionKey("test-key-deterministic-do-not-use-in-prod")
	require.NoError(t, err)

	// Write phase.
	s1 := NewStore()
	s1.SetDB(db)
	s1.SetEncryptionKey(key)
	require.NoError(t, s1.InitTable())
	require.NoError(t, s1.LoadFromDB())
	require.NoError(t, s1.Create(&User{ID: "u_1", Email: "p@example.com", Role: RoleAdmin}))
	secret, err := GenerateTOTPSecret()
	require.NoError(t, err)
	require.NoError(t, s1.SetTOTPSecret("p@example.com", secret))

	// Read phase: a fresh Store loading the same DB must see the secret.
	s2 := NewStore()
	s2.SetDB(db)
	s2.SetEncryptionKey(key)
	require.NoError(t, s2.LoadFromDB())
	got, ok := s2.GetTOTPSecret("p@example.com")
	require.True(t, ok, "MFA secret must survive reload")
	assert.Equal(t, secret, got)
}

// TestStore_SetTOTPSecret_StoresEncrypted — the on-disk row must NOT
// equal the plaintext secret. Reads the raw column directly to prove
// encryption is actually happening (not just a no-op pass-through).
func TestStore_SetTOTPSecret_StoresEncrypted(t *testing.T) {
	t.Parallel()
	s, db := newTestStoreWithKey(t)
	require.NoError(t, s.Create(&User{ID: "u_1", Email: "enc@example.com", Role: RoleAdmin}))

	plaintext := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	require.NoError(t, s.SetTOTPSecret("enc@example.com", plaintext))

	// Bypass the store and read the raw column.
	rows, err := db.RawQuery(`SELECT totp_secret_enc FROM users WHERE email = ?`, "enc@example.com")
	require.NoError(t, err)
	defer rows.Close()
	require.True(t, rows.Next(), "expected one row")
	var enc string
	require.NoError(t, rows.Scan(&enc))
	assert.NotEqual(t, plaintext, enc, "DB column must be encrypted, not the plaintext secret")
	assert.NotEmpty(t, enc, "DB column must contain ciphertext, not empty")
}

// TestStore_SetTOTPSecret_NoEncryptionKey — without an encryption key,
// SetTOTPSecret must REFUSE rather than store plaintext. Storing
// plaintext would degrade T1 protection silently.
func TestStore_SetTOTPSecret_NoEncryptionKey(t *testing.T) {
	t.Parallel()
	s, _ := newTestStoreWithDB(t)
	require.NoError(t, s.Create(&User{ID: "u_1", Email: "k@example.com", Role: RoleAdmin}))
	err := s.SetTOTPSecret("k@example.com", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
	require.Error(t, err, "must refuse to store TOTP secret without encryption key")
	assert.Contains(t, err.Error(), "encryption key")
}

// TestStore_SetTOTPSecret_UnknownUser — must error rather than silently
// no-op (the SetPasswordHash path errors the same way for consistency).
func TestStore_SetTOTPSecret_UnknownUser(t *testing.T) {
	t.Parallel()
	s, _ := newTestStoreWithKey(t)
	err := s.SetTOTPSecret("nobody@example.com", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user not found")
}

// TestStore_VerifyTOTP_HappyPath — code generated from the stored secret
// must verify true.
func TestStore_VerifyTOTP_HappyPath(t *testing.T) {
	t.Parallel()
	s, _ := newTestStoreWithKey(t)
	require.NoError(t, s.Create(&User{ID: "u_1", Email: "v@example.com", Role: RoleAdmin}))
	secret, err := GenerateTOTPSecret()
	require.NoError(t, err)
	require.NoError(t, s.SetTOTPSecret("v@example.com", secret))

	code, err := GenerateTOTPCode(secret, time.Now())
	require.NoError(t, err)

	ok, err := s.VerifyTOTP("v@example.com", code)
	require.NoError(t, err)
	assert.True(t, ok)
}

// TestStore_VerifyTOTP_WrongCode — invalid code must return false, no error.
func TestStore_VerifyTOTP_WrongCode(t *testing.T) {
	t.Parallel()
	s, _ := newTestStoreWithKey(t)
	require.NoError(t, s.Create(&User{ID: "u_1", Email: "w@example.com", Role: RoleAdmin}))
	secret, err := GenerateTOTPSecret()
	require.NoError(t, err)
	require.NoError(t, s.SetTOTPSecret("w@example.com", secret))

	ok, err := s.VerifyTOTP("w@example.com", "000000")
	require.NoError(t, err)
	assert.False(t, ok)
}

// TestStore_VerifyTOTP_NotEnrolled — verifying for a user without TOTP
// must return false (no error) so the caller can route to enrollment.
func TestStore_VerifyTOTP_NotEnrolled(t *testing.T) {
	t.Parallel()
	s, _ := newTestStoreWithKey(t)
	require.NoError(t, s.Create(&User{ID: "u_1", Email: "ne@example.com", Role: RoleAdmin}))
	ok, err := s.VerifyTOTP("ne@example.com", "123456")
	require.NoError(t, err)
	assert.False(t, ok)
}

// TestStore_ClearTOTPSecret_RemovesEnrollment — Clear wipes both RAM and DB
// state; HasTOTP returns false afterwards.
func TestStore_ClearTOTPSecret_RemovesEnrollment(t *testing.T) {
	t.Parallel()
	s, _ := newTestStoreWithKey(t)
	require.NoError(t, s.Create(&User{ID: "u_1", Email: "c@example.com", Role: RoleAdmin}))
	secret, err := GenerateTOTPSecret()
	require.NoError(t, err)
	require.NoError(t, s.SetTOTPSecret("c@example.com", secret))
	require.True(t, s.HasTOTP("c@example.com"))

	require.NoError(t, s.ClearTOTPSecret("c@example.com"))
	assert.False(t, s.HasTOTP("c@example.com"))
	_, ok := s.GetTOTPSecret("c@example.com")
	assert.False(t, ok)
}

// TestStore_ClearTOTPSecret_UnknownUser — must error rather than silently
// no-op (consistent with Set / VerifyPassword shape).
func TestStore_ClearTOTPSecret_UnknownUser(t *testing.T) {
	t.Parallel()
	s, _ := newTestStoreWithKey(t)
	err := s.ClearTOTPSecret("nobody@example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user not found")
}

// TestStore_TOTPEnrolledAt_RecordedOnSet — enrollment timestamp must be
// set when SetTOTPSecret succeeds, and visible via the helper.
func TestStore_TOTPEnrolledAt_RecordedOnSet(t *testing.T) {
	t.Parallel()
	s, _ := newTestStoreWithKey(t)
	require.NoError(t, s.Create(&User{ID: "u_1", Email: "ts@example.com", Role: RoleAdmin}))

	before := time.Now().Add(-time.Second)
	secret, err := GenerateTOTPSecret()
	require.NoError(t, err)
	require.NoError(t, s.SetTOTPSecret("ts@example.com", secret))
	after := time.Now().Add(time.Second)

	enrolledAt, ok := s.TOTPEnrolledAt("ts@example.com")
	require.True(t, ok)
	assert.True(t, enrolledAt.After(before) && enrolledAt.Before(after),
		"enrolled_at %v should be between %v and %v", enrolledAt, before, after)
}

// TestStore_HasTOTP_RequiresAdmin — non-admin users should be rejected from
// TOTP enrollment because the feature is gating ONLY admin actions in this
// slice. The store layer rejects rather than the HTTP layer alone — defence
// in depth so a misconfigured route can't enroll a trader.
func TestStore_SetTOTPSecret_NonAdminRejected(t *testing.T) {
	t.Parallel()
	s, _ := newTestStoreWithKey(t)
	require.NoError(t, s.Create(&User{ID: "u_1", Email: "trader@example.com", Role: RoleTrader}))
	secret, err := GenerateTOTPSecret()
	require.NoError(t, err)
	err = s.SetTOTPSecret("trader@example.com", secret)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "admin")
}
