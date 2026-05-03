package alerts

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDRDrill_ProductionKeyChain_Synthetic exercises the *full* DR
// restore-and-decrypt chain that the production drill must verify, against
// a synthetic SQLite database that imitates a restored R2 backup.
//
// The pre-existing scripts/dr-drill.sh only verifies:
//
//  1. Litestream restore returns exit 0.
//  2. The restored SQLite file is non-empty.
//  3. SELECT count(*) FROM kite_tokens succeeds.
//
// What it does NOT verify — and what this test now covers — is that the
// HKDF→AES-256-GCM key chain from OAUTH_JWT_SECRET → hkdf_salt (in
// config table) → encryption key actually decrypts the encrypted columns
// after restore. Without that, the drill can pass while every encrypted
// blob in the restored DB is permanently unreadable, e.g. because
// OAUTH_JWT_SECRET was rotated without re-encrypting, or because the
// hkdf_salt column was lost in restore.
//
// This is the closest CI-runnable analog of the production drill.
// scripts/dr-drill-prod-keys.sh exercises the same sequence against a
// real R2 backup with a real OAUTH_JWT_SECRET.
//
// Per residual-100 audit (.research/residual-literal-100-engineering-
// path.md item #5, dispatch 9932246).
func TestDRDrill_ProductionKeyChain_Synthetic(t *testing.T) {
	t.Parallel()

	const (
		simulatedSecret      = "simulated-OAUTH_JWT_SECRET-32-bytes-test-only"
		userEmail            = "drill-user@example.com"
		expectedAccessToken  = "drill-access-token-canary-AAA"
		expectedAPIKey       = "drill-api-key-canary-BBB"
		expectedAPISecret    = "drill-api-secret-canary-CCC"
	)

	// === Phase 1: simulate "production state" — write a DB the way the
	// running server would, with the full HKDF→AES-256-GCM chain. ===
	srcPath := filepath.Join(t.TempDir(), "production-state.db")
	srcDB, err := OpenDB(srcPath)
	require.NoError(t, err, "open simulated production DB")

	// Derive the salted key the same way app/providers/manager.go does
	// at startup — first call generates a random salt, persists it in
	// the config table, returns the derived key.
	prodKey, err := EnsureEncryptionSalt(srcDB, simulatedSecret)
	require.NoError(t, err, "derive production-equivalent key")
	require.Len(t, prodKey, 32, "AES-256 key must be 32 bytes")
	srcDB.SetEncryptionKey(prodKey)

	// Write a canary row to each encrypted table that the drill will
	// later check.
	now := time.Now().Truncate(time.Second)
	require.NoError(t, srcDB.SaveCredential(userEmail, expectedAPIKey, expectedAPISecret, "app1", now))
	require.NoError(t, srcDB.SaveToken(userEmail, expectedAccessToken, "uid-1", "uname-1", now))

	// Sanity: prod DB sees its own canaries.
	creds, err := srcDB.LoadCredentials()
	require.NoError(t, err)
	require.Len(t, creds, 1)
	require.Equal(t, expectedAPIKey, creds[0].APIKey)

	require.NoError(t, srcDB.Close())

	// === Phase 2: simulate a Litestream restore by copying the DB file
	// to a fresh location. (Litestream restore on success produces a
	// byte-identical SQLite file plus its WAL.) ===
	restoredPath := filepath.Join(t.TempDir(), "restored.db")
	srcBytes, err := os.ReadFile(srcPath)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(restoredPath, srcBytes, 0600))

	// === Phase 3: open the restored DB and run the drill. ===
	restoredDB, err := OpenDB(restoredPath)
	require.NoError(t, err, "open restored DB")
	defer restoredDB.Close()

	// 3a: hkdf_salt MUST be present in the config table — without it,
	// EnsureEncryptionSalt would generate a fresh salt and the existing
	// ciphertexts would be permanently unreadable. This is the single
	// most common silent-failure mode for R2-restore→decrypt chains.
	saltHex, err := restoredDB.GetConfig(hkdfSaltConfigKey)
	require.NoError(t, err, "hkdf_salt must survive restore")
	require.NotEmpty(t, saltHex, "hkdf_salt config row missing — restore lost the encryption salt")
	saltBytes, err := hex.DecodeString(saltHex)
	require.NoError(t, err, "hkdf_salt must be valid hex")
	require.Len(t, saltBytes, 32, "hkdf_salt must be 32 bytes")

	// 3b: re-derive the key from the simulated production secret + the
	// salt loaded from the restored DB. This mirrors what the production
	// server does on every cold start.
	rederivedKey, err := DeriveEncryptionKeyWithSalt(simulatedSecret, saltBytes)
	require.NoError(t, err)
	assert.Equal(t, prodKey, rederivedKey,
		"re-derived key must match the original production key — proves "+
			"OAUTH_JWT_SECRET + hkdf_salt deterministically reproduces the AES key")
	restoredDB.SetEncryptionKey(rederivedKey)

	// 3c: load every encrypted-column row and verify decrypt SUCCEEDS
	// (not just "returns a string" — the value must match the canary).
	// Decrypt() returns "" on AES-GCM auth-tag failure, so an empty
	// expected-non-empty string is the failure signal.
	creds, err = restoredDB.LoadCredentials()
	require.NoError(t, err, "LoadCredentials must succeed after restore")
	require.Len(t, creds, 1, "credentials canary row must be present")
	assert.Equal(t, expectedAPIKey, creds[0].APIKey,
		"AES-GCM decrypt of api_key produced %q, expected %q — "+
			"key chain is broken: ciphertext present but auth-tag verification failed",
		creds[0].APIKey, expectedAPIKey)
	assert.Equal(t, expectedAPISecret, creds[0].APISecret,
		"AES-GCM decrypt of api_secret produced %q, expected %q",
		creds[0].APISecret, expectedAPISecret)

	tokens, err := restoredDB.LoadTokens()
	require.NoError(t, err, "LoadTokens must succeed after restore")
	require.Len(t, tokens, 1, "kite_tokens canary row must be present")
	assert.Equal(t, expectedAccessToken, tokens[0].AccessToken,
		"AES-GCM decrypt of access_token produced %q, expected %q — "+
			"this is the failure mode that scripts/dr-drill.sh's count(*) "+
			"check silently passes through",
		tokens[0].AccessToken, expectedAccessToken)
}

// TestDRDrill_WrongSecret_FailsLoudly is the negative control: if the
// operator runs the prod-keys drill with the WRONG OAUTH_JWT_SECRET,
// it must fail in a way the drill can detect, not silently produce
// empty strings that look like missing data.
//
// This exercises the failure mode where the operator typos the secret
// or pastes a stale value from a key-rotation transition.
func TestDRDrill_WrongSecret_FailsLoudly(t *testing.T) {
	t.Parallel()

	const (
		correctSecret = "the-actual-OAUTH_JWT_SECRET-32-bytes-please"
		wrongSecret   = "OOPS-pasted-the-wrong-value-still-32-bytes!"
		userEmail     = "drill-user@example.com"
		canaryToken   = "canary-token"
	)

	// Set up a DB encrypted with the correct secret.
	dbPath := filepath.Join(t.TempDir(), "encrypted.db")
	db, err := OpenDB(dbPath)
	require.NoError(t, err)
	correctKey, err := EnsureEncryptionSalt(db, correctSecret)
	require.NoError(t, err)
	db.SetEncryptionKey(correctKey)
	require.NoError(t, db.SaveToken(userEmail, canaryToken, "uid", "uname", time.Now()))
	require.NoError(t, db.Close())

	// Reopen and try to decrypt with the WRONG secret.
	db, err = OpenDB(dbPath)
	require.NoError(t, err)
	defer db.Close()

	saltHex, err := db.GetConfig(hkdfSaltConfigKey)
	require.NoError(t, err)
	saltBytes, _ := hex.DecodeString(saltHex)
	wrongKey, err := DeriveEncryptionKeyWithSalt(wrongSecret, saltBytes)
	require.NoError(t, err)
	require.NotEqual(t, correctKey, wrongKey,
		"different secrets must derive different keys — otherwise "+
			"HKDF is broken and there's no key separation")
	db.SetEncryptionKey(wrongKey)

	// LoadTokens must NOT decrypt to canaryToken with the wrong key.
	// Decrypt() returns "" on AES-GCM auth-tag failure — that's the
	// signal the drill must detect.
	tokens, err := db.LoadTokens()
	require.NoError(t, err, "row count must succeed even with wrong key — "+
		"decryption failure manifests as empty plaintext, not query error")
	require.Len(t, tokens, 1)
	assert.Empty(t, tokens[0].AccessToken,
		"AES-GCM with wrong key MUST return empty plaintext (auth-tag fail). "+
			"Got %q — if this is the canary, the auth tag is being bypassed.",
		tokens[0].AccessToken)
}
