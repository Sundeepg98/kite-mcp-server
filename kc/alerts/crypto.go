package alerts

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// hashSessionID returns HMAC-SHA256(encryptionKey, sessionID) as a hex string.
// If no encryption key is configured, the session ID is returned as-is (fallback).
// Used by the mcp_sessions PK so plaintext session IDs never appear in the DB.
func (d *DB) hashSessionID(sessionID string) string {
	if d.encryptionKey == nil {
		return sessionID
	}
	mac := hmac.New(sha256.New, d.encryptionKey)
	mac.Write([]byte(sessionID))
	return hex.EncodeToString(mac.Sum(nil))
}

// DeriveEncryptionKey derives a 32-byte AES-256 key from a secret using HKDF-SHA256
// with a nil salt (legacy). Retained for backward compatibility during migration.
// New code should use DeriveEncryptionKeyWithSalt.
func DeriveEncryptionKey(secret string) ([]byte, error) {
	return DeriveEncryptionKeyWithSalt(secret, nil)
}

// DeriveEncryptionKeyWithSalt derives a 32-byte AES-256 key from a secret using
// HKDF-SHA256 with the provided salt. Per RFC 5869, a random salt strengthens the
// extract step and is recommended over a nil/zero salt.
func DeriveEncryptionKeyWithSalt(secret string, salt []byte) ([]byte, error) {
	if secret == "" {
		return nil, fmt.Errorf("empty secret")
	}
	hkdfReader := hkdf.New(sha256.New, []byte(secret), salt, []byte("kite-mcp-credential-encryption-v1"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, key); err != nil { // COVERAGE: unreachable — HKDF always produces requested bytes with valid inputs
		return nil, fmt.Errorf("hkdf derive: %w", err)
	}
	return key, nil
}

// hkdfSaltConfigKey is the config table key under which the HKDF salt is stored.
const hkdfSaltConfigKey = "hkdf_salt"

// EnsureEncryptionSalt ensures a random 32-byte HKDF salt exists in the database,
// derives the salted encryption key, and migrates all encrypted data from the old
// nil-salt key to the new salted key on first run. On subsequent runs it simply
// loads the salt and returns the salted key.
//
// Returns the salted encryption key ready for use.
func EnsureEncryptionSalt(db *DB, secret string) ([]byte, error) {
	if secret == "" {
		return nil, fmt.Errorf("empty secret")
	}

	saltHex, err := db.GetConfig(hkdfSaltConfigKey)
	if err == nil && saltHex != "" {
		// Salt already exists — derive key with it and return.
		salt, decErr := hex.DecodeString(saltHex)
		if decErr != nil {
			return nil, fmt.Errorf("decode stored salt: %w", decErr)
		}
		return DeriveEncryptionKeyWithSalt(secret, salt)
	}

	// First run: generate random 32-byte salt.
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil { // COVERAGE: unreachable — Go 1.25 crypto/rand.Read is fatal on failure
		return nil, fmt.Errorf("generate salt: %w", err)
	}

	// Derive old key (nil salt) and new key (with salt).
	oldKey, err := DeriveEncryptionKey(secret)
	if err != nil { // COVERAGE: unreachable — secret is non-empty (checked above), DeriveEncryptionKey always succeeds
		return nil, fmt.Errorf("derive old key: %w", err)
	}
	newKey, err := DeriveEncryptionKeyWithSalt(secret, salt)
	if err != nil { // COVERAGE: unreachable — same as above
		return nil, fmt.Errorf("derive new key: %w", err)
	}

	// Migrate all encrypted columns from old key to new key.
	if err := migrateEncryptedData(db, oldKey, newKey); err != nil {
		return nil, fmt.Errorf("migrate encrypted data: %w", err)
	}

	// Persist the salt only after successful migration.
	if err := db.SetConfig(hkdfSaltConfigKey, hex.EncodeToString(salt)); err != nil {
		return nil, fmt.Errorf("store salt: %w", err)
	}

	return newKey, nil
}

// migrateEncryptedData re-encrypts all sensitive columns from oldKey to newKey.
// Tables: kite_tokens (access_token), kite_credentials (api_key, api_secret),
// oauth_clients (client_secret), mcp_sessions (session_id_enc).
func migrateEncryptedData(db *DB, oldKey, newKey []byte) error {
	tables := []struct {
		table   string
		pkCol   string
		columns []string
	}{
		{"kite_tokens", "email", []string{"access_token"}},
		{"kite_credentials", "email", []string{"api_key", "api_secret"}},
		{"oauth_clients", "client_id", []string{"client_secret"}},
		{"mcp_sessions", "session_id", []string{"session_id_enc"}},
	}

	for _, t := range tables {
		if err := reEncryptTable(db, oldKey, newKey, t.table, t.pkCol, t.columns); err != nil {
			return fmt.Errorf("re-encrypt %s: %w", t.table, err)
		}
	}
	return nil
}

// reEncryptTable reads each row from the given table, decrypts the specified
// columns with oldKey, re-encrypts with newKey, and updates the row.
func reEncryptTable(db *DB, oldKey, newKey []byte, table, pkCol string, columns []string) error {
	selectCols := pkCol
	for _, col := range columns {
		selectCols += ", " + col
	}
	query := fmt.Sprintf("SELECT %s FROM %s", selectCols, table) //nolint:gosec

	rows, err := db.RawQuery(query)
	if err != nil {
		return fmt.Errorf("query: %w", err)
	}
	defer rows.Close()

	type row struct {
		pk     string
		values []string
	}
	var allRows []row
	for rows.Next() {
		r := row{values: make([]string, len(columns))}
		scanDest := make([]any, 1+len(columns))
		scanDest[0] = &r.pk
		for i := range columns {
			scanDest[i+1] = &r.values[i]
		}
		if err := rows.Scan(scanDest...); err != nil { // COVERAGE: unreachable — SQLite query success implies scan success
			return fmt.Errorf("scan: %w", err)
		}
		allRows = append(allRows, r)
	}
	if err := rows.Err(); err != nil { // COVERAGE: unreachable — SQLite driver doesn't produce mid-iteration errors
		return fmt.Errorf("iterate: %w", err)
	}

	for _, r := range allRows {
		setClauses := ""
		args := make([]any, 0, len(columns)+1)
		for i, encVal := range r.values {
			if encVal == "" {
				// Empty value — nothing to re-encrypt.
				if i > 0 {
					setClauses += ", "
				}
				setClauses += columns[i] + " = ?"
				args = append(args, encVal)
				continue
			}
			plaintext := Decrypt(oldKey, encVal)
			reEncrypted, err := Encrypt(newKey, plaintext)
			if err != nil {
				return fmt.Errorf("encrypt %s for pk=%s: %w", columns[i], r.pk, err)
			}
			if i > 0 {
				setClauses += ", "
			}
			setClauses += columns[i] + " = ?"
			args = append(args, reEncrypted)
		}
		args = append(args, r.pk)
		updateQuery := fmt.Sprintf("UPDATE %s SET %s WHERE %s = ?", table, setClauses, pkCol) //nolint:gosec
		if _, err := db.ExecResult(updateQuery, args...); err != nil {
			return fmt.Errorf("update pk=%s: %w", r.pk, err)
		}
	}

	return nil
}

// encrypt encrypts plaintext using AES-256-GCM and returns hex-encoded ciphertext.
// Format: hex(nonce || ciphertext || tag)
func encrypt(key []byte, plaintext string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil { // COVERAGE: unreachable — callers always provide valid 16/24/32-byte key
		return "", fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil { // COVERAGE: unreachable — NewGCM never fails with standard AES block
		return "", fmt.Errorf("gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil { // COVERAGE: unreachable — Go 1.25 crypto/rand.Read is fatal on failure
		return "", fmt.Errorf("nonce: %w", err)
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return hex.EncodeToString(sealed), nil
}

// Encrypt encrypts plaintext using AES-256-GCM with the given key.
// This is the exported wrapper around encrypt for use by external tools (e.g. key rotation CLI).
func Encrypt(key []byte, plaintext string) (string, error) {
	return encrypt(key, plaintext)
}

// Decrypt decrypts hex-encoded AES-256-GCM ciphertext with the given key.
// This is the exported wrapper around decrypt for use by external tools (e.g. key rotation CLI).
func Decrypt(key []byte, hexCiphertext string) string {
	return decrypt(key, hexCiphertext)
}

// decrypt decrypts hex-encoded AES-256-GCM ciphertext.
// Returns the plaintext string. If the value is not valid hex or fails
// decryption, returns it as-is (plaintext fallback for migration).
func decrypt(key []byte, hexCiphertext string) string {
	data, err := hex.DecodeString(hexCiphertext)
	if err != nil {
		return hexCiphertext // Not hex — treat as plaintext (pre-encryption data)
	}
	block, err := aes.NewCipher(key)
	if err != nil { // COVERAGE: unreachable — callers always provide valid 32-byte key
		return hexCiphertext
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil { // COVERAGE: unreachable — NewGCM never fails with standard AES block
		return hexCiphertext
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return hexCiphertext
	}
	plaintext, err := gcm.Open(nil, data[:nonceSize], data[nonceSize:], nil)
	if err != nil {
		return "" // Decryption failed on valid hex data — don't leak ciphertext
	}
	return string(plaintext)
}
