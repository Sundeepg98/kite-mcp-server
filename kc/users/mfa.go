// Package users — MFA (TOTP) enrollment storage on the User store.
//
// This file extends Store with TOTP-based MFA. It treats the TOTP secret
// as T1 data (per docs/data-classification.md): AES-256-GCM encrypted at
// rest using the same HKDF-derived key the rest of T1 storage uses.
//
// Scope: ADMIN ROLE ONLY in this slice. Per the user-direction in the
// brief ("Out of scope: Non-admin user MFA"), enrollment for non-admins
// is rejected at this layer rather than in the HTTP handler — defence in
// depth so a misconfigured route can't sidestep the gate.
//
// All methods are thread-safe and follow the same lock-then-snapshot-
// then-DB pattern the password / role helpers in store.go use.
package users

import (
	"fmt"
	"strings"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
)

// SetEncryptionKey wires the AES-256 key used to encrypt TOTP secrets at
// rest. The caller (composition root in app/wire.go) is expected to
// supply the same HKDF-derived key the rest of the alerts.DB uses, so
// rotation via the existing migrateEncryptedData path stays one operation.
//
// Calling SetTOTPSecret without first calling SetEncryptionKey is a
// programming error and returns an explicit error rather than silently
// storing plaintext — silent plaintext storage would be a T1 protection
// regression, hence fail-closed.
func (s *Store) SetEncryptionKey(key []byte) {
	s.mu.Lock()
	s.encryptionKey = key
	s.mu.Unlock()
}

// hasEncryptionKey reports whether SetEncryptionKey was called.
func (s *Store) hasEncryptionKey() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.encryptionKey) > 0
}

// HasTOTP returns true if the user has an enrolled TOTP secret.
// Unknown users return false (no error path) so the call site can use
// this as a single-line gate.
func (s *Store) HasTOTP(email string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[strings.ToLower(email)]
	return ok && u.TOTPSecretEnc != ""
}

// SetTOTPSecret encrypts and persists a TOTP secret for the given user.
// Returns error in three cases:
//   - encryption key not configured (store-level misconfig)
//   - user not found (call site bug — enroll route should always pre-check)
//   - user is not an admin (slice-1 invariant: MFA is admin-only here)
func (s *Store) SetTOTPSecret(email, plaintextSecret string) error {
	if !s.hasEncryptionKey() {
		return fmt.Errorf("totp: encryption key not configured")
	}
	key := strings.ToLower(strings.TrimSpace(email))
	now := time.Now()

	s.mu.Lock()
	u, ok := s.users[key]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("user not found: %s", key)
	}
	// Slice-1 invariant: MFA is admin-only. The HTTP layer also enforces
	// this, but persisting here for non-admins would let a future bug
	// silently widen the gate. Reject explicitly.
	if u.Role != RoleAdmin {
		s.mu.Unlock()
		return fmt.Errorf("totp enrollment requires admin role: user %s has role=%s", key, u.Role)
	}
	encKey := s.encryptionKey
	s.mu.Unlock()

	enc, err := alerts.Encrypt(encKey, plaintextSecret)
	if err != nil {
		return fmt.Errorf("totp: encrypt secret: %w", err)
	}

	s.mu.Lock()
	u, ok = s.users[key]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("user not found after encrypt: %s", key)
	}
	u.TOTPSecretEnc = enc
	u.TOTPEnrolledAt = now
	u.UpdatedAt = now
	s.mu.Unlock()

	if s.db != nil {
		nowStr := now.Format(time.RFC3339)
		if err := s.db.ExecInsert(
			`UPDATE users SET totp_secret_enc = ?, totp_enrolled_at = ?, updated_at = ? WHERE email = ?`,
			enc, nowStr, nowStr, key,
		); err != nil {
			return fmt.Errorf("persist totp secret: %w", err)
		}
	}
	return nil
}

// GetTOTPSecret returns the decrypted TOTP secret for the given user.
// Returns ("", false) if the user is not enrolled or unknown, or if
// decryption fails (likely key rotation drift). The bool reports
// "successfully retrieved a usable secret"; callers MUST treat false
// as "not enrolled" and not as an error condition.
func (s *Store) GetTOTPSecret(email string) (string, bool) {
	s.mu.RLock()
	u, ok := s.users[strings.ToLower(email)]
	var enc string
	if ok {
		enc = u.TOTPSecretEnc
	}
	encKey := s.encryptionKey
	s.mu.RUnlock()

	if !ok || enc == "" || len(encKey) == 0 {
		return "", false
	}
	plaintext := alerts.Decrypt(encKey, enc)
	if plaintext == "" {
		// alerts.Decrypt returns "" on decryption failure (e.g., key
		// rotation drift). Treat as not-enrolled rather than panic.
		return "", false
	}
	return plaintext, true
}

// VerifyTOTP returns (true, nil) if the supplied 6-digit code matches
// the user's stored TOTP secret within the default skew window. Returns
// (false, nil) for any non-match (wrong code, not enrolled, unknown
// user). Returns a non-nil error only on infrastructure failure
// (encryption key missing). Callers should route a not-enrolled user
// to enrollment, not treat the false as authentication failure.
func (s *Store) VerifyTOTP(email, code string) (bool, error) {
	secret, ok := s.GetTOTPSecret(email)
	if !ok {
		return false, nil
	}
	return VerifyTOTPCode(secret, code, time.Now(), TOTPSkewSteps), nil
}

// ClearTOTPSecret removes a user's TOTP enrollment. Used by an admin
// recovery flow (lost-device) and by the offboarding path. Returns
// error if the user is not found.
func (s *Store) ClearTOTPSecret(email string) error {
	key := strings.ToLower(email)
	now := time.Now()

	s.mu.Lock()
	u, ok := s.users[key]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("user not found: %s", key)
	}
	u.TOTPSecretEnc = ""
	u.TOTPEnrolledAt = time.Time{}
	u.UpdatedAt = now
	s.mu.Unlock()

	if s.db != nil {
		nowStr := now.Format(time.RFC3339)
		if err := s.db.ExecInsert(
			`UPDATE users SET totp_secret_enc = '', totp_enrolled_at = '', updated_at = ? WHERE email = ?`,
			nowStr, key,
		); err != nil {
			return fmt.Errorf("persist totp clear: %w", err)
		}
	}
	return nil
}

// TOTPEnrolledAt returns the enrollment timestamp for the user. Returns
// (zero, false) if the user is not enrolled or unknown.
func (s *Store) TOTPEnrolledAt(email string) (time.Time, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[strings.ToLower(email)]
	if !ok || u.TOTPSecretEnc == "" {
		return time.Time{}, false
	}
	return u.TOTPEnrolledAt, true
}
