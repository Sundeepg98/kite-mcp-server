package users

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"golang.org/x/crypto/bcrypt"
)

// Role constants for user access control.
const (
	RoleAdmin  = "admin"
	RoleTrader = "trader"
	RoleViewer = "viewer"
)

// Status constants for user lifecycle.
const (
	StatusActive     = "active"
	StatusSuspended  = "suspended"
	StatusOffboarded = "offboarded"
)

// User represents a registered user of the system.
type User struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	KiteUID      string    `json:"kite_uid,omitempty"`
	DisplayName  string    `json:"display_name,omitempty"`
	Role         string    `json:"role"`
	Status       string    `json:"status"`
	PasswordHash string    `json:"-"` // bcrypt hash, never serialized
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	LastLogin    time.Time `json:"last_login,omitempty"`
	OnboardedBy  string    `json:"onboarded_by"`
}

// Store is a thread-safe in-memory user store backed by SQLite.
type Store struct {
	mu     sync.RWMutex
	users  map[string]*User // keyed by lowercase email
	db     *alerts.DB
	logger *slog.Logger
}

// NewStore creates a new user store.
func NewStore() *Store {
	return &Store{
		users: make(map[string]*User),
	}
}

// SetDB enables write-through persistence to the given SQLite database.
func (s *Store) SetDB(db *alerts.DB) {
	s.db = db
}

// SetLogger sets the logger for DB error reporting.
func (s *Store) SetLogger(logger *slog.Logger) {
	s.logger = logger
}

// InitTable creates the users table if it does not exist.
func (s *Store) InitTable() error {
	if s.db == nil {
		return nil
	}
	ddl := `
CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    email         TEXT UNIQUE NOT NULL,
    kite_uid      TEXT DEFAULT '',
    display_name  TEXT DEFAULT '',
    role          TEXT NOT NULL DEFAULT 'trader' CHECK(role IN ('admin','trader','viewer')),
    status        TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','suspended','offboarded')),
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    last_login    TEXT,
    onboarded_by  TEXT DEFAULT 'self'
);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);`
	if err := s.db.ExecDDL(ddl); err != nil {
		return err
	}
	// Migration: add password_hash column for admin password-based login.
	// ALTER TABLE ADD COLUMN is idempotent-safe in SQLite (errors if column exists).
	_ = s.db.ExecDDL(`ALTER TABLE users ADD COLUMN password_hash TEXT DEFAULT ''`)
	return nil
}

// LoadFromDB populates the in-memory store from the database.
func (s *Store) LoadFromDB() error {
	if s.db == nil {
		return nil
	}
	rows, err := s.db.RawQuery(`SELECT id, email, kite_uid, display_name, role, status,
		created_at, updated_at, COALESCE(last_login, ''), onboarded_by, COALESCE(password_hash, '') FROM users`)
	if err != nil {
		return fmt.Errorf("query users: %w", err)
	}
	defer rows.Close()

	s.mu.Lock()
	defer s.mu.Unlock()

	for rows.Next() {
		var u User
		var createdAtS, updatedAtS, lastLoginS, onboardedBy string
		if err := rows.Scan(&u.ID, &u.Email, &u.KiteUID, &u.DisplayName, &u.Role, &u.Status,
			&createdAtS, &updatedAtS, &lastLoginS, &onboardedBy, &u.PasswordHash); err != nil {
			return fmt.Errorf("scan user: %w", err)
		}
		u.CreatedAt, _ = time.Parse(time.RFC3339, createdAtS)
		u.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAtS)
		if lastLoginS != "" {
			u.LastLogin, _ = time.Parse(time.RFC3339, lastLoginS)
		}
		u.OnboardedBy = onboardedBy
		s.users[strings.ToLower(u.Email)] = &u
	}
	return rows.Err()
}

// Create inserts a new user into the store. Returns error if user already exists.
func (s *Store) Create(u *User) error {
	key := strings.ToLower(strings.TrimSpace(u.Email))
	if key == "" {
		return fmt.Errorf("email is required")
	}

	s.mu.Lock()
	if _, exists := s.users[key]; exists {
		s.mu.Unlock()
		return fmt.Errorf("user already exists: %s", key)
	}
	stored := *u
	stored.Email = key
	now := time.Now()
	if stored.CreatedAt.IsZero() {
		stored.CreatedAt = now
	}
	if stored.UpdatedAt.IsZero() {
		stored.UpdatedAt = now
	}
	if stored.Role == "" {
		stored.Role = RoleTrader
	}
	if stored.Status == "" {
		stored.Status = StatusActive
	}
	if stored.OnboardedBy == "" {
		stored.OnboardedBy = "self"
	}
	s.users[key] = &stored
	s.mu.Unlock()

	if s.db != nil {
		var lastLogin string
		if !stored.LastLogin.IsZero() {
			lastLogin = stored.LastLogin.Format(time.RFC3339)
		}
		err := s.db.ExecInsert(
			`INSERT OR IGNORE INTO users (id, email, kite_uid, display_name, role, status, created_at, updated_at, last_login, onboarded_by) VALUES (?,?,?,?,?,?,?,?,?,?)`,
			stored.ID, stored.Email, stored.KiteUID, stored.DisplayName, stored.Role, stored.Status,
			stored.CreatedAt.Format(time.RFC3339), stored.UpdatedAt.Format(time.RFC3339),
			lastLogin, stored.OnboardedBy,
		)
		if err != nil && s.logger != nil {
			s.logger.Error("Failed to persist user", "email", key, "error", err)
		}
	}
	return nil
}

// Get retrieves a user by email. Returns a copy and ok=true if found.
func (s *Store) Get(email string) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[strings.ToLower(email)]
	if !ok {
		return nil, false
	}
	cp := *u
	return &cp, true
}

// GetByEmail is an alias for Get (for interface clarity).
func (s *Store) GetByEmail(email string) (*User, bool) {
	return s.Get(email)
}

// Exists returns true if a user with the given email exists.
func (s *Store) Exists(email string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.users[strings.ToLower(email)]
	return ok
}

// IsAdmin returns true if the given email belongs to an admin user.
func (s *Store) IsAdmin(email string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[strings.ToLower(email)]
	return ok && u.Role == RoleAdmin && u.Status == StatusActive
}

// GetStatus returns the user's status. Returns empty string if user not found.
func (s *Store) GetStatus(email string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[strings.ToLower(email)]
	if !ok {
		return ""
	}
	return u.Status
}

// UpdateLastLogin records the current time as the user's last login.
func (s *Store) UpdateLastLogin(email string) {
	key := strings.ToLower(email)
	now := time.Now()

	s.mu.Lock()
	u, ok := s.users[key]
	if ok {
		u.LastLogin = now
		u.UpdatedAt = now
	}
	s.mu.Unlock()

	if !ok {
		return
	}

	if s.db != nil {
		nowStr := now.Format(time.RFC3339)
		if err := s.db.ExecInsert(`UPDATE users SET last_login = ?, updated_at = ? WHERE email = ?`, nowStr, nowStr, key); err != nil && s.logger != nil {
			s.logger.Error("Failed to update last_login", "email", key, "error", err)
		}
	}
}

// UpdateRole changes the user's role. Returns error if user not found or invalid role.
func (s *Store) UpdateRole(email, role string) error {
	if role != RoleAdmin && role != RoleTrader && role != RoleViewer {
		return fmt.Errorf("invalid role: %s", role)
	}
	key := strings.ToLower(email)
	now := time.Now()

	s.mu.Lock()
	u, ok := s.users[key]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("user not found: %s", key)
	}
	u.Role = role
	u.UpdatedAt = now
	s.mu.Unlock()

	if s.db != nil {
		nowStr := now.Format(time.RFC3339)
		if err := s.db.ExecInsert(`UPDATE users SET role = ?, updated_at = ? WHERE email = ?`, role, nowStr, key); err != nil {
			return fmt.Errorf("persist role update: %w", err)
		}
	}
	return nil
}

// UpdateStatus changes the user's status. Returns error if user not found or invalid status.
func (s *Store) UpdateStatus(email, status string) error {
	if status != StatusActive && status != StatusSuspended && status != StatusOffboarded {
		return fmt.Errorf("invalid status: %s", status)
	}
	key := strings.ToLower(email)
	now := time.Now()

	s.mu.Lock()
	u, ok := s.users[key]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("user not found: %s", key)
	}
	u.Status = status
	u.UpdatedAt = now
	s.mu.Unlock()

	if s.db != nil {
		nowStr := now.Format(time.RFC3339)
		if err := s.db.ExecInsert(`UPDATE users SET status = ?, updated_at = ? WHERE email = ?`, status, nowStr, key); err != nil {
			return fmt.Errorf("persist status update: %w", err)
		}
	}
	return nil
}

// UpdateKiteUID sets the Kite user ID for a user.
func (s *Store) UpdateKiteUID(email, kiteUID string) {
	key := strings.ToLower(email)
	now := time.Now()

	s.mu.Lock()
	u, ok := s.users[key]
	if ok {
		u.KiteUID = kiteUID
		u.UpdatedAt = now
	}
	s.mu.Unlock()

	if ok && s.db != nil {
		nowStr := now.Format(time.RFC3339)
		if err := s.db.ExecInsert(`UPDATE users SET kite_uid = ?, updated_at = ? WHERE email = ?`, kiteUID, nowStr, key); err != nil && s.logger != nil {
			s.logger.Error("Failed to update kite_uid", "email", key, "error", err)
		}
	}
}

// List returns all users as a slice (copies).
func (s *Store) List() []*User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*User, 0, len(s.users))
	for _, u := range s.users {
		cp := *u
		out = append(out, &cp)
	}
	return out
}

// Count returns the number of registered users.
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.users)
}

// Delete removes a user from the store.
func (s *Store) Delete(email string) {
	key := strings.ToLower(email)

	s.mu.Lock()
	delete(s.users, key)
	s.mu.Unlock()

	if s.db != nil {
		if err := s.db.ExecInsert(`DELETE FROM users WHERE email = ?`, key); err != nil && s.logger != nil {
			s.logger.Error("Failed to delete user", "email", key, "error", err)
		}
	}
}

// EnsureAdmin creates or updates a user to have admin role.
// Used to seed admin users from ADMIN_EMAILS env var at startup.
func (s *Store) EnsureAdmin(email string) {
	key := strings.ToLower(strings.TrimSpace(email))
	if key == "" {
		return
	}

	s.mu.RLock()
	_, exists := s.users[key]
	s.mu.RUnlock()

	if exists {
		// User exists — just ensure admin role
		if err := s.UpdateRole(key, RoleAdmin); err != nil && s.logger != nil {
			s.logger.Error("Failed to set admin role", "email", key, "error", err)
		}
		return
	}

	// Create new admin user
	now := time.Now()
	u := &User{
		ID:          generateID(),
		Email:       key,
		Role:        RoleAdmin,
		Status:      StatusActive,
		CreatedAt:   now,
		UpdatedAt:   now,
		OnboardedBy: "env",
	}
	if err := s.Create(u); err != nil && s.logger != nil {
		// May have been created concurrently — try setting admin role
		if err2 := s.UpdateRole(key, RoleAdmin); err2 != nil {
			s.logger.Error("Failed to seed admin user", "email", key, "error", err, "role_error", err2)
		}
	}
}

// EnsureUser creates a user if they don't exist, returning the user.
// Used for auto-provisioning on first OAuth login.
func (s *Store) EnsureUser(email, kiteUID, displayName, onboardedBy string) *User {
	key := strings.ToLower(strings.TrimSpace(email))
	if key == "" {
		return nil
	}

	s.mu.RLock()
	existing, exists := s.users[key]
	s.mu.RUnlock()

	if exists {
		cp := *existing
		return &cp
	}

	now := time.Now()
	u := &User{
		ID:          generateID(),
		Email:       key,
		KiteUID:     kiteUID,
		DisplayName: displayName,
		Role:        RoleTrader,
		Status:      StatusActive,
		CreatedAt:   now,
		UpdatedAt:   now,
		OnboardedBy: onboardedBy,
	}
	if err := s.Create(u); err != nil {
		// Concurrent creation — return existing
		s.mu.RLock()
		existing, exists = s.users[key]
		s.mu.RUnlock()
		if exists {
			cp := *existing
			return &cp
		}
		return nil
	}
	cp := *u
	return &cp
}

// EnsureGoogleUser auto-creates a trader account on first Google SSO login.
// Existing users are left unchanged (admins keep their admin role).
func (s *Store) EnsureGoogleUser(email string) {
	s.EnsureUser(email, "", "", "google_sso")
}

// GetRole returns the user's role. Returns empty string if user not found.
func (s *Store) GetRole(email string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[strings.ToLower(email)]
	if !ok {
		return ""
	}
	return u.Role
}

// SetPasswordHash stores a bcrypt password hash for the given user.
func (s *Store) SetPasswordHash(email, hash string) error {
	key := strings.ToLower(email)
	now := time.Now()

	s.mu.Lock()
	u, ok := s.users[key]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("user not found: %s", key)
	}
	u.PasswordHash = hash
	u.UpdatedAt = now
	s.mu.Unlock()

	if s.db != nil {
		nowStr := now.Format(time.RFC3339)
		if err := s.db.ExecInsert(`UPDATE users SET password_hash = ?, updated_at = ? WHERE email = ?`, hash, nowStr, key); err != nil {
			return fmt.Errorf("persist password hash: %w", err)
		}
	}
	return nil
}

// HasPassword returns true if the given user has a non-empty password hash.
func (s *Store) HasPassword(email string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[strings.ToLower(email)]
	return ok && u.PasswordHash != ""
}

// VerifyPassword checks the given plaintext password against the stored bcrypt hash.
// Returns (true, nil) on match, (false, nil) on mismatch, (false, error) on lookup failure.
// For timing safety, always runs bcrypt comparison even for unknown users.
func (s *Store) VerifyPassword(email, password string) (bool, error) {
	s.mu.RLock()
	u, ok := s.users[strings.ToLower(email)]
	var storedHash string
	if ok {
		storedHash = u.PasswordHash
	}
	s.mu.RUnlock()

	if storedHash == "" {
		// Timing-safe: always run bcrypt even for missing users/empty hash.
		// Use a dummy hash so the timing is indistinguishable.
		dummyHash := "$2a$12$000000000000000000000u4JuJnGbPZNqXxQxVv3Q3E3Q3E3Q3E3Q" // invalid but takes constant time
		_ = bcrypt.CompareHashAndPassword([]byte(dummyHash), []byte(password))
		return false, nil
	}

	err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(password))
	if err == bcrypt.ErrMismatchedHashAndPassword {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("bcrypt compare: %w", err)
	}
	return true, nil
}

// generateID creates a simple time-based unique ID for users.
func generateID() string {
	return fmt.Sprintf("u_%d", time.Now().UnixNano())
}
