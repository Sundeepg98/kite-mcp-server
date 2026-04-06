package users

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
)

type FamilyInvitation struct {
	ID           string    `json:"id"`
	AdminEmail   string    `json:"admin_email"`
	InvitedEmail string    `json:"invited_email"`
	Status       string    `json:"status"` // pending, accepted, expired, revoked
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	AcceptedAt   time.Time `json:"accepted_at,omitempty"`
}

type InvitationStore struct {
	mu          sync.RWMutex
	invitations map[string]*FamilyInvitation // keyed by ID
	db          *alerts.DB
}

func NewInvitationStore(db *alerts.DB) *InvitationStore {
	return &InvitationStore{
		invitations: make(map[string]*FamilyInvitation),
		db:          db,
	}
}

func (s *InvitationStore) InitTable() error {
	if s.db == nil {
		return nil
	}
	return s.db.ExecDDL(`CREATE TABLE IF NOT EXISTS family_invitations (
		id            TEXT PRIMARY KEY,
		admin_email   TEXT NOT NULL,
		invited_email TEXT NOT NULL,
		status        TEXT NOT NULL DEFAULT 'pending',
		created_at    TEXT NOT NULL,
		expires_at    TEXT NOT NULL,
		accepted_at   TEXT DEFAULT ''
	)`)
}

func (s *InvitationStore) LoadFromDB() error {
	if s.db == nil {
		return nil
	}
	rows, err := s.db.RawQuery(`SELECT id, admin_email, invited_email, status, created_at, expires_at, COALESCE(accepted_at, '') FROM family_invitations`)
	if err != nil {
		return fmt.Errorf("query invitations: %w", err)
	}
	defer rows.Close()
	s.mu.Lock()
	defer s.mu.Unlock()
	for rows.Next() {
		var inv FamilyInvitation
		var createdS, expiresS, acceptedS string
		if err := rows.Scan(&inv.ID, &inv.AdminEmail, &inv.InvitedEmail, &inv.Status, &createdS, &expiresS, &acceptedS); err != nil {
			return fmt.Errorf("scan invitation: %w", err)
		}
		inv.CreatedAt, _ = time.Parse(time.RFC3339, createdS)
		inv.ExpiresAt, _ = time.Parse(time.RFC3339, expiresS)
		if acceptedS != "" {
			inv.AcceptedAt, _ = time.Parse(time.RFC3339, acceptedS)
		}
		s.invitations[inv.ID] = &inv
	}
	return rows.Err()
}

func (s *InvitationStore) Create(inv *FamilyInvitation) error {
	key := inv.ID
	inv.AdminEmail = strings.ToLower(inv.AdminEmail)
	inv.InvitedEmail = strings.ToLower(inv.InvitedEmail)
	s.mu.Lock()
	s.invitations[key] = inv
	s.mu.Unlock()
	if s.db != nil {
		return s.db.ExecInsert(
			`INSERT INTO family_invitations (id, admin_email, invited_email, status, created_at, expires_at, accepted_at) VALUES (?,?,?,?,?,?,?)`,
			inv.ID, inv.AdminEmail, inv.InvitedEmail, inv.Status,
			inv.CreatedAt.Format(time.RFC3339), inv.ExpiresAt.Format(time.RFC3339), "",
		)
	}
	return nil
}

func (s *InvitationStore) Get(id string) *FamilyInvitation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if inv, ok := s.invitations[id]; ok {
		cp := *inv
		return &cp
	}
	return nil
}

func (s *InvitationStore) GetByInvitedEmail(email string) *FamilyInvitation {
	email = strings.ToLower(email)
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, inv := range s.invitations {
		if inv.InvitedEmail == email && inv.Status == "pending" && time.Now().Before(inv.ExpiresAt) {
			cp := *inv
			return &cp
		}
	}
	return nil
}

func (s *InvitationStore) ListByAdmin(adminEmail string) []*FamilyInvitation {
	adminEmail = strings.ToLower(adminEmail)
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*FamilyInvitation
	for _, inv := range s.invitations {
		if inv.AdminEmail == adminEmail {
			cp := *inv
			result = append(result, &cp)
		}
	}
	return result
}

func (s *InvitationStore) Accept(id string) error {
	s.mu.Lock()
	inv, ok := s.invitations[id]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("invitation not found: %s", id)
	}
	inv.Status = "accepted"
	inv.AcceptedAt = time.Now()
	s.mu.Unlock()
	if s.db != nil {
		return s.db.ExecInsert(`UPDATE family_invitations SET status = 'accepted', accepted_at = ? WHERE id = ?`,
			inv.AcceptedAt.Format(time.RFC3339), id)
	}
	return nil
}

func (s *InvitationStore) Revoke(id string) error {
	s.mu.Lock()
	inv, ok := s.invitations[id]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("invitation not found: %s", id)
	}
	inv.Status = "revoked"
	s.mu.Unlock()
	if s.db != nil {
		return s.db.ExecInsert(`UPDATE family_invitations SET status = 'revoked' WHERE id = ?`, id)
	}
	return nil
}

// CleanupExpired marks all pending invitations past their expiry as expired.
// Call periodically (e.g., daily).
func (s *InvitationStore) CleanupExpired() int {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, inv := range s.invitations {
		if inv.Status == "pending" && now.After(inv.ExpiresAt) {
			inv.Status = "expired"
			count++
			if s.db != nil {
				_ = s.db.ExecInsert(`UPDATE family_invitations SET status = 'expired' WHERE id = ?`, inv.ID)
			}
		}
	}
	return count
}
