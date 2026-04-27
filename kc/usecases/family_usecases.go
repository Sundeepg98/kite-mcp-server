package usecases

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	logport "github.com/zerodha/kite-mcp-server/kc/logger"
	"github.com/zerodha/kite-mcp-server/kc/users"
)

// Wave D Phase 3 Package 5g (Logger sweep): admin/family/setup/
// native-alert use cases type their logger field as the
// kc/logger.Logger port; constructors retain *slog.Logger and
// convert via logport.NewSlog.

// FamilyProvider is the narrow interface the family use cases need from
// the kc.FamilyService. Defined here so usecases remain decoupled from
// the kc package (no import cycle).
type FamilyProvider interface {
	ListMembers(adminEmail string) []*users.User
	CanInvite(adminEmail string) (ok bool, current int, max int)
	MaxUsers(adminEmail string) int
	RemoveMember(adminEmail, memberEmail string) error
}

// FamilyInvitationWriter persists newly created family invitations.
type FamilyInvitationWriter interface {
	Create(inv *users.FamilyInvitation) error
}

// FamilyInvitationReader reads pending invitations for an admin.
type FamilyInvitationReader interface {
	ListByAdmin(adminEmail string) []*users.FamilyInvitation
}

// --- Admin List Family ---

// AdminListFamilyUseCase returns the admin's family members and pending invitations.
type AdminListFamilyUseCase struct {
	family      FamilyProvider
	invitations FamilyInvitationReader
	logger      logport.Logger
}

// NewAdminListFamilyUseCase creates an AdminListFamilyUseCase.
func NewAdminListFamilyUseCase(
	family FamilyProvider,
	invitations FamilyInvitationReader,
	logger *slog.Logger,
) *AdminListFamilyUseCase {
	return &AdminListFamilyUseCase{family: family, invitations: invitations, logger: logport.NewSlog(logger)}
}

// FamilyMemberEntry is one member row in the listing.
type FamilyMemberEntry struct {
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	Status    string    `json:"status"`
	LastLogin time.Time `json:"last_login,omitempty"`
}

// FamilyInvitationEntry is one pending invitation row in the listing.
type FamilyInvitationEntry struct {
	ID           string    `json:"id"`
	InvitedEmail string    `json:"invited_email"`
	Status       string    `json:"status"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// AdminListFamilyResult holds the paginated family listing + pending invites.
type AdminListFamilyResult struct {
	AdminEmail  string                  `json:"admin_email"`
	MaxUsers    int                     `json:"max_users"`
	Total       int                     `json:"total"`
	From        int                     `json:"from"`
	Limit       int                     `json:"limit"`
	MemberCount int                     `json:"member_count"`
	Members     []FamilyMemberEntry     `json:"members"`
	Pending     []FamilyInvitationEntry `json:"pending"`
}

// Execute lists family members for the admin.
func (uc *AdminListFamilyUseCase) Execute(ctx context.Context, query cqrs.AdminListFamilyQuery) (*AdminListFamilyResult, error) {
	if query.AdminEmail == "" {
		return nil, fmt.Errorf("usecases: admin_email is required")
	}
	if uc.family == nil {
		return nil, fmt.Errorf("usecases: family service not available")
	}

	from := query.From
	limit := query.Limit
	from = max(from, 0)
	if limit <= 0 || limit > 500 {
		limit = 50
	}

	members := uc.family.ListMembers(query.AdminEmail)
	entries := make([]FamilyMemberEntry, 0, len(members))
	for _, u := range members {
		entries = append(entries, FamilyMemberEntry{
			Email:     u.Email,
			Role:      u.Role,
			Status:    u.Status,
			LastLogin: u.LastLogin,
		})
	}

	total := len(entries)
	end := from + limit
	if from > total {
		from = total
	}
	if end > total {
		end = total
	}
	entries = entries[from:end]

	var pending []FamilyInvitationEntry
	if uc.invitations != nil {
		for _, inv := range uc.invitations.ListByAdmin(query.AdminEmail) {
			if inv.Status == "pending" && time.Now().Before(inv.ExpiresAt) {
				pending = append(pending, FamilyInvitationEntry{
					ID:           inv.ID,
					InvitedEmail: inv.InvitedEmail,
					Status:       inv.Status,
					ExpiresAt:    inv.ExpiresAt,
				})
			}
		}
	}

	return &AdminListFamilyResult{
		AdminEmail:  query.AdminEmail,
		MaxUsers:    uc.family.MaxUsers(query.AdminEmail),
		Total:       total,
		From:        from,
		Limit:       limit,
		MemberCount: len(entries),
		Members:     entries,
		Pending:     pending,
	}, nil
}

// --- Admin Invite Family Member ---

// AdminInviteFamilyMemberUseCase creates a family invitation after enforcing
// slot limits via FamilyService.CanInvite.
type AdminInviteFamilyMemberUseCase struct {
	family         FamilyProvider
	invitations    FamilyInvitationWriter
	events         *domain.EventDispatcher
	invitationTTL  time.Duration
	idGenerator    func() string
	logger         logport.Logger
}

// NewAdminInviteFamilyMemberUseCase creates an AdminInviteFamilyMemberUseCase.
func NewAdminInviteFamilyMemberUseCase(
	family FamilyProvider,
	invitations FamilyInvitationWriter,
	events *domain.EventDispatcher,
	logger *slog.Logger,
) *AdminInviteFamilyMemberUseCase {
	return &AdminInviteFamilyMemberUseCase{
		family:        family,
		invitations:   invitations,
		events:        events,
		invitationTTL: 7 * 24 * time.Hour,
		idGenerator:   defaultInvitationID,
		logger:        logport.NewSlog(logger),
	}
}

func defaultInvitationID() string {
	return fmt.Sprintf("inv_%d", time.Now().UnixNano())
}

// AdminInviteFamilyMemberResult holds the outcome of a successful invite.
type AdminInviteFamilyMemberResult struct {
	InvitationID string    `json:"invitation_id"`
	InvitedEmail string    `json:"invited_email"`
	ExpiresAt    time.Time `json:"expires_at"`
	SlotsUsed    int       `json:"slots_used"`
	SlotsMax     int       `json:"slots_max"`
}

// Execute creates a pending family invitation after slot + duplicate checks.
func (uc *AdminInviteFamilyMemberUseCase) Execute(ctx context.Context, cmd cqrs.AdminInviteFamilyMemberCommand) (*AdminInviteFamilyMemberResult, error) {
	if cmd.AdminEmail == "" {
		return nil, fmt.Errorf("usecases: admin_email is required")
	}
	if cmd.InvitedEmail == "" {
		return nil, fmt.Errorf("usecases: invited_email is required")
	}
	if strings.EqualFold(cmd.InvitedEmail, cmd.AdminEmail) {
		return nil, fmt.Errorf("usecases: cannot invite yourself")
	}
	if uc.family == nil {
		return nil, fmt.Errorf("usecases: family service not available")
	}
	if uc.invitations == nil {
		return nil, fmt.Errorf("usecases: invitation store not available")
	}

	ok, current, max := uc.family.CanInvite(cmd.AdminEmail)
	if !ok {
		return nil, fmt.Errorf("usecases: family is full (%d/%d); upgrade or remove someone first", current, max)
	}

	for _, u := range uc.family.ListMembers(cmd.AdminEmail) {
		if strings.EqualFold(u.Email, cmd.InvitedEmail) {
			return nil, fmt.Errorf("usecases: %s is already in your family", cmd.InvitedEmail)
		}
	}

	now := time.Now()
	inv := &users.FamilyInvitation{
		ID:           uc.idGenerator(),
		AdminEmail:   cmd.AdminEmail,
		InvitedEmail: cmd.InvitedEmail,
		Status:       "pending",
		CreatedAt:    now,
		ExpiresAt:    now.Add(uc.invitationTTL),
	}
	if err := uc.invitations.Create(inv); err != nil {
		return nil, fmt.Errorf("usecases: create invitation: %w", err)
	}

	if uc.events != nil {
		uc.events.Dispatch(domain.FamilyInvitedEvent{
			AdminEmail:   cmd.AdminEmail,
			InvitedEmail: cmd.InvitedEmail,
			Timestamp:    now,
		})
	}

	return &AdminInviteFamilyMemberResult{
		InvitationID: inv.ID,
		InvitedEmail: cmd.InvitedEmail,
		ExpiresAt:    inv.ExpiresAt,
		SlotsUsed:    current + 1,
		SlotsMax:     max,
	}, nil
}

// --- Admin Remove Family Member ---

// AdminRemoveFamilyMemberUseCase unlinks a family member via FamilyService.
type AdminRemoveFamilyMemberUseCase struct {
	family FamilyProvider
	events *domain.EventDispatcher
	logger logport.Logger
}

// NewAdminRemoveFamilyMemberUseCase creates an AdminRemoveFamilyMemberUseCase.
func NewAdminRemoveFamilyMemberUseCase(
	family FamilyProvider,
	events *domain.EventDispatcher,
	logger *slog.Logger,
) *AdminRemoveFamilyMemberUseCase {
	return &AdminRemoveFamilyMemberUseCase{family: family, events: events, logger: logport.NewSlog(logger)}
}

// AdminRemoveFamilyMemberResult holds the outcome of a remove call.
type AdminRemoveFamilyMemberResult struct {
	RemovedEmail string `json:"removed_email"`
}

// Execute unlinks a family member from the admin.
func (uc *AdminRemoveFamilyMemberUseCase) Execute(ctx context.Context, cmd cqrs.AdminRemoveFamilyMemberCommand) (*AdminRemoveFamilyMemberResult, error) {
	if cmd.AdminEmail == "" {
		return nil, fmt.Errorf("usecases: admin_email is required")
	}
	if cmd.TargetEmail == "" {
		return nil, fmt.Errorf("usecases: target_email is required")
	}
	if strings.EqualFold(cmd.TargetEmail, cmd.AdminEmail) {
		return nil, fmt.Errorf("usecases: cannot remove yourself")
	}
	if uc.family == nil {
		return nil, fmt.Errorf("usecases: family service not available")
	}

	if err := uc.family.RemoveMember(cmd.AdminEmail, cmd.TargetEmail); err != nil {
		return nil, fmt.Errorf("usecases: remove family member: %w", err)
	}

	if uc.events != nil {
		uc.events.Dispatch(domain.FamilyMemberRemovedEvent{
			AdminEmail:   cmd.AdminEmail,
			RemovedEmail: cmd.TargetEmail,
			Timestamp:    time.Now(),
		})
	}

	return &AdminRemoveFamilyMemberResult{RemovedEmail: cmd.TargetEmail}, nil
}
