package usecases

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
	"github.com/zerodha/kite-mcp-server/kc/users"
)

// UserReader provides read-only access to user data (ISP-narrowed).
type UserReader interface {
	List() []*users.User
	Get(email string) (*users.User, bool)
	Count() int
}

// UserWriter provides write operations on user data (ISP-narrowed).
type UserWriter interface {
	UpdateStatus(email, status string) error
	UpdateRole(email, role string) error
	Create(u *users.User) error
}

// UserAuthChecker provides authentication/authorization checks (ISP-narrowed).
type UserAuthChecker interface {
	IsAdmin(email string) bool
}

// UserStore is the composite interface for use cases that need both reads and writes.
// Prefer UserReader or UserWriter directly when possible (Interface Segregation Principle).
type UserStore interface {
	UserReader
	UserWriter
	UserAuthChecker
}

// RiskGuardService abstracts riskguard for admin use cases.
type RiskGuardService interface {
	GetUserStatus(email string) riskguard.UserStatus
	GetEffectiveLimits(email string) riskguard.UserLimits
	GetGlobalFreezeStatus() riskguard.GlobalFreezeStatus
	IsGloballyFrozen() bool
	Freeze(email, by, reason string)
	Unfreeze(email string)
	FreezeGlobal(by, reason string)
	UnfreezeGlobal()
}

// SessionTerminator abstracts session termination.
type SessionTerminator interface {
	TerminateByEmail(email string) int
}

// --- Admin List Users ---

// AdminListUsersUseCase retrieves a paginated list of users.
type AdminListUsersUseCase struct {
	userStore UserReader
	logger    *slog.Logger
}

// NewAdminListUsersUseCase creates an AdminListUsersUseCase with dependencies injected.
func NewAdminListUsersUseCase(store UserReader, logger *slog.Logger) *AdminListUsersUseCase {
	return &AdminListUsersUseCase{userStore: store, logger: logger}
}

// AdminListUsersResult holds the paginated user list.
type AdminListUsersResult struct {
	Total int           `json:"total"`
	From  int           `json:"from"`
	Limit int           `json:"limit"`
	Users []*users.User `json:"users"`
}

// Execute retrieves a paginated list of users.
func (uc *AdminListUsersUseCase) Execute(ctx context.Context, query cqrs.AdminListUsersQuery) (*AdminListUsersResult, error) {
	allUsers := uc.userStore.List()

	from := query.From
	limit := query.Limit
	from = max(from, 0)
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	end := from + limit
	if from > len(allUsers) {
		from = len(allUsers)
	}
	if end > len(allUsers) {
		end = len(allUsers)
	}

	return &AdminListUsersResult{
		Total: len(allUsers),
		From:  from,
		Limit: limit,
		Users: allUsers[from:end],
	}, nil
}

// --- Admin Get User ---

// AdminGetUserUseCase retrieves detailed user information.
type AdminGetUserUseCase struct {
	userStore UserReader
	riskguard RiskGuardService
	logger    *slog.Logger
}

// NewAdminGetUserUseCase creates an AdminGetUserUseCase with dependencies injected.
func NewAdminGetUserUseCase(store UserReader, rg RiskGuardService, logger *slog.Logger) *AdminGetUserUseCase {
	return &AdminGetUserUseCase{userStore: store, riskguard: rg, logger: logger}
}

// AdminGetUserResult holds detailed user information.
type AdminGetUserResult struct {
	User            *users.User             `json:"user"`
	RiskStatus      *riskguard.UserStatus   `json:"risk_status,omitempty"`
	EffectiveLimits *riskguard.UserLimits   `json:"effective_limits,omitempty"`
}

// Execute retrieves a user's detailed information.
func (uc *AdminGetUserUseCase) Execute(ctx context.Context, query cqrs.AdminGetUserQuery) (*AdminGetUserResult, error) {
	if query.TargetEmail == "" {
		return nil, fmt.Errorf("usecases: target_email is required")
	}

	user, found := uc.userStore.Get(query.TargetEmail)
	if !found {
		return nil, fmt.Errorf("usecases: user not found: %s", query.TargetEmail)
	}

	result := &AdminGetUserResult{User: user}

	if uc.riskguard != nil {
		status := uc.riskguard.GetUserStatus(query.TargetEmail)
		result.RiskStatus = &status
		limits := uc.riskguard.GetEffectiveLimits(query.TargetEmail)
		result.EffectiveLimits = &limits
	}

	return result, nil
}

// --- Admin Get Risk Status ---

// AdminGetRiskStatusUseCase retrieves a user's risk status.
type AdminGetRiskStatusUseCase struct {
	riskguard RiskGuardService
	logger    *slog.Logger
}

// NewAdminGetRiskStatusUseCase creates an AdminGetRiskStatusUseCase with dependencies injected.
func NewAdminGetRiskStatusUseCase(rg RiskGuardService, logger *slog.Logger) *AdminGetRiskStatusUseCase {
	return &AdminGetRiskStatusUseCase{riskguard: rg, logger: logger}
}

// AdminGetRiskStatusResult holds a user's risk status.
type AdminGetRiskStatusResult struct {
	TargetEmail     string                 `json:"target_email"`
	GloballyFrozen  bool                   `json:"globally_frozen"`
	UserStatus      riskguard.UserStatus   `json:"user_status"`
	EffectiveLimits riskguard.UserLimits   `json:"effective_limits"`
	OrderHeadroom   float64                `json:"order_headroom"`
}

// Execute retrieves a user's risk status.
func (uc *AdminGetRiskStatusUseCase) Execute(ctx context.Context, query cqrs.AdminGetRiskStatusQuery) (*AdminGetRiskStatusResult, error) {
	if query.TargetEmail == "" {
		return nil, fmt.Errorf("usecases: target_email is required")
	}
	if uc.riskguard == nil {
		return nil, fmt.Errorf("usecases: riskguard not available")
	}

	status := uc.riskguard.GetUserStatus(query.TargetEmail)
	limits := uc.riskguard.GetEffectiveLimits(query.TargetEmail)
	headroom := limits.MaxDailyValueINR - status.DailyPlacedValue
	headroom = max(headroom, 0)

	return &AdminGetRiskStatusResult{
		TargetEmail:     query.TargetEmail,
		GloballyFrozen:  uc.riskguard.IsGloballyFrozen(),
		UserStatus:      status,
		EffectiveLimits: limits,
		OrderHeadroom:   headroom,
	}, nil
}

// --- Admin Suspend User ---

// AdminSuspendUserUseCase suspends a user account.
type AdminSuspendUserUseCase struct {
	userStore  UserStore
	riskguard  RiskGuardService
	sessions   SessionTerminator
	events     *domain.EventDispatcher
	logger     *slog.Logger
}

// NewAdminSuspendUserUseCase creates an AdminSuspendUserUseCase with dependencies injected.
func NewAdminSuspendUserUseCase(
	store UserStore,
	rg RiskGuardService,
	sessions SessionTerminator,
	events *domain.EventDispatcher,
	logger *slog.Logger,
) *AdminSuspendUserUseCase {
	return &AdminSuspendUserUseCase{
		userStore: store,
		riskguard: rg,
		sessions:  sessions,
		events:    events,
		logger:    logger,
	}
}

// AdminSuspendUserResult holds the suspension result.
type AdminSuspendUserResult struct {
	Status              string `json:"status"`
	Email               string `json:"email"`
	SessionsTerminated  int    `json:"sessions_terminated"`
}

// Execute suspends a user.
func (uc *AdminSuspendUserUseCase) Execute(ctx context.Context, cmd cqrs.AdminSuspendUserCommand) (*AdminSuspendUserResult, error) {
	if cmd.TargetEmail == "" {
		return nil, fmt.Errorf("usecases: target_email is required")
	}
	if cmd.AdminEmail == cmd.TargetEmail {
		return nil, fmt.Errorf("usecases: cannot suspend yourself")
	}

	// Last-admin guard.
	target, ok := uc.userStore.Get(cmd.TargetEmail)
	if ok && target.Role == users.RoleAdmin && target.Status == users.StatusActive {
		activeAdmins := 0
		for _, u := range uc.userStore.List() {
			if u.Role == users.RoleAdmin && u.Status == users.StatusActive {
				activeAdmins++
			}
		}
		if activeAdmins <= 1 {
			return nil, fmt.Errorf("usecases: cannot suspend the last active admin")
		}
	}

	if uc.riskguard != nil {
		uc.riskguard.Freeze(cmd.TargetEmail, cmd.AdminEmail, cmd.Reason)
	}

	if err := uc.userStore.UpdateStatus(cmd.TargetEmail, users.StatusSuspended); err != nil {
		return nil, fmt.Errorf("usecases: suspend user: %w", err)
	}

	terminated := 0
	if uc.sessions != nil {
		terminated = uc.sessions.TerminateByEmail(cmd.TargetEmail)
	}

	if uc.events != nil {
		uc.events.Dispatch(domain.UserSuspendedEvent{
			Email:     cmd.TargetEmail,
			By:        cmd.AdminEmail,
			Reason:    cmd.Reason,
			Timestamp: time.Now(),
		})
	}

	return &AdminSuspendUserResult{
		Status:             "suspended",
		Email:              cmd.TargetEmail,
		SessionsTerminated: terminated,
	}, nil
}

// --- Admin Activate User ---

// AdminActivateUserUseCase reactivates a user account.
type AdminActivateUserUseCase struct {
	userStore UserWriter
	logger    *slog.Logger
}

// NewAdminActivateUserUseCase creates an AdminActivateUserUseCase with dependencies injected.
func NewAdminActivateUserUseCase(store UserWriter, logger *slog.Logger) *AdminActivateUserUseCase {
	return &AdminActivateUserUseCase{userStore: store, logger: logger}
}

// Execute activates a user.
func (uc *AdminActivateUserUseCase) Execute(ctx context.Context, cmd cqrs.AdminActivateUserCommand) error {
	if cmd.TargetEmail == "" {
		return fmt.Errorf("usecases: target_email is required")
	}

	if err := uc.userStore.UpdateStatus(cmd.TargetEmail, users.StatusActive); err != nil {
		return fmt.Errorf("usecases: activate user: %w", err)
	}

	return nil
}

// --- Admin Change Role ---

// AdminChangeRoleUseCase changes a user's role.
type AdminChangeRoleUseCase struct {
	userStore UserStore
	logger    *slog.Logger
}

// NewAdminChangeRoleUseCase creates an AdminChangeRoleUseCase with dependencies injected.
func NewAdminChangeRoleUseCase(store UserStore, logger *slog.Logger) *AdminChangeRoleUseCase {
	return &AdminChangeRoleUseCase{userStore: store, logger: logger}
}

// AdminChangeRoleResult holds the role change result.
type AdminChangeRoleResult struct {
	Email   string `json:"email"`
	OldRole string `json:"old_role"`
	NewRole string `json:"new_role"`
}

// Execute changes a user's role.
func (uc *AdminChangeRoleUseCase) Execute(ctx context.Context, cmd cqrs.AdminChangeRoleCommand) (*AdminChangeRoleResult, error) {
	if cmd.TargetEmail == "" {
		return nil, fmt.Errorf("usecases: target_email is required")
	}
	if cmd.NewRole == "" {
		return nil, fmt.Errorf("usecases: new_role is required")
	}

	target, ok := uc.userStore.Get(cmd.TargetEmail)
	if !ok {
		return nil, fmt.Errorf("usecases: user not found: %s", cmd.TargetEmail)
	}

	// Last-admin guard.
	if target.Role == users.RoleAdmin && cmd.NewRole != users.RoleAdmin {
		activeAdmins := 0
		for _, u := range uc.userStore.List() {
			if u.Role == users.RoleAdmin && u.Status == users.StatusActive {
				activeAdmins++
			}
		}
		if activeAdmins <= 1 {
			return nil, fmt.Errorf("usecases: cannot demote the last active admin")
		}
	}

	oldRole := target.Role
	if err := uc.userStore.UpdateRole(cmd.TargetEmail, cmd.NewRole); err != nil {
		return nil, fmt.Errorf("usecases: change role: %w", err)
	}

	return &AdminChangeRoleResult{
		Email:   cmd.TargetEmail,
		OldRole: oldRole,
		NewRole: cmd.NewRole,
	}, nil
}

// --- Admin Freeze User ---

// AdminFreezeUserUseCase freezes a user's trading.
type AdminFreezeUserUseCase struct {
	riskguard RiskGuardService
	logger    *slog.Logger
}

// NewAdminFreezeUserUseCase creates an AdminFreezeUserUseCase with dependencies injected.
func NewAdminFreezeUserUseCase(rg RiskGuardService, logger *slog.Logger) *AdminFreezeUserUseCase {
	return &AdminFreezeUserUseCase{riskguard: rg, logger: logger}
}

// Execute freezes a user's trading.
func (uc *AdminFreezeUserUseCase) Execute(ctx context.Context, cmd cqrs.AdminFreezeUserCommand) error {
	if cmd.TargetEmail == "" {
		return fmt.Errorf("usecases: target_email is required")
	}
	if uc.riskguard == nil {
		return fmt.Errorf("usecases: riskguard not available")
	}

	uc.riskguard.Freeze(cmd.TargetEmail, cmd.AdminEmail, cmd.Reason)
	return nil
}

// --- Admin Unfreeze User ---

// AdminUnfreezeUserUseCase unfreezes a user's trading.
type AdminUnfreezeUserUseCase struct {
	riskguard RiskGuardService
	logger    *slog.Logger
}

// NewAdminUnfreezeUserUseCase creates an AdminUnfreezeUserUseCase with dependencies injected.
func NewAdminUnfreezeUserUseCase(rg RiskGuardService, logger *slog.Logger) *AdminUnfreezeUserUseCase {
	return &AdminUnfreezeUserUseCase{riskguard: rg, logger: logger}
}

// Execute unfreezes a user's trading.
func (uc *AdminUnfreezeUserUseCase) Execute(ctx context.Context, cmd cqrs.AdminUnfreezeUserCommand) error {
	if cmd.TargetEmail == "" {
		return fmt.Errorf("usecases: target_email is required")
	}
	if uc.riskguard == nil {
		return fmt.Errorf("usecases: riskguard not available")
	}

	uc.riskguard.Unfreeze(cmd.TargetEmail)
	return nil
}

// --- Admin Freeze Global ---

// AdminFreezeGlobalUseCase freezes all trading globally.
type AdminFreezeGlobalUseCase struct {
	riskguard RiskGuardService
	logger    *slog.Logger
}

// NewAdminFreezeGlobalUseCase creates an AdminFreezeGlobalUseCase with dependencies injected.
func NewAdminFreezeGlobalUseCase(rg RiskGuardService, logger *slog.Logger) *AdminFreezeGlobalUseCase {
	return &AdminFreezeGlobalUseCase{riskguard: rg, logger: logger}
}

// Execute freezes all trading globally.
func (uc *AdminFreezeGlobalUseCase) Execute(ctx context.Context, cmd cqrs.AdminFreezeGlobalCommand) error {
	if uc.riskguard == nil {
		return fmt.Errorf("usecases: riskguard not available")
	}

	uc.riskguard.FreezeGlobal(cmd.AdminEmail, cmd.Reason)
	return nil
}

// --- Admin Unfreeze Global ---

// AdminUnfreezeGlobalUseCase unfreezes global trading.
type AdminUnfreezeGlobalUseCase struct {
	riskguard RiskGuardService
	logger    *slog.Logger
}

// NewAdminUnfreezeGlobalUseCase creates an AdminUnfreezeGlobalUseCase with dependencies injected.
func NewAdminUnfreezeGlobalUseCase(rg RiskGuardService, logger *slog.Logger) *AdminUnfreezeGlobalUseCase {
	return &AdminUnfreezeGlobalUseCase{riskguard: rg, logger: logger}
}

// Execute unfreezes global trading.
func (uc *AdminUnfreezeGlobalUseCase) Execute(ctx context.Context, cmd cqrs.AdminUnfreezeGlobalCommand) error {
	if uc.riskguard == nil {
		return fmt.Errorf("usecases: riskguard not available")
	}

	uc.riskguard.UnfreezeGlobal()
	return nil
}

