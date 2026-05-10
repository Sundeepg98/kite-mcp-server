package usecases

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/algo2go/kite-mcp-domain"
	logport "github.com/algo2go/kite-mcp-logger"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
	"github.com/algo2go/kite-mcp-users"
)

// AdminUserReader provides read-only access to user data (ISP-narrowed).
//
// F2 close-out (Phase B/D): renamed from usecases.UserReader to
// disambiguate from kc.UserReader (10-method canonical) — the
// usecases version is a 3-method narrow subset for admin tooling
// only. Per the redundancy audit's empirical finding: same name,
// different signatures = future-maintainer confusion. *kc.Manager
// (and kc.UserStoreInterface implementations) satisfy this narrow
// port structurally — no adapter layer needed.
//
// UserAuthChecker was deleted (was dead code — declared but never
// referenced as a field type or function parameter; only embedded in
// the unused UserStore composite via UserAuthChecker.IsAdmin which
// no admin use case actually called).
type AdminUserReader interface {
	List() []*users.User
	Get(email string) (*users.User, bool)
	Count() int
}

// AdminUserWriter provides write operations on user data (ISP-narrowed).
//
// F2 close-out: renamed from usecases.UserWriter (was a 3-method
// narrow subset of kc.UserWriter's 8). Same rename rationale as
// AdminUserReader — disambiguate from the wide kc canonical.
type AdminUserWriter interface {
	UpdateStatus(email, status string) error
	UpdateRole(email, role string) error
	Create(u *users.User) error
}

// AdminUserStore is the composite interface for admin use cases that
// need both reads and writes. Prefer AdminUserReader or AdminUserWriter
// directly when possible (Interface Segregation Principle).
//
// F2 close-out: renamed from usecases.UserStore. UserAuthChecker
// embedding removed — no admin use case calls IsAdmin/HasPassword/
// VerifyPassword on the composite (they route through riskguard /
// session-svc instead).
type AdminUserStore interface {
	AdminUserReader
	AdminUserWriter
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
	userStore AdminUserReader
	logger    logport.Logger
}

// NewAdminListUsersUseCase creates an AdminListUsersUseCase with dependencies injected.
func NewAdminListUsersUseCase(store AdminUserReader, logger *slog.Logger) *AdminListUsersUseCase {
	return &AdminListUsersUseCase{userStore: store, logger: logport.NewSlog(logger)}
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
	userStore AdminUserReader
	riskguard RiskGuardService
	logger    logport.Logger
}

// NewAdminGetUserUseCase creates an AdminGetUserUseCase with dependencies injected.
func NewAdminGetUserUseCase(store AdminUserReader, rg RiskGuardService, logger *slog.Logger) *AdminGetUserUseCase {
	return &AdminGetUserUseCase{userStore: store, riskguard: rg, logger: logport.NewSlog(logger)}
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
	logger    logport.Logger
}

// NewAdminGetRiskStatusUseCase creates an AdminGetRiskStatusUseCase with dependencies injected.
func NewAdminGetRiskStatusUseCase(rg RiskGuardService, logger *slog.Logger) *AdminGetRiskStatusUseCase {
	return &AdminGetRiskStatusUseCase{riskguard: rg, logger: logport.NewSlog(logger)}
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
	// Both MaxDailyValueINR and DailyPlacedValue are now Money VOs (Slices
	// 1 + 3). Compute headroom Money-side via Sub, then drop to float at
	// the JSON boundary because OrderHeadroom is consumed by external
	// dashboards as a primitive number.
	var headroom float64
	if remaining, err := limits.MaxDailyValueINR.Sub(status.DailyPlacedValue); err == nil {
		headroom = remaining.Float64()
	} else {
		// Currency mismatch — should be unreachable in practice (both
		// sides INR). Fall back to primitive subtraction so the
		// dashboard still gets a number.
		headroom = limits.MaxDailyValueINR.Float64() - status.DailyPlacedValue.Float64()
	}
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
	userStore  AdminUserStore
	riskguard  RiskGuardService
	sessions   SessionTerminator
	events     *domain.EventDispatcher
	logger     logport.Logger
}

// NewAdminSuspendUserUseCase creates an AdminSuspendUserUseCase with dependencies injected.
func NewAdminSuspendUserUseCase(
	store AdminUserStore,
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
		logger:    logport.NewSlog(logger),
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
	userStore AdminUserWriter
	logger    logport.Logger
}

// NewAdminActivateUserUseCase creates an AdminActivateUserUseCase with dependencies injected.
func NewAdminActivateUserUseCase(store AdminUserWriter, logger *slog.Logger) *AdminActivateUserUseCase {
	return &AdminActivateUserUseCase{userStore: store, logger: logport.NewSlog(logger)}
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
	userStore AdminUserStore
	logger    logport.Logger
}

// NewAdminChangeRoleUseCase creates an AdminChangeRoleUseCase with dependencies injected.
func NewAdminChangeRoleUseCase(store AdminUserStore, logger *slog.Logger) *AdminChangeRoleUseCase {
	return &AdminChangeRoleUseCase{userStore: store, logger: logport.NewSlog(logger)}
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
	logger    logport.Logger
}

// NewAdminFreezeUserUseCase creates an AdminFreezeUserUseCase with dependencies injected.
func NewAdminFreezeUserUseCase(rg RiskGuardService, logger *slog.Logger) *AdminFreezeUserUseCase {
	return &AdminFreezeUserUseCase{riskguard: rg, logger: logport.NewSlog(logger)}
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
	logger    logport.Logger
}

// NewAdminUnfreezeUserUseCase creates an AdminUnfreezeUserUseCase with dependencies injected.
func NewAdminUnfreezeUserUseCase(rg RiskGuardService, logger *slog.Logger) *AdminUnfreezeUserUseCase {
	return &AdminUnfreezeUserUseCase{riskguard: rg, logger: logport.NewSlog(logger)}
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
	logger    logport.Logger
}

// NewAdminFreezeGlobalUseCase creates an AdminFreezeGlobalUseCase with dependencies injected.
func NewAdminFreezeGlobalUseCase(rg RiskGuardService, logger *slog.Logger) *AdminFreezeGlobalUseCase {
	return &AdminFreezeGlobalUseCase{riskguard: rg, logger: logport.NewSlog(logger)}
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
	logger    logport.Logger
}

// NewAdminUnfreezeGlobalUseCase creates an AdminUnfreezeGlobalUseCase with dependencies injected.
func NewAdminUnfreezeGlobalUseCase(rg RiskGuardService, logger *slog.Logger) *AdminUnfreezeGlobalUseCase {
	return &AdminUnfreezeGlobalUseCase{riskguard: rg, logger: logport.NewSlog(logger)}
}

// Execute unfreezes global trading.
func (uc *AdminUnfreezeGlobalUseCase) Execute(ctx context.Context, cmd cqrs.AdminUnfreezeGlobalCommand) error {
	if uc.riskguard == nil {
		return fmt.Errorf("usecases: riskguard not available")
	}

	uc.riskguard.UnfreezeGlobal()
	return nil
}

