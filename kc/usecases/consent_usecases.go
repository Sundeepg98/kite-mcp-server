package usecases

// consent_usecases.go — DPDP Act 2023 §6(4) right-to-withdraw flow.
//
// Bus contract: WithdrawConsentCommand → WithdrawConsentUseCase → port
// (ConsentWithdrawer) → kc/audit/consent_log table. Domain dispatcher
// emits ConsentWithdrawnEvent for any in-process listeners that need
// to react (e.g. cancel scheduled briefings, stop Telegram dispatch).
//
// PII handling: the command carries plaintext email; the use case is
// the ONLY place that bridges plaintext → SHA-256 hash for the consent
// log. Downstream events carry both fields so plaintext-needing
// consumers (operations, Telegram) and hash-only consumers (audit
// projections) both have what they need without re-hashing.

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	logport "github.com/zerodha/kite-mcp-server/kc/logger"
)

// ConsentWithdrawer is the narrow port the use case needs from the
// audit consent store. The store hashes nothing — the use case passes
// the already-hashed email + the operational fields.
type ConsentWithdrawer interface {
	MarkWithdrawnByEmailHash(emailHash string, withdrawnAt time.Time,
		noticeVersion, reason, ipAddress, userAgent string) (int64, error)
}

// EmailHasher abstracts the SHA-256 hashing helper. Defined as a port
// so the use case stays free of an audit-package import (audit imports
// ports → cycle); the manager wires this to audit.HashEmail.
type EmailHasher interface {
	HashEmail(email string) string
}

// EventDispatcherPort is the narrow dispatcher port for emitting
// ConsentWithdrawnEvent. nil-safe — the use case skips dispatch when
// no dispatcher is wired (DevMode, tests).
type EventDispatcherPort interface {
	Dispatch(event domain.Event)
}

// WithdrawConsentUseCase orchestrates DPDP §6(4) consent withdrawal:
// validate input, hash email, stamp consent_log, dispatch event.
type WithdrawConsentUseCase struct {
	withdrawer ConsentWithdrawer
	hasher     EmailHasher
	dispatcher EventDispatcherPort
	logger     logport.Logger
	now        func() time.Time // injectable clock for deterministic tests
}

// NewWithdrawConsentUseCase builds the use case. dispatcher may be nil.
func NewWithdrawConsentUseCase(
	w ConsentWithdrawer,
	h EmailHasher,
	d EventDispatcherPort,
	logger *slog.Logger,
) *WithdrawConsentUseCase {
	return &WithdrawConsentUseCase{
		withdrawer: w,
		hasher:     h,
		dispatcher: d,
		logger:     logport.NewSlog(logger),
		now:        func() time.Time { return time.Now().UTC() },
	}
}

// SetClock overrides the time source. Tests use this to assert exact
// withdrawn_at timestamps.
func (uc *WithdrawConsentUseCase) SetClock(now func() time.Time) {
	uc.now = now
}

// WithdrawConsentResult carries the outcome of a successful Execute.
// GrantsWithdrawn is the count of active-grant rows that got stamped.
// Zero is a normal outcome (user had nothing to withdraw); the caller
// can decide whether to surface it.
type WithdrawConsentResult struct {
	EmailHash       string `json:"email_hash"`
	GrantsWithdrawn int64  `json:"grants_withdrawn"`
}

// Execute runs the withdrawal. Order:
//
//  1. Validate non-empty email.
//  2. Hash via the wired EmailHasher.
//  3. Mark consent_log rows withdrawn (port call).
//  4. Dispatch ConsentWithdrawnEvent (best-effort; nil dispatcher = skip).
//
// Returns the count of grants that were marked withdrawn so callers can
// distinguish "first-time withdrawal" from "no-op repeat".
func (uc *WithdrawConsentUseCase) Execute(ctx context.Context, cmd cqrs.WithdrawConsentCommand) (*WithdrawConsentResult, error) {
	email := strings.TrimSpace(cmd.Email)
	if email == "" {
		return nil, fmt.Errorf("usecases: withdraw consent: email is required")
	}
	if uc.withdrawer == nil {
		return nil, fmt.Errorf("usecases: withdraw consent: no consent store wired")
	}
	if uc.hasher == nil {
		return nil, fmt.Errorf("usecases: withdraw consent: no email hasher wired")
	}

	emailHash := uc.hasher.HashEmail(email)
	if emailHash == "" {
		return nil, fmt.Errorf("usecases: withdraw consent: hasher returned empty for %q", email)
	}

	now := uc.now()
	updated, err := uc.withdrawer.MarkWithdrawnByEmailHash(
		emailHash, now,
		cmd.NoticeVersion, cmd.Reason, cmd.IPAddress, cmd.UserAgent,
	)
	if err != nil {
		return nil, fmt.Errorf("usecases: withdraw consent: %w", err)
	}

	if uc.dispatcher != nil {
		uc.dispatcher.Dispatch(domain.ConsentWithdrawnEvent{
			Email:     strings.ToLower(email),
			EmailHash: emailHash,
			Reason:    cmd.Reason,
			Timestamp: now,
		})
	}

	if uc.logger != nil {
		uc.logger.Info(ctx, "consent withdrawn",
			"email_hash", emailHash,
			"grants_marked", updated,
			"notice_version", cmd.NoticeVersion,
		)
	}
	return &WithdrawConsentResult{
		EmailHash:       emailHash,
		GrantsWithdrawn: updated,
	}, nil
}
