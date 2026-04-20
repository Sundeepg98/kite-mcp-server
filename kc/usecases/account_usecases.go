package usecases

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/eventsourcing"
)

// CredentialUpdater abstracts credential persistence for account use cases.
// Delete removes a user's credentials (used by DeleteMyAccount).
// Set installs/updates a user's credentials (used by UpdateMyCredentials). The
// apiKey/apiSecret pair is passed as primitive strings — the use case should
// not import kc internal types (circular dependency risk with kc → usecases).
// Has reports whether an entry already exists for the email — needed by
// UpdateMyCredentials to tell first-time registration (CredentialRegistered
// event) from replacement (CredentialRotated event).
// Implementations wrap the kc.KiteCredentialStore.Set call behind this port.
type CredentialUpdater interface {
	Delete(email string)
	Set(email, apiKey, apiSecret string)
	Has(email string) bool
}

// TokenStore abstracts token persistence for account use cases.
type TokenStore interface {
	Delete(email string)
}

// AlertDeleter abstracts alert deletion for account cleanup.
type AlertDeleter interface {
	DeleteByEmail(email string)
}

// AccountDependencies groups stores needed for account deletion.
type AccountDependencies struct {
	CredentialStore CredentialUpdater
	TokenStore      TokenStore
	AlertDeleter    AlertDeleter
	WatchlistStore  WatchlistStore
	TrailingStops   TrailingStopManager
	PaperEngine     PaperEngine
	UserStore       UserStore
	Sessions        SessionTerminator
}

// --- Delete My Account ---

// DeleteMyAccountUseCase permanently deletes a user's account and all data.
type DeleteMyAccountUseCase struct {
	deps   AccountDependencies
	logger *slog.Logger
}

// NewDeleteMyAccountUseCase creates a DeleteMyAccountUseCase with dependencies injected.
func NewDeleteMyAccountUseCase(deps AccountDependencies, logger *slog.Logger) *DeleteMyAccountUseCase {
	return &DeleteMyAccountUseCase{deps: deps, logger: logger}
}

// Execute deletes the user's account and all associated data.
func (uc *DeleteMyAccountUseCase) Execute(ctx context.Context, cmd cqrs.DeleteMyAccountCommand) error {
	if cmd.Email == "" {
		return fmt.Errorf("usecases: email is required")
	}

	if uc.deps.CredentialStore != nil {
		uc.deps.CredentialStore.Delete(cmd.Email)
	}
	if uc.deps.TokenStore != nil {
		uc.deps.TokenStore.Delete(cmd.Email)
	}
	if uc.deps.Sessions != nil {
		uc.deps.Sessions.TerminateByEmail(cmd.Email)
	}
	if uc.deps.AlertDeleter != nil {
		uc.deps.AlertDeleter.DeleteByEmail(cmd.Email)
	}
	if uc.deps.WatchlistStore != nil {
		uc.deps.WatchlistStore.DeleteByEmail(cmd.Email)
	}
	if uc.deps.TrailingStops != nil {
		uc.deps.TrailingStops.CancelByEmail(cmd.Email)
	}
	if uc.deps.PaperEngine != nil {
		if err := uc.deps.PaperEngine.Reset(cmd.Email); err != nil {
			uc.logger.Error("Failed to reset paper trading during account delete", "email", cmd.Email, "error", err)
		}
		if err := uc.deps.PaperEngine.Disable(cmd.Email); err != nil {
			uc.logger.Error("Failed to disable paper trading during account delete", "email", cmd.Email, "error", err)
		}
	}
	if uc.deps.UserStore != nil {
		if err := uc.deps.UserStore.UpdateStatus(cmd.Email, "offboarded"); err != nil {
			uc.logger.Error("Failed to update user status during account delete", "email", cmd.Email, "error", err)
		}
	}

	uc.logger.Info("User self-deleted account via use case", "email", cmd.Email)
	return nil
}

// CredentialSetter abstracts credential persistence for updating credentials.
type CredentialSetter interface {
	Set(email string, entry any)
}

// InvalidateTokenUseCase clears a user's cached Kite access token without
// touching credentials. Used by the login flow when a cached token is
// detected as expired against the live Kite API, and by administrative
// actions (forced re-auth after role change, credential rotation).
//
// Added in Round-5 Phase B to replace direct manager.TokenStore().Delete(email)
// calls scattered across mcp/setup_tools.go — every cached-token clear now
// flows through the CommandBus, giving a uniform audit/observability layer
// for credential lifecycle events.
type InvalidateTokenUseCase struct {
	tokenStore TokenStore
	logger     *slog.Logger
}

// NewInvalidateTokenUseCase creates an InvalidateTokenUseCase with the token
// store injected via the narrow TokenStore port. tokenStore may be nil (tests
// that construct the use case for behaviour-only coverage); Execute handles
// that case as a no-op.
func NewInvalidateTokenUseCase(tokenStore TokenStore, logger *slog.Logger) *InvalidateTokenUseCase {
	return &InvalidateTokenUseCase{tokenStore: tokenStore, logger: logger}
}

// Execute clears the cached token for the command's email. Reason is logged
// at Info level so ops can correlate audit trail entries with the
// credential-lifecycle narrative (expired vs rotated vs admin-forced).
func (uc *InvalidateTokenUseCase) Execute(ctx context.Context, cmd cqrs.InvalidateTokenCommand) error {
	if cmd.Email == "" {
		return fmt.Errorf("usecases: email is required")
	}
	if uc.tokenStore != nil {
		uc.tokenStore.Delete(cmd.Email)
	}
	if uc.logger != nil {
		reason := cmd.Reason
		if reason == "" {
			reason = "unspecified"
		}
		uc.logger.Info("Cached Kite token invalidated via command bus", "email", cmd.Email, "reason", reason)
	}
	return nil
}

// --- Revoke Credentials ---

// RevokeCredentialsUseCase deletes a user's Kite credentials and clears
// their cached access token. Narrower than DeleteMyAccountUseCase — it
// does not touch alerts, watchlists, trailing stops, paper trading, or
// the user's "offboarded" status. Use when the intent is "cut access to
// Kite" while preserving the rest of the account.
//
// Added for Phase B-Audit task #25 so kc/ops dashboard/admin credential
// revoke paths can route through the bus without semantically expanding
// DeleteMyAccountCommand.
type RevokeCredentialsUseCase struct {
	credentialStore CredentialUpdater
	tokenStore      TokenStore
	eventStore      EventAppender
	logger          *slog.Logger
}

// NewRevokeCredentialsUseCase creates a RevokeCredentialsUseCase with
// the credential + token stores injected. Either store may be nil during
// partial bootstrap; Execute tolerates nil as a no-op for that store so
// a half-initialized Manager does not panic.
func NewRevokeCredentialsUseCase(credentialStore CredentialUpdater, tokenStore TokenStore, logger *slog.Logger) *RevokeCredentialsUseCase {
	return &RevokeCredentialsUseCase{credentialStore: credentialStore, tokenStore: tokenStore, logger: logger}
}

// SetEventStore wires the domain audit-log appender. When set, Execute
// appends a credential.revoked StoredEvent after successful revoke.
// Phase C-Credentials (#31). Nil-safe.
func (uc *RevokeCredentialsUseCase) SetEventStore(s EventAppender) { uc.eventStore = s }

// Execute deletes the user's credentials and invalidates the cached
// token. Reason is logged at Info so the audit trail tags intent
// (user-initiated vs admin-forced vs rotation).
func (uc *RevokeCredentialsUseCase) Execute(ctx context.Context, cmd cqrs.RevokeCredentialsCommand) error {
	if cmd.Email == "" {
		return fmt.Errorf("usecases: email is required")
	}
	if uc.credentialStore != nil {
		uc.credentialStore.Delete(cmd.Email)
	}
	if uc.tokenStore != nil {
		uc.tokenStore.Delete(cmd.Email)
	}
	reason := cmd.Reason
	if reason == "" {
		reason = "unspecified"
	}
	if uc.logger != nil {
		uc.logger.Info("Kite credentials revoked via command bus", "email", cmd.Email, "reason", reason)
	}
	uc.appendRevokedEvent(cmd.Email, reason)
	return nil
}

// appendRevokedEvent writes a credential.revoked StoredEvent to the audit
// log. Failures are logged and swallowed — the SQL delete is the source of
// truth and has already succeeded by the time this runs.
func (uc *RevokeCredentialsUseCase) appendRevokedEvent(email, reason string) {
	if uc.eventStore == nil {
		return
	}
	seq, err := uc.eventStore.NextSequence(email)
	if err != nil {
		if uc.logger != nil {
			uc.logger.Warn("event store NextSequence failed on credential.revoked", "email", email, "error", err)
		}
		return
	}
	payload, err := eventsourcing.MarshalPayload(map[string]string{
		"email":  email,
		"reason": reason,
	})
	if err != nil { // COVERAGE: unreachable — map[string]string marshals cleanly
		return
	}
	evt := eventsourcing.StoredEvent{
		AggregateID:   email,
		AggregateType: "Credential",
		EventType:     "credential.revoked",
		Payload:       payload,
		OccurredAt:    time.Now().UTC(),
		Sequence:      seq,
	}
	if err := uc.eventStore.Append(evt); err != nil {
		if uc.logger != nil {
			uc.logger.Warn("event store Append failed on credential.revoked", "email", email, "error", err)
		}
	}
}

// --- Update My Credentials ---

// UpdateMyCredentialsUseCase updates a user's Kite API credentials.
//
// Round-5 Phase B note: this use case now OWNS the persistence step. The
// previous version was validation-only and the MCP tool handler called
// CredentialStore.Set + TokenStore.Delete separately — a CQRS bypass
// that left the command dispatched without the corresponding write.
// The command bus is now the single write entry point for credentials.
type UpdateMyCredentialsUseCase struct {
	credentialStore CredentialUpdater
	tokenStore      TokenStore
	eventStore      EventAppender
	logger          *slog.Logger
}

// NewUpdateMyCredentialsUseCase creates an UpdateMyCredentialsUseCase with dependencies injected.
func NewUpdateMyCredentialsUseCase(credStore CredentialUpdater, tokenStore TokenStore, logger *slog.Logger) *UpdateMyCredentialsUseCase {
	return &UpdateMyCredentialsUseCase{credentialStore: credStore, tokenStore: tokenStore, logger: logger}
}

// SetEventStore wires the domain audit-log appender. When set, Execute
// appends either a credential.registered (first-time) or
// credential.rotated (replacement) StoredEvent after the successful
// credential write. Phase C-Credentials (#31). Nil-safe.
func (uc *UpdateMyCredentialsUseCase) SetEventStore(s EventAppender) { uc.eventStore = s }

// Execute validates then persists the user's credentials and invalidates the
// cached token so the next tool call forces re-authentication against the
// new Kite developer app. Token invalidation is a double-guard — the
// underlying kc.KiteCredentialStore.Set already fires its own
// onTokenInvalidate callback when the API key changes — but calling
// tokenStore.Delete here makes the contract explicit at the use-case
// boundary and lets tests assert it without reaching into internals.
func (uc *UpdateMyCredentialsUseCase) Execute(ctx context.Context, cmd cqrs.UpdateMyCredentialsCommand) error {
	if cmd.Email == "" {
		return fmt.Errorf("usecases: email is required")
	}
	if cmd.APIKey == "" || cmd.APISecret == "" {
		return fmt.Errorf("usecases: both api_key and api_secret are required")
	}

	// Snapshot Has() BEFORE the Set so we can tell first-time registration
	// from rotation. Set is non-transactional with the event append but
	// this check-then-act race is acceptable — worst case a concurrent
	// revoke+re-register emits two Registered events in the log, which is
	// still auditor-correct (they describe two distinct lifecycle moments).
	hadPriorEntry := false
	if uc.credentialStore != nil {
		hadPriorEntry = uc.credentialStore.Has(cmd.Email)
		uc.credentialStore.Set(cmd.Email, cmd.APIKey, cmd.APISecret)
	}
	if uc.tokenStore != nil {
		uc.tokenStore.Delete(cmd.Email)
	}

	uc.logger.Info("User updated credentials via use case", "email", cmd.Email, "prior_entry", hadPriorEntry)
	uc.appendUpdatedEvent(cmd.Email, hadPriorEntry)
	return nil
}

// appendUpdatedEvent writes either a credential.registered or
// credential.rotated StoredEvent depending on whether the email had a
// prior credential entry when Execute ran. Failures are logged and
// swallowed — the SQL write is the source of truth.
func (uc *UpdateMyCredentialsUseCase) appendUpdatedEvent(email string, hadPriorEntry bool) {
	if uc.eventStore == nil {
		return
	}
	seq, err := uc.eventStore.NextSequence(email)
	if err != nil {
		if uc.logger != nil {
			uc.logger.Warn("event store NextSequence failed on credential update", "email", email, "error", err)
		}
		return
	}
	eventType := "credential.registered"
	if hadPriorEntry {
		eventType = "credential.rotated"
	}
	payload, err := eventsourcing.MarshalPayload(map[string]string{
		"email": email,
	})
	if err != nil { // COVERAGE: unreachable — map[string]string marshals cleanly
		return
	}
	evt := eventsourcing.StoredEvent{
		AggregateID:   email,
		AggregateType: "Credential",
		EventType:     eventType,
		Payload:       payload,
		OccurredAt:    time.Now().UTC(),
		Sequence:      seq,
	}
	if err := uc.eventStore.Append(evt); err != nil {
		if uc.logger != nil {
			uc.logger.Warn("event store Append failed on credential update", "email", email, "event_type", eventType, "error", err)
		}
	}
}

