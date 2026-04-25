package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	"github.com/zerodha/kite-mcp-server/kc/eventsourcing"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/kc/papertrading"
	"github.com/zerodha/kite-mcp-server/kc/registry"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
	"github.com/zerodha/kite-mcp-server/kc/ticker"
	"github.com/zerodha/kite-mcp-server/kc/usecases"
	"github.com/zerodha/kite-mcp-server/kc/users"
	"github.com/zerodha/kite-mcp-server/kc/watchlist"
	"github.com/zerodha/kite-mcp-server/oauth"
	tgbot "github.com/zerodha/kite-mcp-server/kc/telegram"
)

type briefingTokenAdapter struct {
	store *kc.KiteTokenStore
}

func (a *briefingTokenAdapter) GetToken(email string) (string, time.Time, bool) {
	entry, ok := a.store.Get(email)
	if !ok {
		return "", time.Time{}, false
	}
	return entry.AccessToken, entry.StoredAt, true
}

func (a *briefingTokenAdapter) IsExpired(storedAt time.Time) bool {
	return kc.IsKiteTokenExpired(storedAt)
}

// briefingCredAdapter bridges kc.Manager to alerts.CredentialGetter.
type briefingCredAdapter struct {
	manager *kc.Manager
}

func (a *briefingCredAdapter) GetAPIKey(email string) string {
	return a.manager.GetAPIKeyForEmail(email)
}

// paperLTPAdapter bridges kc.Manager to papertrading.LTPProvider by using
// any active session's Kite client for read-only LTP lookups.
type paperLTPAdapter struct {
	manager *kc.Manager
}

func (a *paperLTPAdapter) GetLTP(instruments ...string) (map[string]float64, error) {
	sessions := a.manager.SessionManager().ListActiveSessions()
	if len(sessions) == 0 {
		return nil, fmt.Errorf("no active Kite sessions for LTP lookup")
	}
	for _, sess := range sessions {
		data, ok := sess.Data.(*kc.KiteSessionData)
		if !ok || data == nil || data.Kite == nil || data.Kite.Client == nil {
			continue
		}
		ltps, err := data.Kite.Client.GetLTP(instruments...)
		if err != nil {
			continue
		}
		result := make(map[string]float64, len(ltps))
		for k, v := range ltps {
			result[k] = v.LastPrice
		}
		return result, nil
	}
	return nil, fmt.Errorf("no Kite client available for LTP")
}

// instrumentsFreezeAdapter wraps instruments.Manager to implement riskguard.FreezeQuantityLookup.
type instrumentsFreezeAdapter struct {
	mgr *instruments.Manager
}

func (a *instrumentsFreezeAdapter) GetFreezeQuantity(exchange, tradingsymbol string) (uint32, bool) {
	inst, err := a.mgr.GetByTradingsymbol(exchange, tradingsymbol)
	if err != nil {
		return 0, false
	}
	return inst.FreezeQuantity, inst.FreezeQuantity > 0
}

type signerAdapter struct {
	signer *kc.SessionSigner
}

// truncKey safely returns the first n characters of a string, or the whole string if shorter.
func truncKey(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func (s *signerAdapter) Sign(data string) string {
	return s.signer.SignSessionID(data)
}

func (s *signerAdapter) Verify(signed string) (string, error) {
	return s.signer.VerifySessionID(signed)
}

// kiteExchangerAdapter exchanges a Kite request_token for user identity.
//
// Every WRITE in this adapter dispatches through the CommandBus instead of
// touching stores directly — this keeps the CQRS contract uniform across
// the codebase (every mutation hits LoggingMiddleware uniformly). The
// stored *kc.* references are kept only for READS (GetCredentials,
// GetSecretByAPIKey) which are cheap and lock-free.
type kiteExchangerAdapter struct {
	apiKey          string
	apiSecret       string
	tokenStore      *kc.KiteTokenStore     // read-only path (cache lookup)
	credentialStore *kc.KiteCredentialStore // read-only path (per-user creds lookup)
	registryStore   *registry.Store         // unused for writes (kept for HasEntries fast path; may be nil)
	userStore       *users.Store            // unused for writes (provisionUser dispatches via bus)
	logger          *slog.Logger
	authenticator   broker.Authenticator
	commandBus      cqrs.CommandBus // every write goes through here
}

// provisionUser auto-provisions a user on first OAuth login and checks status.
// Returns an error if the user is suspended or offboarded.
//
// Production path: dispatches a ProvisionUserOnLoginCommand on the bus.
// The use case in kc/usecases/oauth_bridge_usecases.go owns the
// suspended/offboarded → error mapping; we translate the sentinel
// errors back to the existing error-message format so callers see no
// behaviour change.
//
// Test fallback: when commandBus is nil (legacy unit tests that wire just
// the adapter without a manager), the adapter calls the user store
// directly using the same business rules. Production NEVER hits this
// path — kcManager.CommandBus() is always non-nil after wire.
func (a *kiteExchangerAdapter) provisionUser(email, kiteUID, displayName string) error {
	email = strings.ToLower(email)
	if a.commandBus == nil {
		return a.provisionUserDirect(email, kiteUID, displayName)
	}
	err := a.commandBus.Dispatch(context.Background(), cqrs.ProvisionUserOnLoginCommand{
		Email:       email,
		KiteUID:     kiteUID,
		DisplayName: displayName,
	})
	if err == nil {
		return nil
	}
	// Map the use case's sentinels to the historical error-message format
	// for backward compatibility with any callers parsing the message.
	switch {
	case errors.Is(err, usecases.ErrUserSuspended):
		return fmt.Errorf("user account is suspended: %s", email)
	case errors.Is(err, usecases.ErrUserOffboarded):
		return fmt.Errorf("user account has been offboarded: %s", email)
	default:
		return err
	}
}

// provisionUserDirect is the test-only direct-store fallback. Holds the
// EXACT same logic the use case implements, just inlined so unit tests
// that don't wire a bus still pass. Production never enters this path —
// see provisionUser's commandBus guard.
//
// (CQRS audit: this is a test seam, not a bypass — it only runs when
// commandBus is nil, which is impossible in any real wire-up.)
func (a *kiteExchangerAdapter) provisionUserDirect(email, kiteUID, displayName string) error {
	if a.userStore == nil {
		return nil
	}
	status := a.userStore.GetStatus(email)
	if status == users.StatusSuspended {
		return fmt.Errorf("user account is suspended: %s", email)
	}
	if status == users.StatusOffboarded {
		return fmt.Errorf("user account has been offboarded: %s", email)
	}
	u := a.userStore.EnsureUser(email, kiteUID, displayName, "self")
	if u != nil {
		a.userStore.UpdateLastLogin(email)
		if kiteUID != "" && u.KiteUID == "" {
			a.userStore.UpdateKiteUID(email, kiteUID)
		}
	}
	return nil
}

func (a *kiteExchangerAdapter) ExchangeRequestToken(requestToken string) (string, error) {
	result, err := a.authenticator.ExchangeToken(a.apiKey, a.apiSecret, requestToken)
	if err != nil {
		return "", fmt.Errorf("kite generate session: %w", err)
	}

	email := result.Email
	if email == "" {
		email = result.UserID
	}

	// Auto-provision user and check status (dispatched via bus, with
	// direct-store fallback when no bus is wired — see provisionUser).
	if err := a.provisionUser(email, result.UserID, result.UserName); err != nil {
		return "", err
	}

	a.logger.Debug("Kite token exchange successful", "email", email, "user_id", result.UserID)

	// Token cache + registry-stamp writes go via the bus in production. The
	// commandBus==nil branch is a unit-test fallback (~36 legacy tests
	// construct adapters without a bus). Production never enters that branch.
	if a.commandBus != nil {
		if dispErr := a.commandBus.Dispatch(context.Background(), cqrs.CacheKiteAccessTokenCommand{
			Email:       email,
			AccessToken: result.AccessToken,
			UserID:      result.UserID,
			UserName:    result.UserName,
		}); dispErr != nil {
			a.logger.Error("Failed to dispatch CacheKiteAccessTokenCommand", "email", email, "error", dispErr)
		}
		if a.apiKey != "" {
			if dispErr := a.commandBus.Dispatch(context.Background(), cqrs.SyncRegistryAfterLoginCommand{
				Email:        email,
				APIKey:       a.apiKey,
				AutoRegister: false,
			}); dispErr != nil {
				a.logger.Debug("SyncRegistryAfterLoginCommand global-stamp dispatch failed", "error", dispErr)
			}
		}
	} else {
		// Bus-less test fallback. Same semantics as the bus path; production
		// never enters this branch.
		if a.tokenStore != nil {
			a.tokenStore.Set(strings.ToLower(email), &kc.KiteTokenEntry{
				AccessToken: result.AccessToken,
				UserID:      result.UserID,
				UserName:    result.UserName,
			})
		}
		if a.registryStore != nil && a.apiKey != "" {
			a.registryStore.UpdateLastUsedAt(a.apiKey)
		}
	}

	return email, nil
}

func (a *kiteExchangerAdapter) ExchangeWithCredentials(requestToken, apiKey, apiSecret string) (string, error) {
	result, err := a.authenticator.ExchangeToken(apiKey, apiSecret, requestToken)
	if err != nil {
		return "", fmt.Errorf("kite generate session with per-user credentials: %w", err)
	}

	email := result.Email
	if email == "" {
		email = result.UserID
	}

	// Auto-provision user and check status (dispatched via bus).
	if err := a.provisionUser(email, result.UserID, result.UserName); err != nil {
		return "", err
	}

	a.logger.Debug("Kite token exchange (per-user credentials) successful", "email", email, "user_id", result.UserID)
	lowerEmail := strings.ToLower(email)

	if a.commandBus != nil {
		// Three writes in sequence: token cache, credential store, registry sync.
		// Each is a separate command to keep handlers narrow + auditable.
		if dispErr := a.commandBus.Dispatch(context.Background(), cqrs.CacheKiteAccessTokenCommand{
			Email:       lowerEmail,
			AccessToken: result.AccessToken,
			UserID:      result.UserID,
			UserName:    result.UserName,
		}); dispErr != nil {
			a.logger.Error("Failed to dispatch CacheKiteAccessTokenCommand", "email", lowerEmail, "error", dispErr)
		}
		if dispErr := a.commandBus.Dispatch(context.Background(), cqrs.StoreUserKiteCredentialsCommand{
			Email:     lowerEmail,
			APIKey:    apiKey,
			APISecret: apiSecret,
		}); dispErr != nil {
			a.logger.Error("Failed to dispatch StoreUserKiteCredentialsCommand", "email", lowerEmail, "error", dispErr)
		}
		if dispErr := a.commandBus.Dispatch(context.Background(), cqrs.SyncRegistryAfterLoginCommand{
			Email:        lowerEmail,
			APIKey:       apiKey,
			APISecret:    apiSecret,
			Label:        "Self-provisioned",
			AutoRegister: true,
		}); dispErr != nil {
			a.logger.Error("Failed to dispatch SyncRegistryAfterLoginCommand", "email", lowerEmail, "error", dispErr)
		}
	} else {
		// Bus-less test fallback. Mirrors the production behaviour with
		// direct-store calls so the legacy unit tests pass. Production
		// never enters this branch.
		a.exchangeWithCredentialsDirect(lowerEmail, apiKey, apiSecret, result)
	}

	return email, nil
}

// exchangeWithCredentialsDirect is the test-only fallback for
// ExchangeWithCredentials. Holds the same store-mutation sequence as the
// pre-CQRS implementation. Production never enters this path.
func (a *kiteExchangerAdapter) exchangeWithCredentialsDirect(lowerEmail, apiKey, apiSecret string, result broker.AuthResult) {
	if a.tokenStore != nil {
		a.tokenStore.Set(lowerEmail, &kc.KiteTokenEntry{
			AccessToken: result.AccessToken,
			UserID:      result.UserID,
			UserName:    result.UserName,
		})
	}
	if a.credentialStore != nil {
		a.credentialStore.Set(lowerEmail, &kc.KiteCredentialEntry{
			APIKey:    apiKey,
			APISecret: apiSecret,
		})
	}
	if a.registryStore == nil {
		return
	}
	if oldEntry, oldFound := a.registryStore.GetByEmail(lowerEmail); oldFound && oldEntry.APIKey != apiKey {
		a.registryStore.MarkStatus(oldEntry.APIKey, registry.StatusReplaced)
	}
	if existing, found := a.registryStore.GetByAPIKeyAnyStatus(apiKey); !found {
		regID := fmt.Sprintf("self-%s-%s", lowerEmail, truncKey(apiKey, 8))
		_ = a.registryStore.Register(&registry.AppRegistration{
			ID: regID, APIKey: apiKey, APISecret: apiSecret, AssignedTo: lowerEmail,
			Label: "Self-provisioned", Status: registry.StatusActive,
			Source: registry.SourceSelfProvisioned, RegisteredBy: lowerEmail,
		})
	} else if existing.AssignedTo != lowerEmail {
		_ = a.registryStore.Update(existing.ID, lowerEmail, "", "")
	}
	a.registryStore.UpdateLastUsedAt(apiKey)
}

func (a *kiteExchangerAdapter) GetCredentials(email string) (string, string, bool) {
	email = strings.ToLower(email)
	entry, ok := a.credentialStore.Get(email)
	if !ok {
		// Fall back to global credentials if available
		if a.apiKey != "" && a.apiSecret != "" {
			return a.apiKey, a.apiSecret, true
		}
		return "", "", false
	}
	return entry.APIKey, entry.APISecret, true
}

func (a *kiteExchangerAdapter) GetSecretByAPIKey(apiKey string) (string, bool) {
	return a.credentialStore.GetSecretByAPIKey(apiKey)
}

// clientPersisterAdapter bridges alerts.DB to oauth.ClientPersister.
//
// Reads (LoadClients) bypass the bus — they're idempotent queries with no
// state change. Writes (SaveClient, DeleteClient) dispatch through the
// CommandBus so every OAuth-client mutation hits LoggingMiddleware, same
// as every other write in the codebase.
type clientPersisterAdapter struct {
	db         *alerts.DB
	commandBus cqrs.CommandBus // every write dispatches here
	logger     *slog.Logger
}

// SaveClient dispatches a SaveOAuthClientCommand. Falls back to a direct
// DB write if no bus has been wired (test paths that exercise the
// adapter without a manager).
func (a *clientPersisterAdapter) SaveClient(clientID, clientSecret, redirectURIsJSON, clientName string, createdAt time.Time, isKiteKey bool) error {
	if a.commandBus == nil {
		// Bus-less fallback (e.g. unit tests that wire just the adapter).
		return a.db.SaveClient(clientID, clientSecret, redirectURIsJSON, clientName, createdAt, isKiteKey)
	}
	return a.commandBus.Dispatch(context.Background(), cqrs.SaveOAuthClientCommand{
		ClientID:         clientID,
		ClientSecret:     clientSecret,
		RedirectURIsJSON: redirectURIsJSON,
		ClientName:       clientName,
		CreatedAtUnix:    createdAt.UnixNano(),
		IsKiteAPIKey:     isKiteKey,
	})
}

func (a *clientPersisterAdapter) LoadClients() ([]*oauth.ClientLoadEntry, error) {
	entries, err := a.db.LoadClients()
	if err != nil {
		return nil, err
	}
	result := make([]*oauth.ClientLoadEntry, len(entries))
	for i, e := range entries {
		result[i] = &oauth.ClientLoadEntry{
			ClientID:     e.ClientID,
			ClientSecret: e.ClientSecret,
			RedirectURIs: e.RedirectURIs,
			ClientName:   e.ClientName,
			CreatedAt:    e.CreatedAt,
			IsKiteAPIKey: e.IsKiteAPIKey,
		}
	}
	return result, nil
}

// DeleteClient dispatches a DeleteOAuthClientCommand. Same fallback as
// SaveClient.
func (a *clientPersisterAdapter) DeleteClient(clientID string) error {
	if a.commandBus == nil {
		return a.db.DeleteClient(clientID)
	}
	return a.commandBus.Dispatch(context.Background(), cqrs.DeleteOAuthClientCommand{
		ClientID: clientID,
	})
}

// registryAdapter bridges registry.Store to oauth.KeyRegistry.
type registryAdapter struct {
	store *registry.Store
}

func (a *registryAdapter) HasEntries() bool {
	return a.store.HasEntries()
}

func (a *registryAdapter) GetByEmail(email string) (*oauth.RegistryEntry, bool) {
	reg, found := a.store.GetByEmail(email)
	if !found {
		return nil, false
	}
	return &oauth.RegistryEntry{
		APIKey:       reg.APIKey,
		APISecret:    reg.APISecret,
		RegisteredBy: reg.RegisteredBy,
	}, true
}

func (a *registryAdapter) GetSecretByAPIKey(apiKey string) (apiSecret string, ok bool) {
	reg, found := a.store.GetByAPIKey(apiKey)
	if !found {
		return "", false
	}
	return reg.APISecret, true
}

// telegramManagerAdapter bridges *kc.Manager to telegram.KiteManager.
// It adapts interface return types so *kc.Manager satisfies the telegram-local interface.
type telegramManagerAdapter struct {
	m *kc.Manager
}

func (a *telegramManagerAdapter) TelegramStore() tgbot.TelegramLookup {
	return a.m.TelegramStore()
}
func (a *telegramManagerAdapter) AlertStoreConcrete() *alerts.Store {
	return a.m.AlertStoreConcrete()
}
func (a *telegramManagerAdapter) WatchlistStoreConcrete() *watchlist.Store {
	return a.m.WatchlistStoreConcrete()
}
func (a *telegramManagerAdapter) GetAPIKeyForEmail(email string) string {
	return a.m.GetAPIKeyForEmail(email)
}
func (a *telegramManagerAdapter) GetAccessTokenForEmail(email string) string {
	return a.m.GetAccessTokenForEmail(email)
}
func (a *telegramManagerAdapter) TelegramNotifier() *alerts.TelegramNotifier {
	return a.m.TelegramNotifier()
}
func (a *telegramManagerAdapter) InstrumentsManagerConcrete() *instruments.Manager {
	return a.m.InstrumentsManagerConcrete()
}
func (a *telegramManagerAdapter) IsTokenValid(email string) bool {
	return a.m.IsTokenValid(email)
}
func (a *telegramManagerAdapter) RiskGuard() *riskguard.Guard {
	return a.m.RiskGuard()
}
func (a *telegramManagerAdapter) PaperEngineConcrete() *papertrading.PaperEngine {
	return a.m.PaperEngineConcrete()
}
func (a *telegramManagerAdapter) TickerServiceConcrete() *ticker.Service {
	return a.m.TickerServiceConcrete()
}

// makeEventPersister returns a domain.Event handler that appends events to the domain audit log.
// This is the production event persistence path — events are written but never read back
// for state reconstitution. The domain_events table serves as an immutable audit trail
// for compliance, debugging, and activity dashboards.
// Each event is stored with the given aggregateType. The aggregate ID is derived from
// the event's fields (e.g. OrderID for orders, AlertID for alerts, Email for users).
func makeEventPersister(store *eventsourcing.EventStore, aggregateType string, logger *slog.Logger) func(domain.Event) {
	return func(e domain.Event) {
		aggregateID := deriveAggregateID(e)
		payload, err := eventsourcing.MarshalPayload(e)
		if err != nil {
			logger.Error("Failed to marshal domain event payload", "event_type", e.EventType(), "error", err)
			return
		}
		seq, err := store.NextSequence(aggregateID)
		if err != nil {
			logger.Error("Failed to get next sequence", "event_type", e.EventType(), "aggregate", aggregateID, "error", err)
			return
		}
		if err := store.Append(eventsourcing.StoredEvent{
			AggregateID:   aggregateID,
			AggregateType: aggregateType,
			EventType:     e.EventType(),
			Payload:       payload,
			OccurredAt:    e.OccurredAt(),
			Sequence:      seq,
		}); err != nil {
			logger.Error("Failed to persist domain event", "event_type", e.EventType(), "error", err)
		}
	}
}

// deriveAggregateID extracts the most meaningful aggregate identifier from a domain event.
func deriveAggregateID(e domain.Event) string {
	switch ev := e.(type) {
	case domain.OrderPlacedEvent:
		return ev.OrderID
	case domain.OrderModifiedEvent:
		return ev.OrderID
	case domain.OrderCancelledEvent:
		return ev.OrderID
	case domain.PositionOpenedEvent:
		return domain.PositionAggregateID(ev.Email, ev.Instrument, ev.Product)
	case domain.PositionClosedEvent:
		return domain.PositionAggregateID(ev.Email, ev.Instrument, ev.Product)
	case domain.AlertCreatedEvent:
		return ev.AlertID
	case domain.AlertTriggeredEvent:
		return ev.AlertID
	case domain.AlertDeletedEvent:
		return ev.AlertID
	case domain.UserFrozenEvent:
		return ev.Email
	case domain.UserSuspendedEvent:
		return ev.Email
	case domain.GlobalFreezeEvent:
		return ev.By
	case domain.FamilyInvitedEvent:
		return ev.AdminEmail
	case domain.FamilyMemberRemovedEvent:
		return ev.AdminEmail
	case domain.RiskLimitBreachedEvent:
		return ev.Email
	case domain.SessionCreatedEvent:
		return ev.SessionID
	default:
		return "unknown"
	}
}
