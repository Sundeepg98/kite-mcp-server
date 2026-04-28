package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	"github.com/zerodha/kite-mcp-server/kc/eventsourcing"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	logport "github.com/zerodha/kite-mcp-server/kc/logger"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
	tgbot "github.com/zerodha/kite-mcp-server/kc/telegram"
	"github.com/zerodha/kite-mcp-server/kc/usecases"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// briefingTokenAdapter bridges a token store to alerts.TokenChecker.
//
// Phase 3a kc/-side close-out: store is typed as the kc.TokenStoreInterface
// port rather than the concrete *kc.KiteTokenStore. The two methods used
// by GetToken — Get(email) — are part of the interface, so narrowing
// the field eliminates a Concrete-pattern leak at this construction site
// without behaviour change. The concrete *kc.KiteTokenStore satisfies
// the interface structurally so existing struct-literal sites (tests,
// wire.go's briefingSvc construction) keep compiling under
// implicit-conversion.
type briefingTokenAdapter struct {
	store kc.TokenStoreInterface
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

// riskguardLTPAdapter bridges paperLTPAdapter (kite-style "EXCHANGE:SYMBOL"
// argument) to riskguard.LTPLookup (separate exchange + tradingsymbol
// arguments). PR-C uses this to plumb Kite live quotes into the SEBI
// OTR band check. Reuses paperLTPAdapter.GetLTP under the hood — same
// active-session iteration, same client lookup, same fallback semantics.
type riskguardLTPAdapter struct {
	manager *kc.Manager
}

// GetLTP looks up the last-traded price for one instrument. Returns
// (price, true) on success, (0, false) on any failure (no active
// sessions, broker unavailable, instrument not quoted). The OTR band
// check fails open on (_, false), which is the intended SEBI-
// conservative behaviour (don't block valid orders on missing oracle
// data).
func (a *riskguardLTPAdapter) GetLTP(exchange, tradingsymbol string) (float64, bool) {
	if a.manager == nil || exchange == "" || tradingsymbol == "" {
		return 0, false
	}
	key := exchange + ":" + tradingsymbol
	bridge := &paperLTPAdapter{manager: a.manager}
	ltps, err := bridge.GetLTP(key)
	if err != nil {
		return 0, false
	}
	p, ok := ltps[key]
	if !ok || p <= 0 {
		return 0, false
	}
	return p, true
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
//
// commandBus is a structural invariant: it is NEVER nil at use time. The
// production wire-up sets it from kcManager.CommandBus(); tests that
// build a struct literal without one trigger ensureBus() on first use,
// which constructs a local InMemoryBus with the same handlers the manager
// would have wired. The adapter therefore has a single dispatch path —
// no "fallback to raw store write" gate.
type kiteExchangerAdapter struct {
	apiKey    string
	apiSecret string
	// Phase 3a kc/-side close-out: the four store fields below are typed
	// as kc-package interfaces (TokenStoreInterface, CredentialStoreInterface,
	// users.UserStore via the kc.UserStoreInterface alias path here is
	// retained as *users.Store because users.Store has a few non-interface
	// methods the local-bus path uses indirectly via localUserProvisioner —
	// see adapters_local_bus.go's narrowed port story below) where the
	// methods used by both direct reads (GetCredentials, GetSecretByAPIKey)
	// AND the test-local-bus handler backing (oauthBridgeStores → local*
	// adapters) are all on the kc-level interface surface. *kc.KiteTokenStore
	// / *kc.KiteCredentialStore / *registry.Store / *users.Store satisfy
	// these interfaces structurally so app/app.go's struct-literal
	// construction site can pass kcManager.TokenStore() / .CredentialStore()
	// / .RegistryStore() / .UserStore() (port accessors) instead of the
	// *Concrete() siblings.
	tokenStore      kc.TokenStoreInterface      // read paths AND test-local-bus handler backing
	credentialStore kc.CredentialStoreInterface // read paths AND test-local-bus handler backing
	registryStore   kc.RegistryStoreInterface   // test-local-bus handler backing
	userStore       kc.UserStoreInterface       // test-local-bus handler backing
	// Wave D Phase 3 Package 7c-4b: logger field carries the
	// kc/logger.Logger port. Constructor sites (adapters_local_bus.go)
	// take *slog.Logger params and wrap via logport.NewSlog.
	logger        logport.Logger
	authenticator broker.Authenticator
	commandBus    cqrs.CommandBus // never nil at use time — see ensureBus
	busOnce       sync.Once
}

// ensureBus guarantees a.commandBus is non-nil before any Dispatch call.
// In production, app/app.go wires kcManager.CommandBus() at struct-literal
// time so this is a no-op (commandBus already non-nil). In tests that
// build a struct literal without a manager, this constructs an in-process
// bus with the same six OAuth-bridge handlers the manager would have
// registered, backed by whatever stores the test put on the adapter.
//
// Rationale: the adapter MUST always go through Dispatch, never a raw
// store write — that's the CQRS invariant. We satisfy it by ensuring
// every code path has a real bus, not by gating writes on a nil check.
func (a *kiteExchangerAdapter) ensureBus() {
	a.busOnce.Do(func() {
		if a.commandBus != nil {
			return
		}
		// newLocalOAuthBridgeBus takes *slog.Logger (Package 7c keeps
		// signature stable for its other callers). AsSlog unwraps the
		// port back to slog at this single boundary.
		a.commandBus = newLocalOAuthBridgeBus(logport.AsSlog(a.logger), oauthBridgeStores{
			Users:       a.userStore,
			Tokens:      a.tokenStore,
			Credentials: a.credentialStore,
			Registry:    a.registryStore,
		})
	})
}

// provisionUser auto-provisions a user on first OAuth login and checks status.
// Returns an error if the user is suspended or offboarded.
//
// Single dispatch path: ensureBus() guarantees a non-nil bus, then we
// dispatch ProvisionUserOnLoginCommand. The use case in
// kc/usecases/oauth_bridge_usecases.go owns the suspended/offboarded →
// error mapping.
//
// E1+E4: errors wrap the upstream sentinel via %w so caller-side
// errors.Is checks still match, AND the email is hashed (audit.HashEmail
// — same canonical form the consent log uses) before being embedded
// in the message. Plaintext emails in error strings leak through every
// log layer the error touches; the hash gives operators correlation
// power without the PII exposure.
func (a *kiteExchangerAdapter) provisionUser(email, kiteUID, displayName string) error {
	email = strings.ToLower(email)
	a.ensureBus()
	err := a.commandBus.Dispatch(context.Background(), cqrs.ProvisionUserOnLoginCommand{
		Email:       email,
		KiteUID:     kiteUID,
		DisplayName: displayName,
	})
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, usecases.ErrUserSuspended):
		return fmt.Errorf("user account is suspended (email_hash=%s): %w", audit.HashEmail(email), usecases.ErrUserSuspended)
	case errors.Is(err, usecases.ErrUserOffboarded):
		return fmt.Errorf("user account has been offboarded (email_hash=%s): %w", audit.HashEmail(email), usecases.ErrUserOffboarded)
	default:
		return err
	}
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

	a.logger.Debug(context.Background(), "Kite token exchange successful", "email", email, "user_id", result.UserID)

	// Token cache + registry-stamp writes — single dispatch path via the
	// bus. ensureBus() above already guaranteed non-nil; provisionUser
	// called it for us.
	if dispErr := a.commandBus.Dispatch(context.Background(), cqrs.CacheKiteAccessTokenCommand{
		Email:       email,
		AccessToken: result.AccessToken,
		UserID:      result.UserID,
		UserName:    result.UserName,
	}); dispErr != nil {
		a.logger.Error(context.Background(), "Failed to dispatch CacheKiteAccessTokenCommand", dispErr, "email", email)
	}
	if a.apiKey != "" {
		if dispErr := a.commandBus.Dispatch(context.Background(), cqrs.SyncRegistryAfterLoginCommand{
			Email:        email,
			APIKey:       a.apiKey,
			AutoRegister: false,
		}); dispErr != nil {
			a.logger.Debug(context.Background(), "SyncRegistryAfterLoginCommand global-stamp dispatch failed", "error", dispErr)
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

	a.logger.Debug(context.Background(), "Kite token exchange (per-user credentials) successful", "email", email, "user_id", result.UserID)
	lowerEmail := strings.ToLower(email)

	// Three writes in sequence: token cache, credential store, registry sync.
	// Each dispatched as a separate command. ensureBus() in provisionUser
	// already guaranteed a.commandBus is non-nil.
	if dispErr := a.commandBus.Dispatch(context.Background(), cqrs.CacheKiteAccessTokenCommand{
		Email:       lowerEmail,
		AccessToken: result.AccessToken,
		UserID:      result.UserID,
		UserName:    result.UserName,
	}); dispErr != nil {
		a.logger.Error(context.Background(), "Failed to dispatch CacheKiteAccessTokenCommand", dispErr, "email", lowerEmail)
	}
	if dispErr := a.commandBus.Dispatch(context.Background(), cqrs.StoreUserKiteCredentialsCommand{
		Email:     lowerEmail,
		APIKey:    apiKey,
		APISecret: apiSecret,
	}); dispErr != nil {
		a.logger.Error(context.Background(), "Failed to dispatch StoreUserKiteCredentialsCommand", dispErr, "email", lowerEmail)
	}
	if dispErr := a.commandBus.Dispatch(context.Background(), cqrs.SyncRegistryAfterLoginCommand{
		Email:        lowerEmail,
		APIKey:       apiKey,
		APISecret:    apiSecret,
		Label:        "Self-provisioned",
		AutoRegister: true,
	}); dispErr != nil {
		a.logger.Error(context.Background(), "Failed to dispatch SyncRegistryAfterLoginCommand", dispErr, "email", lowerEmail)
	}

	return email, nil
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
//
// commandBus is a structural invariant: NEVER nil at use time.
// ensureBus() lazily constructs a local InMemoryBus when none was wired
// (e.g. unit tests that build a struct literal). No "bus or raw write"
// gate — every code path goes through Dispatch.
type clientPersisterAdapter struct {
	db         *alerts.DB
	commandBus cqrs.CommandBus
	// Wave D Phase 3 Package 7c-4b: see kiteExchangerAdapter for the
	// logport.Logger port migration rationale.
	logger     logport.Logger
	busOnce    sync.Once
}

func (a *clientPersisterAdapter) ensureBus() {
	a.busOnce.Do(func() {
		if a.commandBus != nil {
			return
		}
		// AsSlog: see kiteExchangerAdapter.ensureBus rationale.
		a.commandBus = newLocalOAuthClientBus(logport.AsSlog(a.logger), a.db)
	})
}

// SaveClient dispatches a SaveOAuthClientCommand. ensureBus() guarantees
// a non-nil bus first; production wires kcManager.CommandBus() directly,
// tests get a local InMemoryBus that hits the same use case.
func (a *clientPersisterAdapter) SaveClient(clientID, clientSecret, redirectURIsJSON, clientName string, createdAt time.Time, isKiteKey bool) error {
	a.ensureBus()
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

// DeleteClient dispatches a DeleteOAuthClientCommand.
func (a *clientPersisterAdapter) DeleteClient(clientID string) error {
	a.ensureBus()
	return a.commandBus.Dispatch(context.Background(), cqrs.DeleteOAuthClientCommand{
		ClientID: clientID,
	})
}

// registryAdapter bridges a registry store to oauth.KeyRegistry.
//
// Phase 3a kc/-side close-out: store is typed as kc.RegistryStoreInterface
// port. The three methods called below — HasEntries, GetByEmail,
// GetByAPIKey — are all on the interface. *registry.Store satisfies it
// structurally so the construction site at app/app.go can pass
// kcManager.RegistryStore() instead of RegistryStoreConcrete().
type registryAdapter struct {
	store kc.RegistryStoreInterface
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
//
// Phase 3a kc/-side migration: the bot's KiteManager interface no longer
// returns concrete pointer types — it returns telegram-local narrow ports
// (AlertLookup, WatchlistLookup, InstrumentLookup, PaperEngineLookup,
// TickerLookup). Each accessor below returns the same concrete pointer
// the manager owns; Go's structural-interface satisfaction lets the
// concrete type pass through as the narrower port without an explicit
// cast. nil-safety: each method returns the typed nil so the call-site
// `if x == nil` guards in commands.go / trading_commands.go work
// correctly even when the concrete underlying type is unset (e.g.,
// PaperEngine disabled, TickerService not yet started).
type telegramManagerAdapter struct {
	m *kc.Manager
}

func (a *telegramManagerAdapter) TelegramStore() tgbot.TelegramLookup {
	return a.m.TelegramStore()
}
func (a *telegramManagerAdapter) AlertStore() tgbot.AlertLookup {
	if s := a.m.AlertStoreConcrete(); s != nil {
		return s
	}
	return nil
}
func (a *telegramManagerAdapter) WatchlistStore() tgbot.WatchlistLookup {
	if s := a.m.WatchlistStoreConcrete(); s != nil {
		return s
	}
	return nil
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
func (a *telegramManagerAdapter) InstrumentsManager() tgbot.InstrumentLookup {
	if im := a.m.InstrumentsManagerConcrete(); im != nil {
		return im
	}
	return nil
}
func (a *telegramManagerAdapter) IsTokenValid(email string) bool {
	return a.m.IsTokenValid(email)
}
func (a *telegramManagerAdapter) RiskGuard() *riskguard.Guard {
	return a.m.RiskGuard()
}
func (a *telegramManagerAdapter) PaperEngine() tgbot.PaperEngineLookup {
	if pe := a.m.PaperEngineConcrete(); pe != nil {
		return pe
	}
	return nil
}
func (a *telegramManagerAdapter) TickerService() tgbot.TickerLookup {
	if ts := a.m.TickerServiceConcrete(); ts != nil {
		return ts
	}
	return nil
}

// makeEventPersister returns a domain.Event handler that appends events to the domain audit log.
// This is the production event persistence path — events are written but never read back
// for state reconstitution. The domain_events table serves as an immutable audit trail
// for compliance, debugging, and activity dashboards.
// Each event is stored with the given aggregateType. The aggregate ID is derived from
// the event's fields (e.g. OrderID for orders, AlertID for alerts, Email for users).
//
// PR-D Item 2: deriveEmailHash extracts the user-association field from
// the typed event (Email / AdminEmail) and stores its SHA-256 hex digest
// on StoredEvent.EmailHash. The persisted row carries the hash, never
// the plaintext — the original event payload is JSON-marshalled as-is
// for in-process consumers, but the indexable email_hash column gives
// auditors and the data-portability export a PII-free correlation key.
// Wave D Phase 3 Package 7c-4b: signature retains *slog.Logger for
// backward-compat with existing callers (app/wire.go, tests). The
// internal log path uses kc/logger.Logger via logport.NewSlog so
// the typed-port + ctx threading benefits propagate without breaking
// the public surface. Constructor-shim pattern matches the
// established deprecation approach in cqrs/billing/ops Package 7c.
func makeEventPersister(store *eventsourcing.EventStore, aggregateType string, logger *slog.Logger) func(domain.Event) {
	port := logport.NewSlog(logger)
	return func(e domain.Event) {
		// Event persister has no request ctx in scope; use
		// context.Background() per the helper-function convention.
		ctx := context.Background()
		aggregateID := deriveAggregateID(e)
		payload, err := eventsourcing.MarshalPayload(e)
		if err != nil {
			port.Error(ctx, "Failed to marshal domain event payload", err, "event_type", e.EventType())
			return
		}
		seq, err := store.NextSequence(aggregateID)
		if err != nil {
			port.Error(ctx, "Failed to get next sequence", err, "event_type", e.EventType(), "aggregate", aggregateID)
			return
		}
		if err := store.Append(eventsourcing.StoredEvent{
			AggregateID:   aggregateID,
			AggregateType: aggregateType,
			EventType:     e.EventType(),
			Payload:       payload,
			OccurredAt:    e.OccurredAt(),
			Sequence:      seq,
			EmailHash:     deriveEmailHash(e),
		}); err != nil {
			port.Error(ctx, "Failed to persist domain event", err, "event_type", e.EventType())
		}
	}
}

// deriveEmailHash extracts the user-association field from a typed
// domain.Event and returns its SHA-256 hex digest. Returns "" for
// system events that have no user (GlobalFreezeEvent, etc.).
//
// Centralised here so the persister and any future direct-Append
// callers (use cases that bypass the dispatcher path) produce
// identical hash values.
func deriveEmailHash(e domain.Event) string {
	switch ev := e.(type) {
	case domain.OrderPlacedEvent:
		return audit.HashEmail(ev.Email)
	case domain.OrderModifiedEvent:
		return audit.HashEmail(ev.Email)
	case domain.OrderCancelledEvent:
		return audit.HashEmail(ev.Email)
	case domain.OrderFilledEvent:
		return audit.HashEmail(ev.Email)
	case domain.PositionOpenedEvent:
		return audit.HashEmail(ev.Email)
	case domain.PositionClosedEvent:
		return audit.HashEmail(ev.Email)
	case domain.AlertCreatedEvent:
		return audit.HashEmail(ev.Email)
	case domain.AlertTriggeredEvent:
		return audit.HashEmail(ev.Email)
	case domain.AlertDeletedEvent:
		return audit.HashEmail(ev.Email)
	case domain.UserFrozenEvent:
		return audit.HashEmail(ev.Email)
	case domain.UserSuspendedEvent:
		return audit.HashEmail(ev.Email)
	case domain.RiskLimitBreachedEvent:
		return audit.HashEmail(ev.Email)
	case domain.SessionCreatedEvent:
		return audit.HashEmail(ev.Email)
	// SessionCleared / SessionInvalidated key by session_id only, no
	// email field — empty hash means "session-scoped, not user-scoped".
	case domain.FamilyInvitedEvent:
		// Hash the admin (the data subject doing the inviting). The
		// invited email is also user data but isn't queried-by-user
		// in our schema; if needed a future migration can split.
		return audit.HashEmail(ev.AdminEmail)
	case domain.FamilyMemberRemovedEvent:
		return audit.HashEmail(ev.AdminEmail)
	case domain.WatchlistCreatedEvent:
		return audit.HashEmail(ev.Email)
	case domain.WatchlistDeletedEvent:
		return audit.HashEmail(ev.Email)
	case domain.WatchlistItemAddedEvent:
		return audit.HashEmail(ev.Email)
	case domain.WatchlistItemRemovedEvent:
		return audit.HashEmail(ev.Email)
	case domain.CredentialRegisteredEvent:
		return audit.HashEmail(ev.Email)
	case domain.CredentialRotatedEvent:
		return audit.HashEmail(ev.Email)
	case domain.CredentialRevokedEvent:
		return audit.HashEmail(ev.Email)
	case domain.ConsentWithdrawnEvent:
		// Already pre-hashed by the use case; pass through if non-empty.
		if ev.EmailHash != "" {
			return ev.EmailHash
		}
		return audit.HashEmail(ev.Email)
	case domain.TierChangedEvent:
		return audit.HashEmail(ev.UserEmail)
	case domain.AnomalyBaselineSnapshottedEvent:
		return audit.HashEmail(ev.UserEmail)
	case domain.AnomalyCacheInvalidatedEvent:
		return audit.HashEmail(ev.UserEmail)
	case domain.AnomalyCacheEvictedEvent:
		return audit.HashEmail(ev.UserEmail)
	case domain.RiskguardKillSwitchTrippedEvent:
		// Global kill-switch typically has empty UserEmail; hash falls
		// back to "" so the email_hash WHERE query excludes it (system
		// event, not user-correlated).
		if ev.UserEmail == "" {
			return ""
		}
		return audit.HashEmail(ev.UserEmail)
	case domain.RiskguardDailyCounterResetEvent:
		return audit.HashEmail(ev.UserEmail)
	case domain.RiskguardRejectionEvent:
		return audit.HashEmail(ev.UserEmail)
	case domain.TelegramSubscribedEvent:
		return audit.HashEmail(ev.UserEmail)
	case domain.TelegramChatBoundEvent:
		return audit.HashEmail(ev.UserEmail)
	case domain.OrderRejectedEvent:
		return audit.HashEmail(ev.Email)
	case domain.PositionConvertedEvent:
		return audit.HashEmail(ev.Email)
	case domain.PaperOrderRejectedEvent:
		return audit.HashEmail(ev.Email)
	case domain.MFOrderRejectedEvent:
		return audit.HashEmail(ev.Email)
	case domain.MFOrderPlacedEvent:
		return audit.HashEmail(ev.Email)
	case domain.MFOrderCancelledEvent:
		return audit.HashEmail(ev.Email)
	case domain.MFSIPPlacedEvent:
		return audit.HashEmail(ev.Email)
	case domain.MFSIPCancelledEvent:
		return audit.HashEmail(ev.Email)
	case domain.GTTRejectedEvent:
		return audit.HashEmail(ev.Email)
	case domain.GTTPlacedEvent:
		return audit.HashEmail(ev.Email)
	case domain.GTTModifiedEvent:
		return audit.HashEmail(ev.Email)
	case domain.GTTDeletedEvent:
		return audit.HashEmail(ev.Email)
	case domain.TrailingStopTriggeredEvent:
		return audit.HashEmail(ev.Email)
	case domain.TrailingStopSetEvent:
		return audit.HashEmail(ev.Email)
	case domain.TrailingStopCancelledEvent:
		return audit.HashEmail(ev.Email)
	case domain.NativeAlertPlacedEvent:
		return audit.HashEmail(ev.Email)
	case domain.NativeAlertModifiedEvent:
		return audit.HashEmail(ev.Email)
	case domain.NativeAlertDeletedEvent:
		return audit.HashEmail(ev.Email)
	case domain.PaperTradingEnabledEvent:
		return audit.HashEmail(ev.Email)
	case domain.PaperTradingDisabledEvent:
		return audit.HashEmail(ev.Email)
	case domain.PaperTradingResetEvent:
		return audit.HashEmail(ev.Email)
	case domain.GlobalFreezeEvent:
		// System event — no user-association field. Empty hash means
		// "this row is not user-correlated" (the email_hash WHERE
		// query won't include it, which is correct).
		return ""
	default:
		return ""
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
	case domain.TierChangedEvent:
		return ev.UserEmail
	case domain.WatchlistCreatedEvent:
		return ev.WatchlistID
	case domain.WatchlistDeletedEvent:
		return ev.WatchlistID
	case domain.WatchlistItemAddedEvent:
		return ev.WatchlistID
	case domain.WatchlistItemRemovedEvent:
		return ev.WatchlistID
	case domain.AnomalyBaselineSnapshottedEvent:
		return domain.AnomalyCacheAggregateID(ev.UserEmail)
	case domain.AnomalyCacheInvalidatedEvent:
		return domain.AnomalyCacheAggregateID(ev.UserEmail)
	case domain.AnomalyCacheEvictedEvent:
		return domain.AnomalyCacheAggregateID(ev.UserEmail)
	case domain.PluginRegisteredEvent:
		return domain.PluginWatcherAggregateID(ev.Path)
	case domain.PluginUnregisteredEvent:
		return domain.PluginWatcherAggregateID(ev.Path)
	case domain.PluginReloadTriggeredEvent:
		return domain.PluginWatcherAggregateID(ev.Path)
	case domain.PluginWatcherStartedEvent:
		return domain.PluginWatcherAggregateID("")
	case domain.PluginWatcherStoppedEvent:
		return domain.PluginWatcherAggregateID("")
	case domain.RiskguardKillSwitchTrippedEvent:
		return domain.RiskguardCountersAggregateID(ev.UserEmail)
	case domain.RiskguardDailyCounterResetEvent:
		return domain.RiskguardCountersAggregateID(ev.UserEmail)
	case domain.RiskguardRejectionEvent:
		return domain.RiskguardCountersAggregateID(ev.UserEmail)
	case domain.TelegramSubscribedEvent:
		return domain.TelegramSubscriptionAggregateID(ev.UserEmail)
	case domain.TelegramChatBoundEvent:
		return domain.TelegramSubscriptionAggregateID(ev.UserEmail)
	case domain.OrderRejectedEvent:
		// When OrderID is non-empty (modify/cancel rejections) the event
		// joins the existing order aggregate stream so a forensic walk
		// of the order ID sees place→reject inline. When OrderID is
		// empty (place_order failures, no broker ID issued) it falls
		// back to a per-rejection synthetic key built from email + the
		// event's own timestamp. See domain.OrderRejectedAggregateID.
		return domain.OrderRejectedAggregateID(ev.OrderID, ev.Email, ev.Timestamp)
	case domain.PositionConvertedEvent:
		// Keyed by (email, exchange, tradingsymbol, OLD product) so a
		// CNC->MIS->CNC sequence threads through a stable aggregate
		// stream rooted on the original holding's product. Matches the
		// pre-ES untyped key shape so existing rows aren't orphaned.
		return domain.PositionConvertedAggregateID(ev.Email, ev.Instrument.Exchange, ev.Instrument.Tradingsymbol, ev.OldProduct)
	case domain.PaperOrderRejectedEvent:
		// Paper IDs ("PAPER_<n>") are process-unique via atomic counter,
		// no email prefix needed. Empty OrderID (defence in depth) lands
		// in "paper:unknown" rather than colliding with real rows.
		return domain.PaperOrderAggregateID(ev.OrderID)
	case domain.MFOrderRejectedEvent:
		// Mirrors OrderRejectedAggregateID: non-empty OrderID joins
		// the existing MF aggregate stream; empty falls back to
		// synthetic "mf-rejected:<email>:<rfc3339-nanos>" key.
		return domain.MFOrderRejectedAggregateID(ev.OrderID, ev.Email, ev.Timestamp)
	case domain.GTTRejectedEvent:
		// Non-zero TriggerID joins the existing GTT aggregate stream
		// (matches the appendAuxEvent success path's "<id>" key shape);
		// zero falls back to synthetic "gtt-rejected:<email>:<ts>".
		return domain.GTTRejectedAggregateID(ev.TriggerID, ev.Email, ev.Timestamp)
	case domain.TrailingStopTriggeredEvent:
		// Keyed by TrailingStopID — uuid-derived 8-char prefix, globally
		// unique across users. The trailing stop's full lifecycle (set
		// -> N triggers -> cancel) replays under one aggregate stream.
		return domain.TrailingStopAggregateID(ev.TrailingStopID)
	case domain.MFOrderPlacedEvent:
		// Keyed by OrderID; pairs with MFOrderRejectedEvent (cancel
		// source) under the same aggregate when both fire.
		return domain.MFAggregateID(ev.OrderID)
	case domain.MFOrderCancelledEvent:
		return domain.MFAggregateID(ev.OrderID)
	case domain.MFSIPPlacedEvent:
		// Distinct ID namespace from MFOrder; same MFAggregateID helper
		// since SIPID is a Kite-assigned string just like OrderID.
		return domain.MFAggregateID(ev.SIPID)
	case domain.MFSIPCancelledEvent:
		return domain.MFAggregateID(ev.SIPID)
	case domain.GTTPlacedEvent:
		// fmt.Sprintf("%d", triggerID) matches the existing aux-event
		// aggregate-ID shape so existing rows and new typed events sort
		// under the same stream.
		return domain.GTTAggregateID(ev.TriggerID)
	case domain.GTTModifiedEvent:
		return domain.GTTAggregateID(ev.TriggerID)
	case domain.GTTDeletedEvent:
		return domain.GTTAggregateID(ev.TriggerID)
	case domain.TrailingStopSetEvent:
		// Same TrailingStopID-keyed routing as TrailingStopTriggeredEvent
		// so set->triggers->cancel replays under one aggregate stream.
		return domain.TrailingStopAggregateID(ev.TrailingStopID)
	case domain.TrailingStopCancelledEvent:
		return domain.TrailingStopAggregateID(ev.TrailingStopID)
	case domain.NativeAlertPlacedEvent:
		// UUID is empty at place time (broker assigns lazily); helper
		// falls back to email when UUID is empty (matching the prior
		// PlaceNativeAlertUseCase aggregate-id choice).
		return domain.NativeAlertAggregateID(ev.UUID, ev.Email)
	case domain.NativeAlertModifiedEvent:
		return domain.NativeAlertAggregateID(ev.UUID, ev.Email)
	case domain.NativeAlertDeletedEvent:
		return domain.NativeAlertAggregateID(ev.UUID, ev.Email)
	case domain.PaperTradingEnabledEvent:
		// Keyed by email — paper account is per-user, full enable/reset/
		// disable lifecycle replays under one stream.
		return domain.PaperTradingAggregateID(ev.Email)
	case domain.PaperTradingDisabledEvent:
		return domain.PaperTradingAggregateID(ev.Email)
	case domain.PaperTradingResetEvent:
		return domain.PaperTradingAggregateID(ev.Email)
	default:
		return "unknown"
	}
}
