package app

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	"github.com/zerodha/kite-mcp-server/kc/eventsourcing"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/kc/papertrading"
	"github.com/zerodha/kite-mcp-server/kc/registry"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
	"github.com/zerodha/kite-mcp-server/kc/ticker"
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
type kiteExchangerAdapter struct {
	apiKey        string
	apiSecret     string
	tokenStore    *kc.KiteTokenStore
	credentialStore *kc.KiteCredentialStore
	registryStore *registry.Store
	userStore     *users.Store
	logger        *slog.Logger
	authenticator broker.Authenticator // handles Kite auth lifecycle (token exchange, etc.)
}

// provisionUser auto-provisions a user on first OAuth login and checks status.
// Returns an error if the user is suspended or offboarded.
func (a *kiteExchangerAdapter) provisionUser(email, kiteUID, displayName string) error {
	if a.userStore == nil {
		return nil
	}
	email = strings.ToLower(email)

	// Check if user exists and their status
	status := a.userStore.GetStatus(email)
	if status == users.StatusSuspended {
		return fmt.Errorf("user account is suspended: %s", email)
	}
	if status == users.StatusOffboarded {
		return fmt.Errorf("user account has been offboarded: %s", email)
	}

	// Auto-provision new users as traders
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

	// Auto-provision user and check status
	if err := a.provisionUser(email, result.UserID, result.UserName); err != nil {
		return "", err
	}

	a.logger.Debug("Kite token exchange successful", "email", email, "user_id", result.UserID)

	// Cache the access token keyed by email
	a.tokenStore.Set(strings.ToLower(email), &kc.KiteTokenEntry{
		AccessToken: result.AccessToken,
		UserID:      result.UserID,
		UserName:    result.UserName,
	})

	// Update last-used timestamp for the global API key in the registry
	if a.registryStore != nil && a.apiKey != "" {
		a.registryStore.UpdateLastUsedAt(a.apiKey)
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

	// Auto-provision user and check status
	if err := a.provisionUser(email, result.UserID, result.UserName); err != nil {
		return "", err
	}

	a.logger.Debug("Kite token exchange (per-user credentials) successful", "email", email, "user_id", result.UserID)

	// Cache the access token keyed by email
	a.tokenStore.Set(strings.ToLower(email), &kc.KiteTokenEntry{
		AccessToken: result.AccessToken,
		UserID:      result.UserID,
		UserName:    result.UserName,
	})

	// Store per-user credentials so all future operations use them
	lowerEmail := strings.ToLower(email)
	a.credentialStore.Set(lowerEmail, &kc.KiteCredentialEntry{
		APIKey:    apiKey,
		APISecret: apiSecret,
	})

	// Auto-register self-provisioned keys in the registry (single source of truth).
	if a.registryStore != nil {
		// Check if user previously had a DIFFERENT key — must check before registering new one.
		oldEntry, oldFound := a.registryStore.GetByEmail(lowerEmail)
		if oldFound && oldEntry.APIKey != apiKey {
			a.registryStore.MarkStatus(oldEntry.APIKey, registry.StatusReplaced)
			a.logger.Info("Marked old registry key as replaced",
				"email", lowerEmail, "old_key", truncKey(oldEntry.APIKey, 8)+"...", "new_key", truncKey(apiKey, 8)+"...")
		}

		existing, found := a.registryStore.GetByAPIKeyAnyStatus(apiKey)
		if !found {
			// New key — register it
			regID := fmt.Sprintf("self-%s-%s", lowerEmail, truncKey(apiKey, 8))
			if err := a.registryStore.Register(&registry.AppRegistration{
				ID:           regID,
				APIKey:       apiKey,
				APISecret:    apiSecret,
				AssignedTo:   lowerEmail,
				Label:        "Self-provisioned",
				Status:       registry.StatusActive,
				Source:       registry.SourceSelfProvisioned,
				RegisteredBy: lowerEmail,
			}); err != nil {
				a.logger.Warn("Failed to auto-register self-provisioned key in registry",
					"email", lowerEmail, "error", err)
			} else {
				a.logger.Info("Auto-registered self-provisioned key in registry",
					"email", lowerEmail, "api_key", truncKey(apiKey, 8)+"...")
			}
		} else if existing.AssignedTo != lowerEmail {
			// Key exists but assigned to a different user — update assignment
			_ = a.registryStore.Update(existing.ID, lowerEmail, "", "")
		}
		// Record last used time for this key
		a.registryStore.UpdateLastUsedAt(apiKey)
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
type clientPersisterAdapter struct {
	db *alerts.DB
}

func (a *clientPersisterAdapter) SaveClient(clientID, clientSecret, redirectURIsJSON, clientName string, createdAt time.Time, isKiteKey bool) error {
	return a.db.SaveClient(clientID, clientSecret, redirectURIsJSON, clientName, createdAt, isKiteKey)
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

func (a *clientPersisterAdapter) DeleteClient(clientID string) error {
	return a.db.DeleteClient(clientID)
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
	case domain.PositionClosedEvent:
		return ev.OrderID
	case domain.AlertTriggeredEvent:
		return ev.AlertID
	case domain.UserFrozenEvent:
		return ev.Email
	case domain.UserSuspendedEvent:
		return ev.Email
	case domain.GlobalFreezeEvent:
		return ev.By
	case domain.FamilyInvitedEvent:
		return ev.AdminEmail
	case domain.RiskLimitBreachedEvent:
		return ev.Email
	case domain.SessionCreatedEvent:
		return ev.SessionID
	default:
		return "unknown"
	}
}
