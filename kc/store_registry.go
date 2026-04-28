package kc

import (
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/billing"
	"github.com/zerodha/kite-mcp-server/kc/registry"
	"github.com/zerodha/kite-mcp-server/kc/users"
	"github.com/zerodha/kite-mcp-server/kc/watchlist"
)

// StoreRegistry groups all persistence store accessors that Manager previously
// exposed directly. Manager retains a *StoreRegistry field and thin delegator
// methods (defined below) forward to it for backward compatibility with the
// 73 files that already depend on the Manager-level accessors.
//
// Concrete vs interface-typed accessor pairing
// --------------------------------------------
// Each store has two accessors: an interface-typed one (e.g., TokenStore() →
// TokenStoreInterface) and a *Concrete()-suffixed sibling (e.g.,
// TokenStoreConcrete() → *KiteTokenStore). The interface-typed pair is the
// canonical "consumer" surface — application logic that depends on a store
// should accept the narrowest interface that lets it work, per ISP and the
// hexagonal port discipline.
//
// The *Concrete() siblings are an architectural escape hatch retained
// **for construction-site use only** — composition-root files that pass
// concrete pointer types into adapter struct literals or service
// constructors that legitimately need access to fields/methods not on the
// interface surface. Examples: app/app.go's kiteExchangerAdapter (needs
// *KiteTokenStore for direct cache access on a CQRS-bypass-ok read path),
// app/wire.go's briefingTokenAdapter, kc/ops/handler.go (UI handler that
// needs *registry.Store for List() shape — wider than RegistryReader.List()
// can express). Phase 3a kc/-side migration documented this status; the
// *Concrete() methods are not "leaks" to be retired — they are an
// architectural exception, symmetric with the mcp/-consumer side's
// admin_baseline_tool.go / admin_cache_info_tool.go AuditStoreConcrete
// uses for forensics-only methods (UserOrderStats / StatsCacheHitRate).
//
// Phase 3a-complete state at this commit:
//   - Consumer surfaces (mcp/, kc/telegram, kc/manager_use_cases.go's
//     read paths) route through interface-typed accessors.
//   - Construction-site surfaces (app/app.go, app/wire.go, kc/ops/handler.go,
//     and kc-internal manager_queries_escapes.go's audit fallback) use
//     *Concrete() siblings explicitly because they need concrete-type
//     access for adapter constructions.
//
// Future deletion of the *Concrete() siblings would require either
// (a) widening every store interface to absorb every concrete-only method
// (UserOrderStats, StatsCacheHitRate, etc.) — anti-Go-idiom, surface bloat,
// fails ISP, or (b) restructuring the construction-site adapters to take
// interface fields and threading the concrete-method calls through their
// own adapter ports — substantial app/wire.go churn that ADR 0006 §"What
// was rejected" explicitly excluded for ROI reasons. Both options are
// anti-rec'd; the current state is the calibrated end-state.
type StoreRegistry struct {
	m *Manager
}

func newStoreRegistry(m *Manager) *StoreRegistry {
	return &StoreRegistry{m: m}
}

// TokenStore returns the per-email Kite token store.
func (s *StoreRegistry) TokenStore() TokenStoreInterface { return s.m.tokenStore }

// TokenStoreConcrete returns the concrete token store (for internal wiring).
func (s *StoreRegistry) TokenStoreConcrete() *KiteTokenStore { return s.m.tokenStore }

// CredentialStore returns the per-email Kite credential store.
func (s *StoreRegistry) CredentialStore() CredentialStoreInterface { return s.m.credentialStore }

// CredentialStoreConcrete returns the concrete credential store.
func (s *StoreRegistry) CredentialStoreConcrete() *KiteCredentialStore { return s.m.credentialStore }

// AlertStore returns the per-user alert store.
func (s *StoreRegistry) AlertStore() AlertStoreInterface { return s.m.alertSvc.AlertStore() }

// AlertStoreConcrete returns the concrete alert store.
func (s *StoreRegistry) AlertStoreConcrete() *alerts.Store { return s.m.alertSvc.AlertStore() }

// TelegramStore returns the per-user Telegram chat ID store.
func (s *StoreRegistry) TelegramStore() TelegramStoreInterface { return s.m.alertSvc.AlertStore() }

// AlertDB returns the optional SQLite database used for persistence.
func (s *StoreRegistry) AlertDB() *alerts.DB { return s.m.alertDB }

// WatchlistStore returns the per-user watchlist store.
func (s *StoreRegistry) WatchlistStore() WatchlistStoreInterface { return s.m.watchlistStore }

// WatchlistStoreConcrete returns the concrete watchlist store.
func (s *StoreRegistry) WatchlistStoreConcrete() *watchlist.Store { return s.m.watchlistStore }

// UserStore returns the user identity store.
func (s *StoreRegistry) UserStore() UserStoreInterface { return s.m.userStore }

// UserStoreConcrete returns the concrete user store.
func (s *StoreRegistry) UserStoreConcrete() *users.Store { return s.m.userStore }

// RegistryStore returns the key registry store.
func (s *StoreRegistry) RegistryStore() RegistryStoreInterface { return s.m.registryStore }

// RegistryStoreConcrete returns the concrete registry store.
func (s *StoreRegistry) RegistryStoreConcrete() *registry.Store { return s.m.registryStore }

// AuditStore returns the audit trail store, or nil if not configured.
func (s *StoreRegistry) AuditStore() AuditStoreInterface {
	if s.m.auditStore == nil {
		return nil
	}
	return s.m.auditStore
}

// AuditStoreConcrete returns the concrete audit store.
func (s *StoreRegistry) AuditStoreConcrete() *audit.Store { return s.m.auditStore }

// SetAuditStore wires the audit store.
func (s *StoreRegistry) SetAuditStore(store *audit.Store) { s.m.auditStore = store }

// BillingStore returns the billing store, or nil if not configured.
func (s *StoreRegistry) BillingStore() BillingStoreInterface {
	if s.m.billingStore == nil {
		return nil
	}
	return s.m.billingStore
}

// BillingStoreConcrete returns the concrete billing store.
func (s *StoreRegistry) BillingStoreConcrete() *billing.Store { return s.m.billingStore }

// SetBillingStore sets the billing store.
func (s *StoreRegistry) SetBillingStore(store *billing.Store) { s.m.billingStore = store }

// InvitationStore returns the invitation store, or nil if not configured.
func (s *StoreRegistry) InvitationStore() *users.InvitationStore { return s.m.invitationStore }

// SetInvitationStore sets the invitation store.
func (s *StoreRegistry) SetInvitationStore(store *users.InvitationStore) {
	s.m.invitationStore = store
}

// ---------------------------------------------------------------------------
// Manager-level delegators (moved from manager.go; preserved for backward
// compatibility with existing call sites across 5 packages / 73 files).
// ---------------------------------------------------------------------------

// Stores returns the store registry.
func (m *Manager) Stores() *StoreRegistry { return m.stores }

// TokenStore returns the per-email token store.
func (m *Manager) TokenStore() TokenStoreInterface { return m.stores.TokenStore() }

// TokenStoreConcrete returns the concrete token store.
func (m *Manager) TokenStoreConcrete() *KiteTokenStore { return m.stores.TokenStoreConcrete() }

// CredentialStore returns the per-email Kite credential store.
func (m *Manager) CredentialStore() CredentialStoreInterface { return m.stores.CredentialStore() }

// CredentialStoreConcrete returns the concrete credential store.
func (m *Manager) CredentialStoreConcrete() *KiteCredentialStore {
	return m.stores.CredentialStoreConcrete()
}

// AlertStore returns the per-user alert store.
func (m *Manager) AlertStore() AlertStoreInterface { return m.stores.AlertStore() }

// AlertStoreConcrete returns the concrete alert store.
func (m *Manager) AlertStoreConcrete() *alerts.Store { return m.stores.AlertStoreConcrete() }

// TelegramStore returns the per-user Telegram chat ID store.
func (m *Manager) TelegramStore() TelegramStoreInterface { return m.stores.TelegramStore() }

// AlertDB returns the optional SQLite database used for persistence.
func (m *Manager) AlertDB() *alerts.DB { return m.stores.AlertDB() }

// WatchlistStore returns the per-user watchlist store.
func (m *Manager) WatchlistStore() WatchlistStoreInterface { return m.stores.WatchlistStore() }

// WatchlistStoreConcrete returns the concrete watchlist store.
func (m *Manager) WatchlistStoreConcrete() *watchlist.Store {
	return m.stores.WatchlistStoreConcrete()
}

// UserStore returns the user identity store.
func (m *Manager) UserStore() UserStoreInterface { return m.stores.UserStore() }

// UserStoreConcrete returns the concrete user store.
func (m *Manager) UserStoreConcrete() *users.Store { return m.stores.UserStoreConcrete() }

// RegistryStore returns the key registry store.
func (m *Manager) RegistryStore() RegistryStoreInterface { return m.stores.RegistryStore() }

// RegistryStoreConcrete returns the concrete registry store.
func (m *Manager) RegistryStoreConcrete() *registry.Store { return m.stores.RegistryStoreConcrete() }

// AuditStore returns the audit trail store, or nil if not configured.
func (m *Manager) AuditStore() AuditStoreInterface { return m.stores.AuditStore() }

// AuditStoreConcrete returns the concrete audit store.
func (m *Manager) AuditStoreConcrete() *audit.Store { return m.stores.AuditStoreConcrete() }

// SetAuditStore wires the audit store.
func (m *Manager) SetAuditStore(store *audit.Store) { m.stores.SetAuditStore(store) }

// BillingStore returns the billing store, or nil if not configured.
func (m *Manager) BillingStore() BillingStoreInterface { return m.stores.BillingStore() }

// BillingStoreConcrete returns the concrete billing store.
func (m *Manager) BillingStoreConcrete() *billing.Store { return m.stores.BillingStoreConcrete() }

// SetBillingStore sets the billing store.
func (m *Manager) SetBillingStore(store *billing.Store) { m.stores.SetBillingStore(store) }

// InvitationStore returns the invitation store, or nil if not configured.
func (m *Manager) InvitationStore() *users.InvitationStore { return m.stores.InvitationStore() }

// SetInvitationStore sets the invitation store.
func (m *Manager) SetInvitationStore(store *users.InvitationStore) {
	m.stores.SetInvitationStore(store)
}
