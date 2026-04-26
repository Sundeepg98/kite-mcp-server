package domain

import (
	"sync"
	"time"
)

// Event is the interface all domain events must satisfy.
type Event interface {
	// EventType returns a unique string identifier for the event kind.
	EventType() string
	// OccurredAt returns the timestamp when the event was created.
	OccurredAt() time.Time
}

// --- Concrete domain events ---

// OrderPlacedEvent is emitted after an order is successfully placed.
type OrderPlacedEvent struct {
	Email           string
	OrderID         string
	Instrument      InstrumentKey
	Qty             Quantity
	Price           Money
	TransactionType string // "BUY" or "SELL"
	Timestamp       time.Time
}

func (e OrderPlacedEvent) EventType() string    { return "order.placed" }
func (e OrderPlacedEvent) OccurredAt() time.Time { return e.Timestamp }

// OrderModifiedEvent is emitted after an order is successfully modified.
type OrderModifiedEvent struct {
	Email     string
	OrderID   string
	Timestamp time.Time
}

func (e OrderModifiedEvent) EventType() string    { return "order.modified" }
func (e OrderModifiedEvent) OccurredAt() time.Time { return e.Timestamp }

// OrderCancelledEvent is emitted after an order is successfully cancelled.
type OrderCancelledEvent struct {
	Email     string
	OrderID   string
	Timestamp time.Time
}

func (e OrderCancelledEvent) EventType() string    { return "order.cancelled" }
func (e OrderCancelledEvent) OccurredAt() time.Time { return e.Timestamp }

// OrderFilledEvent is emitted after an order is filled by the exchange.
//
// Status carries the broker-reported terminal status (T4):
//
//   - "COMPLETE" — full quantity filled, single tranche. The pre-T4
//     default; fill_watcher only emitted on this case.
//   - "PARTIAL" — partial fill (multi-tranche execution or kill-fill
//     timeout). Downstream consumers should treat FilledQty as the
//     actual matched quantity, not the order's requested quantity.
//   - "AMO"      — after-market order, queued for next session. Emitted
//     when the broker accepts the order outside trading hours; the
//     "fill" here is logical placement, not an exchange match.
//
// Empty Status means the producer didn't set it (legacy emitters). New
// emit sites must set Status explicitly so the projection / activity
// feed can distinguish partial fills.
type OrderFilledEvent struct {
	Email      string
	OrderID    string
	FilledQty  Quantity
	FilledPrice Money
	Status     string
	Timestamp  time.Time
}

func (e OrderFilledEvent) EventType() string    { return "order.filled" }
func (e OrderFilledEvent) OccurredAt() time.Time { return e.Timestamp }

// PositionOpenedEvent is emitted when a new position is opened.
//
// Aggregate-ID rule: positions do not have a broker-assigned unique ID —
// Kite's Position struct doesn't expose an "opening order" field — so we
// can't reliably join open and close events by ID. Instead, we key
// position events by the natural tuple (email, exchange, symbol, product)
// via PositionAggregateID() below. A single user-instrument-product
// aggregate may contain multiple open→close lifecycles across time;
// walking the event stream makes lifecycle boundaries visible.
//
// Product is required for the aggregate ID. PositionID is kept for
// tracing — it equals the opening order ID from place_order — but is
// no longer the aggregate key.
type PositionOpenedEvent struct {
	Email           string
	PositionID      string // opening order ID (historical trace only)
	Instrument      InstrumentKey
	Product         string // MIS, CNC, NRML — part of aggregate key
	Qty             Quantity
	AvgPrice        Money
	TransactionType string // "BUY" or "SELL"
	Timestamp       time.Time
}

func (e PositionOpenedEvent) EventType() string    { return "position.opened" }
func (e PositionOpenedEvent) OccurredAt() time.Time { return e.Timestamp }

// PositionClosedEvent is emitted after a position is closed via close_position.
// OrderID is the closing order (fresh from Kite), not the opening one —
// use PositionAggregateID() to join with the corresponding open event.
type PositionClosedEvent struct {
	Email           string
	OrderID         string // the closing order's ID
	Instrument      InstrumentKey
	Product         string // MIS, CNC, NRML — part of aggregate key
	Qty             Quantity
	TransactionType string // opposite direction used to close
	Timestamp       time.Time
}

func (e PositionClosedEvent) EventType() string    { return "position.closed" }
func (e PositionClosedEvent) OccurredAt() time.Time { return e.Timestamp }

// PositionAggregateID returns the natural aggregate key for position events.
// Format: "email:exchange:tradingsymbol:product". Both PositionOpenedEvent
// and PositionClosedEvent for the same (user, instrument, product) triple
// land under the same aggregate ID, allowing event-store replay to
// reconstruct the full position history.
func PositionAggregateID(email string, instrument InstrumentKey, product string) string {
	return email + ":" + instrument.Exchange + ":" + instrument.Tradingsymbol + ":" + product
}

// AlertCreatedEvent is emitted when a new price alert is created.
type AlertCreatedEvent struct {
	Email       string
	AlertID     string
	Instrument  InstrumentKey
	TargetPrice Money
	Direction   string // "above", "below", "drop_pct", "rise_pct"
	Timestamp   time.Time
}

func (e AlertCreatedEvent) EventType() string    { return "alert.created" }
func (e AlertCreatedEvent) OccurredAt() time.Time { return e.Timestamp }

// AlertTriggeredEvent is emitted when a price alert fires.
type AlertTriggeredEvent struct {
	Email        string
	AlertID      string
	Instrument   InstrumentKey
	TargetPrice  Money
	CurrentPrice Money
	Direction    string // "above", "below", "drop_pct", "rise_pct"
	Timestamp    time.Time
}

func (e AlertTriggeredEvent) EventType() string    { return "alert.triggered" }
func (e AlertTriggeredEvent) OccurredAt() time.Time { return e.Timestamp }

// AlertDeletedEvent is emitted when a price alert is deleted.
type AlertDeletedEvent struct {
	Email   string
	AlertID string
	Timestamp time.Time
}

func (e AlertDeletedEvent) EventType() string    { return "alert.deleted" }
func (e AlertDeletedEvent) OccurredAt() time.Time { return e.Timestamp }

// RiskLimitBreachedEvent is emitted when riskguard blocks an order.
type RiskLimitBreachedEvent struct {
	Email    string
	Reason   string // matches riskguard.RejectionReason values
	Message  string
	ToolName string
	Timestamp time.Time
}

func (e RiskLimitBreachedEvent) EventType() string    { return "risk.limit_breached" }
func (e RiskLimitBreachedEvent) OccurredAt() time.Time { return e.Timestamp }

// SessionCreatedEvent is emitted when a new MCP session is established.
type SessionCreatedEvent struct {
	Email     string
	SessionID string
	Broker    string // "zerodha", "angelone", etc.
	Timestamp time.Time
}

func (e SessionCreatedEvent) EventType() string    { return "session.created" }
func (e SessionCreatedEvent) OccurredAt() time.Time { return e.Timestamp }

// SessionClearedEvent is emitted when the Kite session data attached to an
// MCP session is cleared (without terminating the session itself). Phase C
// ES: append-only audit record of the clear, keyed by session ID.
type SessionClearedEvent struct {
	SessionID string
	Reason    string // "post_credential_register" / "profile_check_failed" / "admin_action"
	Timestamp time.Time
}

func (e SessionClearedEvent) EventType() string    { return "session.cleared" }
func (e SessionClearedEvent) OccurredAt() time.Time { return e.Timestamp }

// SessionInvalidatedEvent is emitted when an MCP session is ended (the
// SessionRegistry entry is evicted, cleanup hooks run). Distinct from
// SessionClearedEvent which keeps the session alive without broker data.
type SessionInvalidatedEvent struct {
	SessionID string
	Reason    string // "expired" / "admin_action" / "logout"
	Timestamp time.Time
}

func (e SessionInvalidatedEvent) EventType() string    { return "session.invalidated" }
func (e SessionInvalidatedEvent) OccurredAt() time.Time { return e.Timestamp }

// UserFrozenEvent is emitted when a user's trading is frozen (manual or auto).
type UserFrozenEvent struct {
	Email    string
	FrozenBy string // "admin", "riskguard:circuit-breaker"
	Reason   string
	Timestamp time.Time
}

func (e UserFrozenEvent) EventType() string    { return "user.frozen" }
func (e UserFrozenEvent) OccurredAt() time.Time { return e.Timestamp }

// UserSuspendedEvent is emitted when an admin suspends a user account.
type UserSuspendedEvent struct {
	Email    string
	By       string // admin email
	Reason   string
	Timestamp time.Time
}

func (e UserSuspendedEvent) EventType() string    { return "user.suspended" }
func (e UserSuspendedEvent) OccurredAt() time.Time { return e.Timestamp }

// GlobalFreezeEvent is emitted when an admin activates the server-wide trading freeze.
type GlobalFreezeEvent struct {
	By     string // admin email
	Reason string
	Timestamp time.Time
}

func (e GlobalFreezeEvent) EventType() string    { return "global.freeze" }
func (e GlobalFreezeEvent) OccurredAt() time.Time { return e.Timestamp }

// FamilyInvitedEvent is emitted when an admin invites a family member.
type FamilyInvitedEvent struct {
	AdminEmail   string
	InvitedEmail string
	Timestamp    time.Time
}

func (e FamilyInvitedEvent) EventType() string    { return "family.invited" }
func (e FamilyInvitedEvent) OccurredAt() time.Time { return e.Timestamp }

// FamilyMemberRemovedEvent is emitted when an admin unlinks a family member
// from their billing plan.
type FamilyMemberRemovedEvent struct {
	AdminEmail   string
	RemovedEmail string
	Timestamp    time.Time
}

func (e FamilyMemberRemovedEvent) EventType() string    { return "family.member_removed" }
func (e FamilyMemberRemovedEvent) OccurredAt() time.Time { return e.Timestamp }

// WatchlistCreatedEvent is emitted when a new watchlist is created.
type WatchlistCreatedEvent struct {
	Email       string
	WatchlistID string
	Name        string
	Timestamp   time.Time
}

func (e WatchlistCreatedEvent) EventType() string    { return "watchlist.created" }
func (e WatchlistCreatedEvent) OccurredAt() time.Time { return e.Timestamp }

// WatchlistDeletedEvent is emitted when a watchlist is deleted.
type WatchlistDeletedEvent struct {
	Email       string
	WatchlistID string
	Name        string // captured before deletion for audit trail
	ItemCount   int    // captured before deletion so auditors see the scope
	Timestamp   time.Time
}

func (e WatchlistDeletedEvent) EventType() string    { return "watchlist.deleted" }
func (e WatchlistDeletedEvent) OccurredAt() time.Time { return e.Timestamp }

// WatchlistItemAddedEvent is emitted when an instrument is added to a watchlist.
type WatchlistItemAddedEvent struct {
	Email       string
	WatchlistID string
	Instrument  InstrumentKey
	Timestamp   time.Time
}

func (e WatchlistItemAddedEvent) EventType() string    { return "watchlist.item_added" }
func (e WatchlistItemAddedEvent) OccurredAt() time.Time { return e.Timestamp }

// WatchlistItemRemovedEvent is emitted when an instrument is removed from a watchlist.
type WatchlistItemRemovedEvent struct {
	Email       string
	WatchlistID string
	ItemID      string
	Timestamp   time.Time
}

func (e WatchlistItemRemovedEvent) EventType() string    { return "watchlist.item_removed" }
func (e WatchlistItemRemovedEvent) OccurredAt() time.Time { return e.Timestamp }

// CredentialRegisteredEvent is emitted the first time a user registers Kite
// API credentials (no prior CredentialStore entry for this email). Distinct
// from CredentialRotatedEvent so auditors can tell onboarding from key
// rotation without walking the full credential history.
type CredentialRegisteredEvent struct {
	Email     string
	Timestamp time.Time
}

func (e CredentialRegisteredEvent) EventType() string    { return "credential.registered" }
func (e CredentialRegisteredEvent) OccurredAt() time.Time { return e.Timestamp }

// CredentialRotatedEvent is emitted when a user replaces existing Kite API
// credentials with a new key/secret pair. Emitted by UpdateMyCredentials
// when a prior credential entry exists for the email.
type CredentialRotatedEvent struct {
	Email     string
	Timestamp time.Time
}

func (e CredentialRotatedEvent) EventType() string    { return "credential.rotated" }
func (e CredentialRotatedEvent) OccurredAt() time.Time { return e.Timestamp }

// CredentialRevokedEvent is emitted when credentials are removed — via the
// dashboard DELETE endpoint, admin force-revoke, or the credentials half of
// DeleteMyAccount. Reason tags the lifecycle narrative ("user_self",
// "admin_revoke", "credential_rotation", "account_deleted").
type CredentialRevokedEvent struct {
	Email     string
	Reason    string
	Timestamp time.Time
}

func (e CredentialRevokedEvent) EventType() string    { return "credential.revoked" }
func (e CredentialRevokedEvent) OccurredAt() time.Time { return e.Timestamp }

// TierChangedEvent is emitted when a user's billing subscription tier
// transitions — free→paid (upgrade), paid→free (cancellation), or
// paid→paid (cross-grade between Pro/Premium/SoloPro). Emitted from the
// billing.Store on every successful SetSubscription call where the
// effective tier differs from the prior persisted tier. Stays silent
// for no-op writes (same tier in, same tier out) so the audit log
// reflects real state transitions, not redundant webhook replays.
//
// FromTier and ToTier are integer codes matching billing.Tier (0=Free,
// 1=Pro, 2=Premium, 3=SoloPro). Stored as int rather than the typed
// billing.Tier to keep kc/domain free of an upward dependency on
// kc/billing — the convention mirrors UserFrozenEvent.FrozenBy / Reason
// which carry semantic strings without importing their producer.
//
// Reason tags the lifecycle narrative ("stripe_checkout",
// "stripe_subscription_updated", "stripe_subscription_deleted",
// "admin_set_billing_tier") so auditors can distinguish webhook-driven
// changes from operator-driven changes without joining against another
// table.
type TierChangedEvent struct {
	UserEmail string
	FromTier  int
	ToTier    int
	Reason    string
	Timestamp time.Time
}

func (e TierChangedEvent) EventType() string    { return "billing.tier_changed" }
func (e TierChangedEvent) OccurredAt() time.Time { return e.Timestamp }

// ConsentWithdrawnEvent is emitted when a user invokes their DPDP §6(4)
// right to rescind previously-granted consent. The withdrawal does not
// erase the original grant from consent_log (the log is append-only and
// auditors need to see the full history); instead, the prior grant row
// gets stamped with withdrawn_at and a new "withdraw" action row is
// appended.
//
// EmailHash is the SHA-256 hex digest of the lowercased email — same
// canonical form audit.HashEmail produces — so the event correlates to
// the audit log without leaking the plaintext email through the event
// dispatcher / persister chain. Plaintext Email is retained alongside
// for in-process consumers (Telegram notifier, riskguard) that need
// it for operational outreach. PR-D Item 2 will migrate other domain
// events to this dual-field shape.
type ConsentWithdrawnEvent struct {
	Email     string
	EmailHash string
	Reason    string
	Timestamp time.Time
}

func (e ConsentWithdrawnEvent) EventType() string    { return "consent.withdrawn" }
func (e ConsentWithdrawnEvent) OccurredAt() time.Time { return e.Timestamp }

// RiskguardKillSwitchTrippedEvent is emitted when riskguard's global trading
// freeze (a.k.a. the "kill switch") is engaged at the riskguard layer —
// distinct from the admin-tool-level GlobalFreezeEvent which records the
// admin command. This event captures the riskguard state mutation itself
// (kill switch went 0→1), making the counters aggregate's freeze lifecycle
// fully reconstructable from the event stream.
//
// Active is true when the kill switch was tripped (off→on); when an
// operator unfreezes globally, a separate event with Active=false is
// emitted so the on/off transitions are symmetric in the audit log.
//
// FrozenBy carries the operator/system tag passed into FreezeGlobal —
// typically an admin email but may be a synthetic tag like
// "riskguard:auto" in future auto-trip scenarios.
type RiskguardKillSwitchTrippedEvent struct {
	UserEmail string // empty for global kill-switch (the canonical case)
	FrozenBy  string
	Reason    string
	Active    bool // true=tripped (frozen), false=lifted (unfrozen)
	Timestamp time.Time
}

func (e RiskguardKillSwitchTrippedEvent) EventType() string    { return "riskguard.kill_switch_tripped" }
func (e RiskguardKillSwitchTrippedEvent) OccurredAt() time.Time { return e.Timestamp }

// RiskguardDailyCounterResetEvent is emitted when riskguard rolls a user's
// per-day counters (DailyOrderCount, DailyPlacedValue) on the 9:15 AM IST
// trading-day boundary. Mostly observable for forensic timeline replay —
// auditors who walk the counters aggregate stream see explicit reset
// boundaries rather than having to infer them from gaps in the event log.
//
// Reason is currently always "trading_day_boundary"; reserved as a string
// so future paths (admin-forced reset, end-of-week rollover) can tag
// themselves without bumping the event schema.
type RiskguardDailyCounterResetEvent struct {
	UserEmail string
	Reason    string
	Timestamp time.Time
}

func (e RiskguardDailyCounterResetEvent) EventType() string    { return "riskguard.daily_counter_reset" }
func (e RiskguardDailyCounterResetEvent) OccurredAt() time.Time { return e.Timestamp }

// RiskguardRejectionEvent is emitted when the circuit-breaker's sliding
// rejection window for a user is incremented (recordRejection called).
// Distinct from RiskLimitBreachedEvent which is emitted at the use-case
// layer when an order is blocked: this event captures the COUNTER
// mutation inside the riskguard aggregate, so the counters aggregate
// stream can be replayed to reconstruct the auto-freeze state machine
// without joining against the order pipeline.
//
// Reason mirrors the RejectionReason that drove the recordRejection call
// (e.g. "order_value_limit", "daily_value_limit", "anomaly_high"). Used
// by future read-side projectors that count by reason to surface
// "user X is hitting the order_value cap repeatedly" without scanning
// the full audit log.
type RiskguardRejectionEvent struct {
	UserEmail string
	Reason    string
	Timestamp time.Time
}

func (e RiskguardRejectionEvent) EventType() string    { return "riskguard.rejection_recorded" }
func (e RiskguardRejectionEvent) OccurredAt() time.Time { return e.Timestamp }

// RiskguardCountersAggregateID returns the natural aggregate key for
// per-user riskguard counter events. Format: "riskguard:<email>" or
// "riskguard:global" for the kill-switch (global-scope) events. The
// "riskguard:" prefix keeps these aggregate streams disjoint from
// per-email user-aggregate streams (UserFrozenEvent, etc.) so a future
// projector can replay the counters aggregate cleanly.
func RiskguardCountersAggregateID(email string) string {
	if email == "" {
		return "riskguard:global"
	}
	return "riskguard:" + email
}

// AnomalyBaselineSnapshottedEvent is emitted when the audit Store's
// in-memory UserOrderStats baseline cache writes a fresh (mean, stdev,
// count) tuple for a (user, days) pair. Carries the user email plus
// the snapshotted statistical fields so a downstream consumer can
// reconstruct the anomaly baseline projection without re-querying the
// 30-day order history.
//
// Aggregate-ID rule: keyed by AnomalyCacheAggregateID(UserEmail) (one
// logical baseline per user across all days windows; Days is a payload
// field, not part of the aggregate key). Below-threshold snapshots
// (count < minBaselineOrders) write the floor sentinel
// (mean=0, stdev=0) — BelowFloor=true so projector consumers can
// distinguish "user is new and we suppressed stats" from "real
// distribution centred at zero" (the latter is impossible at the SQL
// layer but BelowFloor makes the intent unambiguous).
type AnomalyBaselineSnapshottedEvent struct {
	UserEmail  string
	Days       int
	Mean       float64
	Stdev      float64
	Count      float64
	BelowFloor bool // true when count<minBaselineOrders and mean/stdev are zeroed sentinels
	Timestamp  time.Time
}

func (e AnomalyBaselineSnapshottedEvent) EventType() string    { return "anomaly.baseline_snapshotted" }
func (e AnomalyBaselineSnapshottedEvent) OccurredAt() time.Time { return e.Timestamp }

// AnomalyCacheInvalidatedEvent is emitted when every cached
// UserOrderStats entry for a given user is purged — typically when a
// new place_order / modify_order row lands in the audit log so the
// next anomaly check sees the fresh data. Reason tags the trigger
// ("order_recorded" / "manual" / "admin_clear").
//
// Aggregate-ID rule: keyed by AnomalyCacheAggregateID(UserEmail) —
// invalidation is per user, all days windows at once.
type AnomalyCacheInvalidatedEvent struct {
	UserEmail string
	Reason    string
	Timestamp time.Time
}

func (e AnomalyCacheInvalidatedEvent) EventType() string    { return "anomaly.cache_invalidated" }
func (e AnomalyCacheInvalidatedEvent) OccurredAt() time.Time { return e.Timestamp }

// AnomalyCacheEvictedEvent is emitted when the cache drops a single
// entry for a reason other than user-scoped invalidation. Reason
// distinguishes the two eviction paths:
//
//   - "ttl_expired"   — lazy eviction on Get() when storedAt+ttl < now
//   - "size_overflow" — random single-entry eviction on Set() when
//     len(entries) >= maxEntries and the incoming key is net-new
//
// Aggregate-ID rule: keyed by AnomalyCacheAggregateID(UserEmail).
// UserEmail may be empty for size_overflow when the evicted entry's
// key was not parseable — defence in depth, since cacheKey() is the
// only writer, but the event still carries enough to forensically
// trace the dropped slot.
type AnomalyCacheEvictedEvent struct {
	UserEmail string
	Days      int
	Reason    string // "ttl_expired" / "size_overflow"
	Timestamp time.Time
}

func (e AnomalyCacheEvictedEvent) EventType() string    { return "anomaly.cache_evicted" }
func (e AnomalyCacheEvictedEvent) OccurredAt() time.Time { return e.Timestamp }

// AnomalyCacheAggregateID returns the natural aggregate key for
// anomaly-cache events. Format: "anomaly:<email>". The "anomaly:"
// prefix keeps these streams disjoint from per-email user-aggregate
// streams (UserFrozenEvent, etc.) and the "riskguard:<email>" stream,
// so a future projector can replay the anomaly cache aggregate
// cleanly without filtering by event type.
func AnomalyCacheAggregateID(email string) string {
	if email == "" {
		return "anomaly:unknown"
	}
	return "anomaly:" + email
}

// PluginRegisteredEvent is emitted when a plugin binary is registered
// for hot-reload watching via WatchPluginBinary. Captures the
// (plugin-name, path) pair so the plugin-watcher aggregate stream lets
// auditors / read-side projectors reconstruct the full set of currently-
// watched binaries by replaying the (registered, unregistered) pairs.
//
// PluginName is the logical plugin identifier (typically the basename
// of Path, derived inside WatchPluginBinary). Path is the absolute
// filesystem path that subscribed to fsnotify events. Both fields are
// required at emit time.
type PluginRegisteredEvent struct {
	PluginName string
	Path       string
	Timestamp  time.Time
}

func (e PluginRegisteredEvent) EventType() string     { return "plugin.registered" }
func (e PluginRegisteredEvent) OccurredAt() time.Time { return e.Timestamp }

// PluginUnregisteredEvent is emitted when a plugin path is removed from
// the watcher's registry — currently only via ClearPluginWatches (test
// path), but reserved for a future production unregister API. Pairs
// with PluginRegisteredEvent so the watcher aggregate stream is closed
// (registered + unregistered events have matching Path).
type PluginUnregisteredEvent struct {
	PluginName string
	Path       string
	Timestamp  time.Time
}

func (e PluginUnregisteredEvent) EventType() string     { return "plugin.unregistered" }
func (e PluginUnregisteredEvent) OccurredAt() time.Time { return e.Timestamp }

// PluginReloadTriggeredEvent is emitted when the watcher debounce timer
// fires Close() on a registered BinaryReloadable, signaling that the
// plugin's subprocess will be relaunched on the next tool invocation.
// This is the workhorse event of the plugin-watcher aggregate: every
// dev-loop rebuild surfaces here, giving the audit log an explicit
// reload boundary that read-side projectors can use to compute
// "reloads/hour by plugin" without scanning fsnotify-level traces.
type PluginReloadTriggeredEvent struct {
	PluginName string
	Path       string
	Timestamp  time.Time
}

func (e PluginReloadTriggeredEvent) EventType() string     { return "plugin.reload_triggered" }
func (e PluginReloadTriggeredEvent) OccurredAt() time.Time { return e.Timestamp }

// PluginWatcherStartedEvent is emitted exactly once per
// StartPluginBinaryWatcher invocation that actually starts the watcher
// goroutine (idempotent re-Start calls are silent). Captures the
// fsnotify watcher coming online so the aggregate stream has explicit
// "watcher up" boundaries between reload bursts.
type PluginWatcherStartedEvent struct {
	Timestamp time.Time
}

func (e PluginWatcherStartedEvent) EventType() string     { return "plugin.watcher_started" }
func (e PluginWatcherStartedEvent) OccurredAt() time.Time { return e.Timestamp }

// PluginWatcherStoppedEvent is emitted exactly once per
// StopPluginBinaryWatcher invocation that actually stops a running
// watcher (no-op stops on never-started watchers are silent). Pairs
// with PluginWatcherStartedEvent so the aggregate stream's lifecycle
// transitions are symmetric.
type PluginWatcherStoppedEvent struct {
	Timestamp time.Time
}

func (e PluginWatcherStoppedEvent) EventType() string     { return "plugin.watcher_stopped" }
func (e PluginWatcherStoppedEvent) OccurredAt() time.Time { return e.Timestamp }

// PluginWatcherAggregateID returns the natural aggregate key for plugin-
// watcher events. Per-path mutations (registered, unregistered,
// reload_triggered) key by the absolute Path so a single plugin's
// lifecycle replays as a coherent stream. Watcher-lifecycle events
// (started, stopped) have no path and key by the singleton string
// "plugin-watcher:global" so they form their own aggregate stream
// disjoint from per-plugin streams.
func PluginWatcherAggregateID(path string) string {
	if path == "" {
		return "plugin-watcher:global"
	}
	return "plugin-watcher:" + path
}

// TelegramSubscribedEvent is emitted the first time a user binds a
// Telegram chat ID to their account (no prior chat-ID mapping in the
// alerts.Store). Distinct from TelegramChatBoundEvent so auditors can
// tell first-time onboarding from re-binding without walking the full
// Telegram-subscription history.
//
// Aggregate-ID rule: keyed by TelegramSubscriptionAggregateID(UserEmail)
// — one logical Telegram subscription per user. ChatID can change over
// time (re-bind to a new chat, e.g. user lost device); the email is the
// stable aggregate identifier.
type TelegramSubscribedEvent struct {
	UserEmail string
	ChatID    int64
	Timestamp time.Time
}

func (e TelegramSubscribedEvent) EventType() string     { return "telegram.subscribed" }
func (e TelegramSubscribedEvent) OccurredAt() time.Time { return e.Timestamp }

// TelegramChatBoundEvent is emitted when an existing Telegram subscriber
// re-binds to a different chat ID (rotation) — e.g. the user lost
// access to the old chat or moved to a new device. OldChatID and
// NewChatID are both captured so projector consumers can render the
// rotation history without joining against a separate snapshot.
//
// Stays silent for no-op writes (same chat ID in, same chat ID out)
// so the event log reflects real state transitions, not redundant
// setup-tool replays. Pattern mirrors TierChangedEvent's
// "real transitions only" contract.
//
// Aggregate-ID rule: same as TelegramSubscribedEvent — keyed by
// TelegramSubscriptionAggregateID(UserEmail). The full chat-bind
// lifecycle for a user lives under one aggregate stream regardless of
// how many times the chat ID rotates.
type TelegramChatBoundEvent struct {
	UserEmail string
	OldChatID int64
	NewChatID int64
	Timestamp time.Time
}

func (e TelegramChatBoundEvent) EventType() string     { return "telegram.chat_bound" }
func (e TelegramChatBoundEvent) OccurredAt() time.Time { return e.Timestamp }

// TelegramSubscriptionAggregateID returns the natural aggregate key for
// per-user Telegram subscription events. Format: "telegram:<email>".
// The "telegram:" prefix keeps these aggregate streams disjoint from
// per-email user-aggregate streams (UserFrozenEvent, etc.) and the
// "riskguard:<email>" / "anomaly:<email>" streams, so a future
// projector can replay the Telegram subscription aggregate cleanly
// without filtering by event type.
func TelegramSubscriptionAggregateID(email string) string {
	if email == "" {
		return "telegram:unknown"
	}
	return "telegram:" + email
}

// OrderRejectedEvent is emitted when the broker fails an order mutation —
// place, modify, or cancel — for any reason that surfaces from the
// Kite API (rate limit, exchange reject, insufficient margin, invalid
// symbol, etc.). Captures the user-visible failure path on the order
// pipeline so the audit/projection stream isn't silent on broker
// rejections; previously these errors were logged but not event-sourced,
// leaving a hole in the order aggregate's lifecycle.
//
// Distinct from RiskLimitBreachedEvent (pre-broker, riskguard-internal):
// OrderRejected fires only AFTER riskguard allowed the call AND the
// broker round-trip returned an error. Together the two events cover
// the two failure surfaces — internal pre-trade gates and external
// post-broker rejections — so an auditor walking the user's stream
// sees every reason an order didn't reach a placed/modified/cancelled
// terminal state.
//
// OrderID may be empty when the rejection is on place_order — the
// broker never assigned an ID before failing. For modify/cancel the
// caller-supplied OrderID is preserved so the rejection joins the
// existing order aggregate stream. ToolName tags the failure surface
// ("place_order", "modify_order", "cancel_order") so projector queries
// can partition rejections by mutation type without parsing Reason.
//
// Reason is the broker error message (best-effort string); kept verbose
// so a forensic walk can distinguish "MARGIN_INSUFFICIENT" from "RATE_LIMIT"
// without re-querying the broker. Caller is responsible for stripping
// PII from the error before emit (Kite errors don't carry user identifiers
// in practice — but the contract is "don't ship plaintext credentials").
type OrderRejectedEvent struct {
	Email     string
	OrderID   string // may be empty for place_order failures (no broker-assigned ID)
	ToolName  string // "place_order" / "modify_order" / "cancel_order"
	Reason    string // broker error message, best-effort
	Timestamp time.Time
}

func (e OrderRejectedEvent) EventType() string    { return "order.rejected" }
func (e OrderRejectedEvent) OccurredAt() time.Time { return e.Timestamp }

// OrderRejectedAggregateID returns the natural aggregate key for an
// OrderRejectedEvent. When OrderID is non-empty (modify/cancel paths,
// where the caller supplied the broker-assigned ID), the rejection
// joins the existing order aggregate stream — a downstream projector
// walking aggregate_id="ORD-123" sees place→reject→modify→reject→cancel
// transitions in one chronological view. When OrderID is empty
// (place_order failure, no broker ID was assigned), the event keys by
// "rejected:<email>:<unix-nanos>" so each rejection lands in its own
// aggregate slot without colliding with other users' rejections or
// future rejections from the same user. The "rejected:" prefix keeps
// these stand-alone streams disjoint from real order streams so a
// projector that filters by aggregate_type="Order" doesn't conflate
// "no broker ID issued" rejections with placed orders.
func OrderRejectedAggregateID(orderID, email string, occurredAt time.Time) string {
	if orderID != "" {
		return orderID
	}
	if email == "" {
		return "rejected:unknown"
	}
	return "rejected:" + email + ":" + occurredAt.UTC().Format(time.RFC3339Nano)
}

// PositionConvertedEvent is emitted when a user converts a position
// from one product type to another (e.g. CNC->MIS for intraday squaring,
// MIS->CNC to carry forward overnight). Replaces the prior untyped
// appendAuxEvent("position.converted", map[string]any{...}) emit in
// kc/usecases/convert_position.go so the audit stream uses a typed
// domain.Event with stable field names — projector consumers no longer
// need to type-assert against an opaque map[string]any payload.
//
// Aggregate-ID rule: keyed by (email, exchange, tradingsymbol, OLD
// product) via PositionConvertedAggregateID. Using the OLD product
// (not the new) means a CNC->MIS->CNC sequence threads through a
// stable aggregate stream rooted on the original holding's product.
// Stable across reverse conversions, matches the pre-ES key shape
// so existing rows aren't orphaned by the migration.
//
// PositionType ("day" / "overnight") is preserved verbatim from the
// Kite ConvertPosition API param so a forensic walk can distinguish
// intraday squaring from carry-forward conversions without re-querying
// position state.
type PositionConvertedEvent struct {
	Email           string
	Instrument      InstrumentKey
	TransactionType string // "BUY" or "SELL" (the position direction being converted)
	Quantity        int
	OldProduct      string // MIS, CNC, NRML — pre-conversion product
	NewProduct      string // MIS, CNC, NRML — post-conversion product
	PositionType    string // "day" or "overnight" — Kite Convert API param
	Timestamp       time.Time
}

func (e PositionConvertedEvent) EventType() string    { return "position.converted" }
func (e PositionConvertedEvent) OccurredAt() time.Time { return e.Timestamp }

// PositionConvertedAggregateID returns the natural aggregate key for
// position-conversion events. Format:
// "<email>|<exchange>|<tradingsymbol>|<oldProduct>". The pipe separator
// (rather than colon) avoids ambiguity with the time.RFC3339 colons
// projector consumers parse out of OrderRejectedEvent's synthetic
// keys. Empty email falls back to "position-converted:unknown" so a
// malformed dispatch lands in its own quarantine slot rather than
// colliding with real rows.
func PositionConvertedAggregateID(email, exchange, tradingsymbol, oldProduct string) string {
	if email == "" {
		return "position-converted:unknown"
	}
	return email + "|" + exchange + "|" + tradingsymbol + "|" + oldProduct
}

// PaperOrderRejectedEvent is emitted when the paper-trading engine
// rejects a virtual order. Sources:
//
//   - "place_market"   — MARKET order rejected because LTP unavailable
//                        (no LTP provider, instrument not subscribed).
//   - "place_limit"    — LIMIT BUY rejected at place time because the
//                        notional exceeds the user's cash balance.
//   - "fill_immediate" — fillOrder rejected a BUY because the snap-to-
//                        LTP price exceeded cash balance (covers the
//                        market path and marketable-LIMIT path).
//   - "fill_monitor"   — background monitor rejected a queued BUY at
//                        fill time when cash dropped below required
//                        notional between place and fill.
//
// Distinct event type from real OrderRejectedEvent so projector
// consumers (activity feeds, dashboards) can filter "real broker
// rejection" vs "virtual-account rejection" without parsing OrderID
// prefixes — paper IDs use "PAPER_<n>" but relying on prefix-sniffing
// for projection-side classification is fragile, so we surface the
// distinction at the event type itself.
//
// Aggregate-ID rule: keyed by OrderID via PaperOrderAggregateID. Paper
// order IDs ("PAPER_<n>") are already process-unique via the atomic
// orderSeq counter in kc/papertrading/engine.go, so no email prefix
// is needed to disambiguate. Empty OrderID falls back to
// "paper:unknown" — never observed in practice (orderID is assigned
// before any rejection branch) but defence in depth keeps malformed
// dispatches out of real rows.
type PaperOrderRejectedEvent struct {
	Email     string
	OrderID   string
	Reason    string // human-readable rejection reason (cash shortage, LTP unavailable)
	Source    string // "place_market" / "place_limit" / "fill_immediate" / "fill_monitor"
	Timestamp time.Time
}

func (e PaperOrderRejectedEvent) EventType() string    { return "paper.order_rejected" }
func (e PaperOrderRejectedEvent) OccurredAt() time.Time { return e.Timestamp }

// PaperOrderAggregateID returns the natural aggregate key for paper-
// trading order events. Currently used by PaperOrderRejectedEvent only;
// future paper.* events should reuse this helper so the per-paper-
// order aggregate stream stays coherent. Empty OrderID falls back to
// "paper:unknown" so malformed dispatches don't collide with real rows.
func PaperOrderAggregateID(orderID string) string {
	if orderID == "" {
		return "paper:unknown"
	}
	return orderID
}

// --- Event dispatcher ---

// EventDispatcher is a simple in-process pub/sub for domain events.
// Handlers are called synchronously in the order they were registered.
// Use goroutines inside handlers if async processing is needed.
type EventDispatcher struct {
	mu       sync.RWMutex
	handlers map[string][]func(Event)
}

// NewEventDispatcher creates a ready-to-use dispatcher.
func NewEventDispatcher() *EventDispatcher {
	return &EventDispatcher{
		handlers: make(map[string][]func(Event)),
	}
}

// Subscribe registers a handler for the given event type.
// The handler will be called every time an event of that type is dispatched.
func (d *EventDispatcher) Subscribe(eventType string, handler func(Event)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.handlers[eventType] = append(d.handlers[eventType], handler)
}

// Dispatch sends an event to all registered handlers for its type.
// Handlers are called synchronously under a read lock, so Subscribe
// calls from within a handler will deadlock — use a goroutine if needed.
func (d *EventDispatcher) Dispatch(event Event) {
	d.mu.RLock()
	handlers := d.handlers[event.EventType()]
	d.mu.RUnlock()

	for _, h := range handlers {
		h(event)
	}
}
