package alerts

import "time"

// AlertStoreInterface defines operations for managing per-user price alerts.
//
// Anchor 5 PR 5.2 (per .research/anchor-5-prs-design.md): this interface
// was relocated from `kc/interfaces.go:30` to its owning package
// (kc/alerts) so that kc/ports/alert.go can eventually drop its kc-parent
// import in PR 5.3 (Wave B-2). The legacy `kc.AlertStoreInterface` is
// preserved as a single-line type alias in kc/interfaces.go to keep the
// existing 11+ reverse-dep call sites compiling unchanged. Both names
// reference the SAME interface — Go type aliases are not new types — so
// satisfaction by *alerts.Store is preserved at the alias site.
//
// Telegram chat ID operations are separated into TelegramStoreInterface
// (still in kc/interfaces.go because TelegramStore types live there).
//
// Method set (12 methods, identical to the pre-move interface — only
// the type qualifier changes since we are now in the alerts package):
//   Add, AddWithReferencePrice, AddComposite — alert creation
//   Delete, DeleteByEmail                    — removal
//   List, ListAll                            — querying by email/all
//   GetByToken                               — querying by instrument token
//   MarkTriggered, MarkNotificationSent      — lifecycle transitions
//   ActiveCount                              — count for limit enforcement
type AlertStoreInterface interface {
	// Add creates a new alert and returns its ID.
	Add(email, tradingsymbol, exchange string, instrumentToken uint32, targetPrice float64, direction Direction) (string, error)

	// AddWithReferencePrice creates a new alert with an optional reference price.
	AddWithReferencePrice(email, tradingsymbol, exchange string, instrumentToken uint32, targetPrice float64, direction Direction, referencePrice float64) (string, error)

	// AddComposite creates a new composite alert combining multiple per-
	// instrument conditions via AND/ANY logic. Returns the alert ID.
	AddComposite(email, name string, logic CompositeLogic, conds []CompositeCondition) (string, error)

	// Delete removes an alert by ID for the given email.
	Delete(email, alertID string) error

	// DeleteByEmail removes all alerts for the given email.
	DeleteByEmail(email string)

	// List returns all alerts for the given email.
	List(email string) []*Alert

	// GetByToken returns all active (non-triggered) alerts matching the instrument token.
	GetByToken(instrumentToken uint32) []*Alert

	// MarkTriggered marks an alert as triggered with the current price.
	MarkTriggered(alertID string, currentPrice float64) bool

	// MarkNotificationSent records when a Telegram notification was sent.
	MarkNotificationSent(alertID string, sentAt time.Time)

	// ListAll returns all alerts grouped by email.
	ListAll() map[string][]*Alert

	// ActiveCount returns the number of active alerts for a user.
	ActiveCount(email string) int
}
