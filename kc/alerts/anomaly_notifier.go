package alerts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/domain"
	logport "github.com/zerodha/kite-mcp-server/kc/logger"
)

// AnomalyNotifier subscribes to domain.RiskguardRejectionEvent and pushes
// a Telegram message to every configured admin's chat. It closes the
// PULL-only gap surfaced in observability-audit-and-roadmap.md §1.4
// (the existing admin_list_anomaly_flags MCP tool requires the operator
// to remember to poll; this surface provides real-time push).
//
// Per-(user_email, reason) deduplication with a 5-minute default TTL
// prevents alert storms when a single misconfigured user trips the
// same flag repeatedly. The dedup map is bounded by natural churn —
// entries time out without explicit cleanup goroutines.
//
// Trader email is HASHED in the message body via SHA-256 (same shape
// as audit.HashEmail) — operators get a stable correlation key without
// PII exposure on the Telegram channel (which has its own infrastructure
// trust boundaries). The reason and timestamp ARE included plaintext;
// they're not user-identifying.
//
// HandleEvent is the dispatcher Subscribe target. It MUST be quick
// (Dispatch holds an RLock); the actual Telegram send runs in a
// goroutine.
type AnomalyNotifier struct {
	notifier *TelegramNotifier
	store    *Store
	admins   []string
	logger   logport.Logger
	ttl      time.Duration

	// dedupMu guards dedup. Map key is "<email>|<reason>"; value is
	// the time after which a fresh notification for that pair is
	// allowed.
	dedupMu sync.Mutex
	dedup   map[string]time.Time
}

const defaultAnomalyDedupTTL = 5 * time.Minute

// NewAnomalyNotifier constructs an AnomalyNotifier with the default
// 5-minute dedup TTL. Pass nil notifier or empty admins for a no-op
// instance (HandleEvent silently skips when there are no recipients).
func NewAnomalyNotifier(notifier *TelegramNotifier, store *Store, admins []string, logger *slog.Logger) *AnomalyNotifier {
	return newAnomalyNotifierWithTTL(notifier, store, admins, logger, defaultAnomalyDedupTTL)
}

// newAnomalyNotifierWithTTL is the internal constructor allowing tests
// to override the dedup TTL for tight-window assertions.
func newAnomalyNotifierWithTTL(notifier *TelegramNotifier, store *Store, admins []string, logger *slog.Logger, ttl time.Duration) *AnomalyNotifier {
	return &AnomalyNotifier{
		notifier: notifier,
		store:    store,
		admins:   admins,
		logger:   logport.NewSlog(logger),
		ttl:      ttl,
		dedup:    make(map[string]time.Time),
	}
}

// HandleEvent processes a domain.RiskguardRejectionEvent (other event
// types are ignored — defensive against subscribe-misconfiguration).
//
// Quick path: returns immediately after lookup-and-decision; the actual
// Telegram send runs in a goroutine to keep the dispatcher unblocked.
func (a *AnomalyNotifier) HandleEvent(evt domain.Event) {
	if a == nil || a.notifier == nil || a.store == nil || len(a.admins) == 0 {
		return
	}
	rej, ok := evt.(domain.RiskguardRejectionEvent)
	if !ok {
		return
	}

	// Per-(email, reason) dedup check.
	key := rej.UserEmail + "|" + rej.Reason
	now := time.Now()
	a.dedupMu.Lock()
	if expiry, exists := a.dedup[key]; exists && now.Before(expiry) {
		a.dedupMu.Unlock()
		return
	}
	a.dedup[key] = now.Add(a.ttl)
	// Opportunistic GC: if the map has grown past 10K entries (worst-
	// case ~2K rejections/min × 5min TTL), prune expired entries
	// inline. At normal rates the prune branch never runs.
	if len(a.dedup) > 10_000 {
		for k, exp := range a.dedup {
			if now.After(exp) {
				delete(a.dedup, k)
			}
		}
	}
	a.dedupMu.Unlock()

	// Build the message once; HTML format matches the existing
	// briefings + manual-trade confirmation flows.
	traderHash := hashEmail(rej.UserEmail)
	body := fmt.Sprintf(
		"<b>⚠️ Riskguard rejection</b>\n"+
			"Reason: <code>%s</code>\n"+
			"Trader (hashed): <code>%s</code>\n"+
			"At: %s",
		rej.Reason,
		traderHash,
		rej.Timestamp.UTC().Format(time.RFC3339),
	)

	// Resolve every admin's chat-id and dispatch in goroutines so a
	// single slow admin doesn't block the others. The store accessor
	// is safe under concurrent Get.
	for _, adminEmail := range a.admins {
		adminEmail = strings.TrimSpace(strings.ToLower(adminEmail))
		if adminEmail == "" {
			continue
		}
		chatID, ok := a.store.GetTelegramChatID(adminEmail)
		if !ok {
			// Admin has not registered their Telegram chat — silent
			// skip. Logged at Debug to support troubleshooting
			// without noise.
			a.logger.Debug(context.Background(), "anomaly notifier: admin has no telegram chat ID, skipping",
				"admin_email_hash", hashEmail(adminEmail))
			continue
		}
		go a.sendOne(chatID, body, adminEmail, rej.Reason)
	}
}

// sendOne dispatches a single HTML message to chatID. Failures are
// logged at Warn (not Error) — Telegram outages should not crowd
// genuine errors out of the operator's view.
func (a *AnomalyNotifier) sendOne(chatID int64, body, adminEmail, reason string) {
	if err := a.notifier.SendHTMLMessage(chatID, body); err != nil {
		a.logger.Warn(context.Background(), "anomaly notifier: failed to send Telegram alert",
			"admin_email_hash", hashEmail(adminEmail),
			"reason", reason,
			"error", err.Error())
	}
}

// hashEmail returns the SHA-256 hex digest of the lowercased email,
// matching audit.HashEmail's shape. Inlined to avoid a kc/audit import
// (audit imports alerts via consent.go's `*alerts.DB` field; reverse
// would create a cycle).
func hashEmail(email string) string {
	if email == "" {
		return ""
	}
	h := sha256.Sum256([]byte(strings.ToLower(email)))
	return hex.EncodeToString(h[:])
}
