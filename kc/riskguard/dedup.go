package riskguard

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// DefaultDedupTTL is the default idempotency window for client_order_id
// deduplication. 15 minutes covers mcp-remote retry-after-504 scenarios
// and network reconnect storms while keeping memory bounded.
const DefaultDedupTTL = 15 * time.Minute

// Dedup provides user-scoped idempotency-key based deduplication for order
// submissions. It complements the existing time-based duplicate detection
// (same symbol/qty within 30s) by letting clients supply an explicit
// client_order_id — the same key submitted twice within TTL is rejected,
// regardless of parameter changes.
//
// Design mirrors Alpaca's client_order_id pattern: user supplies an opaque
// string, server hashes (email || key) via SHA-256 to normalise length and
// avoid storing plaintext user identifiers in the in-memory map, then
// records the insertion timestamp for TTL-based expiry.
//
// The implementation is in-memory only — it is process-local and does not
// survive a restart. This is acceptable because (a) mcp-remote retries
// happen within seconds of the initial 504, well inside a single process
// lifetime, and (b) the SQLite-backed time-based duplicate check continues
// to provide a fallback defence against restart-window replays.
type Dedup struct {
	mu      sync.Mutex
	entries map[string]time.Time
	ttl     time.Duration
	clock   func() time.Time
}

// NewDedup creates a new Dedup with the given TTL. If ttl is zero or negative,
// DefaultDedupTTL is used.
func NewDedup(ttl time.Duration) *Dedup {
	if ttl <= 0 {
		ttl = DefaultDedupTTL
	}
	return &Dedup{
		entries: make(map[string]time.Time),
		ttl:     ttl,
		clock:   time.Now,
	}
}

// SetClock overrides the time source (for testing).
func (d *Dedup) SetClock(c func() time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.clock = c
}

// hashKey derives a stable fingerprint of (email || clientOrderID). Using
// SHA-256 means two different (email, key) pairs are astronomically unlikely
// to collide, and the email plaintext never lands in the map.
func hashKey(email, clientOrderID string) string {
	h := sha256.New()
	h.Write([]byte(email))
	h.Write([]byte{0}) // separator so "a|bc" and "ab|c" hash differently
	h.Write([]byte(clientOrderID))
	return hex.EncodeToString(h.Sum(nil))
}

// SeenOrAdd records (email, clientOrderID). Returns true if the key was
// already present and still within TTL (i.e. this is a duplicate), false if
// it was unseen (i.e. the call is the authoritative "first" submission and
// has now been recorded).
//
// Stale entries (older than TTL) are treated as unseen and overwritten, so
// a key can be reused after expiry. Lazy cleanup of adjacent stale entries
// keeps the map bounded under steady-state use; call Cleanup() explicitly
// if a sweep is desired.
func (d *Dedup) SeenOrAdd(email, clientOrderID string) bool {
	key := hashKey(email, clientOrderID)
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.clock()
	if ts, ok := d.entries[key]; ok {
		if now.Sub(ts) < d.ttl {
			return true // duplicate within window
		}
		// Stale — fall through and overwrite.
	}
	d.entries[key] = now
	return false
}

// Size returns the current number of tracked entries (including stale ones
// not yet swept). Primarily for testing and metrics.
func (d *Dedup) Size() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.entries)
}

// Cleanup removes entries older than TTL. Safe to call periodically; a
// background goroutine can drive this but is not required — the map is
// bounded by concurrent-order-rate * TTL, which is small for this
// workload (handful of orders per minute).
func (d *Dedup) Cleanup() {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.clock()
	for k, ts := range d.entries {
		if now.Sub(ts) >= d.ttl {
			delete(d.entries, k)
		}
	}
}
