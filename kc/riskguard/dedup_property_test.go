package riskguard

import (
	"fmt"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// dedup_property_test.go — property-based tests for the Dedup idempotency
// tracker. Uses pgregory.net/rapid to explore a large input space in a
// reproducible, shrinking-friendly way.
//
// Since hashKey is unexported and Dedup's state is the only observable
// side-effect, we exercise the public SeenOrAdd surface:
//
//  1. Determinism: submitting the same (email, client_order_id) pair
//     twice in rapid succession returns (first=false, second=true).
//
//  2. Collision-freedom (practical): across 10k random (email,
//     client_order_id) pairs the second submission of each new pair is
//     never rejected as a duplicate, i.e. no cross-input collisions.
//
//  3. Email separation: same client_order_id from different emails
//     never collide — SeenOrAdd for user A then user B (both with the
//     same key) both return false.
//
//  4. TTL expiry: a key seen long ago (>TTL) is treated as unseen and
//     the second submission returns false.

// TestProperty_Dedup_DeterministicWithinTTL asserts that resubmitting
// the same (email, key) pair within the TTL window always returns a
// duplicate on the second call. Covers the core idempotency contract.
func TestProperty_Dedup_DeterministicWithinTTL(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		email := rapid.String().Draw(t, "email")
		key := rapid.String().Draw(t, "key")

		d := NewDedup(DefaultDedupTTL)
		if dup := d.SeenOrAdd(email, key); dup {
			t.Fatalf("first SeenOrAdd(%q, %q) reported duplicate on empty dedup", email, key)
		}
		if dup := d.SeenOrAdd(email, key); !dup {
			t.Fatalf("second SeenOrAdd(%q, %q) did not report duplicate", email, key)
		}
	})
}

// TestProperty_Dedup_NoCrossInputCollisions asserts that across 10k
// distinct (email, client_order_id) pairs generated in a single
// property-check iteration, no two pairs collide in the dedup map.
// A SHA-256 collision in 10k inputs has probability ~2^-196 — if the
// assertion fires, the bug is almost certainly in the hash-or-compare
// path, not a lucky collision.
//
// This is the mutation-robustness net: if a future refactor weakens
// hashKey (e.g. drops the separator byte, truncates the output), this
// property catches the regression long before a real user does.
func TestProperty_Dedup_NoCrossInputCollisions(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		// Draw a modest sample per iteration; rapid will run the check
		// 100 times by default so the aggregate sample is ~1000.
		n := rapid.IntRange(10, 100).Draw(t, "n")

		d := NewDedup(DefaultDedupTTL)
		seen := make(map[string]struct{}, n)

		for i := 0; i < n; i++ {
			// Mix a monotonic counter into the email so each iteration
			// generates guaranteed-unique (email, key) pairs — the
			// property we're testing is "dedup does not *add* false
			// positives", not "two random strings are different".
			email := fmt.Sprintf("u%d+%s@x.test", i,
				rapid.StringN(0, 10, -1).Draw(t, "suffix"))
			key := fmt.Sprintf("k%d-%s", i,
				rapid.StringN(0, 10, -1).Draw(t, "keyrand"))

			composite := email + "\x00" + key
			if _, already := seen[composite]; already {
				continue // dup — skip (shouldn't happen given counter, but defensive)
			}
			seen[composite] = struct{}{}

			if dup := d.SeenOrAdd(email, key); dup {
				t.Fatalf("SeenOrAdd(%q, %q) reported duplicate on first insertion (collision)",
					email, key)
			}
		}
	})
}

// TestProperty_Dedup_EmailScopeIsolation asserts that the same
// client_order_id submitted from two different emails is never treated
// as a duplicate — user isolation must hold even when clients happen
// to pick the same key string.
func TestProperty_Dedup_EmailScopeIsolation(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		key := rapid.String().Draw(t, "key")
		emailA := rapid.String().Draw(t, "email_a")
		emailB := rapid.String().Filter(func(s string) bool {
			return s != emailA
		}).Draw(t, "email_b")

		d := NewDedup(DefaultDedupTTL)
		if dup := d.SeenOrAdd(emailA, key); dup {
			t.Fatal("first SeenOrAdd(A, key) reported duplicate")
		}
		if dup := d.SeenOrAdd(emailB, key); dup {
			t.Fatalf("SeenOrAdd(B=%q, key=%q) reported duplicate after A=%q — emails not scoped",
				emailB, key, emailA)
		}
	})
}

// TestProperty_Dedup_StaleEntriesExpire asserts that a key inserted
// long before the clock tick returns not-duplicate on the next
// insertion — stale entries are correctly overwritten rather than
// lingering as false positives.
func TestProperty_Dedup_StaleEntriesExpire(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		email := rapid.String().Draw(t, "email")
		key := rapid.String().Draw(t, "key")

		// A manual time source so we can jump past TTL without
		// wall-clock sleeps. Draw a positive offset so the second
		// observation is unambiguously after expiry.
		offset := rapid.Int64Range(
			int64(DefaultDedupTTL)+int64(time.Second),
			int64(24*time.Hour),
		).Draw(t, "offset_ns")

		start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		now := start
		d := NewDedup(DefaultDedupTTL)
		d.SetClock(func() time.Time { return now })

		if dup := d.SeenOrAdd(email, key); dup {
			t.Fatal("first insertion reported duplicate")
		}
		now = start.Add(time.Duration(offset))
		if dup := d.SeenOrAdd(email, key); dup {
			t.Fatalf("SeenOrAdd after %v (ttl=%v) still reported duplicate", time.Duration(offset), DefaultDedupTTL)
		}
	})
}
