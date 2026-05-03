package kc

import (
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMultiTenant_CredentialIsolation_UserABNoCrossLeak is the headline
// security invariant for the multi-tenant deployment: two distinct
// users' credentials must never leak across the email-key boundary.
//
// Threat model: a user-A query for credentials must NEVER return
// user-B's API key or secret. Caller-site bugs (e.g. accidentally
// passing the wrong session's email) are out of scope; this test
// covers the store-side guarantee that:
//
//   1. Get(A) returns A's credentials, never B's.
//   2. Get(B) returns B's credentials, never A's.
//   3. Get(unknown) returns ok=false, no leak of any user's data.
//   4. Setting one user's credentials does not mutate another's.
//   5. Deleting one user's credentials leaves others untouched.
//   6. Case-sensitive-looking emails fold correctly via Set's
//      lower-case key — but two semantically-distinct emails
//      (alice vs alice2) NEVER collide.
//
// E2E scope marker for the "Item 5c — multi-tenant credential
// isolation" sprint commit: this test is the canonical proof that
// per-email isolation holds at the store layer. Higher layers (use
// cases, MCP tool handlers) propagate the email through ctx and
// should not need re-testing for the same invariant — the store's
// keying behaviour is the single point of failure.
func TestMultiTenant_CredentialIsolation_UserABNoCrossLeak(t *testing.T) {
	t.Parallel()

	store := NewKiteCredentialStore()

	aliceEntry := &KiteCredentialEntry{
		APIKey:    "alice_api_key_abc",
		APISecret: "alice_api_secret_xyz",
	}
	bobEntry := &KiteCredentialEntry{
		APIKey:    "bob_api_key_123",
		APISecret: "bob_api_secret_456",
	}

	store.Set("alice@example.com", aliceEntry)
	store.Set("bob@example.com", bobEntry)

	// (1) + (2) — each Get returns its own entry, not the other's.
	gotA, okA := store.Get("alice@example.com")
	require.True(t, okA, "Get(alice) must succeed")
	assert.Equal(t, "alice_api_key_abc", gotA.APIKey)
	assert.Equal(t, "alice_api_secret_xyz", gotA.APISecret)
	assert.NotEqual(t, "bob_api_key_123", gotA.APIKey,
		"alice's Get must NEVER return bob's API key")
	assert.NotEqual(t, "bob_api_secret_456", gotA.APISecret,
		"alice's Get must NEVER return bob's API secret")

	gotB, okB := store.Get("bob@example.com")
	require.True(t, okB, "Get(bob) must succeed")
	assert.Equal(t, "bob_api_key_123", gotB.APIKey)
	assert.NotEqual(t, "alice_api_key_abc", gotB.APIKey,
		"bob's Get must NEVER return alice's API key")

	// (3) — unknown email returns ok=false, no data.
	gotUnknown, okU := store.Get("eve@example.com")
	assert.False(t, okU, "Get(eve) must fail for unregistered email")
	assert.Nil(t, gotUnknown)

	// (4) — overwriting alice does NOT mutate bob.
	store.Set("alice@example.com", &KiteCredentialEntry{
		APIKey:    "alice_rotated_key",
		APISecret: "alice_rotated_secret",
	})
	gotB2, _ := store.Get("bob@example.com")
	assert.Equal(t, "bob_api_key_123", gotB2.APIKey,
		"rotating alice's creds must not touch bob's")

	// (5) — deleting alice leaves bob untouched.
	store.Delete("alice@example.com")
	_, okA2 := store.Get("alice@example.com")
	assert.False(t, okA2, "alice gone after Delete")
	gotB3, okB3 := store.Get("bob@example.com")
	require.True(t, okB3, "bob must survive alice's deletion")
	assert.Equal(t, "bob_api_key_123", gotB3.APIKey)

	// (6) — case-folding consistency. The store lowercases on Set, so
	// "ALICE@example.com" and "alice@example.com" address the same
	// slot — but "alice@example.com" and "alice2@example.com" are
	// distinct identities. This sanity-check pins the boundary.
	store.Set("Charlie@Example.com", &KiteCredentialEntry{
		APIKey:    "charlie_key",
		APISecret: "charlie_secret",
	})
	gotCLower, okCL := store.Get("charlie@example.com")
	require.True(t, okCL, "case-folded lookup must hit")
	assert.Equal(t, "charlie_key", gotCLower.APIKey)

	gotCUpper, okCU := store.Get("CHARLIE@EXAMPLE.COM")
	require.True(t, okCU, "case-folded all-upper lookup must hit")
	assert.Equal(t, "charlie_key", gotCUpper.APIKey)

	_, okC2 := store.Get("charlie2@example.com")
	assert.False(t, okC2,
		"distinct email charlie2 must NOT collide with charlie")
}

// TestMultiTenant_CredentialIsolation_ConcurrentSetGet exercises the
// isolation guarantee under concurrent Set+Get from N goroutines, each
// targeting a unique email. The race detector + assertion that each
// goroutine's Get returns ITS OWN data prove the lock discipline.
//
// 50 goroutines × 50 iterations = 2500 round trips. Bounded enough to
// run in <1s; the race detector is the actual signal.
func TestMultiTenant_CredentialIsolation_ConcurrentSetGet(t *testing.T) {
	t.Parallel()

	store := NewKiteCredentialStore()
	const numUsers = 50
	const iterations = 50

	var wg sync.WaitGroup
	wg.Add(numUsers)
	for i := 0; i < numUsers; i++ {
		go func(userIdx int) {
			defer wg.Done()
			email := strings.ToLower("user" + itoaLower(userIdx) + "@example.com")
			expectedKey := "key_for_user_" + itoaLower(userIdx)
			expectedSecret := "secret_for_user_" + itoaLower(userIdx)
			for j := 0; j < iterations; j++ {
				store.Set(email, &KiteCredentialEntry{
					APIKey:    expectedKey,
					APISecret: expectedSecret,
				})
				got, ok := store.Get(email)
				if !ok {
					t.Errorf("goroutine %d: Get(%s) returned ok=false", userIdx, email)
					return
				}
				if got.APIKey != expectedKey {
					t.Errorf("goroutine %d: APIKey leak — got %q, want %q",
						userIdx, got.APIKey, expectedKey)
					return
				}
				if got.APISecret != expectedSecret {
					t.Errorf("goroutine %d: APISecret leak — got %q, want %q",
						userIdx, got.APISecret, expectedSecret)
					return
				}
			}
		}(i)
	}
	wg.Wait()
}

// itoaLower is a deterministic small-int → string helper that avoids
// pulling strconv into the test for one call site. Equivalent to
// strconv.Itoa for the 0-99 range exercised by the concurrent test.
func itoaLower(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return string(rune('0'+n/10)) + string(rune('0'+n%10))
}
