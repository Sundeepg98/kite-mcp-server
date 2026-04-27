package billing

import (
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// Money VO Slice 4 — billing tier amounts.
//
// Conventions established by Slices 1-2 (commits 5ce3eb0, 0e516e7):
//
//   - tier-amount fields hold domain.Money instead of float64 so the
//     "INR vs USD" coercion is no longer silent;
//   - the zero Money is the "unset / no subscription" sentinel
//     (IsZero() returns true);
//   - cross-currency comparison/addition surfaces an error rather than
//     coercing — Money.Add and Money.GreaterThan both return error;
//   - SQLite columns stay REAL — bind via .Float64() / wrap via NewINR()
//     at the persistence boundary, no DDL type churn.
//
// These tests are intentionally written first (TDD red) so the green
// implementation must satisfy the specified surface and the documented
// boundary semantics.

// TestTierMonthlyINR_Canonical pins the canonical INR amount per tier.
// Free has zero Money — IsZero() is the "no paid plan" sentinel that
// downstream MRR computations key off. Paid tiers carry the published
// per-month rupee amounts; the constants live alongside Tier so the
// billing package owns its own pricing surface (Stripe stores the
// authoritative price list, this is the in-process mirror used for
// audit-event annotation and dashboard display).
func TestTierMonthlyINR_Canonical(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		tier Tier
		want float64
	}{
		{"free is zero Money", TierFree, 0},
		{"solo_pro is 500 INR", TierSoloPro, 500},
		{"pro is 999 INR", TierPro, 999},
		{"premium is 2999 INR", TierPremium, 2999},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := TierMonthlyINR(tc.tier)
			assert.Equal(t, "INR", got.Currency,
				"all tier monthly amounts must be denominated in INR")
			assert.Equal(t, tc.want, got.Float64(),
				"TierMonthlyINR(%v).Float64() = %v, want %v",
				tc.tier, got.Float64(), tc.want)
		})
	}
}

// TestTierMonthlyINR_FreeIsZeroMoney verifies the "no subscription"
// semantic: TierFree returns the zero Money, IsZero is true, IsPositive
// is false. This is the sentinel callers use to detect "this user
// pays nothing" without comparing against a magic float.
func TestTierMonthlyINR_FreeIsZeroMoney(t *testing.T) {
	t.Parallel()
	m := TierMonthlyINR(TierFree)
	assert.True(t, m.IsZero(), "TierFree must produce zero Money")
	assert.False(t, m.IsPositive(), "TierFree zero Money is not positive")
}

// TestTierMonthlyINR_PaidTiersArePositive verifies all paid tiers
// return positive Money — a smoke check that we don't accidentally ship
// a paid-tier mapping at zero (which would make MRR computations
// silently free-ride paid users).
func TestTierMonthlyINR_PaidTiersArePositive(t *testing.T) {
	t.Parallel()
	for _, tier := range []Tier{TierSoloPro, TierPro, TierPremium} {
		assert.True(t, TierMonthlyINR(tier).IsPositive(),
			"paid tier %v must produce positive Money", tier)
	}
}

// TestSubscription_MonthlyAmount_ZeroForFree pins the round-trip
// behaviour for the free / unset path: a Subscription created without
// MonthlyAmount round-trips through SetSubscription as zero Money.
// Mirrors the IsZero() sentinel established in Slice 1
// (UserLimits.MaxSingleOrderINR — zero means "unset, fall back to
// SystemDefaults"). Here zero means "free / no paid plan".
func TestSubscription_MonthlyAmount_ZeroForFree(t *testing.T) {
	t.Parallel()
	s := newTestStore()
	require.NoError(t, s.SetSubscription(&Subscription{
		AdminEmail: "free@example.com",
		Tier:       TierFree,
		Status:     StatusActive,
	}))

	got := s.GetSubscription("free@example.com")
	require.NotNil(t, got)
	assert.True(t, got.MonthlyAmount.IsZero(),
		"a Free subscription must have zero MonthlyAmount")
	assert.Equal(t, "INR", got.MonthlyAmount.Currency,
		"the zero-Money default still carries the INR currency tag so "+
			"comparisons against a non-zero INR amount don't trip a "+
			"currency-mismatch error")
}

// TestSubscription_MonthlyAmount_PaidPersistRoundtrip pins the SQLite
// boundary: store a Subscription with a non-zero MonthlyAmount, reload
// from disk via LoadFromDB, and verify the Money survives the REAL
// column round-trip. Same pattern as Slice 1's
// limits_money_test.go::TestPersist_MaxSingleOrderINR_Roundtrip.
func TestSubscription_MonthlyAmount_PaidPersistRoundtrip(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := NewStore(db, logger)
	require.NoError(t, s.InitTable())

	require.NoError(t, s.SetSubscription(&Subscription{
		AdminEmail:    "paid@example.com",
		Tier:          TierPro,
		Status:        StatusActive,
		MaxUsers:      5,
		MonthlyAmount: domain.NewINR(999),
	}))

	// Reload from DB using a fresh Store backed by the same db.
	s2 := NewStore(db, logger)
	require.NoError(t, s2.InitTable())
	require.NoError(t, s2.LoadFromDB())

	got := s2.GetSubscription("paid@example.com")
	require.NotNil(t, got)
	assert.Equal(t, 999.0, got.MonthlyAmount.Float64(),
		"MonthlyAmount must survive SQLite REAL round-trip")
	assert.Equal(t, "INR", got.MonthlyAmount.Currency)
	assert.True(t, got.MonthlyAmount.IsPositive())
}

// TestSubscription_MonthlyAmount_RejectsCrossCurrencyAdd is the type-
// safety win for Slice 4: trying to Add a USD amount to an INR
// MonthlyAmount returns an error rather than silently coercing. This
// is the same property Slices 1+2 added for limits / order prices, now
// extended to billing amounts — once two paid plans are denominated
// in different currencies (INR retail, USD enterprise) we fail loud
// instead of producing a corrupt MRR figure.
func TestSubscription_MonthlyAmount_RejectsCrossCurrencyAdd(t *testing.T) {
	t.Parallel()
	inr := domain.NewINR(999)
	usd := domain.Money{Amount: 12, Currency: "USD"}

	_, err := inr.Add(usd)
	require.Error(t, err,
		"Money.Add must reject INR+USD; tier-amount math may not "+
			"silently coerce currencies")

	_, err = inr.GreaterThan(usd)
	require.Error(t, err,
		"Money.GreaterThan must reject INR vs USD; tier-amount "+
			"comparisons may not silently coerce currencies")
}

// TestTierChangedEvent_CarriesMonthlyAmount pins the new field on the
// TierChangedEvent: every emitted transition carries the to-tier's
// canonical monthly Money. This makes the event self-describing —
// auditors can compute MRR delta by summing event.Amount across
// transitions without a join into the billing table.
//
// Free→Free no-op transitions don't fire (the same-tier suppression
// from store.go remains intact); but every fired event has Amount
// populated.
func TestTierChangedEvent_CarriesMonthlyAmount(t *testing.T) {
	t.Parallel()

	s := newTestStore()
	dispatcher := domain.NewEventDispatcher()
	s.SetEventDispatcher(dispatcher)

	var captured domain.TierChangedEvent
	seen := false
	dispatcher.Subscribe("billing.tier_changed", func(e domain.Event) {
		captured = e.(domain.TierChangedEvent)
		seen = true
	})

	s.SetChangeReason("admin_set_billing_tier")
	require.NoError(t, s.SetSubscription(&Subscription{
		AdminEmail: "newproupgrade@example.com",
		Tier:       TierPro,
		Status:     StatusActive,
	}))

	require.True(t, seen, "tier change must dispatch event")
	assert.Equal(t, "INR", captured.Amount.Currency)
	assert.Equal(t, 999.0, captured.Amount.Float64(),
		"event.Amount must carry the canonical Pro monthly INR amount")
	assert.Equal(t, int(TierPro), captured.ToTier)
}

// TestTierChangedEvent_DowngradeAmountIsZero verifies a paid→free
// transition surfaces zero Money on the event — auditors building an
// MRR ledger key off the IsZero check rather than parsing ToTier
// integers.
func TestTierChangedEvent_DowngradeAmountIsZero(t *testing.T) {
	t.Parallel()

	s := newTestStore()
	require.NoError(t, s.SetSubscription(&Subscription{
		AdminEmail: "exiter@example.com",
		Tier:       TierPro,
		Status:     StatusActive,
	}))

	dispatcher := domain.NewEventDispatcher()
	s.SetEventDispatcher(dispatcher)

	var captured domain.TierChangedEvent
	seen := false
	dispatcher.Subscribe("billing.tier_changed", func(e domain.Event) {
		captured = e.(domain.TierChangedEvent)
		seen = true
	})

	s.SetChangeReason("stripe_subscription_deleted")
	require.NoError(t, s.SetSubscription(&Subscription{
		AdminEmail: "exiter@example.com",
		Tier:       TierFree,
		Status:     StatusCanceled,
	}))

	require.True(t, seen, "downgrade must dispatch event")
	assert.True(t, captured.Amount.IsZero(),
		"downgrade to Free must surface zero MonthlyAmount on the event")
	assert.Equal(t, int(TierFree), captured.ToTier)
}

// TestSetSubscription_AutoStampsMonthlyAmount verifies the ergonomic
// path: callers (webhook handler, admin tool) never need to set
// MonthlyAmount manually — SetSubscription stamps the canonical
// TierMonthlyINR(tier) value when the input Money is zero. Callers
// that pass an explicit MonthlyAmount (e.g. an enterprise contract
// at a non-list price) are honoured.
func TestSetSubscription_AutoStampsMonthlyAmount(t *testing.T) {
	t.Parallel()
	s := newTestStore()

	// Caller leaves MonthlyAmount unset (zero Money) — store fills it.
	require.NoError(t, s.SetSubscription(&Subscription{
		AdminEmail: "auto@example.com",
		Tier:       TierPremium,
		Status:     StatusActive,
	}))
	got := s.GetSubscription("auto@example.com")
	require.NotNil(t, got)
	assert.Equal(t, 2999.0, got.MonthlyAmount.Float64(),
		"unset MonthlyAmount must default to TierMonthlyINR(Premium)")

	// Caller supplies a custom enterprise amount — store preserves it.
	require.NoError(t, s.SetSubscription(&Subscription{
		AdminEmail:    "enterprise@example.com",
		Tier:          TierPremium,
		Status:        StatusActive,
		MonthlyAmount: domain.NewINR(15000),
	}))
	got = s.GetSubscription("enterprise@example.com")
	require.NotNil(t, got)
	assert.Equal(t, 15000.0, got.MonthlyAmount.Float64(),
		"explicit MonthlyAmount must be preserved (enterprise contract)")
}
