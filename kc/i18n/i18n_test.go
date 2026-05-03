package i18n

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLocaleConstants pins the locale-tag values so external callers
// (cookie, header, query-param parsing) can rely on the exact strings.
func TestLocaleConstants(t *testing.T) {
	t.Parallel()
	assert.Equal(t, Locale("en"), LocaleEN)
	assert.Equal(t, Locale("hi"), LocaleHI)
}

// TestT_KnownKey returns the right-locale string for a known key.
func TestT_KnownKey(t *testing.T) {
	t.Parallel()
	en := T(LocaleEN, "landing.cta.try_demo")
	hi := T(LocaleHI, "landing.cta.try_demo")
	require.NotEmpty(t, en, "en string must be present")
	require.NotEmpty(t, hi, "hi string must be present")
	assert.NotEqual(t, en, hi, "hi must differ from en")
}

// TestT_UnknownKey_FallbackToEN returns the English string when the
// requested locale is missing the key.
func TestT_UnknownKey_FallbackToEN(t *testing.T) {
	t.Parallel()
	// Synthetic key only present in en. The package contract is:
	// T(hi, k) returns en[k] when hi[k] is missing — never empty,
	// never the literal key.
	got := T(LocaleHI, "i18n.test.en_only_key")
	assert.NotEmpty(t, got, "missing-hi must fall back to en, not empty")
	assert.NotEqual(t, "i18n.test.en_only_key", got, "fallback must not return the key literal")
}

// TestT_TotallyUnknownKey returns the key itself when neither locale
// has it. This makes missing translations visible in the UI rather
// than rendering a blank.
func TestT_TotallyUnknownKey(t *testing.T) {
	t.Parallel()
	got := T(LocaleEN, "totally.fake.unknown.key.xyz")
	assert.Equal(t, "totally.fake.unknown.key.xyz", got,
		"fully-unknown keys must echo the key for debuggability")
}

// TestLocaleFromContext_Default returns en for empty ctx (no leakage
// from default Go context).
func TestLocaleFromContext_Default(t *testing.T) {
	t.Parallel()
	got := LocaleFromContext(context.Background())
	assert.Equal(t, LocaleEN, got)
}

// TestLocaleFromContext_Set_Get round-trips a locale.
func TestLocaleFromContext_Set_Get(t *testing.T) {
	t.Parallel()
	ctx := WithLocale(context.Background(), LocaleHI)
	assert.Equal(t, LocaleHI, LocaleFromContext(ctx))
}

// TestParseAcceptLanguage extracts the highest-q-value supported locale
// from a browser-style Accept-Language header. Unsupported locales
// fall back to en.
func TestParseAcceptLanguage(t *testing.T) {
	t.Parallel()
	cases := []struct {
		header string
		want   Locale
	}{
		{"hi-IN,hi;q=0.9,en;q=0.8", LocaleHI},
		{"en-US,en;q=0.9", LocaleEN},
		{"hi", LocaleHI},
		{"", LocaleEN},
		{"fr-FR,fr;q=0.9", LocaleEN}, // unsupported -> en fallback
		{"en-IN,hi;q=0.5", LocaleEN}, // q-ranked: en wins
		{"hi-IN", LocaleHI},          // language tag with region
	}
	for _, c := range cases {
		got := ParseAcceptLanguage(c.header)
		assert.Equalf(t, c.want, got, "ParseAcceptLanguage(%q)", c.header)
	}
}

// TestSupportedLocales returns exactly the two we have translations for.
// Keeps the consumer side honest — adding ja/ta/etc. requires both a
// translations file AND adding to this list, so we can't accidentally
// pick a locale we don't have strings for.
func TestSupportedLocales(t *testing.T) {
	t.Parallel()
	got := SupportedLocales()
	assert.ElementsMatch(t, []Locale{LocaleEN, LocaleHI}, got)
}

// TestRiskGuardReasonStrings — the 10 RiskGuard rejection reasons all
// have HI translations. This is the most user-facing I/O strip.
func TestRiskGuardReasonStrings(t *testing.T) {
	t.Parallel()
	keys := []string{
		"riskguard.reason.kill_switch",
		"riskguard.reason.order_value_limit",
		"riskguard.reason.quantity_limit",
		"riskguard.reason.daily_order_limit",
		"riskguard.reason.rate_limit",
		"riskguard.reason.duplicate_order",
		"riskguard.reason.daily_value_limit",
		"riskguard.reason.auto_freeze",
		"riskguard.reason.confirmation_required",
		"riskguard.reason.off_hours_blocked",
	}
	for _, k := range keys {
		en := T(LocaleEN, k)
		hi := T(LocaleHI, k)
		assert.NotEqualf(t, k, en, "%q en must not be the key literal", k)
		assert.NotEqualf(t, k, hi, "%q hi must not be the key literal", k)
		assert.NotEqualf(t, en, hi, "%q hi must differ from en", k)
	}
}

// TestLandingStrings — the 9 landing-page hero + CTA strings all
// translated.
func TestLandingStrings(t *testing.T) {
	t.Parallel()
	keys := []string{
		"landing.hero.tagline",
		"landing.cta.try_demo",
		"landing.cta.self_host",
		"landing.cta.compare",
		"landing.feature.tools.title",
		"landing.feature.paper_trading.title",
		"landing.feature.safety.title",
		"landing.feature.widgets.title",
		"landing.feature.indicators.title",
	}
	for _, k := range keys {
		assert.NotEqualf(t, k, T(LocaleEN, k), "%q must have en", k)
		assert.NotEqualf(t, k, T(LocaleHI, k), "%q must have hi", k)
	}
}

// TestBriefingStrings — morning/EOD briefing template strings.
func TestBriefingStrings(t *testing.T) {
	t.Parallel()
	keys := []string{
		"briefing.morning.greeting",
		"briefing.morning.token_active",
		"briefing.morning.token_expired",
		"briefing.morning.alerts_active",
		"briefing.eod.greeting",
		"briefing.eod.holdings_pnl",
		"briefing.eod.positions_pnl",
		"briefing.eod.no_positions",
	}
	for _, k := range keys {
		assert.NotEqualf(t, k, T(LocaleEN, k), "%q must have en", k)
		assert.NotEqualf(t, k, T(LocaleHI, k), "%q must have hi", k)
	}
}

// TestOAuthStrings — login choice screen.
func TestOAuthStrings(t *testing.T) {
	t.Parallel()
	keys := []string{
		"oauth.login.title",
		"oauth.login.prompt",
		"oauth.login.with_google",
		"oauth.login.with_kite",
	}
	for _, k := range keys {
		assert.NotEqualf(t, k, T(LocaleEN, k), "%q must have en", k)
		assert.NotEqualf(t, k, T(LocaleHI, k), "%q must have hi", k)
	}
}
