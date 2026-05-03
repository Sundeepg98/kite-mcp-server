package riskguard

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zerodha/kite-mcp-server/kc/i18n"
)

// TestRejectionMessage_KnownReason_EN returns the English translated
// canonical reason text plus the appended check-side detail when the
// detail differs from the canonical text.
func TestRejectionMessage_KnownReason_EN(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	got := rejectionMessage(ctx, CheckResult{
		Allowed: false,
		Reason:  ReasonOrderValue,
		Message: "limit ₹50000, attempted ₹75000",
	})
	// English translation of riskguard.reason.order_value_limit
	// must appear, plus the parenthetical detail.
	assert.Contains(t, got, "Order value exceeds the per-order cap of ₹50,000",
		"canonical English reason must appear")
	assert.Contains(t, got, "limit ₹50000, attempted ₹75000",
		"check-side detail must be appended")
}

// TestRejectionMessage_KnownReason_HI returns the Hindi translated
// canonical reason text when ctx carries LocaleHI.
func TestRejectionMessage_KnownReason_HI(t *testing.T) {
	t.Parallel()
	ctx := i18n.WithLocale(context.Background(), i18n.LocaleHI)
	got := rejectionMessage(ctx, CheckResult{
		Allowed: false,
		Reason:  ReasonTradingFrozen,
		Message: "",
	})
	// Hindi text contains the Devanagari character class — easiest to
	// verify by checking for a non-ASCII codepoint.
	hasNonASCII := false
	for _, r := range got {
		if r > 127 {
			hasNonASCII = true
			break
		}
	}
	assert.True(t, hasNonASCII, "hi-locale message must contain Devanagari script: %q", got)
	assert.NotContains(t, got, "Trading is currently disabled",
		"hi-locale message must not be the English canonical")
}

// TestRejectionMessage_UnknownReason_FallsBackToMessage returns the
// check-side Message when no translation exists for the Reason. This
// preserves backwards-compatible behaviour for any RejectionReason
// not yet in the translation table.
func TestRejectionMessage_UnknownReason_FallsBackToMessage(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	originalMsg := "synthetic check-side detail for an unmapped reason"
	got := rejectionMessage(ctx, CheckResult{
		Allowed: false,
		Reason:  RejectionReason("unmapped_synthetic_reason_xyz"),
		Message: originalMsg,
	})
	assert.Equal(t, originalMsg, got,
		"unmapped reason must fall through to the check's Message")
}

// TestRejectionMessage_DuplicateText_NoParenthetical avoids duplicating
// the canonical text when result.Message is identical (or empty). The
// returned string must read cleanly, not "X (X)".
func TestRejectionMessage_DuplicateText_NoParenthetical(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	got := rejectionMessage(ctx, CheckResult{
		Allowed: false,
		Reason:  ReasonTradingFrozen,
		Message: "", // empty -> no parenthetical
	})
	assert.NotContains(t, got, "()",
		"empty Message must not produce trailing '()' artifact")
	// Count occurrences of "(": should be zero or one (parenthetical
	// for the appended detail), never two (double-rendering).
	assert.LessOrEqual(t, strings.Count(got, "("), 1,
		"must not double-render parens")
}

// TestRejectionMessage_HI_FallsBackToEN_WhenHIMissing — synthetic
// Reason that exists only in en JSON would still yield English. We
// don't currently have a half-translated reason in the table, but the
// fallback path is exercised by i18n.T's en-fallback semantics —
// covered in kc/i18n/i18n_test.go::TestT_UnknownKey_FallbackToEN.
// This test pins the behaviour for the rejection-message wrapper:
// hi locale + reason without hi translation must still produce non-
// empty output via en fallback (not the key literal, not result.Message
// alone — the wrapper preserves the en text).
func TestRejectionMessage_HI_KnownReason_NotEmptyOrKey(t *testing.T) {
	t.Parallel()
	ctx := i18n.WithLocale(context.Background(), i18n.LocaleHI)
	got := rejectionMessage(ctx, CheckResult{
		Allowed: false,
		Reason:  ReasonRateLimit,
		Message: "",
	})
	assert.NotEmpty(t, got)
	assert.NotEqual(t, "riskguard.reason.rate_limit", got,
		"must not return the i18n key literal")
}
