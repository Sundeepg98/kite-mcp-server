package ops

// ops_push100_test.go: push ops coverage from ~89% toward 100%.
// Targets remaining uncovered branches in handler.go, user_render.go,
// dashboard.go, dashboard_templates.go, overview_sse.go, and admin_render.go.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

)

// ---------------------------------------------------------------------------
// Helpers unique to this file
// ---------------------------------------------------------------------------

// newPush100OpsHandler creates a minimal ops handler with nil userStore for nil-path tests.


// ---------------------------------------------------------------------------
// user_render.go: fmtINR edge cases
// ---------------------------------------------------------------------------
func TestPush100_FmtINR_ExactlyThreeDigits(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "\u20B9999.00", fmtINR(999))
}


func TestPush100_FmtINR_FourDigits(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "\u20B91,000.00", fmtINR(1000))
}


func TestPush100_FmtINR_NegativeSmall(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "-\u20B950.50", fmtINR(-50.50))
}


func TestPush100_FmtINR_Zero(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "\u20B90.00", fmtINR(0))
}


func TestPush100_FmtINR_NegativeLarge(t *testing.T) {
	t.Parallel()
	result := fmtINR(-1234567.89)
	assert.True(t, strings.HasPrefix(result, "-\u20B9"))
	assert.Contains(t, result, "12,34,567.89")
}


// ---------------------------------------------------------------------------
// user_render.go: fmtINRShort edge cases
// ---------------------------------------------------------------------------
func TestPush100_FmtINRShort_ExactlyLakh(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "\u20B91.0L", fmtINRShort(100000))
}


func TestPush100_FmtINRShort_ExactlyThousand(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "\u20B91.0K", fmtINRShort(1000))
}


func TestPush100_FmtINRShort_BelowThousand(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "\u20B9500", fmtINRShort(500))
}


func TestPush100_FmtINRShort_NegativeLakh(t *testing.T) {
	t.Parallel()
	// Negative value: -200000 -> abs >= 100000 -> format with v/100000 = -2.0
	result := fmtINRShort(-200000)
	assert.Contains(t, result, "-2.0L")
}


// ---------------------------------------------------------------------------
// admin_render.go: formatInt edge cases
// ---------------------------------------------------------------------------
func TestPush100_FormatInt_Small(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "0", formatInt(0))
	assert.Equal(t, "999", formatInt(999))
}


func TestPush100_FormatInt_WithCommas(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "1,000", formatInt(1000))
	assert.Equal(t, "1,000,000", formatInt(1000000))
}


// ---------------------------------------------------------------------------
// admin_render.go: formatFloat
// ---------------------------------------------------------------------------
func TestPush100_FormatFloat_Decimal(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "3.14", formatFloat(3.14))
	assert.Equal(t, "0.00", formatFloat(0))
}


// ---------------------------------------------------------------------------
// overview_render.go: boolClass
// ---------------------------------------------------------------------------
func TestPush100_BoolClass_True(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "active", boolClass(true, "active"))
}


func TestPush100_BoolClass_False(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "", boolClass(false, "active"))
}


// ---------------------------------------------------------------------------
// user_render.go: barClass
// ---------------------------------------------------------------------------
func TestPush100_BarClass_Boundaries(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "safe", barClass(0))
	assert.Equal(t, "safe", barClass(69))
	assert.Equal(t, "warn", barClass(70))
	assert.Equal(t, "warn", barClass(89))
	assert.Equal(t, "danger", barClass(90))
	assert.Equal(t, "danger", barClass(100))
}


// ---------------------------------------------------------------------------
// user_render.go: distanceClass boundaries
// ---------------------------------------------------------------------------
func TestPush100_DistanceClass_Boundaries(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "dist-green", distanceClass(0))
	assert.Equal(t, "dist-green", distanceClass(1.99))
	assert.Equal(t, "dist-amber", distanceClass(2.0))
	assert.Equal(t, "dist-amber", distanceClass(4.99))
	assert.Equal(t, "dist-red", distanceClass(5.0))
}


// ---------------------------------------------------------------------------
// user_render.go: getCatColor/getCatLabel for all known categories
// ---------------------------------------------------------------------------
func TestPush100_GetCatColor_AllKnown(t *testing.T) {
	t.Parallel()
	knownCats := []string{
		"order", "query", "market_data", "alert", "notification",
		"ticker", "setup", "mf_order", "trailing_stop", "watchlist", "analytics",
	}
	for _, cat := range knownCats {
		bg, fg := getCatColor(cat)
		assert.NotEmpty(t, bg, "bg for %s", cat)
		assert.NotEmpty(t, fg, "fg for %s", cat)
	}
}


func TestPush100_GetCatLabel_AllKnown(t *testing.T) {
	t.Parallel()
	expected := map[string]string{
		"order": "ORDER", "query": "QUERY", "market_data": "MARKET",
		"alert": "ALERT", "notification": "NOTIF", "ticker": "TICKER",
		"setup": "SETUP", "mf_order": "MF ORDER", "trailing_stop": "TRAILING",
		"watchlist": "WATCHLIST", "analytics": "ANALYTICS",
	}
	for cat, label := range expected {
		assert.Equal(t, label, getCatLabel(cat))
	}
}


// ---------------------------------------------------------------------------
// user_render.go: fmtTimeDDMon / fmtTimeHMS edge cases
// ---------------------------------------------------------------------------
func TestPush100_FmtTimeDDMon_NonZero(t *testing.T) {
	t.Parallel()
	ts := time.Date(2026, 1, 5, 14, 30, 0, 0, time.UTC)
	assert.Equal(t, "05 Jan 14:30", fmtTimeDDMon(ts))
}


func TestPush100_FmtTimeHMS_NonZero(t *testing.T) {
	t.Parallel()
	ts := time.Date(2026, 1, 5, 9, 5, 3, 0, time.UTC)
	assert.Equal(t, "09:05:03", fmtTimeHMS(ts))
}


// ---------------------------------------------------------------------------
// dashboard_templates.go: toFloat / toInt with string values
// ---------------------------------------------------------------------------
func TestPush100_ToFloat_ValidString(t *testing.T) {
	t.Parallel()
	assert.InDelta(t, 3.14, toFloat("3.14"), 0.001)
}


func TestPush100_ToInt_Float64(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 42, toInt(float64(42.7)))
}


// ---------------------------------------------------------------------------
// handler.go: truncKey
// ---------------------------------------------------------------------------
func TestPush100_TruncKey_Short(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "ab", truncKey("abcde", 2))
}


func TestPush100_TruncKey_ExactLength(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "abc", truncKey("abc", 5))
}


// ===========================================================================
// dashboard.go: writeJSON encode error path
// ===========================================================================
func TestPush100_WriteJSON_EncodeError(t *testing.T) {
	t.Parallel()
	d, _ := newPush100Dashboard(t)
	rec := httptest.NewRecorder()
	// func() is not JSON-encodable, triggers the error path
	d.writeJSON(rec, map[string]interface{}{"fn": func() {}})
	// Should still set Content-Type even on error
	assert.Contains(t, rec.Header().Get("Content-Type"), "application/json")
}


// ===========================================================================
// handler.go: writeJSON and writeJSONError encode error path
// ===========================================================================
func TestPush100_Handler_WriteJSON_EncodeError(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)
	rec := httptest.NewRecorder()
	h.writeJSON(rec, map[string]interface{}{"fn": func() {}})
	assert.Contains(t, rec.Header().Get("Content-Type"), "application/json")
}


func TestPush100_Handler_WriteJSONError(t *testing.T) {
	t.Parallel()
	h := newPush100OpsHandlerFull(t)
	rec := httptest.NewRecorder()
	h.writeJSONError(rec, http.StatusBadRequest, "test error msg")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "test error msg")
}
