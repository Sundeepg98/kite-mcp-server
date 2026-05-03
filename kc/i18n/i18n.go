// Package i18n provides minimal locale-keyed string lookup for the Kite
// MCP user-facing surfaces (landing page, briefing templates, RiskGuard
// rejection messages, OAuth login screen).
//
// Design constraints (per the internal-100 sprint Item 2 brief):
//   - Leaf package — zero internal repo deps, so any package can import.
//   - JSON-file translation source under locales/ — version-controlled,
//     auditable, no external CMS dependency.
//   - English fallback for missing keys (T(LocaleHI, k) returns en[k]
//     when hi[k] is absent). Keeps the UI from rendering blank when a
//     translator hasn't covered a string yet.
//   - Unknown-key passthrough — T(loc, k) returns the literal key when
//     neither locale has it, surfacing missing translations during dev
//     and not crashing in prod.
//
// Locale resolution at runtime:
//   1. Explicit query / cookie / user-pref (set via WithLocale on ctx)
//   2. Accept-Language header (ParseAcceptLanguage)
//   3. Default LocaleEN
//
// Initial Hindi coverage: 30 strings across landing/briefing/RiskGuard/
// OAuth — the most-visible surfaces for an Indian retail trader.
package i18n

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

// Locale identifies a translation set. The string value must match the
// JSON filename under locales/ and the standard IETF BCP-47 language tag
// for client header / cookie negotiation.
type Locale string

const (
	LocaleEN Locale = "en"
	LocaleHI Locale = "hi"
)

// supportedLocales is the closed set of locales we ship translations for.
// Adding a new locale requires (a) a new locales/<tag>.json file AND
// (b) a new entry here. The two-step gate is intentional — a JSON file
// without registration won't load (silent gap), and a registration
// without JSON won't pass tests.
var supportedLocales = []Locale{LocaleEN, LocaleHI}

// SupportedLocales returns a copy of the supported-locale list. Callers
// (Accept-Language parser, Locale picker UI) should iterate this rather
// than hard-coding the set.
func SupportedLocales() []Locale {
	out := make([]Locale, len(supportedLocales))
	copy(out, supportedLocales)
	return out
}

// IsSupported reports whether the given locale string maps to a
// shipping translation set. Used by ParseAcceptLanguage and any cookie/
// query-parameter validation.
func IsSupported(loc Locale) bool {
	for _, s := range supportedLocales {
		if s == loc {
			return true
		}
	}
	return false
}

// localeCtxKey is the context key for the request-scoped locale value.
// Unexported to prevent type collisions with other packages.
type localeCtxKey struct{}

// WithLocale returns a child ctx carrying the given locale. Read by
// LocaleFromContext during T() lookups in handlers.
func WithLocale(ctx context.Context, loc Locale) context.Context {
	return context.WithValue(ctx, localeCtxKey{}, loc)
}

// LocaleFromContext extracts the request-scoped locale, defaulting to
// LocaleEN when ctx has no locale value (e.g., default Go context,
// non-HTTP code paths).
func LocaleFromContext(ctx context.Context) Locale {
	if ctx == nil {
		return LocaleEN
	}
	v := ctx.Value(localeCtxKey{})
	if v == nil {
		return LocaleEN
	}
	loc, ok := v.(Locale)
	if !ok {
		return LocaleEN
	}
	if !IsSupported(loc) {
		return LocaleEN
	}
	return loc
}

//go:embed locales/*.json
var localeFS embed.FS

// translations is the loaded { locale -> { key -> value } } map. Built
// once at package init from the embedded JSON files. Read-only after
// init, so no mutex needed for reads.
var (
	translations  map[Locale]map[string]string
	loadErr       error
	loadOnce      sync.Once
	enFallbackMap map[string]string
)

// loadTranslations populates the translations map from locales/*.json.
// Idempotent — runs once via sync.Once at first T() call.
//
// Failure mode: if any locale's JSON is malformed or missing, loadErr
// is set and lookups for that locale fall through to en (which itself
// must always load — a malformed en.json is a build-time bug). loadErr
// is exposed via LoadError() so tests / startup can fail loudly when
// configured.
func loadTranslations() {
	translations = make(map[Locale]map[string]string, len(supportedLocales))
	var firstErr error

	for _, loc := range supportedLocales {
		path := fmt.Sprintf("locales/%s.json", loc)
		data, err := localeFS.ReadFile(path)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("i18n: read %s: %w", path, err)
			}
			continue
		}
		// JSON has _meta + key->string entries. Decode into raw
		// map[string]any first so _meta (object) and string values
		// can coexist; flatten string entries into the lookup map.
		var raw map[string]any
		if err := json.Unmarshal(data, &raw); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("i18n: parse %s: %w", path, err)
			}
			continue
		}
		flat := make(map[string]string, len(raw))
		for k, v := range raw {
			if k == "_meta" {
				continue
			}
			if s, ok := v.(string); ok {
				flat[k] = s
			}
		}
		translations[loc] = flat
	}
	if en, ok := translations[LocaleEN]; ok {
		enFallbackMap = en
	} else {
		enFallbackMap = map[string]string{}
	}
	loadErr = firstErr
}

// LoadError returns any error encountered while loading translation
// files at init. Callers (test helpers, startup health checks) should
// treat a non-nil return as a hard failure.
func LoadError() error {
	loadOnce.Do(loadTranslations)
	return loadErr
}

// T returns the translated string for the given (locale, key) pair.
// Resolution order:
//  1. translations[loc][key] if present and non-empty
//  2. translations[en][key] (English fallback) if present and non-empty
//  3. key itself (passthrough) so missing translations are visible
//
// Args support is intentionally minimal: callers wanting interpolation
// should use the {placeholder} convention in the JSON value and
// strings.Replace at the call site, e.g.:
//
//	msg := i18n.T(loc, "briefing.morning.alerts_active")
//	msg = strings.Replace(msg, "{n}", strconv.Itoa(count), 1)
//
// Avoiding fmt-style format-string interpolation here prevents the
// classic CWE-134 footgun and keeps translator-side templates free of
// Go-specific verbs.
func T(loc Locale, key string) string {
	loadOnce.Do(loadTranslations)
	if !IsSupported(loc) {
		loc = LocaleEN
	}
	if m, ok := translations[loc]; ok {
		if v, ok := m[key]; ok && v != "" {
			return v
		}
	}
	// English fallback for non-en locales.
	if loc != LocaleEN {
		if v, ok := enFallbackMap[key]; ok && v != "" {
			return v
		}
	}
	// Final passthrough — surface the missing key in the UI.
	return key
}

// TFromContext is sugar for T(LocaleFromContext(ctx), key).
func TFromContext(ctx context.Context, key string) string {
	return T(LocaleFromContext(ctx), key)
}

// ParseAcceptLanguage extracts the highest-q-value supported locale
// from a browser-style Accept-Language header. Returns LocaleEN for an
// empty header or a header containing only unsupported locales.
//
// Spec compliance is partial — we honor q-values and exact / language
// tag matches but skip the long tail of fallback chains. For our
// 2-locale ship-set this is sufficient; expand later if we add a
// 3rd / 4th locale.
//
// Examples:
//
//	"hi-IN,hi;q=0.9,en;q=0.8"  -> hi  (hi has higher implicit q=1)
//	"en-US,en;q=0.9"           -> en
//	"fr-FR,fr;q=0.9"           -> en  (no fr translation; en fallback)
//	"en-IN,hi;q=0.5"           -> en  (en has higher q)
//	""                         -> en  (empty header; default)
func ParseAcceptLanguage(header string) Locale {
	header = strings.TrimSpace(header)
	if header == "" {
		return LocaleEN
	}
	type ranked struct {
		loc Locale
		q   float64
	}
	var entries []ranked
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		// Split off ";q=N.N" suffix; default q=1.0 when absent.
		q := 1.0
		tag := part
		if semi := strings.Index(part, ";"); semi >= 0 {
			tag = strings.TrimSpace(part[:semi])
			rest := strings.TrimSpace(part[semi+1:])
			if strings.HasPrefix(rest, "q=") {
				var qv float64
				if _, err := fmt.Sscanf(rest[2:], "%f", &qv); err == nil {
					q = qv
				}
			}
		}
		// Match: hi == hi, hi-IN -> hi, en-US -> en.
		base := strings.ToLower(tag)
		if dash := strings.Index(base, "-"); dash >= 0 {
			base = base[:dash]
		}
		loc := Locale(base)
		if !IsSupported(loc) {
			continue
		}
		entries = append(entries, ranked{loc, q})
	}
	if len(entries) == 0 {
		return LocaleEN
	}
	// Pick the highest-q-value entry (stable: first wins on ties).
	best := entries[0]
	for _, e := range entries[1:] {
		if e.q > best.q {
			best = e
		}
	}
	return best.loc
}
