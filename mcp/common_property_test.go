package mcp

import (
	"testing"

	"pgregory.net/rapid"
)

// common_property_test.go — property-based tests for ArgParser + Safe*
// converters. Uses pgregory.net/rapid for generator-driven exploration
// (no cgo, lightweight). Existing common_fuzz_test.go covers fuzz-shrunk
// panic discovery; this file asserts algebraic properties that hold for
// every input in the generator's range.
//
// Properties under test:
//
//  1. Defaults round-trip: for every key the caller never set, the
//     parser returns the supplied default value (no spurious reads).
//
//  2. Present-value round-trip: for every key the caller did set with
//     a type-matching value, the parser returns that value exactly.
//
//  3. No-panic invariant: every ArgParser method tolerates any input
//     (nil args, wrong-type values, numeric edge cases) without
//     panicking — it only ever falls back to the default.
//
// Scope note: Safe* converters already have per-converter fuzz targets
// in common_fuzz_test.go. These properties focus on the composition
// surface (ArgParser over arbitrary maps) rather than per-converter
// details, to avoid duplicating the fuzz coverage.

// TestProperty_ArgParser_DefaultsWhenKeyMissing asserts that calling any
// ArgParser getter with a key not present in the args map always returns
// the supplied default, across an arbitrary map shape and key choice.
func TestProperty_ArgParser_DefaultsWhenKeyMissing(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate an arbitrary args map with string keys and scalar
		// values. The draws are small (<= 10 entries) because the
		// property is structural — more entries don't exercise more
		// code paths.
		args := rapid.MapOfN(
			rapid.String(),
			rapid.OneOf(
				rapid.String().AsAny(),
				rapid.Int().AsAny(),
				rapid.Float64().AsAny(),
				rapid.Bool().AsAny(),
			),
			0, 10,
		).Draw(t, "args")

		// Pick a key that is NOT in the map. We draw a random string
		// and reject if it happens to be in the map (rare for random
		// strings vs <=10 entries).
		missing := rapid.String().Filter(func(s string) bool {
			_, present := args[s]
			return !present
		}).Draw(t, "missing_key")

		p := NewArgParser(args)

		// Draw arbitrary defaults and verify round-trip.
		ds := rapid.String().Draw(t, "default_string")
		if got := p.String(missing, ds); got != ds {
			t.Fatalf("String(missing=%q, default=%q) = %q, want default", missing, ds, got)
		}

		di := rapid.Int().Draw(t, "default_int")
		if got := p.Int(missing, di); got != di {
			t.Fatalf("Int(missing=%q, default=%d) = %d, want default", missing, di, got)
		}

		df := rapid.Float64().Draw(t, "default_float")
		if got := p.Float(missing, df); got != df && !(isNaN(got) && isNaN(df)) {
			t.Fatalf("Float(missing=%q, default=%v) = %v, want default", missing, df, got)
		}

		db := rapid.Bool().Draw(t, "default_bool")
		if got := p.Bool(missing, db); got != db {
			t.Fatalf("Bool(missing=%q, default=%v) = %v, want default", missing, db, got)
		}

		// StringArray returns nil for missing keys (not a default
		// parameter — matches the existing API).
		if got := p.StringArray(missing); got != nil {
			t.Fatalf("StringArray(missing=%q) = %v, want nil", missing, got)
		}
	})
}

// TestProperty_ArgParser_ReturnsStoredValueWhenPresent asserts that when
// a key is present in the args map with a value of the requested type,
// the parser returns that value exactly — the default is never
// consulted for type-matching present values.
func TestProperty_ArgParser_ReturnsStoredValueWhenPresent(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		key := rapid.String().Filter(func(s string) bool {
			return s != "" // avoid empty-key edge case
		}).Draw(t, "key")

		// String round-trip.
		wantS := rapid.String().Draw(t, "string_value")
		pS := NewArgParser(map[string]any{key: wantS})
		if got := pS.String(key, "DEFAULT_SENTINEL"); got != wantS {
			t.Fatalf("String(%q) = %q, want stored %q", key, got, wantS)
		}

		// Int round-trip.
		wantI := rapid.Int().Draw(t, "int_value")
		pI := NewArgParser(map[string]any{key: wantI})
		if got := pI.Int(key, -999); got != wantI {
			t.Fatalf("Int(%q) = %d, want stored %d", key, got, wantI)
		}

		// Float round-trip. Filter out NaN because NaN != NaN.
		wantF := rapid.Float64().Filter(func(f float64) bool {
			return !isNaN(f)
		}).Draw(t, "float_value")
		pF := NewArgParser(map[string]any{key: wantF})
		if got := pF.Float(key, -0.12345); got != wantF {
			t.Fatalf("Float(%q) = %v, want stored %v", key, got, wantF)
		}

		// Bool round-trip.
		wantB := rapid.Bool().Draw(t, "bool_value")
		pB := NewArgParser(map[string]any{key: wantB})
		if got := pB.Bool(key, !wantB); got != wantB {
			t.Fatalf("Bool(%q) = %v, want stored %v", key, got, wantB)
		}
	})
}

// TestProperty_ArgParser_NeverPanics asserts that feeding arbitrary
// junk into every ArgParser method never triggers a panic. This
// complements common_fuzz_test.go which targets the individual
// SafeAssert* converters; here we cover the composition path (the
// parser over arbitrary maps with arbitrary keys).
func TestProperty_ArgParser_NeverPanics(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Allow nil values, empty maps, wrong-type values — the full
		// junk drawer.
		args := rapid.MapOfN(
			rapid.String(),
			rapid.OneOf(
				rapid.String().AsAny(),
				rapid.Int().AsAny(),
				rapid.Float64().AsAny(),
				rapid.Bool().AsAny(),
				rapid.Just[any](nil),
				rapid.SliceOf(rapid.String()).AsAny(),
			),
			0, 5,
		).Draw(t, "args")

		p := NewArgParser(args)
		key := rapid.String().Draw(t, "query_key")

		// Each call must return without panicking. We don't care
		// what the result is — just that it doesn't crash.
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ArgParser panicked on args=%v key=%q: %v", args, key, r)
			}
		}()

		_ = p.String(key, "fallback")
		_ = p.Int(key, 0)
		_ = p.Float(key, 0.0)
		_ = p.Bool(key, false)
		_ = p.StringArray(key)
		_ = p.Raw()
		_ = p.Required(key)
	})
}

// isNaN is a tiny helper — avoids importing math purely for IsNaN.
func isNaN(f float64) bool { return f != f }
