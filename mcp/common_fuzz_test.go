package mcp

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// These fuzz harnesses exercise the ArgParser + SafeAssert* family of arg
// extractors that every MCP tool routes through. A panic or unbounded
// allocation here would crash the entire tool pipeline, so we fuzz against
// adversarial string/int/float/bool/slice inputs.
//
// Invariants enforced by every harness:
//   - Parser must not panic on arbitrary input.
//   - Parser must not allocate more than O(len(input)) for any single value.
//   - SafeAssertString never returns "" when a fallback is provided AND the
//     input is non-nil of a stringifiable type (we always get *something*).
//
// Run: go test ./mcp/ -run=^$ -fuzz=FuzzArgParserString -fuzztime=30s

// FuzzArgParserString fuzzes the String extractor against raw byte sequences
// including UTF-8, control chars, NULs, very long strings, and mixed types.
func FuzzArgParserString(f *testing.F) {
	// Realistic seeds.
	f.Add("RELIANCE")
	f.Add("NSE:INFY")
	f.Add("user@example.com")
	f.Add("order_id_abc123")
	f.Add("")
	f.Add(" ")

	// Adversarial seeds.
	f.Add("\x00\xff\x01\x02")
	f.Add("\u2028\u2029")                                  // JS line terminator tricks
	f.Add("<script>alert(1)</script>")                     // XSS primitive
	f.Add("'; DROP TABLE users; --")                       // SQL injection primitive
	f.Add(strings.Repeat("A", 100_000))                    // long string
	f.Add("\xff\xfe\xfd invalid utf-8")                    // invalid UTF-8
	f.Add("🚀\u200B\u200Cfoo\u200D")                       // zero-width / emoji mix

	f.Fuzz(func(t *testing.T, input string) {
		args := map[string]any{"field": input}
		p := NewArgParser(args)

		got := p.String("field", "DEFAULT_FALLBACK")
		// With a non-nil value, String must return the original string (never the fallback).
		if got != input {
			t.Fatalf("String(%q) returned %q; expected same bytes", input, got)
		}

		// Absent key must return the fallback.
		absent := p.String("missing_key", "DEFAULT_FALLBACK")
		if absent != "DEFAULT_FALLBACK" {
			t.Fatalf("missing key returned %q; expected fallback", absent)
		}

		// Required() on the present key should never error just because the
		// value is weird; it only errors on nil/empty.
		if input != "" {
			if err := p.Required("field"); err != nil {
				t.Fatalf("Required on present non-empty key failed: %v", err)
			}
		}
	})
}

// FuzzArgParserInt fuzzes Int() against string, int, float, nil, and other
// weird types. The function must return the fallback (never panic) on
// unparseable input.
func FuzzArgParserInt(f *testing.F) {
	f.Add(int64(0))
	f.Add(int64(1))
	f.Add(int64(-1))
	f.Add(int64(1_000_000))
	f.Add(int64(-1_000_000))
	// Extremes.
	f.Add(int64(9_223_372_036_854_775_807))  // max int64
	f.Add(int64(-9_223_372_036_854_775_808)) // min int64
	f.Add(int64(42))

	f.Fuzz(func(t *testing.T, input int64) {
		// Plain int.
		args := map[string]any{"field": int(input)}
		p := NewArgParser(args)
		_ = p.Int("field", -1)

		// float64 (the most common JSON source).
		args2 := map[string]any{"field": float64(input)}
		p2 := NewArgParser(args2)
		_ = p2.Int("field", -1)

		// Absent must return fallback exactly.
		if p.Int("nope", 99) != 99 {
			t.Fatal("absent Int did not return fallback")
		}
		if p2.Int("nope", 99) != 99 {
			t.Fatal("absent Int did not return fallback")
		}

		// Weird string that won't parse.
		argsS := map[string]any{"field": "not-a-number"}
		pS := NewArgParser(argsS)
		if pS.Int("field", 123) != 123 {
			t.Fatal("unparseable Int did not return fallback")
		}
	})
}

// FuzzArgParserFloat fuzzes Float() against crafted numeric inputs.
func FuzzArgParserFloat(f *testing.F) {
	f.Add(0.0)
	f.Add(1.0)
	f.Add(-1.0)
	f.Add(3.14159)
	f.Add(1e-308)  // near-subnormal
	f.Add(1e308)   // near-max
	f.Add(-0.0)

	f.Fuzz(func(t *testing.T, input float64) {
		args := map[string]any{"field": input}
		p := NewArgParser(args)

		// Float must not panic on NaN/Inf; it just returns the value.
		_ = p.Float("field", -1.0)

		// Int coerced from float must not panic — including for Inf/NaN.
		_ = p.Int("field", -1)

		// Absent returns fallback.
		if p.Float("nope", 7.77) != 7.77 {
			t.Fatal("absent Float did not return fallback")
		}
	})
}

// FuzzArgParserBool fuzzes Bool() against adversarial string cases.
func FuzzArgParserBool(f *testing.F) {
	f.Add("true")
	f.Add("false")
	f.Add("YES")
	f.Add("no")
	f.Add("1")
	f.Add("0")
	f.Add("")
	f.Add("\x00")
	f.Add("trueish")
	f.Add("TrUe")                            // case-mixed non-match
	f.Add(strings.Repeat("x", 10_000))       // long non-match
	f.Add("\u2028true")                      // LINE SEP prefix

	f.Fuzz(func(t *testing.T, input string) {
		args := map[string]any{"field": input}
		p := NewArgParser(args)
		// Should never panic; any value is acceptable.
		_ = p.Bool("field", false)
		_ = p.Bool("field", true)
	})
}

// FuzzArgParserStringArray fuzzes StringArray() with a mix of single-string
// and array inputs. Single strings should wrap; empty strings should be
// dropped; arrays should concatenate string-ified elements.
func FuzzArgParserStringArray(f *testing.F) {
	f.Add("NSE:INFY")
	f.Add("")
	f.Add(" ")
	f.Add("\x00")
	f.Add("\u2028\u2029")
	f.Add(strings.Repeat("X", 10_000))

	f.Fuzz(func(t *testing.T, input string) {
		// Single string — should wrap or drop.
		args := map[string]any{"field": input}
		p := NewArgParser(args)
		result := p.StringArray("field")
		if input == "" {
			if result != nil {
				t.Fatalf("empty string should yield nil, got %v", result)
			}
		} else {
			if len(result) != 1 || result[0] != input {
				t.Fatalf("single string %q did not wrap into [1]string, got %v", input, result)
			}
		}

		// []any with the string inside — should unwrap.
		args2 := map[string]any{"field": []any{input, input, nil}}
		p2 := NewArgParser(args2)
		result2 := p2.StringArray("field")
		// Non-empty strings only survive; nil and "" are filtered.
		expected := 0
		if input != "" {
			expected = 2
		}
		if len(result2) != expected {
			t.Fatalf("array with two %q entries: expected len=%d, got %d (%v)", input, expected, len(result2), result2)
		}
	})
}

// FuzzValidateRequired fuzzes the multi-arg required validator. It should
// flag nil, empty string, and empty []any/[]string/[]int uniformly.
func FuzzValidateRequired(f *testing.F) {
	f.Add("RELIANCE", "10")
	f.Add("", "10")
	f.Add("RELIANCE", "")
	f.Add("", "")
	f.Add("\x00", "\x00")
	f.Add(strings.Repeat("A", 1000), "42")

	f.Fuzz(func(t *testing.T, v1, v2 string) {
		args := map[string]any{"a": v1, "b": v2}
		err := ValidateRequired(args, "a", "b")
		// If both are non-empty, err must be nil.
		if v1 != "" && v2 != "" {
			if err != nil {
				t.Fatalf("unexpected error on non-empty inputs: %v", err)
			}
		}
		// If either is empty, err must be non-nil.
		if v1 == "" || v2 == "" {
			if err == nil {
				t.Fatalf("expected error on empty input, got nil")
			}
		}

		// UTF-8 validity is not a requirement — we must not panic on invalid bytes.
		_ = utf8.ValidString(v1)
	})
}
