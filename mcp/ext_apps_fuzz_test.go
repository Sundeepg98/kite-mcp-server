package mcp

import (
	"encoding/json"
	"strings"
	"testing"
)

// These fuzz harnesses exercise injectData, the function that splices
// user-controlled JSON into widget HTML. Any XSS breakout here compromises
// every MCP App widget. We enforce four invariants on the *injected data*
// (not the surrounding template, which legitimately contains </script>):
//
//  1. The injected data must never contain a literal "</script>" — that
//     would let attacker data close the opening <script> tag early.
//  2. The injected data must never contain a literal U+2028 / U+2029 byte
//     — JS string literals terminate on those, letting attacker data
//     escape the JSON string and execute as script.
//  3. The injected data must never contain a literal "<!--" — some HTML
//     parsers treat it specially inside <script>.
//  4. The placeholder "__INJECTED_DATA__" must be replaced (not left literal).
//
// The test template is structured so the first line-break after
// dataPlaceholder marks the end of the injected region. We extract that
// region before running substring checks so the closing "</script>" in the
// template footer is not mistaken for a breakout.
//
// Run:
//   go test ./mcp/ -run=^$ -fuzz=FuzzInjectDataString -fuzztime=30s
//   go test ./mcp/ -run=^$ -fuzz=FuzzInjectDataJSON   -fuzztime=30s

// Split-marker template: everything before BEGIN and after END is template
// boilerplate (may contain </script>). Everything between is the injected
// payload and must be XSS-safe.
const injectTestTemplate = `<html><body><script>/*BEGIN*/window.__DATA__="__INJECTED_DATA__"/*END*/</script></body></html>`

// extractInjected returns the substring between /*BEGIN*/ and /*END*/ — i.e.
// the attacker-controlled region. Returns "" if the markers aren't present
// (which indicates injectData silently destroyed the template, itself a bug).
func extractInjected(out string) string {
	const begin = "/*BEGIN*/"
	const end = "/*END*/"
	bi := strings.Index(out, begin)
	ei := strings.Index(out, end)
	if bi < 0 || ei < 0 || ei <= bi {
		return ""
	}
	return out[bi+len(begin) : ei]
}

// assertNoScriptBreakout checks all invariants on the injected output.
func assertNoScriptBreakout(t *testing.T, out, input string) {
	t.Helper()

	region := extractInjected(out)
	if region == "" {
		t.Fatalf("template markers missing in output; injectData destroyed template\nout=%q", out)
	}

	// Invariant 1: no literal </script> in the injected region.
	if strings.Contains(region, "</script>") {
		t.Fatalf("XSS breakout: </script> present in injected region for input %q\nregion=%q", input, region)
	}

	// Invariant 2: no raw U+2028 / U+2029 in the injected region.
	if strings.ContainsRune(region, '\u2028') {
		t.Fatalf("XSS breakout: raw U+2028 present in injected region for input %q\nregion=%q", input, region)
	}
	if strings.ContainsRune(region, '\u2029') {
		t.Fatalf("XSS breakout: raw U+2029 present in injected region for input %q\nregion=%q", input, region)
	}

	// Invariant 3: no literal <!-- in the injected region.
	if strings.Contains(region, "<!--") {
		t.Fatalf("XSS breakout: literal <!-- present in injected region for input %q\nregion=%q", input, region)
	}

	// Invariant 4: placeholder must be consumed (never left literal anywhere).
	if strings.Contains(out, `"__INJECTED_DATA__"`) {
		t.Fatalf("placeholder not replaced for input %q\nout=%q", input, out)
	}
}

// FuzzInjectDataString treats the input as the value of a JSON string and
// injects it. No matter what bytes the input has, the output must be
// XSS-safe in a <script> tag context.
func FuzzInjectDataString(f *testing.F) {
	// Benign seeds.
	f.Add("hello")
	f.Add("")
	f.Add("NSE:INFY")
	f.Add("{\"not\": \"actual json, just a string\"}")

	// Adversarial seeds — each is a known XSS primitive.
	f.Add("</script><script>alert(1)</script>")
	f.Add("\u2028alert(1)//")
	f.Add("\u2029alert(1)//")
	f.Add("<!--<script>alert(1)</script>-->")
	f.Add("\"+alert(1)+\"")
	f.Add("';alert(1);//")
	f.Add("\x00\x01\x02\x03\x04\x05")
	f.Add("\xff\xfe\xfd")
	f.Add(strings.Repeat("A", 100_000))
	// Mixed escapes.
	f.Add("</script\u2028>")
	f.Add("<!--\u2029-->")

	f.Fuzz(func(t *testing.T, input string) {
		// Feed the raw string as the data.
		out := injectData(injectTestTemplate, input)
		assertNoScriptBreakout(t, out, input)

		// Also feed it as a nested field inside a map.
		out2 := injectData(injectTestTemplate, map[string]any{"symbol": input, "nested": map[string]any{"x": input}})
		assertNoScriptBreakout(t, out2, input)

		// Output must always be valid Go string (length reasonable, no crash).
		if len(out) == 0 {
			t.Fatal("empty output is never valid")
		}
	})
}

// FuzzInjectDataJSON fuzzes with inputs that, if interpreted as JSON,
// would stress the marshaler: arrays, deeply nested maps, giant strings,
// weird number types.
func FuzzInjectDataJSON(f *testing.F) {
	// Seed as raw JSON payloads.
	f.Add(`{}`)
	f.Add(`null`)
	f.Add(`[]`)
	f.Add(`{"a":"b"}`)
	f.Add(`{"nested":{"a":{"b":{"c":{"d":"deep"}}}}}`)
	f.Add(`[1,2,3,"\u2028","</script>","<!--"]`)
	f.Add(`{"xss":"</script><script>alert(1)</script>"}`)
	f.Add(`{"sep":"\u2028\u2029"}`)
	f.Add(`{"unicode":"\u0000\u0001"}`)
	f.Add(strings.Repeat("A", 50_000))

	f.Fuzz(func(t *testing.T, rawJSON string) {
		// Attempt to parse as JSON. If it parses, inject the parsed value;
		// otherwise inject the raw string (which tests the fallback-to-null
		// path inside injectData when Marshal fails).
		var parsed any
		if err := json.Unmarshal([]byte(rawJSON), &parsed); err != nil {
			// Not valid JSON — inject as a string value.
			out := injectData(injectTestTemplate, rawJSON)
			assertNoScriptBreakout(t, out, rawJSON)
			return
		}

		out := injectData(injectTestTemplate, parsed)
		assertNoScriptBreakout(t, out, rawJSON)
	})
}

// FuzzInjectDataHTML fuzzes with arbitrary HTML templates to ensure the
// placeholder is correctly found (not accidentally matched twice or inside
// attacker-controlled template bytes).
func FuzzInjectDataHTML(f *testing.F) {
	f.Add(injectTestTemplate)
	f.Add(`<script>"__INJECTED_DATA__"</script>`)
	f.Add(`<!-- no placeholder here --><script></script>`)
	f.Add(``)
	f.Add(`"__INJECTED_DATA__" "__INJECTED_DATA__"`) // two placeholders — only first replaced

	f.Fuzz(func(t *testing.T, htmlTemplate string) {
		out := injectData(htmlTemplate, map[string]any{"x": 1})

		// If template contained no placeholder, output equals template.
		if !strings.Contains(htmlTemplate, `"__INJECTED_DATA__"`) {
			if out != htmlTemplate {
				t.Fatalf("template without placeholder was modified\nin=%q\nout=%q", htmlTemplate, out)
			}
			return
		}

		// If template contained exactly one placeholder, output must no
		// longer contain it (strings.Replace with n=1 consumed it).
		if strings.Count(htmlTemplate, `"__INJECTED_DATA__"`) == 1 {
			if strings.Contains(out, `"__INJECTED_DATA__"`) {
				t.Fatalf("single placeholder not replaced\nin=%q\nout=%q", htmlTemplate, out)
			}
		}
	})
}
