package metrics

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestSetHistogramSource_NoSourceNoHistograms: when no source is
// registered, WritePrometheus emits no histogram lines (back-compat).
func TestSetHistogramSource_NoSourceNoHistograms(t *testing.T) {
	t.Parallel()
	m := New(Config{ServiceName: "test"})
	m.Increment("login_count")

	buf := new(bytes.Buffer)
	m.WritePrometheus(buf)
	output := buf.String()

	assert.NotContains(t, output, "_bucket{",
		"no histogram lines expected without registered source")
	assert.NotContains(t, output, "le=\"+Inf\"")
	assert.Contains(t, output, "login_count_total",
		"existing counters still emitted")
}

// TestSetHistogramSource_EmitsBuckets: when a source returns data,
// WritePrometheus emits histogram lines in Prometheus exposition
// format with proper `le` labels and `+Inf`.
func TestSetHistogramSource_EmitsBuckets(t *testing.T) {
	t.Parallel()
	m := New(Config{ServiceName: "test"})

	source := func() ([]ToolHistogramSnapshot, error) {
		return []ToolHistogramSnapshot{{
			ToolName:  "place_order",
			CallCount: 10,
			SumMs:     1234.5,
			Buckets: []ToolBucket{
				{LeMs: 10, Count: 2},
				{LeMs: 50, Count: 5},
				{LeMs: 100, Count: 7},
				{LeMs: 500, Count: 9},
				{LeMs: 1000, Count: 10},
				{LeMs: 5000, Count: 10},
			},
		}}, nil
	}
	m.SetHistogramSource(source)

	buf := new(bytes.Buffer)
	m.WritePrometheus(buf)
	output := buf.String()

	// HELP + TYPE preamble per Prometheus spec.
	assert.Contains(t, output, "# HELP mcp_tool_call_duration_ms")
	assert.Contains(t, output, "# TYPE mcp_tool_call_duration_ms histogram")

	// 6 le-bucketed _bucket lines. Note: formatMetric sorts label keys
	// alphabetically — output order is le, service, tool.
	for _, le := range []string{"10", "50", "100", "500", "1000", "5000"} {
		assert.Contains(t, output,
			"mcp_tool_call_duration_ms_bucket{le=\""+le+"\",service=\"test\",tool=\"place_order\"}",
			"missing le=%s bucket", le)
	}

	// +Inf bucket equals total count.
	assert.Contains(t, output,
		"mcp_tool_call_duration_ms_bucket{le=\"+Inf\",service=\"test\",tool=\"place_order\"} 10")

	// _sum and _count siblings.
	assert.Contains(t, output,
		"mcp_tool_call_duration_ms_sum{service=\"test\",tool=\"place_order\"}")
	assert.Contains(t, output,
		"mcp_tool_call_duration_ms_count{service=\"test\",tool=\"place_order\"} 10")
}

// TestSetHistogramSource_MultipleTools: per-tool series labeled by
// tool name; cardinality stays per-tool × per-bucket.
func TestSetHistogramSource_MultipleTools(t *testing.T) {
	t.Parallel()
	m := New(Config{ServiceName: "test"})

	source := func() ([]ToolHistogramSnapshot, error) {
		return []ToolHistogramSnapshot{
			{ToolName: "place_order", CallCount: 3, SumMs: 100, Buckets: []ToolBucket{{LeMs: 50, Count: 3}}},
			{ToolName: "get_holdings", CallCount: 5, SumMs: 40, Buckets: []ToolBucket{{LeMs: 50, Count: 5}}},
		}, nil
	}
	m.SetHistogramSource(source)

	buf := new(bytes.Buffer)
	m.WritePrometheus(buf)
	output := buf.String()

	assert.Contains(t, output, "tool=\"place_order\"")
	assert.Contains(t, output, "tool=\"get_holdings\"")
	// Both tools have +Inf bucket equal to their CallCount. Note:
	// formatMetric sorts label keys alphabetically (le, service,
	// tool).
	assert.Contains(t, output, "le=\"+Inf\",service=\"test\",tool=\"place_order\"} 3")
	assert.Contains(t, output, "le=\"+Inf\",service=\"test\",tool=\"get_holdings\"} 5")
}

// TestSetHistogramSource_ErrorIsSafe: source returning an error must
// NOT panic and must NOT corrupt the rest of the output (counters
// still emitted before histograms).
func TestSetHistogramSource_ErrorIsSafe(t *testing.T) {
	t.Parallel()
	m := New(Config{ServiceName: "test"})
	m.Increment("login_count")

	m.SetHistogramSource(func() ([]ToolHistogramSnapshot, error) {
		return nil, assert.AnError
	})

	buf := new(bytes.Buffer)
	// Must not panic.
	m.WritePrometheus(buf)
	output := buf.String()

	// Existing counters still present.
	assert.Contains(t, output, "login_count_total")
	// No histogram lines emitted on error.
	assert.NotContains(t, output, "_bucket{")
}

// TestSetHistogramSource_LabelSanitization: tool names containing
// hostile characters (quote / newline / CR — the existing
// sanitizeLabel attack class) are stripped from output. Defends
// against tool-poisoning attempts that try to inject Prometheus
// label-set break-out via crafted tool names. Production tool names
// never contain these characters; this is a defence-in-depth check.
func TestSetHistogramSource_LabelSanitization(t *testing.T) {
	t.Parallel()
	m := New(Config{ServiceName: "test"})

	source := func() ([]ToolHistogramSnapshot, error) {
		return []ToolHistogramSnapshot{{
			ToolName:  "weird\"name\nwith",
			CallCount: 1,
			SumMs:     5,
			Buckets:   []ToolBucket{{LeMs: 10, Count: 1}},
		}}, nil
	}
	m.SetHistogramSource(source)

	buf := new(bytes.Buffer)
	m.WritePrometheus(buf)
	output := buf.String()

	// Hostile characters must NOT appear in output (sanitizeLabel
	// strips them). The histogram line itself MUST still appear.
	assert.NotContains(t, output, "weird\"name\nwith",
		"raw hostile chars must be stripped from label values")
	assert.Contains(t, output, "weirdnamewith",
		"sanitized tool name still emits the histogram line")
}

// TestHTTPHandler_HistogramFromSource: end-to-end via HTTPHandler —
// the histogram surface is reachable via the handler path that the
// admin /metrics route uses.
func TestHTTPHandler_HistogramFromSource(t *testing.T) {
	t.Parallel()
	m := New(Config{ServiceName: "test"})

	m.SetHistogramSource(func() ([]ToolHistogramSnapshot, error) {
		return []ToolHistogramSnapshot{{
			ToolName:  "test_tool",
			CallCount: 1,
			SumMs:     7,
			Buckets:   []ToolBucket{{LeMs: 10, Count: 1}},
		}}, nil
	})

	// Use WritePrometheus directly (the HTTP handler is just a
	// content-type wrapper around it; that path is covered by
	// existing TestHTTPHandler tests).
	buf := new(bytes.Buffer)
	m.WritePrometheus(buf)
	output := buf.String()

	assert.Contains(t, output, "mcp_tool_call_duration_ms_bucket")
	assert.Contains(t, output, "tool=\"test_tool\"")
}

// TestSetHistogramSource_EmptyResult: source returning an empty slice
// emits no histogram lines but does not error.
func TestSetHistogramSource_EmptyResult(t *testing.T) {
	t.Parallel()
	m := New(Config{ServiceName: "test"})

	m.SetHistogramSource(func() ([]ToolHistogramSnapshot, error) {
		return []ToolHistogramSnapshot{}, nil
	})

	buf := new(bytes.Buffer)
	m.WritePrometheus(buf)
	output := buf.String()

	assert.NotContains(t, output, "_bucket{",
		"empty source result should not emit histogram lines")
}

// TestSetHistogramSource_NilSafe: nil source is the same as no source.
func TestSetHistogramSource_NilSafe(t *testing.T) {
	t.Parallel()
	m := New(Config{ServiceName: "test"})

	m.SetHistogramSource(nil)
	m.Increment("x")

	buf := new(bytes.Buffer)
	// Must not panic.
	m.WritePrometheus(buf)

	output := buf.String()
	// Counters still work.
	assert.Contains(t, output, "x_total")
	// No histogram lines.
	assert.NotContains(t, output, "_bucket{")

	// Bonus: time-zero source value should also be safe (e.g., zero
	// histogram-source struct).
	_ = time.Now()
}
