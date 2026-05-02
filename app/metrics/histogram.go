package metrics

import (
	"bytes"
	"fmt"
)

// ToolBucket is a single Prometheus-style cumulative bucket. Mirrors
// kc/audit.ToolHistogramBucket but lives in this package so the
// metrics surface does not import kc/audit (would invert the layer
// graph). The wire-up site (app/wire.go) bridges the two shapes via
// a small adapter closure.
type ToolBucket struct {
	LeMs  int64
	Count int
}

// ToolHistogramSnapshot is the histogram-source row for a single tool.
// CallCount equals the +Inf bucket; SumMs is the sum of all
// duration_ms values in the window. Buckets must be cumulative
// non-decreasing per Prometheus convention.
type ToolHistogramSnapshot struct {
	ToolName  string
	CallCount int
	SumMs     float64
	Buckets   []ToolBucket
}

// HistogramSource is invoked at scrape time to produce the per-tool
// latency histogram snapshots. Returning a non-nil error suppresses
// histogram emission for the scrape (counters and other metrics still
// emit). Nil source = no histograms emitted (back-compat default).
type HistogramSource func() ([]ToolHistogramSnapshot, error)

// SetHistogramSource registers (or replaces, or clears with nil) the
// histogram source. Safe to call concurrently with WritePrometheus —
// the source pointer is read once per scrape.
func (m *Manager) SetHistogramSource(src HistogramSource) {
	m.histMu.Lock()
	defer m.histMu.Unlock()
	m.histogramSource = src
}

// histogramSource returns the currently registered source under lock.
func (m *Manager) currentHistogramSource() HistogramSource {
	m.histMu.Lock()
	defer m.histMu.Unlock()
	return m.histogramSource
}

// writeToolHistograms emits Prometheus exposition-format histogram
// lines for every snapshot the source returns. No-op when source is
// nil or returns an error (the error is intentionally swallowed —
// observability-axis failures should never crowd genuine errors out
// of the operator's view, and a single bad scrape doesn't justify a
// 5xx).
//
// Output format per Prometheus convention:
//
//	# HELP mcp_tool_call_duration_ms tool call latency distribution
//	# TYPE mcp_tool_call_duration_ms histogram
//	mcp_tool_call_duration_ms_bucket{le="10",service="X",tool="Y"} N
//	mcp_tool_call_duration_ms_bucket{le="50",service="X",tool="Y"} N
//	... (one line per bucket, cumulative, ascending)
//	mcp_tool_call_duration_ms_bucket{le="+Inf",service="X",tool="Y"} TOTAL
//	mcp_tool_call_duration_ms_sum{service="X",tool="Y"} SUM_MS
//	mcp_tool_call_duration_ms_count{service="X",tool="Y"} TOTAL
func (m *Manager) writeToolHistograms(buf *bytes.Buffer) {
	src := m.currentHistogramSource()
	if src == nil {
		return
	}
	snaps, err := src()
	if err != nil || len(snaps) == 0 {
		return
	}

	// HELP + TYPE preamble per Prometheus spec. Emitted ONCE per
	// metric family (not per series).
	const metricName = "mcp_tool_call_duration_ms"
	fmt.Fprintf(buf, "# HELP %s Tool call latency distribution in milliseconds\n", metricName)
	fmt.Fprintf(buf, "# TYPE %s histogram\n", metricName)

	for _, snap := range snaps {
		base := map[string]string{"tool": snap.ToolName}
		// _bucket lines, ascending le.
		for _, b := range snap.Buckets {
			labels := cloneLabels(base)
			labels["le"] = fmt.Sprintf("%d", b.LeMs)
			m.formatMetric(buf, metricName+"_bucket", labels, float64(b.Count))
		}
		// +Inf bucket = total CallCount.
		infLabels := cloneLabels(base)
		infLabels["le"] = "+Inf"
		m.formatMetric(buf, metricName+"_bucket", infLabels, float64(snap.CallCount))
		// _sum and _count siblings (no le label).
		m.formatMetric(buf, metricName+"_sum", cloneLabels(base), snap.SumMs)
		m.formatMetric(buf, metricName+"_count", cloneLabels(base), float64(snap.CallCount))
	}
}

// cloneLabels returns a shallow copy so each formatMetric call gets
// its own labels map (formatMetric mutates with the service label).
func cloneLabels(in map[string]string) map[string]string {
	out := make(map[string]string, len(in)+1)
	for k, v := range in {
		out[k] = v
	}
	return out
}

