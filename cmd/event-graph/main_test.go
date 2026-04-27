package main

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// updateSnapshot regenerates docs/event-flow.md from the current
// CanonicalPersisterSubscriptions slice. Pass `-update` to refresh
// the snapshot when a new Subscribe entry lands.
//
// Pattern matches Go's standard golden-file convention (see e.g.
// cmd/gofmt's testdata/*.golden). The flag lives at file scope so
// `go test ./cmd/event-graph -update` works without ceremony.
var updateSnapshot = flag.Bool("update", false, "regenerate docs/event-flow.md snapshot")

// snapshotPath is the relative path from this test file to the
// rendered Mermaid output checked into the repo as the CQRS
// "domain-event-flow visualization" rubric deliverable.
//
// docs/event-flow.md lives at the repo root's docs/ tree; from
// cmd/event-graph/ that's two levels up.
const snapshotPath = "../../docs/event-flow.md"

// TestEventFlow_MatchesSnapshot is the regression-protection
// contract for the event-flow visualization. Every Subscribe entry
// added to providers.CanonicalPersisterSubscriptions must either
// (a) update docs/event-flow.md (run `go test ./cmd/event-graph
// -update` to regenerate), or (b) be intentionally unsubscribed.
//
// Without this test, a new event-type addition would silently drop
// out of the diagram and the CQRS rubric criterion would regress.
func TestEventFlow_MatchesSnapshot(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := renderEventFlow(&buf); err != nil {
		t.Fatalf("renderEventFlow: %v", err)
	}
	got := buf.String()

	abs, err := filepath.Abs(snapshotPath)
	if err != nil {
		t.Fatalf("filepath.Abs: %v", err)
	}

	if *updateSnapshot {
		if err := os.WriteFile(abs, []byte(got), 0o644); err != nil {
			t.Fatalf("write snapshot: %v", err)
		}
		t.Logf("snapshot regenerated at %s (%d bytes)", abs, len(got))
		return
	}

	want, err := os.ReadFile(abs)
	if err != nil {
		t.Fatalf("read snapshot %s: %v (run `go test ./cmd/event-graph -update` to generate)", abs, err)
	}

	// Normalize line endings: docs/event-flow.md may be checked in
	// with CRLF on Windows hosts; renderer always emits LF. Compare
	// after stripping CR.
	wantStr := strings.ReplaceAll(string(want), "\r\n", "\n")
	if got != wantStr {
		t.Errorf("rendered output differs from snapshot.\n\nRun `go test ./cmd/event-graph -update` to regenerate.\n\n--- got (%d bytes) ---\n%s\n--- want (%d bytes) ---\n%s",
			len(got), got, len(wantStr), wantStr)
	}
}

// TestRenderEventFlow_ContainsAllEventTypes is the data-driven
// invariant test. Independent of the snapshot file: every
// EventType in CanonicalPersisterSubscriptions must appear in the
// rendered output. Catches the class of bug where the renderer
// silently skips entries (e.g. an off-by-one in a loop).
func TestRenderEventFlow_ContainsAllEventTypes(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := renderEventFlow(&buf); err != nil {
		t.Fatalf("renderEventFlow: %v", err)
	}
	got := buf.String()

	for _, sub := range canonicalSubs() {
		if !strings.Contains(got, sub.EventType) {
			t.Errorf("rendered output missing EventType %q", sub.EventType)
		}
		if !strings.Contains(got, sub.AggregateType) {
			t.Errorf("rendered output missing AggregateType %q", sub.AggregateType)
		}
	}
}
