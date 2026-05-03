// cmd/event-graph renders the domain event-flow diagram from the
// canonical CanonicalPersisterSubscriptions slice in app/providers.
// Output is Mermaid-compatible markdown and is checked in at
// docs/event-flow.md as the CQRS "domain-event-flow visualization"
// rubric deliverable.
//
// Wave D Phase 2 follow-up — closes CQRS dim 97 → 98 (per
// .research/post-wave-d-skipped-items-reeval.md item 9, commit
// a66d807). Free side benefit of P2.4f's data-driven subscription
// list: the diagram emerges by walking that slice rather than
// hand-maintaining it.
//
// Usage:
//
//	go run ./cmd/event-graph                # write to docs/event-flow.md
//	go run ./cmd/event-graph -o -           # write to stdout
//	go run ./cmd/event-graph -o /tmp/x.md   # write to a custom path
//
// Regeneration via test (preferred for CI):
//
//	go test ./cmd/event-graph -update       # regenerates docs/event-flow.md
//
// The snapshot test (TestEventFlow_MatchesSnapshot) fails CI on any
// CanonicalPersisterSubscriptions change that hasn't been mirrored
// into docs/event-flow.md, forcing every event-type addition or
// removal to land alongside a doc refresh.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/zerodha/kite-mcp-server/app/providers"
)

func main() {
	out := flag.String("o", "docs/event-flow.md", "output path, or '-' for stdout")
	flag.Parse()

	w, closer, err := openWriter(*out)
	if err != nil {
		log.Fatalf("open writer: %v", err)
	}
	defer closer()

	if err := renderEventFlow(w); err != nil {
		log.Fatalf("render: %v", err)
	}
}

// openWriter resolves the -o flag value to an io.Writer. Returns a
// no-op closer for stdout; for file paths, returns a closer that
// flushes + closes.
func openWriter(path string) (io.Writer, func(), error) {
	if path == "-" {
		return os.Stdout, func() {}, nil
	}
	// #nosec G304 -- path is a CLI -o flag from a developer running the event-graph binary, not request input.
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { _ = f.Close() }, nil
}

// canonicalSubs returns the static subscription list. Indirected
// through this helper so the test can assert "every event in the
// list appears in the output" without re-importing the providers
// package's exported variable directly (keeps the test's intent
// explicit: the data-source is canonical, not a private mock).
func canonicalSubs() []providers.EventStorePersister {
	return providers.CanonicalPersisterSubscriptions
}

// renderEventFlow writes the Mermaid-formatted event-flow diagram
// to w. The output is a complete markdown document with a header,
// rationale paragraph, and a fenced ```mermaid block containing a
// flowchart-LR graph of EventType -> AggregateType edges.
//
// AggregateType nodes are merged (multiple events sharing the same
// aggregate type emit a fan-in pattern), making the diagram readable
// even at 36 entries. Sorting:
//   - EventTypes preserve canonical order (matches dispatch ordering)
//   - AggregateType nodes are listed once, alphabetically
//
// Returns any io.Writer error from w.Write.
func renderEventFlow(w io.Writer) error {
	subs := canonicalSubs()

	// Collect unique aggregate types alphabetically for stable
	// node-declaration ordering. Mermaid auto-deduplicates node IDs
	// but explicit declaration with a deterministic order keeps the
	// rendered SVG layout reproducible across re-renders.
	aggSet := make(map[string]struct{}, len(subs))
	for _, s := range subs {
		aggSet[s.AggregateType] = struct{}{}
	}
	aggList := make([]string, 0, len(aggSet))
	for a := range aggSet {
		aggList = append(aggList, a)
	}
	sort.Strings(aggList)

	var b strings.Builder
	b.WriteString("# Domain Event Flow\n\n")
	b.WriteString("Auto-generated from `app/providers.CanonicalPersisterSubscriptions` (Wave D Phase 2 Slice P2.4f).\n")
	b.WriteString("Run `go test ./cmd/event-graph -update` to regenerate after adding/removing subscriptions.\n\n")
	b.WriteString(fmt.Sprintf("**%d events** persist via the dispatcher → audit-log path; ", len(subs)))
	b.WriteString(fmt.Sprintf("they fan into **%d aggregate streams** for projector queries.\n\n", len(aggList)))
	b.WriteString("```mermaid\n")
	b.WriteString("flowchart LR\n")

	// Aggregate-type nodes — emitted first so the layout engine
	// sees the right-side targets before any edges land.
	for _, a := range aggList {
		fmt.Fprintf(&b, "    %s[%q]\n", aggNodeID(a), a)
	}
	b.WriteString("\n")

	// Event-type → aggregate-type edges, in canonical order.
	for _, s := range subs {
		fmt.Fprintf(&b, "    %q --> %s\n", s.EventType, aggNodeID(s.AggregateType))
	}

	b.WriteString("```\n")
	_, err := io.WriteString(w, b.String())
	return err
}

// aggNodeID converts an aggregate-type string into a Mermaid-safe
// node identifier (Mermaid allows alphanumeric + underscore in
// auto-IDs; we lowercase and strip nothing because the canonical
// list uses CamelCase identifiers like "Order" and "RiskguardCounters"
// that are already safe). Keeps the function pure for testability
// even though current inputs are all alphanumeric.
func aggNodeID(s string) string {
	return "agg_" + s
}
