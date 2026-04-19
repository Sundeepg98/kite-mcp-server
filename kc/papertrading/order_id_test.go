package papertrading

import (
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// order_id_test.go — contracts for the paper-trading order-ID generator.
//
// These tests pin the two invariants that let us remove the ~57
// `time.Sleep(time.Millisecond)` calls sprinkled across engine_edge,
// engine_integration, engine, and papertrading tests. Before this
// commit, order IDs were `fmt.Sprintf("PAPER_%d", time.Now().UnixNano())`
// and Windows' UnixNano resolution (100ns ticks) meant two successive
// PlaceOrder calls within the same tick collided on the primary key,
// so tests had to sleep 1ms between calls.
//
// After the atomic-counter redesign:
//   - IDs are monotonic (Add(1) on an atomic.Uint64)
//   - 10,000 successive calls from N goroutines all produce distinct IDs
//   - Format remains "PAPER_<decimal>" so DB schema + log parsers keep working

// TestPaperOrderID_UniqueAcrossRapidSuccession verifies that 1,000 calls to
// nextOrderID in tight succession return 1,000 distinct strings. This is
// the property the prior time.Now().UnixNano() impl FAILED under on
// Windows (100ns tick resolution), which is exactly why 57 test sites
// had a 1ms sleep around successive PlaceOrder calls.
func TestPaperOrderID_UniqueAcrossRapidSuccession(t *testing.T) {
	t.Parallel()
	seen := make(map[string]struct{}, 1000)
	for i := 0; i < 1000; i++ {
		id := nextOrderID()
		if id == "" {
			t.Fatalf("nextOrderID returned empty string at iteration %d", i)
		}
		if !strings.HasPrefix(id, "PAPER_") {
			t.Fatalf("nextOrderID returned %q; want PAPER_<digits>", id)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("collision at iteration %d: %q already seen", i, id)
		}
		seen[id] = struct{}{}
	}
	require.Len(t, seen, 1000, "all 1000 IDs must be distinct")
}

// TestPaperOrderID_UniqueAcrossGoroutines verifies atomicity: 10
// concurrent goroutines each allocating 1,000 IDs must all be distinct.
// Catches any future refactor that drops the atomic and reintroduces a
// race on the counter.
func TestPaperOrderID_UniqueAcrossGoroutines(t *testing.T) {
	t.Parallel()
	const workers = 10
	const perWorker = 1000

	var mu sync.Mutex
	seen := make(map[string]struct{}, workers*perWorker)
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			local := make([]string, 0, perWorker)
			for i := 0; i < perWorker; i++ {
				local = append(local, nextOrderID())
			}
			mu.Lock()
			for _, id := range local {
				if _, dup := seen[id]; dup {
					t.Errorf("cross-goroutine collision on %q", id)
				}
				seen[id] = struct{}{}
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	assert.Len(t, seen, workers*perWorker,
		"10 workers x 1000 IDs must all be distinct under concurrent allocation")
}

// TestPaperOrderID_FormatPreserved locks in the "PAPER_<decimal>" format
// so consumers that parse order IDs (log aggregation, SQL queries using
// LIKE 'PAPER_%', dashboard filters) do not break when the generator is
// refactored further.
func TestPaperOrderID_FormatPreserved(t *testing.T) {
	t.Parallel()
	id := nextOrderID()
	assert.True(t, strings.HasPrefix(id, "PAPER_"), "prefix must remain PAPER_")
	// Suffix must be all digits.
	suffix := strings.TrimPrefix(id, "PAPER_")
	assert.NotEmpty(t, suffix, "suffix must be non-empty")
	for i, r := range suffix {
		assert.True(t, r >= '0' && r <= '9',
			"suffix rune %d (%q) must be a digit in %q", i, r, id)
	}
}
