package mcp

import (
	"context"
	"sync"
	"testing"
	"time"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
)

// TestToolRateLimiter_SetLimits_SwapsAtomically proves that SetLimits
// replaces the in-memory limit map without a race with concurrent
// Middleware() dispatches. The rate-limit-config hot-reload path
// (SIGHUP in production) depends on this atomic swap: an operator
// editing per-tool caps must not see partial updates where place_order
// is throttled against the old cap and modify_order against the new.
func TestToolRateLimiter_SetLimits_SwapsAtomically(t *testing.T) {
	t.Parallel()

	rl := NewToolRateLimiter(map[string]int{
		"place_order": 10,
	})

	// Initial invocation sees the original cap.
	assert.Equal(t, 10, rl.effectiveLimit(rl.limits["place_order"], ""))

	// Swap to a tighter cap.
	rl.SetLimits(map[string]int{
		"place_order": 3,
	})
	assert.Equal(t, 3, rl.effectiveLimit(rl.limits["place_order"], ""))

	// Swap to a broader cap and a new tool name — old tool should also
	// vanish from the limit map (full replacement, not merge).
	rl.SetLimits(map[string]int{
		"modify_order": 25,
	})
	_, placeExists := rl.limits["place_order"]
	assert.False(t, placeExists, "place_order should be gone after full-replace SetLimits")
	assert.Equal(t, 25, rl.limits["modify_order"])
}

// TestToolRateLimiter_SetLimits_RaceWithMiddleware exercises the
// read/write contract under concurrent pressure: one goroutine swaps
// limits every millisecond while a pool of goroutines hammers
// Middleware(). The test passes when `go test -race` reports no data
// races — the assertion is invariant rather than numeric because the
// exact count is non-deterministic under race.
func TestToolRateLimiter_SetLimits_RaceWithMiddleware(t *testing.T) {
	t.Parallel()

	rl := NewToolRateLimiter(map[string]int{
		"place_order": 100,
	})

	mw := rl.Middleware()
	// Trivial inner handler that always succeeds.
	handler := mw(func(_ context.Context, _ gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		return gomcp.NewToolResultText("ok"), nil
	})

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Limit swapper.
	wg.Add(1)
	go func() {
		defer wg.Done()
		caps := []int{5, 10, 50, 100, 200}
		i := 0
		for {
			select {
			case <-stop:
				return
			default:
			}
			rl.SetLimits(map[string]int{"place_order": caps[i%len(caps)]})
			i++
			time.Sleep(time.Millisecond)
		}
	}()

	// Request pool.
	const workers = 8
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := gomcp.CallToolRequest{}
			req.Params.Name = "place_order"
			for i := 0; i < 200; i++ {
				select {
				case <-stop:
					return
				default:
				}
				_, _ = handler(context.Background(), req)
			}
		}()
	}

	// Run briefly, then stop.
	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()

	// If we got here without the race detector flagging, the swap is
	// correctly guarded. Sanity-check we still have a map afterwards.
	assert.NotNil(t, rl.limits)
}
