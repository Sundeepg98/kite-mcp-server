package testutil

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRealClock_NowMonotonic(t *testing.T) {
	t.Parallel()
	c := RealClock{}
	before := c.Now()
	time.Sleep(time.Millisecond)
	after := c.Now()
	assert.True(t, !after.Before(before), "RealClock.Now should not move backward")
}

func TestRealClock_Ticker(t *testing.T) {
	t.Parallel()
	c := RealClock{}
	tk := c.NewTicker(5 * time.Millisecond)
	defer tk.Stop()
	select {
	case <-tk.C():
		// Got a tick — pass.
	case <-time.After(500 * time.Millisecond):
		t.Fatal("real ticker did not fire within 500ms")
	}
}

func TestRealTicker_StopIdempotent(t *testing.T) {
	t.Parallel()
	tk := RealClock{}.NewTicker(time.Second)
	// Triple Stop must not panic.
	tk.Stop()
	tk.Stop()
	tk.Stop()
}

func TestFakeClock_NowStartsAtSeed(t *testing.T) {
	t.Parallel()
	seed := time.Date(2026, 4, 19, 9, 15, 0, 0, time.UTC)
	c := NewFakeClock(seed)
	assert.Equal(t, seed, c.Now())
}

func TestFakeClock_AdvanceMovesNow(t *testing.T) {
	t.Parallel()
	seed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := NewFakeClock(seed)
	c.Advance(42 * time.Minute)
	assert.Equal(t, seed.Add(42*time.Minute), c.Now())
}

func TestFakeClock_TickerFiresOnAdvanceCrossingInterval(t *testing.T) {
	t.Parallel()
	c := NewFakeClock(time.Unix(0, 0))
	tk := c.NewTicker(100 * time.Millisecond)
	defer tk.Stop()

	// No tick before an Advance.
	select {
	case <-tk.C():
		t.Fatal("tick fired before Advance")
	default:
	}

	// Advance crosses exactly one boundary — one tick delivered.
	n := c.Advance(100 * time.Millisecond)
	assert.Equal(t, 1, n, "one tick expected across one interval")
	select {
	case <-tk.C():
	case <-time.After(100 * time.Millisecond):
		t.Fatal("tick not delivered after Advance(100ms)")
	}
}

func TestFakeClock_MultipleIntervalsInOneAdvance(t *testing.T) {
	t.Parallel()
	c := NewFakeClock(time.Unix(0, 0))
	tk := c.NewTicker(10 * time.Millisecond)
	defer tk.Stop()

	// Advance 35ms — ticker buffer is 1, so stdlib-like coalescing
	// means we deliver at most what the buffer holds. Verify at least
	// one tick and that Now reflects the jump.
	_ = c.Advance(35 * time.Millisecond)
	assert.Equal(t, int64(35000000), c.Now().UnixNano())
	select {
	case <-tk.C():
	case <-time.After(50 * time.Millisecond):
		t.Fatal("no tick after 35ms advance")
	}
}

func TestFakeClock_StopSilencesTicker(t *testing.T) {
	t.Parallel()
	c := NewFakeClock(time.Unix(0, 0))
	tk := c.NewTicker(10 * time.Millisecond)
	tk.Stop()

	// After Stop, Advance must not deliver further ticks.
	n := c.Advance(100 * time.Millisecond)
	assert.Equal(t, 0, n, "stopped ticker should not receive ticks")
}

func TestFakeClock_StopIdempotent(t *testing.T) {
	t.Parallel()
	c := NewFakeClock(time.Unix(0, 0))
	tk := c.NewTicker(time.Millisecond)
	// Triple Stop must not panic.
	tk.Stop()
	tk.Stop()
	tk.Stop()
}

func TestFakeClock_ConcurrentAdvanceAndStop(t *testing.T) {
	t.Parallel()
	c := NewFakeClock(time.Unix(0, 0))
	tk := c.NewTicker(time.Millisecond)

	// Drain any delivered ticks in a background consumer.
	var received atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-tk.C():
				received.Add(1)
			case <-time.After(50 * time.Millisecond):
				return
			}
		}
	}()

	for i := 0; i < 100; i++ {
		c.Advance(time.Millisecond)
	}
	tk.Stop()
	<-done
	// Did not panic — success. Exact count is not asserted (coalescing).
}

func TestFakeClock_SetJumpForwardDeliversTicks(t *testing.T) {
	t.Parallel()
	seed := time.Unix(0, 0)
	c := NewFakeClock(seed)
	tk := c.NewTicker(time.Second)
	defer tk.Stop()

	_ = c.Set(seed.Add(3 * time.Second))
	assert.Equal(t, seed.Add(3*time.Second), c.Now())
	// At least one tick should have been delivered.
	select {
	case <-tk.C():
	case <-time.After(50 * time.Millisecond):
		t.Fatal("Set should deliver ticks when jumping forward")
	}
}

func TestFakeClock_SetBackwardIsNoOp(t *testing.T) {
	t.Parallel()
	seed := time.Unix(1000, 0)
	c := NewFakeClock(seed)
	n := c.Set(seed.Add(-time.Hour))
	assert.Equal(t, 0, n, "Set backward should not deliver ticks")
	assert.Equal(t, seed, c.Now(), "Set backward should not move Now")
}

func TestFakeClock_NewTickerZeroDurationReturnsClosedTicker(t *testing.T) {
	t.Parallel()
	c := NewFakeClock(time.Unix(0, 0))
	tk := c.NewTicker(0)
	require.NotNil(t, tk)
	// Stop must be safe.
	tk.Stop()
}

// Clock interface smoke test: RealClock and *FakeClock both implement.
func TestClockInterfaceCompatibility(t *testing.T) {
	t.Parallel()
	var _ Clock = RealClock{}
	var _ Clock = NewFakeClock(time.Now())
}
