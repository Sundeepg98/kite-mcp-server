package logger

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

// TestNewSlog_NilDefaults asserts NewSlog handles a nil *slog.Logger
// by falling back to slog.Default(). The contract is "always returns
// a usable Logger" — call sites must not have to nil-check.
func TestNewSlog_NilDefaults(t *testing.T) {
	t.Parallel()

	l := NewSlog(nil)
	if l == nil {
		t.Fatal("NewSlog(nil) returned nil; expected a fallback Logger")
	}

	// Must not panic when invoked.
	l.Info(context.Background(), "smoke")
}

// TestSlogAdapter_LevelRouting confirms that each Logger method emits
// at the matching slog level. We capture the JSON output of a
// slog.JSONHandler so the assertion is precise (level field present,
// msg matches).
func TestSlogAdapter_LevelRouting(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	h := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	l := NewSlog(slog.New(h))
	ctx := context.Background()

	cases := []struct {
		method func()
		level  string
		msg    string
	}{
		{func() { l.Debug(ctx, "dbg-msg") }, "DEBUG", "dbg-msg"},
		{func() { l.Info(ctx, "info-msg") }, "INFO", "info-msg"},
		{func() { l.Warn(ctx, "warn-msg") }, "WARN", "warn-msg"},
		{func() { l.Error(ctx, "err-msg", errors.New("boom")) }, "ERROR", "err-msg"},
	}
	for _, tc := range cases {
		buf.Reset()
		tc.method()
		out := buf.String()
		if !strings.Contains(out, `"level":"`+tc.level+`"`) {
			t.Errorf("expected level %q in output, got %q", tc.level, out)
		}
		if !strings.Contains(out, `"msg":"`+tc.msg+`"`) {
			t.Errorf("expected msg %q in output, got %q", tc.msg, out)
		}
	}
}

// TestSlogAdapter_ErrorAttachesError checks that the err parameter is
// emitted under the canonical "error" key, while a nil err is silently
// omitted (no fake "error":"<nil>" attribute).
func TestSlogAdapter_ErrorAttachesError(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	l := NewSlog(slog.New(slog.NewJSONHandler(&buf, nil)))

	l.Error(context.Background(), "with-err", errors.New("kaboom"))
	if !strings.Contains(buf.String(), `"error":"kaboom"`) {
		t.Errorf("expected error attribute, got %q", buf.String())
	}

	buf.Reset()
	l.Error(context.Background(), "no-err", nil)
	if strings.Contains(buf.String(), `"error":`) {
		t.Errorf("expected no error attribute when err==nil, got %q", buf.String())
	}
}

// TestSlogAdapter_With chains a With call and confirms the attached
// attribute shows up on every subsequent record from the child logger
// — and that the parent logger is unaffected.
func TestSlogAdapter_With(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	parent := NewSlog(slog.New(slog.NewJSONHandler(&buf, nil)))
	child := parent.With("request_id", "rid-42")

	buf.Reset()
	child.Info(context.Background(), "child-msg")
	if !strings.Contains(buf.String(), `"request_id":"rid-42"`) {
		t.Errorf("child output missing request_id: %q", buf.String())
	}

	buf.Reset()
	parent.Info(context.Background(), "parent-msg")
	if strings.Contains(buf.String(), "request_id") {
		t.Errorf("parent output should NOT carry child's With attrs: %q", buf.String())
	}
}

// TestSlogAdapter_LevelFiltering proves Debug records are dropped when
// the underlying handler is configured at LevelInfo. This exercises
// the Enabled fast-path inside slogAdapter.log.
func TestSlogAdapter_LevelFiltering(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	h := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	l := NewSlog(slog.New(h))

	l.Debug(context.Background(), "should-be-dropped")
	if buf.Len() != 0 {
		t.Errorf("debug message not filtered at LevelInfo: %q", buf.String())
	}

	l.Info(context.Background(), "should-pass")
	if !strings.Contains(buf.String(), "should-pass") {
		t.Errorf("info message wrongly filtered: %q", buf.String())
	}
}

// TestSlogAdapter_AsSlog_Bridge ensures AsSlog returns the underlying
// *slog.Logger for the slog adapter and nil for foreign Loggers.
// Critical for the incremental migration: code that needs to hand a
// slog.Logger to a third-party API can do so when the runtime
// implementation is the slog adapter, but is signalled (nil) to fall
// back to a discard logger when a noop / capture is in play.
func TestSlogAdapter_AsSlog_Bridge(t *testing.T) {
	t.Parallel()

	base := slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil))
	if got := AsSlog(NewSlog(base)); got != base {
		t.Errorf("AsSlog should return underlying *slog.Logger, got different pointer")
	}
	if got := AsSlog(NewNoop()); got != nil {
		t.Errorf("AsSlog should return nil for non-slog Logger, got %v", got)
	}
}

// TestNoop_DoesNotPanic verifies the noop logger handles every method
// with arbitrary args, including a nil context. The noop is hot-path
// in tests so this test specifically dispatches every method to catch
// any future regression where someone accidentally indexes the args
// slice.
func TestNoop_DoesNotPanic(t *testing.T) {
	t.Parallel()

	l := NewNoop()
	l.Debug(context.Background(), "x")
	l.Info(context.Background(), "x", "k", "v")
	l.Warn(context.Background(), "x")
	l.Error(context.Background(), "x", errors.New("nope"), "k", "v")
	l.Error(context.Background(), "x", nil)
	if child := l.With("k", "v"); child == nil {
		t.Fatal("noop With returned nil")
	}
}

// TestCapture_RecordsArgsAndLevels asserts CaptureLogger preserves
// every call's level, message, and args. Used by other packages'
// tests to verify "we logged this" assertions.
func TestCapture_RecordsArgsAndLevels(t *testing.T) {
	t.Parallel()

	c := NewCapture()
	ctx := context.Background()

	c.Debug(ctx, "d", "k1", 1)
	c.Info(ctx, "i", "k2", 2)
	c.Warn(ctx, "w", "k3", 3)
	c.Error(ctx, "e", errors.New("oops"), "k4", 4)

	got := c.Records()
	if len(got) != 4 {
		t.Fatalf("expected 4 records, got %d", len(got))
	}
	want := []struct {
		level string
		msg   string
	}{
		{"debug", "d"},
		{"info", "i"},
		{"warn", "w"},
		{"error", "e"},
	}
	for i, tc := range want {
		if got[i].Level != tc.level || got[i].Msg != tc.msg {
			t.Errorf("record %d: got (%s,%s) want (%s,%s)", i, got[i].Level, got[i].Msg, tc.level, tc.msg)
		}
	}

	// The error record should have "error" appended automatically.
	last := got[3].Args
	if len(last) != 4 {
		t.Fatalf("error record args length: got %d (%v) want 4", len(last), last)
	}
	if last[2] != errorKey {
		t.Errorf("expected canonical error key, got %v", last[2])
	}
}

// TestCapture_With_Prefixes confirms a child logger from With prefixes
// every record's Args with the With pairs, and that records flow to
// the same underlying buffer (so the parent observes children).
func TestCapture_With_Prefixes(t *testing.T) {
	t.Parallel()

	root := NewCapture()
	child := root.With("component", "billing")
	ctx := context.Background()

	root.Info(ctx, "from-root", "k", "v")
	child.Info(ctx, "from-child", "k", "v")

	records := root.Records()
	if len(records) != 2 {
		t.Fatalf("expected 2 records on root, got %d", len(records))
	}
	if got := records[1].Args; len(got) < 2 || got[0] != "component" || got[1] != "billing" {
		t.Errorf("child record missing prefix: %v", got)
	}
	if got := records[0].Args; len(got) >= 2 && got[0] == "component" {
		t.Errorf("root record should NOT carry child prefix: %v", got)
	}
}

// TestCapture_Concurrent guards the mutex around Records — the
// CaptureLogger is documented as concurrent-safe. Without the mutex,
// `go test -race` would flag this.
func TestCapture_Concurrent(t *testing.T) {
	t.Parallel()

	c := NewCapture()
	ctx := context.Background()

	const N = 100
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < N; i++ {
			c.Info(ctx, "a")
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < N; i++ {
			c.With("k", i).Info(ctx, "b")
		}
	}()
	wg.Wait()

	if got := len(c.Records()); got != 2*N {
		t.Errorf("got %d records, want %d", got, 2*N)
	}
}
