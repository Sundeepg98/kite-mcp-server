#!/usr/bin/env bash
set -euo pipefail
SCRATCH=/tmp/algo2go-clockport-bootstrap

rm -rf "$SCRATCH"
mkdir -p "$SCRATCH"
cd "$SCRATCH"

git init -q -b master
git config user.email "69564967+Sundeepg98@users.noreply.github.com"
git config user.name "Sundeep"

# ---------------------------------------------------------------------
# clock.go — port + RealClock implementation. Verbatim copy of the
# production port portion of testutil/clock.go (lines 22-71 of the
# original) with package rename, expanded docstring, and the
# production-only zero-deps invariant assertion kept.
# ---------------------------------------------------------------------
cat > clock.go <<'CLOCK_EOF'
// Package clockport provides a minimal time-source port that production
// code can depend on without coupling to wall-clock behavior. The matching
// in-memory test fakes (FakeClock) live in
// github.com/zerodha/kite-mcp-server/testutil — a deliberate split: the
// production interface stays infrastructure-clean (zero algo2go deps,
// pure stdlib), while the test fakes stay where Go conventions expect
// them (a testutil package adjacent to the consumer's tests).
//
// Architectural rationale:
// Production reverse-deps that previously imported testutil just to reach
// `testutil.Clock`/`testutil.Ticker`/`testutil.RealClock{}` (e.g.,
// kc/fill_watcher.go in the kite-mcp-server reference consumer) now
// import this module instead. testutil retains FakeClock + fakeTicker +
// NewFakeClock (genuinely test-only). The split eliminates the
// "test helpers used in production paths" misnomer.
//
// What this port does NOT help with:
//   - Sleeps that wait for external I/O (TCP bind, HTTP server readiness,
//     SQLite worker drain). A fake clock cannot make the OS bind faster;
//     those sleeps stay and belong to integration-test scope.
//   - Time-based business rules expressed in the domain layer (e.g.,
//     order expiry windows, market-hours gates). Those should be wrapped
//     by their own domain-level abstractions if they need fake-clock
//     coverage.
package clockport

import (
	"sync"
	"time"
)

// Clock is the minimal time-source port. The two methods we need today
// are Now (wall time) and NewTicker (a channel that fires at intervals).
// Callers who also need Sleep can layer it on top of NewTicker + receive.
type Clock interface {
	// Now returns the current time as perceived by this clock.
	Now() time.Time
	// NewTicker returns a Ticker that fires at the given interval. Stop
	// must be called by the caller to release resources.
	NewTicker(d time.Duration) Ticker
}

// Ticker abstracts the tick channel + Stop pair. The real implementation
// wraps *time.Ticker; fake implementations (e.g.,
// github.com/zerodha/kite-mcp-server/testutil.FakeClock's fakeTicker)
// deliver ticks when their Advance method crosses the interval boundary.
type Ticker interface {
	// C returns the channel on which ticks are delivered.
	C() <-chan time.Time
	// Stop stops the ticker. It is safe to call multiple times.
	Stop()
}

// ---------------------------------------------------------------------
// Real implementation — thin wrapper around the stdlib time package.
// ---------------------------------------------------------------------

// RealClock is the production clock. Zero-value is ready to use; no
// constructor needed.
type RealClock struct{}

// Now returns time.Now().
func (RealClock) Now() time.Time { return time.Now() }

// NewTicker returns a real time.Ticker wrapped to satisfy the Ticker
// interface.
func (RealClock) NewTicker(d time.Duration) Ticker {
	return &realTicker{t: time.NewTicker(d)}
}

type realTicker struct {
	t    *time.Ticker
	once sync.Once
}

func (r *realTicker) C() <-chan time.Time { return r.t.C }
func (r *realTicker) Stop()               { r.once.Do(r.t.Stop) }
CLOCK_EOF

# ---------------------------------------------------------------------
# clock_test.go — RealClock tests + interface compatibility assertion
# (the FakeClock half of clock_test.go remains in testutil).
# ---------------------------------------------------------------------
cat > clock_test.go <<'CLOCK_TEST_EOF'
package clockport

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Real implementation tests live alongside the port. FakeClock tests
// remain in github.com/zerodha/kite-mcp-server/testutil/clock_test.go
// where the fake implementation lives.

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
	tk.Stop()
	tk.Stop() // must not panic on second call
	require.NotNil(t, tk)
}

// Compile-time assertion: RealClock implements Clock.
var _ Clock = RealClock{}
CLOCK_TEST_EOF

# ---------------------------------------------------------------------
# go.mod — single dep on stretchr/testify (test-only)
# ---------------------------------------------------------------------
cat > go.mod <<'GOMOD_EOF'
module github.com/algo2go/kite-mcp-clockport

go 1.25.0

require github.com/stretchr/testify v1.10.0

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
GOMOD_EOF

# Run go mod tidy to produce go.sum
/usr/local/go/bin/go mod tidy 2>&1 | tail -3

# ---------------------------------------------------------------------
# Bootstrap files: LICENSE, CODEOWNERS, .gitignore, README
# ---------------------------------------------------------------------
cat > LICENSE <<'LICENSE_EOF'
MIT License

Copyright (c) 2025 Zerodha Tech (original Clock + Ticker port design —
                                  pure stdlib leaf hosting the time-
                                  source abstraction with RealClock
                                  zero-value default; original location
                                  was testutil/clock.go in
                                  Sundeepg98/kite-mcp-server)
Copyright (c) 2026 algo2go contributors (extraction, packaging,
                                  port-fakes split)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
LICENSE_EOF

mkdir -p .github
echo '* @Sundeepg98' > .github/CODEOWNERS

cat > .gitignore <<'GITIGNORE_EOF'
*.exe
*.dll
*.so
*.dylib
*.bin
*.test
*.prof
coverage.out
coverage.html
*.cov
*.tmp
*.log
.DS_Store
Thumbs.db
.vscode/
.idea/
*.swp
*.swo
*~
vendor/
.env
.env.local
GITIGNORE_EOF

cat > README.md <<'README_EOF'
# kite-mcp-clockport

[![Go Reference](https://pkg.go.dev/badge/github.com/algo2go/kite-mcp-clockport.svg)](https://pkg.go.dev/github.com/algo2go/kite-mcp-clockport)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Clock + Ticker port interfaces for the algo2go ecosystem. Pure stdlib
leaf hosting the time-source abstraction with `RealClock` zero-value
default. Production code that needs to be testable without wall-clock
waits imports this module; in-memory test fakes (`FakeClock`,
`fakeTicker`, `NewFakeClock`) live in
[`Sundeepg98/kite-mcp-server`'s testutil package](https://github.com/Sundeepg98/kite-mcp-server/tree/master/testutil)
because they are genuinely test-only.

## Why a separate module?

The original port + RealClock + FakeClock all lived in
`testutil/clock.go` — but production reverse-deps (e.g.,
kc/fill_watcher.go) had to import `testutil` just to reach the port,
inverting the typical "test helpers, never imported by production"
naming. This module separates the production-clean port from the
test-only fakes:

- **Centralizes** the Clock + Ticker contract for any algo2go consumer
  needing a testable time abstraction
- **Eliminates** the "production imports testutil" misnomer in
  consumer codebases
- **Keeps** the test fakes adjacent to consumer tests (testutil) where
  Go conventions expect them

## Stability promise

**v0.x — unstable.** Pin `v0.1.0` deliberately.

## Install

```bash
go get github.com/algo2go/kite-mcp-clockport@v0.1.0
```

## Public API

```go
type Clock interface {
    Now() time.Time
    NewTicker(d time.Duration) Ticker
}

type Ticker interface {
    C() <-chan time.Time
    Stop()
}

type RealClock struct{}    // zero-value default; production
```

`RealClock{}` returns `time.Now()` and wraps `time.NewTicker`. In tests,
swap it for any structurally-compatible fake — e.g.,
`testutil.NewFakeClock(t)` from
[Sundeepg98/kite-mcp-server's testutil package](https://github.com/Sundeepg98/kite-mcp-server/tree/master/testutil).

## What this port does NOT help with

- Sleeps waiting for external I/O (TCP bind, HTTP server readiness,
  SQLite worker drain). A fake clock cannot speed up the OS bind;
  those sleeps belong to integration-test scope.
- Time-based business rules in the domain layer (order expiry,
  market-hours gates). Those should wrap their own domain-level
  abstractions if they need fake-clock coverage.

## Dependencies

- **NONE** at runtime (pure stdlib `sync` + `time`)
- `github.com/stretchr/testify` v1.10.0 (test-only)

Joins `kite-mcp-sectors` and `kite-mcp-isttz` as the third zero-deps
algo2go module.

## Reference consumer

[`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
— consumed in `kc/fill_watcher.go` (production: real-flow bridge for
`domain.OrderFilledEvent` polling) and `app/ratelimit_cleanup_test.go`
(test adapter for rate-limiter cleanup goroutine driving). The matching
`testutil.FakeClock` lives at
`Sundeepg98/kite-mcp-server/testutil/clock.go` and structurally
satisfies `clockport.Clock` via Go duck typing.

## License

MIT — see [LICENSE](LICENSE).

## Authors

Original port design: [Sundeepg98](https://github.com/Sundeepg98)
(Zerodha Tech), originally located in `testutil/clock.go`. Multi-module
promotion (2026-05-10): algo2go contributors.

## Path A inauguration arc

This is the **28th algo2go module**. The Path A.1-A.26 arc closed at
27 modules with kc/sectors A.26 (the final extractable kc/* module).
Path A.27 extends the arc by 1 to address the testutil-misnaming
problem properly: the production port is now external, separate from
the test fakes.

The matching halt findings (which led to this module) are documented
in `.research/testutil-clock-port-split-design.md` in the reference
consumer's repo (commit fa6c70a in Sundeepg98/kite-mcp-server).
README_EOF

# ---------------------------------------------------------------------
# Initial commit
# ---------------------------------------------------------------------
git add LICENSE .github/CODEOWNERS .gitignore README.md go.mod go.sum clock.go clock_test.go
git status --short | head
git commit -m "chore: initial release — Clock + Ticker port interfaces (Path A.27)

Initial release of github.com/algo2go/kite-mcp-clockport, the 28th
algo2go module. Pure stdlib leaf hosting the production Clock +
Ticker port interfaces with RealClock zero-value default.

Original location: testutil/clock.go in Sundeepg98/kite-mcp-server
(lines 22-71 of the original file plus 3 RealClock tests from
testutil/clock_test.go lines 12-41). The matching test fakes
(FakeClock + fakeTicker + NewFakeClock) remain in
Sundeepg98/kite-mcp-server's testutil package because they are
genuinely test-only.

Architectural rationale:
  - Production reverse-deps (kc/fill_watcher.go) previously had to
    import testutil just to reach the port interface, inverting
    the typical 'test helpers, never imported by production'
    naming.
  - This module separates the production-clean port (zero algo2go
    deps, pure stdlib) from the test fakes (FakeClock stays in
    testutil where Go conventions expect them).
  - Eliminates the testutil-misnaming problem fundamentally.

Joins kite-mcp-sectors and kite-mcp-isttz as the third zero-deps
algo2go module. Runtime deps: stdlib only (sync + time). Test deps:
stretchr/testify v1.10.0.

Empirical state at extraction:
  - 2 .go files (clock.go + clock_test.go); ~120 LOC total
  - Standalone build PASS; standalone tests PASS
  - 1 production reverse-dep in reference consumer
    (kc/fill_watcher.go) + 1 test-adapter reverse-dep
    (app/ratelimit_cleanup_test.go)

Halt findings that led to this module are documented in
Sundeepg98/kite-mcp-server commit fa6c70a:
.research/testutil-clock-port-split-design.md (Phase 1 design +
Phase 1A/1B execution attempt + import-cycle blocker at kc/ports
+ recovery options A/B/C; option B = this module).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"

# Verify standalone build
/usr/local/go/bin/go build ./... 2>&1 | tail -3
/usr/local/go/bin/go test -count=1 -timeout 30s ./... 2>&1 | tail -5

git log --oneline | head -5
