#!/usr/bin/env bash
set -euo pipefail
ROOT=/mnt/d/Sundeep/projects/kite-mcp-server
cd "$ROOT"
[ "$(git rev-parse --abbrev-ref HEAD)" != "master" ] && { echo "ERROR: not on master"; exit 1; }
echo "HEAD: $(git rev-parse HEAD)"

# Phase A.27 cutover: kc/fill_watcher.go production reverse-dep migrates
# from testutil.Clock/Ticker/RealClock to clockport.Clock/Ticker/RealClock.
# testutil/clock.go's production port section (lines 22-71 of original)
# is removed; FakeClock + fakeTicker remain (test-only) but their
# NewTicker return type changes from `Ticker` to `clockport.Ticker`.

# 1. kc/fill_watcher.go: import + 4 type/value uses
sed -i 's#"github.com/zerodha/kite-mcp-server/testutil"#"github.com/algo2go/kite-mcp-clockport"#' kc/fill_watcher.go
sed -i 's#testutil\.Clock#clockport.Clock#g' kc/fill_watcher.go
sed -i 's#testutil\.Ticker#clockport.Ticker#g' kc/fill_watcher.go
sed -i 's#testutil\.RealClock#clockport.RealClock#g' kc/fill_watcher.go

# 2. app/ratelimit_cleanup_test.go: import (add clockport) + 1 type
# Test file currently imports only testutil; needs to also import
# clockport for the fakeTickerAdapter type signature.
# We do this with a multi-line sed: add `clockport` import beneath testify.
# The single-word edit changes `testutil.Ticker` → `clockport.Ticker`
# in fakeTickerAdapter's struct field.
python3 - <<'PYEOF'
import re
p = "app/ratelimit_cleanup_test.go"
with open(p, encoding="utf-8") as f: s = f.read()
# Insert clockport import alphabetically before testutil
old_import = '\t"github.com/zerodha/kite-mcp-server/testutil"\n'
new_import = '\t"github.com/algo2go/kite-mcp-clockport"\n\t"github.com/zerodha/kite-mcp-server/testutil"\n'
if old_import in s and '"github.com/algo2go/kite-mcp-clockport"' not in s:
    s = s.replace(old_import, new_import, 1)
# Update field type
s = s.replace("t testutil.Ticker", "t clockport.Ticker")
# Update doc comments to reflect new module
s = s.replace("testutil.Clock (testutil.Ticker)", "clockport.Clock (clockport.Ticker)")
s = s.replace("`testutil.Clock`'s", "`clockport.Clock`'s")
s = s.replace("returns `testutil.Ticker`", "returns `clockport.Ticker`")
with open(p, "w", encoding="utf-8") as f: f.write(s)
print("ratelimit_cleanup_test.go: import + type updated")
PYEOF

# 3. testutil/clock.go: delete production port + add clockport import +
# update FakeClock.NewTicker return type
python3 - <<'PYEOF'
import re
p = "testutil/clock.go"
with open(p, encoding="utf-8") as f: s = f.read()

# Replace the entire pre-FakeClock section (package doc + imports +
# Clock/Ticker interfaces + RealClock + realTicker) with a slimmer
# version that imports clockport and only narrates the test-fake role.
new_header = '''// Package testutil hosts in-memory test fakes for the production ports
// defined in github.com/algo2go/kite-mcp-clockport. Production code does
// NOT import testutil; only _test.go files do.
//
// FakeClock + fakeTicker provide a deterministic implementation of
// clockport.Clock + clockport.Ticker that advances only when Advance()
// is called. This lets rate-limit / scheduler-style goroutines be
// driven forward without wall-clock waits.
//
// The matching production port + RealClock implementation live at
// github.com/algo2go/kite-mcp-clockport (Path A.27, 28th algo2go
// module). The split is documented at
// .research/testutil-clock-port-split-design.md (commit fa6c70a) and
// .research/path-a-27-clockport-pick.md (this commit).
//
// What this fake does NOT help with:
//   - Sleeps that wait for external I/O (TCP bind, HTTP server readiness,
//     SQLite worker drain). A fake clock cannot make the OS bind faster;
//     those sleeps stay and belong to integration-test scope.
package testutil

import (
\t"sync"
\t"time"

\t"github.com/algo2go/kite-mcp-clockport"
)

// ---------------------------------------------------------------------
// Fake implementation — deterministic, advances only via Advance.
// Implements clockport.Clock (structural typing — no explicit declaration
// needed; the var-_-clockport.Clock assertion in clock_test.go enforces it).
// ---------------------------------------------------------------------
'''.replace("\\t", "\t")

# Match from package doc up to `// Fake implementation` line (exclusive)
m = re.search(r'\A.*?// Fake implementation — deterministic, advances only via Advance\.\n// ---------------------------------------------------------------------\n', s, re.DOTALL)
if m is None:
    raise SystemExit("ERROR: testutil/clock.go header pattern not found")
s = new_header + s[m.end():]

# FakeClock.NewTicker return type: `Ticker` -> `clockport.Ticker`
s = s.replace(
    "func (f *FakeClock) NewTicker(d time.Duration) Ticker {",
    "func (f *FakeClock) NewTicker(d time.Duration) clockport.Ticker {",
)

with open(p, "w", encoding="utf-8") as f: f.write(s)
print("testutil/clock.go: header replaced + NewTicker return type updated")
PYEOF

# 4. testutil/clock_test.go: remove RealClock tests (3 funcs); update
# interface compatibility assertion to use clockport.Clock
python3 - <<'PYEOF'
import re
p = "testutil/clock_test.go"
with open(p, encoding="utf-8") as f: s = f.read()

# Add clockport import
old_imports = '\t"github.com/stretchr/testify/assert"\n\t"github.com/stretchr/testify/require"\n)'
new_imports = '\t"github.com/stretchr/testify/assert"\n\t"github.com/stretchr/testify/require"\n\n\t"github.com/algo2go/kite-mcp-clockport"\n)'
if old_imports in s and '"github.com/algo2go/kite-mcp-clockport"' not in s:
    s = s.replace(old_imports, new_imports, 1)

# Remove TestRealClock_NowMonotonic, TestRealClock_Ticker, TestRealTicker_StopIdempotent
# (they live in clockport's clock_test.go now).
# Match each function definition through the next blank-line-then-funcdef boundary.
patterns = [
    r'func TestRealClock_NowMonotonic\(t \*testing\.T\) \{[\s\S]+?\n\}\n\n',
    r'func TestRealClock_Ticker\(t \*testing\.T\) \{[\s\S]+?\n\}\n\n',
    r'func TestRealTicker_StopIdempotent\(t \*testing\.T\) \{[\s\S]+?\n\}\n\n',
]
for pat in patterns:
    s, n = re.subn(pat, "", s, count=1)
    if n != 1:
        raise SystemExit(f"ERROR: pattern not matched once: {pat[:60]}")

# Add a header comment at top of file (after package + imports) noting
# RealClock tests have moved.
header_marker = ')\n\n'  # end of import block
note = '\n// TestRealClock_* tests live in github.com/algo2go/kite-mcp-clockport\n// alongside the production port + RealClock implementation. This file\n// covers the FakeClock test fakes only.\n\n'
# Insert note once, after first ')\n\n' (end of import group)
idx = s.index(header_marker) + len(header_marker)
s = s[:idx] + note + s[idx:]

# Update interface compatibility assertion: `var _ Clock = ...` -> `var _ clockport.Clock = ...`
s = s.replace(
    "// Clock interface smoke test: RealClock and *FakeClock both implement.",
    "// Clock interface smoke test: *FakeClock implements clockport.Clock.\n// (RealClock-side coverage lives in github.com/algo2go/kite-mcp-clockport.)",
)
s = s.replace("var _ Clock = RealClock{}\n\t", "")  # remove RealClock assertion
s = s.replace("var _ Clock = NewFakeClock(time.Now())", "var _ clockport.Clock = NewFakeClock(time.Now())")

with open(p, "w", encoding="utf-8") as f: f.write(s)
print("testutil/clock_test.go: 3 RealClock tests removed; FakeClock assertion uses clockport.Clock")
PYEOF

# 5. Update root go.mod + testutil/go.mod to add the new external require
# Root go.mod: add require + go.sum entries via tidy
GO=/usr/local/go/bin/go
$GO mod tidy 2>&1 | tail -3

# testutil/go.mod tidy
(cd testutil && $GO mod tidy 2>&1 | tail -3)

# 6. Empirical guard: zero direct `testutil.Clock` / `.Ticker` / `.RealClock`
# refs in production .go files
prod_stale=$(grep -rE 'testutil\.(Clock|Ticker|RealClock)\b' --include='*.go' \
  | grep -v '_test\.go:' \
  | grep -v 'testutil/clock\.go:' \
  | grep -v 'testutil/clock_test\.go:' \
  | grep -v '^\s*//' \
  || true)
if [ -n "$prod_stale" ]; then
  echo "ERROR: stale production refs to testutil.Clock/Ticker/RealClock:"
  echo "$prod_stale"
  exit 1
fi
echo "OK: 0 stale production testutil.Clock/Ticker/RealClock refs"

# 7. WSL2 build + tools=111 invariant
$GO build ./...
echo "BUILD: PASS"
$GO test -run "^TestHTTPRoundtrip_InitToolsList$" -count=1 -timeout 60s ./mcp/ 2>&1 | tail -3

echo "Files changed: $(git status --short | grep -vE '^\?\?' | wc -l)"
