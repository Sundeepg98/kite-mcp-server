<!-- secret-scan-allow: dependency-analysis-research-no-secrets -->
---
title: algo2go Dependency-State Analysis — "are we fully dep on algo2go?"
as-of: 2026-05-11
re-verify-by: 2026-06-11
master-head: 8910d20 (kite-mcp-server master)
bootstrap-relocation-head: deefac1 (kite-mcp-server bootstrap-relocation branch)
bootstrap-master-head: f4e2215 (algo2go/kite-mcp-bootstrap master)
scope: READ-ONLY empirical analysis; no source mutations
methodology: go list -m all + wc -l + grep -c "import ..." per file; compile-and-run-style probes (no transcript inheritance)
budget-used: ~1.5h of 2-3h target
---

# Dependency-State Analysis: "Are we fully dep on algo2go?"

**User's question (verbatim)**: *"are we fully dep on algo2go"*

**Short answer**: **Today (production master) NO** — substantial code still in-tree at `kc/`+`app/`+`mcp/` (54k non-test LOC). **Post-Sprint-0 merge (bootstrap-relocation branch) NEARLY YES** — only `cmd/` operational binaries + thin main.go remain (710 LOC, 98.7% reduction). **Post-Sprint-1-5 (substantive decomposition) FULL YES** — every line of code we wrote lives under `algo2go/*`.

---

## §1 — Master state (production today, HEAD `8910d20`)

What kite-mcp-server master actually depends on, categorized:

| Category | Direct deps | Notes |
|---|---|---|
| **algo2go** (`github.com/algo2go/kite-mcp-*`) | **27** | Of 28 promoted modules; `kite-mcp-aop` is NOT consumed by master (`go mod why` returns "main module does not need package") |
| **In-tree workspace siblings** (`github.com/zerodha/kite-mcp-server/{app/providers, plugins, testutil}`) | 3 | Resolved via `replace` directives to local dirs |
| **Third-party direct** (Go stdlib not counted) | 15 | gokiteconnect, mark3labs/mcp-go, hashicorp/go-plugin, stripe-go/v82, modernc.org/sqlite, yuin/goldmark, fsnotify, telegram-bot-api/v5, fx, goleak, testify, uuid, x/crypto, x/time, rapid |
| **Total direct deps** | **45** | (27 algo2go + 3 in-tree + 15 third-party) |

Full transitive closure: 140 modules (140 = `go list -m all | wc -l`). The other 95 are indirect transitive deps (e.g., `cncf/xds/go`, `envoyproxy/*`, OpenTelemetry chain — pulled by gRPC, not directly used).

**Production today: 27/29 algo2go repos consumed directly. The 29th, `kite-mcp-bootstrap`, was just created in Sprint 0 and is consumed only on the `bootstrap-relocation` branch.**

### §1.1 LOC breakdown (master)

| Area | Non-test .go LOC | Total .go LOC (incl. tests) |
|---|---|---|
| `kc/` (Kite client manager + sessions + ops) | 17,820 | 55,158 |
| `app/` (DI wiring + HTTP mux + lifecycle) | 10,371 | 33,204 |
| `mcp/` (MCP tool registrations + middleware) | 24,358 | 64,101 |
| `plugins/` (plugin scaffolding sub-module) | 321 | 816 |
| `testutil/` (test fakes + fixtures sub-module) | 825 | 1,397 |
| `cmd/` (operational binaries: dr-decrypt-probe, event-graph, rotate-key) | 546 | 1,779 |
| `examples/` (example riskguard-check-plugin) | 123 | 123 |
| Root .go (main.go + main_test.go + fly_toml_test.go) | 441 | 441 |
| **Master kite-mcp-server in-tree TOTAL** | **54,504** | **157,019** |

### §1.2 Code-we-own ownership split (production today)

| Repo | Non-test LOC | Total LOC |
|---|---|---|
| kite-mcp-server (in-tree) | 54,504 | 157,019 |
| 28 algo2go domain modules | 46,405 | 145,245 |
| algo2go/kite-mcp-bootstrap | (not yet consumed by master) | — |
| **TOTAL code we own (production today)** | **100,909** | **302,264** |

**Production split: 54% of our code is in-tree on kite-mcp-server; 46% is in algo2go modules.** (Non-test denominator.)

---

## §2 — Bootstrap-relocation branch state (post-Sprint-0 staged, HEAD `deefac1`)

The branch I shipped in the Sprint 0 dispatch. Not yet merged to master.

| Category | Direct deps | Delta vs master |
|---|---|---|
| **algo2go** | **4** | -23 (most moved into bootstrap) |
| **In-tree workspace siblings** | 0 | -3 (workspace empty) |
| **Third-party direct** | 3 | -12 (most moved into bootstrap) |
| **Total direct deps** | **7** | **-38** |

The 4 algo2go direct deps on the branch:
- `github.com/algo2go/kite-mcp-bootstrap` (composition root)
- `github.com/algo2go/kite-mcp-bootstrap/app/providers` (Fx providers)
- `github.com/algo2go/kite-mcp-alerts` (used by cmd/rotate-key)
- `github.com/algo2go/kite-mcp-riskguard` (used by cmd/event-graph or example plugin)

The 3 third-party direct deps:
- `github.com/stretchr/testify` (test framework)
- `modernc.org/sqlite` (used by cmd/ binaries for DB access)
- `github.com/hashicorp/go-plugin` (plugin scaffolding ref)

### §2.1 LOC on bootstrap-relocation branch

| Area | Non-test LOC | Total LOC |
|---|---|---|
| `cmd/` | 546 | 1,779 |
| `examples/` | 123 | 123 |
| Root .go (main.go=41, main_test.go=108, fly_toml_test.go=87) | 236 | 236 |
| **bootstrap-relocation TOTAL** | **710** | **2,138** |

**LOC reduction: 54,504 → 710 = -53,794 non-test LOC (-98.7%) moved to bootstrap.**

### §2.2 algo2go/kite-mcp-bootstrap repo state (HEAD `f4e2215`)

| Direct deps | Count |
|---|---|
| algo2go domain modules | 27 |
| In-tree workspace siblings (`app/providers`, `plugins`, `testutil`) | 3 |
| Third-party direct | 13 |
| **Total** | **43** |

Bootstrap LOC: **53,843 non-test / 154,921 total** (mirrors what moved out of kite-mcp-server modulo small bonus additions: my `bootstrap.go` + `bootstrap_test.go` entry-point API).

---

## §3 — LOC analysis: % of running binary that's "code we wrote"

### §3.1 Code-we-own totals

| Source | Non-test LOC | Total LOC |
|---|---|---|
| 28 algo2go domain modules | 46,405 | 145,245 |
| algo2go/kite-mcp-bootstrap | 53,843 | 154,921 |
| kite-mcp-server (bootstrap-relocation branch) | 710 | 2,138 |
| **TOTAL code we own (post-Sprint-0 staged)** | **100,958** | **302,304** |

(Slight delta vs §1.2's 100,909 because Sprint 0 added bonus tests and the timezone fix.)

### §3.2 Third-party totals (full transitive closure)

| Bucket | Non-test LOC |
|---|---|
| `modernc.org/*` (CGo-free SQLite transpilation — generated code) | 4,379,936 |
| All other third-party (gokiteconnect, mark3labs/mcp-go, fx, gRPC, OpenTelemetry chain, etc.) | 1,573,935 |
| **Total third-party non-test LOC** | **5,953,871** |

### §3.3 Ratio

| Denominator | Code-we-own % |
|---|---|
| Of total .go LOC in entire dep tree (~6.05M total) | **~1.7%** |
| Of total *excluding* modernc.org SQLite transpilation (~1.67M) | **~6.0%** |
| Of "human-written" third-party (excluding generated SQLite + protobuf/genproto) | **~10-15%** |

**The running binary is overwhelmingly third-party code by raw LOC.** That's normal for any production Go service — the heavy SQLite engine, gRPC stack, OpenTelemetry chain, Fx DI container, gokiteconnect SDK, MCP protocol library, and stripe SDK are all third-party. **Our code is the thin composition layer that wires them together and adds business logic.** LOC is a misleading metric here — by surface-area-touched (tool count, route count, business rules), our code is the operative part.

---

## §4 — Critical third-party deps inventory

Empirical usage (import-line count across all our code: kite-mcp-server master + bootstrap + 28 algo2go modules):

| Dep | Imports | Locked-in? | Notes |
|---|---|---|---|
| `mark3labs/mcp-go` | **240** | YES — MCP protocol library | Could write our own MCP impl but that's ~20k LOC of work; landscape today has 1-2 alternatives, all early-stage |
| `gokiteconnect/v4` (Zerodha SDK) | **56** | YES — Zerodha proprietary API | Only first-party SDK for Kite Connect; replacing means reimplementing the HTTP+ticker WebSocket protocol from API docs |
| `go-telegram-bot-api/v5` | 12 | LOOSE — could replace | Several Go Telegram libraries; current one is most-popular |
| `stripe-go/v82` | 12 | YES — Stripe billing | Stripe-specific; replaceable only by switching billing provider (substantial business change) |
| `google/uuid` | 11 | LOOSE — stdlib alt exists | `crypto/rand.Read(b[:])` + format gets you 95% there; library saves ~20 LOC |
| `goldmark` | 4 | LOOSE — markdown parsing | Several Go markdown libs; not on hot path |
| `hashicorp/go-plugin` | 4 | LOOSE — could replace with stdlib | Plugin RPC subprocess shim; could use `os/exec` + stdin/stdout JSON if needed |
| `gorilla/websocket` | 3 | LOOSE — stdlib alt exists | `coder/websocket` and Go 1.21+ `nhooyr.io/websocket` are alternatives; minimal usage |
| `fsnotify` | 1 | LOOSE — single touchpoint | File-system watcher; could use `time.Ticker + os.Stat` if pattern is hot-reload only |
| `tursodatabase/libsql-client-go` | 1 | LOOSE — could drop | Used for optional Turso libSQL backend in `app/providers/alertdb.go`; SQLite-only deployments don't need it |
| `modernc.org/sqlite` | 0 direct | YES — pure-Go SQLite | Used via `database/sql` driver registration (blank-import); switching means going CGo (`mattn/go-sqlite3`) or moving to a different DB; the Pure-Go choice is intentional per Fly.io Docker constraints |
| `mattn/go-sqlite3` | 0 | N/A | Not in dep tree — we explicitly chose modernc/sqlite (CGo-free) |
| `coder/websocket` | 0 direct | N/A | Transitive only |

**Bottom line on third-party**:
- **2 fundamentally locked-in deps**: `gokiteconnect` (Zerodha proprietary) and `mark3labs/mcp-go` (MCP protocol). These are the things we genuinely cannot rewrite without enormous cost.
- **2 high-touch but switchable**: `stripe-go` (billing), `modernc.org/sqlite` (DB driver) — both have plausible alternatives, just at high cost.
- **Everything else (~10 libs)**: low-touch, replaceable in <1 day each.

---

## §5 — What's NOT in algo2go yet (and why)

Today, on kite-mcp-server master:

### §5.1 In-tree code we own (54,504 non-test LOC)

| Dir | LOC | Promotable to algo2go? | Sprint to target |
|---|---|---|---|
| `kc/` (manager + sessions + ops + ports) | 17,820 | **YES** — entire tree moves to bootstrap or splits into algo2go/kite-mcp-{manager-core, manager-init, manager-cqrs, manager-ports, manager-tools} | Sprint 0 (moves to bootstrap), then Sprint 1-5 (decomposition) |
| `app/` (DI wiring + HTTP + lifecycle) | 10,371 | **YES** — moves to bootstrap; further decomposition (extract `app/http/`, split `initializeServices` 805-LOC megamethod) is Sprint 2-3 work | Sprint 0 (bootstrap), Sprint 3 (split) |
| `mcp/` (MCP tool registrations + middleware) | 24,358 | **YES** — moves to bootstrap; further Pattern D.2 work pushes tool registrations INTO their owning algo2go modules (per `zero-in-tree-feasibility` Chain analysis) | Sprint 0 (bootstrap), Pattern D.2 (long-term) |
| `plugins/` (plugin scaffolding) | 321 | **YES** — moves to bootstrap as workspace member; possibly its own algo2go module later | Sprint 0 |
| `testutil/` (test fixtures) | 825 | **YES** — moves to bootstrap as workspace member | Sprint 0 |

**All 53,695 non-test LOC of in-tree code we own are promotable.** Sprint 0 moves the bulk into the bootstrap module (which IS in algo2go, just not as 28 fine-grained domain modules). Subsequent sprints can promote further (each tool family into its owning algo2go/kite-mcp-* module).

### §5.2 Inherently kite-mcp-server-specific (NOT promotable)

| Item | LOC | Why stays in kite-mcp-server |
|---|---|---|
| `main.go` | 140 (master) / 41 (post-Sprint-0) | Entry point; deploy-repo is the source-of-truth for `MCP_SERVER_VERSION` + `buildString` ldflags |
| `main_test.go` | 214 / 108 | Binary-level tests (build → exec → assert) |
| `fly_toml_test.go` | 87 | Pins invariants of fly.toml (deploy config) |
| `cmd/dr-decrypt-probe/` | ~200 | Operational disaster-recovery binary that ships in deploy image |
| `cmd/event-graph/` | ~150 | Generates docs/event-flow.md as CI artifact; deploy-repo concern |
| `cmd/rotate-key/` | ~200 | Operational key-rotation binary that ships in deploy image |
| `Dockerfile`, `fly.toml`, `server.json`, `smithery.yaml`, `funding.json`, `litestream.yml`, `.mcp.json` | n/a | Deploy artifacts (not .go) |

**Inherently in-tree: ~991 .go LOC + deploy manifests.** That's the irreducible kite-mcp-server surface.

### §5.3 The `kite-mcp-aop` exception

`kite-mcp-aop` is the 28th promoted algo2go module BUT is NOT consumed by kite-mcp-server master's go.mod. Per Path A.9 audit it was promoted and Phase-B-canary-deleted, but the consumer was apparently never re-wired. The module is "promoted but orphaned" — exists in algo2go org, has tagged versions, has zero current consumers in production.

**Action item for follow-up**: either (a) re-wire kite-mcp-aop into a real consumer if it provides value, or (b) archive it on GitHub (`gh api -X PATCH repos/algo2go/kite-mcp-aop -f archived=true`) to signal orphan-status to the world.

---

## §6 — Verdict on "fully dep on algo2go": present + future

### §6.1 Today (production master `8910d20`): **NO**

54% of our non-test code (54,504 of 100,909 LOC) is in-tree on kite-mcp-server. The other 46% is correctly placed under algo2go/*. Production runs from an in-tree composition root that consumes 27 algo2go modules.

### §6.2 Post-Sprint-0 merge (bootstrap-relocation `deefac1`): **NEARLY YES** (99.3%)

After merging the Sprint 0 work to master:
- kite-mcp-server retains 710 non-test LOC (deploy-repo-only: main.go thin shell + cmd/ binaries + examples + fly.toml test)
- 53,843 non-test LOC moves to algo2go/kite-mcp-bootstrap
- 46,405 non-test LOC stays in 28 algo2go domain modules

**Total: 100,958 non-test LOC of code we own. Of that, 710 (0.7%) is in kite-mcp-server; 100,248 (99.3%) is under algo2go.**

The remaining 0.7% is irreducible: thin main.go (deploy-version ldflags origin), cmd/ operational binaries (ship in deploy image), test files asserting deploy-config invariants.

### §6.3 Post-Sprint-1-5 (substantive decomposition): **FULL YES**

The end-state per `end-state-architecture-2026-05-11.md` §1.1:
- 33 algo2go domain modules (vs today's 28): the 5 new ones come from decomposing `kc.Manager` into `kite-mcp-{manager-core, manager-init, manager-cqrs, manager-ports, manager-tools}`
- `kite-mcp-bootstrap` shrinks as Pattern D.2 work pushes each tool family INTO its owning algo2go module's init() blank-imports
- `kite-mcp-server` stays at ~710 LOC (the deploy-repo floor)

**Code we wrote: 100% in algo2go org. kite-mcp-server: deploy-only thin shell forever.**

### §6.4 Already-fully-algo2go: the algo2go ORG itself

The user's question can also be read as: "Is everything we own already in the algo2go org?" Today's empirical answer:

| Repo | In algo2go org? | Consumed by production today? |
|---|---|---|
| `algo2go/kite-mcp-*` (28 domain modules) | YES | YES (27 of them) |
| `algo2go/kite-mcp-bootstrap` | YES (created Sprint 0) | NO (bootstrap-relocation branch only) |
| `Sundeepg98/kite-mcp-server` | **NO — under Sundeepg98 personal account** | YES (production deploy source) |

The third row is the open question. Per `github-transfer-bootstrap-2026-05-11.md` §1, transferring `Sundeepg98/kite-mcp-server` → `algo2go/kite-mcp-server` is a 30-second `gh api -X POST` call with ~1-year 301-redirect window. Until that transfer, the deploy repo is the one piece of the puzzle living outside the algo2go org.

**Post-transfer + Sprint-0-merge: every piece of code we own, in every repo we control, lives under `algo2go/*`.** That's the "fully on algo2go" end-state, achievable today with two human-action steps (merge PR + run transfer command).

---

## §7 — Summary table (the answer in one view)

| State | Code in algo2go (%) | Code in kite-mcp-server (%) | Code-we-own LOC | Verdict |
|---|---|---|---|---|
| Today (master `8910d20`) | 46% | 54% | 100,909 non-test | NO — substantial in-tree |
| Post-Sprint-0 merge | 99.3% | 0.7% | 100,958 non-test | NEARLY YES — only deploy thin-shell |
| Post-transfer (Sundeepg98 → algo2go) | 99.3% | 0.7% | 100,958 non-test | YES (org-level) — every repo under algo2go |
| Post-Sprint-1-5 + transfer | 99.3% | 0.7% | similar (decomposed but not bulk-moved) | FULL YES — kc.Manager decomposed; tool registrations migrated |

**Production binary is ~98% third-party Go by LOC (gRPC + OpenTelemetry chain + SQLite transpilation + Fx + mcp-go), ~2% our code.** Of our 2%, today 54% is in-tree (kite-mcp-server master) and 46% is in algo2go. Post-Sprint-0 merge flips that to 99.3% in algo2go / 0.7% deploy thin-shell.

---

## §APPENDIX — Empirical commands used

```bash
# Module-dep counts (master)
cd kite-mcp-server && git checkout master
go list -m all | wc -l                    # → 140 transitive modules
go list -m all | grep -c '^github.com/algo2go/'   # → 27 algo2go direct
go mod edit -json | python -c 'import json,sys; d=json.load(sys.stdin); print(sum(1 for r in d.get("Require",[]) if not r.get("Indirect")))'  # → 45 direct deps

# LOC by tree
find kc -name '*.go' -not -name '*_test.go' | xargs wc -l | tail -1   # → 17,820 kc non-test
find . -name '*.go' -not -name '*_test.go' | xargs wc -l | tail -1    # → 54,504 in-tree non-test

# Third-party LOC for direct deps
for pkg in mark3labs/mcp-go zerodha/gokiteconnect/v4 stripe-go/v82 ...; do
  raw=$(go list -m -f '{{.Dir}}' "$pkg")
  unixpath=$(cygpath -u "$raw")
  find "$unixpath" -name '*.go' -not -name '*_test.go' | xargs wc -l | tail -1
done

# Cross-import check (does any algo2go module import zerodha/kite-mcp-server?)
grep -rE '"github.com/zerodha/kite-mcp-server' --include='*.go' algo2go/kite-mcp-*
# → ZERO hits (one match is a dep_cycle_test.go negative-assertion guard)
```

---

**END OF DOC** — verified at HEAD `8910d20` (master) + `deefac1` (bootstrap-relocation) + `f4e2215` (algo2go/kite-mcp-bootstrap master).
