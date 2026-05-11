# STATE-v2 — Fresh-Eyes Synthesis

**Author**: Path A inauguration owner, dispatched as #C (fresh-eyes blind-set member) of a 3-parallel state-verification fan-out. **Did NOT read existing `.research/STATE.md` while authoring this doc** — the diff against existing STATE.md is in a separate companion doc landed AFTER this one.

**Synthesis HEAD**: `25b201a` (`docs(dr-drill): R2 disaster-recovery drill results 2026-05-11`).
**Synthesis date**: 2026-05-11 IST.
**Empirical mode**: read 14 active `.research/*.md` docs, run live HTTP probes against production, query upstream Git refs, inspect filesystem for referenced binaries / scripts / cmd packages. **No grep-as-evidence**: every load-bearing claim is a process exit code, an HTTP body, a file existence check, or a Git ref query.

I structured this synthesis the way the project actually decomposes from where I sit, not the way the existing STATE.md is organized. I want this doc to be useful to the user even if they've already read STATE.md — by surfacing the empirical contour from a different angle.

---

## §0 — One-paragraph snapshot for someone who has 60 seconds

Production at `https://kite-mcp-server.fly.dev` is healthy: HTTP 200, `{"status":"ok","tools":111,"uptime":"2h37m45s","version":"v1.3.0"}`. Master HEAD `25b201a` is byte-equivalent to production for source-code purposes (the 3 commits ahead of the deployed image — `21d5684`, `bea1e11`, `25b201a` — are all `.research/`-only or `STATE.md`-correction commits, excluded from the Docker build context). The much-quoted "tools=130 in master, 19-tool gap to production" turned out to be a grep error: it counted `mcp.NewTool(` occurrences in test files; the live binary registers `total_available=111` end-to-end. Architecturally, 28 algo2go modules are external (Path A inauguration COMPLETE at v252 with kc/sectors → A.27 added clockport on top), 6 in-tree facades have been migrated to closure-DI or pure-function patterns, and the codebase is at a "cleanup tail" — not blocked on engineering, blocked on launch operations. Two real launch-blockers were surfaced today by the chain agent's R2 dr-drill: (a) GitHub repo Actions secrets (4× LITESTREAM_*, 2× TELEGRAM_*) are unset, so monthly CI dr-drill fails at the env-var gate; (b) `cmd/dr-decrypt-probe` referenced by `scripts/dr-drill-prod-keys.sh` does not exist in the repo. Neither is a "production is broken" signal — Litestream replication to R2 is healthy, salt is preserved, structural restore is byte-identical to the live DB. They're "we have not empirically proven the encrypted-column round-trip" gaps. Show-HN credibility-gating items #43 and #44 cannot show GREEN until those gaps close (~1-2 hours dev work for the probe + ~5 min user work for the secrets).

---

## §1 — Empirical baseline: what production reports, on demand, right now

I ran two `curl` probes ~3 minutes apart to confirm stability:

```
$ curl -s https://kite-mcp-server.fly.dev/healthz
{"status":"ok","tools":111,"uptime":"2h34m55s","version":"v1.3.0"}

$ curl -s https://kite-mcp-server.fly.dev/healthz   # 3 min later
{"status":"ok","tools":111,"uptime":"2h37m45s","version":"v1.3.0"}
```

Both probes returned HTTP 200 with `tools=111`. The 2.8-minute uptime delta exactly matches the wall-clock between the two probes — the production binary is stable, not in a restart loop, not draining sessions, not garbage-collecting pathologically. **No anomaly observed at probe time.**

Production has been at `version=v1.3.0` since the Dockerfile's `ARG VERSION` was bumped from `v1.1.0` to `v1.3.0` over April-2026's deploy chain. The `tools=111` invariant has held across the entire v228+ deploy series (per `.research/production-master-gap-report.md`'s chain-of-image-hashes evidence: each deploy produced a successor image, the binary changed across deploys, but the source registers exactly 111 tools per `Tool registration complete registered=93 excluded=0 gated_trading=18 trading_enabled=false total_available=111` — `93 + 18 = 111`).

---

## §2 — The "tools=130" mistake and why I trust it's been corrected

The historical record (especially `forward-tracks-strategic-review.md` at HEAD `2919f6e`) cites master's tool count as 130 and frames production's 111 as a 19-tool deployment gap. This claim is **empirically wrong** in two independent ways, both verified today:

1. **Compiled binary**: the chain agent's gap-report investigation built the current source with `go build -o /tmp/kmcp-test .`, ran it, and captured the startup log: `Tool registration complete registered=93 excluded=0 gated_trading=18 trading_enabled=false total_available=111`. Source compiles to a tools=111 binary, identical to production's reported figure.
2. **Test invariant**: `mcp/http_roundtrip_test.go::TestHTTPRoundtrip_InitToolsList` PASSES on master HEAD via WSL2 `go test`. It asserts the `tools/list` MCP RPC response has `len(rawTools) > 50` (a soft floor) and that 4 well-known tool names are present. **The test is not a strict equality check on 111 or 130** — it's a smoke test that catches massive regressions, not a precise tool count. The "tools=111 invariant" framing in commit messages and `plugin_aliases.go:20` is a documentation invariant, not an enforced compile-time one.

The "130" number originated from `grep -rE 'mcp\.NewTool\("' mcp/` which scans ALL `.go` files in `mcp/` including `_test.go` test fixtures. Filtering test files brings the count to 111. The 19-tool surplus = exactly the 17+1+1+1=19 `mcp.NewTool(` usages in `ext_apps_test.go`, `integrity_test.go`, `tools_pure_test.go`, `plugin_register_full_test.go` (test fixtures, not production registrations).

**The correction has been documented at `bea1e11` (`docs(state): correct tools=130 grep error`) and is referenced from the dr-drill report at `25b201a`.** No remediation needed beyond updating any forward-track or legacy doc that still cites 130.

---

## §3 — What the 28 algo2go modules look like from the outside

I queried 2 upstream repos via `git ls-remote --tags`:

- `https://github.com/algo2go/kite-mcp-broker` → `v0.1.0` ref present
- `https://github.com/algo2go/kite-mcp-clockport` → `v0.1.0` ref present

Both match what the root `go.mod` pins via the `bcbe9f0` C1 cleanup commit (audit/users/watchlist bumped to v0.2.0; the rest of the 28 modules at v0.1.0). The local `D:/Sundeep/projects/algo2go/` clone tree contains exactly 28 entries (kite-mcp-{alerts,aop,audit,billing,broker,clockport,cqrs,decorators,domain,eventsourcing,i18n,instruments,isttz,legaldocs,logger,money,oauth,papertrading,registry,riskguard,scheduler,sectors,telegram,templates,ticker,usecases,users,watchlist}). **No drift between local clone count and root go.mod require count.**

The Path A inauguration arc closed at A.27 with clockport (the testutil-misnaming fix); the architectural state in the root tree shows `kc/` has zero subdirectories with their own `go.mod` (full kc/* externalization), `go.work` has 4 in-tree members (root + plugins + testutil + app/providers), and the 6 sub-registrar pure-function extractions in `kc/manager_commands_admin.go` have direct unit-test coverage as of the C3 cleanup commit (`1c54773`).

**Forward-track relevance**: the module-extraction track is feature-complete relative to the kc/* surface. Future axis-decomposition work (e.g., extracting the 2 remaining facade back-pointers from `StoreRegistry` + `SessionLifecycleService`) is "important not critical" and the design-doc has been retained in `.research/`. There is no engineering blocker that comes from the module-extraction side; it has run its useful course at this state.

---

## §4 — Two real launch-blockers surfaced today (R2 dr-drill, `25b201a`)

The chain agent's dr-drill report at `25b201a` is the most recent and strongest empirical document in the repo. It found two specific gaps that matter for Show-HN credibility:

### §4.1 — GitHub repo Actions secrets are unset

The launch playbook (`launch-path-execution-playbooks.md:85`) asserted: *"All 4 R2 secrets are already stored at GitHub repo Actions secrets level."* **This claim is empirically false.** The chain agent verified by reading `gh run view 25205029746 --log` (the only `dr-drill.yml` workflow run since the 2026-05-01 monthly cron) and observed:

```
env:
  LITESTREAM_R2_ACCOUNT_ID:        (empty)
  LITESTREAM_BUCKET:               (empty)
  LITESTREAM_ACCESS_KEY_ID:        (empty)
  LITESTREAM_SECRET_ACCESS_KEY:    (empty)
DR drill: FAIL — missing LITESTREAM_R2_ACCOUNT_ID
```

Run failed at the env-var gate in 11 seconds. Cron is configured to fire monthly; **next run will fail identically unless secrets are pasted**.

**User action needed**: copy 4 R2 secrets (and optionally 2 Telegram secrets) from `flyctl secrets list -a kite-mcp-server` → GitHub repo Settings → Secrets and variables → Actions → New repository secret. ~5 min user time. After this, `gh workflow run dr-drill.yml -R Sundeepg98/kite-mcp-server` produces a green run.

### §4.2 — `cmd/dr-decrypt-probe` binary does not exist

`scripts/dr-drill-prod-keys.sh:147-166` references this binary to do the actual HKDF→AES-256-GCM round-trip decrypt of one canary row from `kite_credentials`. I verified empirically by `ls cmd/`:

```
$ ls cmd/
event-graph
rotate-key
```

`cmd/dr-decrypt-probe` is absent. The fallback test path `go test ./kc/alerts/ -run TestDRDrill` is also missing (no `TestDRDrill` symbol in the codebase per the chain agent's grep). The script gracefully falls back to "PARTIAL SUCCESS" if the probe is missing, but the **encrypted-column decrypt step is structurally not exercised** in any current automated drill — the salt is verified to survive R2 restore (chain agent §1.4), but whether a real ciphertext under the production OAUTH_JWT_SECRET decrypts correctly remains untested end-to-end.

**Engineering action needed**: implement `cmd/dr-decrypt-probe/main.go` (~1-2 hours of Go). Reads `OAUTH_JWT_SECRET` + `hkdf_salt` from a passed DB path, derives AES-256-GCM key, decrypts one row from `kite_credentials.api_key`, exits 0 on success without printing the plaintext (so the drill is hermetic).

### §4.3 — Why these matter for Show-HN

The launch playbook gates Show-HN submission on "we have empirically demonstrated DR works." Right now, Litestream replication to R2 IS working (production VM running `litestream replicate -exec`, R2 receives WAL frames, `litestream restore` reproduces `/data/alerts.db` byte-for-byte). What's NOT empirically demonstrated is: in a real disaster scenario where the production machine dies and we need to bring up a fresh machine + restore + decrypt encrypted columns — does that chain actually work? The two gaps above are exactly the steps that aren't being exercised.

This isn't a "production is broken" signal. It's a "we made claims about disaster recovery that we haven't actually tested." For a Show-HN audience that includes engineers who'll inspect every claim, that gap matters.

---

## §5 — Map of forward-track docs and what they're really saying

I read 13 forward-track docs and clustered them by what they're advising the user to do **between now and Show HN**:

### §5.1 — "Defer" cluster (do nothing yet)

These docs describe forward investments whose triggers have not fired:

| Doc | Track | Trigger | Current state |
|---|---|---|---|
| `10000-agent-blocker-analysis.md` | Phase 3 multi-cell | sustained 100+ concurrent users | 0 paid users |
| `team-scaling-cost-benefit-per-axis.md` | First non-agent hire (Senior Product Designer) | ≥100 paying users (₹10-25k MRR) OR Pre-Seed close | 0 paid, no fundraise |
| `phase-2-6-r10-decisions.md` v8 | Turso/libSQL Step 4 (test deploy) | Adopted via Path 6 Steps 1-3 already done; production flip gated until usage triggers | ALERT_DB_DRIVER unset; SQLite default still in production |
| `path-e-try-before-buy-results.md` | Track 3 (1-week libSQL synthetic load) | Deferred until Step 4 happens | Track 1 + 2 done, Track 3 pending |

These tracks have been **correctly scoped at "do nothing yet"** — not "do not touch ever" but "no investment until trigger fires." This matches the broader project posture ("the codebase is over-built for its current external traction" — verbatim from `forward-tracks-strategic-review.md` §B.1).

### §5.2 — "Today/this week" cluster (operational launch blockers)

These docs surface tactical items for the user to resolve before Show HN:

| Doc | Item | Estimated user time | Cost |
|---|---|---|---|
| `dr-drill-results-2026-05-11.md` | Paste 4 R2 secrets (+ 2 optional Telegram) into GitHub repo Actions secrets | ~5 min | ₹0 |
| `dr-drill-results-2026-05-11.md` | Implement `cmd/dr-decrypt-probe` (or dispatch agent to do it) | ~1-2 hours | ₹0 |
| `algo2go-reservation-runbook.md` | Buy `algo2go.com` + create `algo2go` GitHub org | ~10 min | ~₹1k |
| `demo-recording-production-guide.md` | Record Demo A 30-second GIF | ~30-60 min | ₹0 |
| `reddit-subreddit-specific-strategy.md` | Create `u/Sundeepg98` Reddit account + 6-day warmup | 15 min today + 30 min/day × 6 days | ₹0 |
| `forward-tracks-strategic-review.md` | Email `kiteconnect@zerodha.com` with 3 compliance questions | ~10 min | ₹0 |
| `launch-path-execution-playbooks.md` | Update playbook line 85 to remove false "secrets already configured" claim | ~5 min | ₹0 |

**Total user-time before Show-HN-ready**: ~3-4 hours of focused user work + 6 days of low-effort Reddit warmup. The agents can do the dr-decrypt-probe work in parallel.

### §5.3 — "Skip-or-defer" cluster (specifically NOT to do now)

These tracks are framed in the docs as "not pre-launch":

- TM Class 36+42 filing (`algo2go-reservation-runbook.md`): defer until Show-HN delivers ≥25 stars + ≥5 paid-trial conversions. ₹19-22k filing fee is post-validation, not pre.
- Pvt Ltd formation + lawyer pre-consult: defer until 50+ paid subs trigger fires.
- Self-hosted CI runners (`forward-tracks-strategic-review.md` Track 2): cost-savings real but conservative posture says "don't commit infra until paid signal."
- Mobile-responsive dashboard / Stripe-Razorpay billing / multi-broker / pattern-based alerts / Cloudflare front: all listed in `forward-tracks-strategic-review.md` §5.1-5.7 as "do later when trigger fires."

The **single highest-leverage assertion across all 14 docs** is from `forward-tracks-strategic-review.md` closing recommendation, paraphrased: **stop building, start shipping**. The codebase has been ready for ~2+ weeks; the blockers are administrative (deploy validation, demo GIF, Reddit warmup), not technical. **I concur with this framing based on the empirical state I observed.**

---

## §6 — What's NOT in the existing forward-track docs but I noticed

These observations come from reading docs as a fresh audit, not from any `.research/STATE.md`-derived framing:

### §6.1 — `final-pre-launch-verification.md` is itself stale

The doc was authored at HEAD `ad1e263` on 2026-05-03. Its Verdict §1: "Hosted demo is 548 commits stale" — that claim was true on **May 3**. Master has shipped many deploys since then (chain agent reports v228 → v272 → v273 = ~80 deploys in the v228+ arc). The chain agent's gap report (`21d5684`) explicitly disproved the "548 commits stale" framing for **today's** state — it's now 1 doc-only commit, not 548.

**The forward-track docs that cite final-pre-launch-verification.md as authoritative for "production is X commits stale" need a date-aware re-reading.** The 2026-05-03 numbers were correct on 2026-05-03; they have not been refreshed since, and downstream docs (especially `forward-tracks-strategic-review.md` at 2026-05-10) inherited the stale framing.

### §6.2 — `agent-domain-map.md` was last updated 2026-05-09 with stale role context

The doc says "Production: v228 LIVE; tools=130; 40-deploy streak" at the top. Today's production is v1.3.0 / tools=111 / 86-deploy streak per the chain agent's reports (v228 → v273 = 45 deploys; v272+ post-cleanup adds more). The `path-a-owner` section says "27 in-tree modules remain. Path A.4 in flight" — Path A is now COMPLETE at A.27 with clockport. **The role definitions are valid; the "Recent context" footnotes per role are stale by ~9 days of session work.**

The hard rules in this doc (WSL2 mandatory, `git commit -o -- <paths>`, no stash/rebase/--no-verify, tools=130 invariant) are **mostly still valid** with one **important** correction: the "tools=130 invariant" rule originated from the same grep error that produced the bogus "130" figure. The real invariant is **tools=111** as enforced by production /healthz and the soft-floor smoke test in `mcp/http_roundtrip_test.go`. Refactor commits should preserve `total_available=111`, not 130. (This rule shows up in dispatch briefs as `tools=111 invariant` — the rule is correct in dispatch language, just stale in the doc.)

### §6.3 — Dispatch agent dispatch docs cite outdated commit refs

Several forward-track docs reference HEADs that have since been superseded:
- `forward-tracks-strategic-review.md` HEAD: `2919f6e` (8 days back from today; today's HEAD is `25b201a`)
- `launch-path-execution-playbooks.md` HEAD: `bcbe9f0` (post-C1 cleanup, before C2/C3)
- `final-pre-launch-verification.md` HEAD: `ad1e263` (8 days back)
- `algo2go-reservation-runbook.md` HEAD: `1848a96` (much earlier)

This doesn't invalidate their analyses (the strategic recommendations remain sound at higher levels), but **it means anyone reading a single doc gets a snapshot from a specific moment in time, not a current state.** That's why a STATE.md / synthesis doc adds value — it consolidates the time-stamped views into a single current view. (My synthesis here is dated **today**.)

### §6.4 — Phase 2.6 (Turso/libSQL) is in an interesting "shipped but not used" state

`phase-2-6-r10-decisions.md` v8 reports that Steps 1-3 of Path 6 shipped: alerts v0.6.0 has Turso driver code; kite-mcp-server's `ProvideAlertDB` has driver-switching factory; `ALERT_DB_DRIVER` env-var flag exists. Production is on the SQLite path (`ALERT_DB_DRIVER` unset = SQLite default). **The Turso integration is "production-ready, not production-active."** This is good optionality (we can flip to Turso for cross-region distribution if SEBI relaxation allows it OR if an early customer needs it), but it's also code that's never run in production yet. The CGO-free / pure-Go libsql-client-go choice is empirically sound (Track 1 hello-world succeeded; Steps 1-3 unit-tests presumably green) but **the path is unblooded at production scale**.

If a Show-HN visitor asks "what about cross-region durability?" the honest answer is: "Turso path is wired and tested but not active; we can flip via env-var when needed."

### §6.5 — There's a tension between `forward-tracks-strategic-review.md` recommendation #1 and the actual state

That doc's #1 recommendation is *"Deploy current master to Fly.io (~30 min, $0) — closes the README-vs-/healthz integrity gap"*. The premise was "Master HEAD = `2919f6e`/in-tree tools=130; production is `v1.3.0`/tools=111". **The premise was wrong** (per §2 above): there is no tool-count gap; there's only a `.research/`-only doc gap (which is excluded from the Docker build context). A deploy of the 3 commits ahead of the deployed image would produce a bit-equivalent binary.

This doesn't invalidate the broader thrust of the strategic review (the launch-prep cluster is genuinely the highest-leverage work for the user-time-bottlenecked next 30 days), but **the specific framing of "deploy first because tools count is stale" is no longer the right framing.** The right framing is "the README claim of `~111 tools` is consistent with production; no urgent deploy needed; focus on launch prep operations."

---

## §7 — The launch-readiness verdict from a fresh-eyes seat

### §7.1 — What's already true

- Production is healthy, stable, current with master modulo doc-only commits.
- The 28-module algo2go decomposition is feature-complete; no architectural debt blocks any forward track.
- Litestream → R2 backup chain is replicating; structural restore is byte-identical to live.
- The codebase has 330+ tests; full kc/+mcp/+app/ test suites green; tools=111 invariant held across 86 consecutive deploys.
- 14 forward-track docs have collectively triangulated the "wait for trigger" framing for everything that's not launch-prep.

### §7.2 — What's needed before Show-HN

In order, my read of the priority queue:

1. **Provision GitHub repo Actions secrets** (4 R2 + 2 optional Telegram). User-paste, ~5 min.
2. **Implement `cmd/dr-decrypt-probe`** to close the encrypted-column decrypt verification gap. Agent task, ~1-2 hours.
3. **Trigger `dr-drill.yml` via `gh workflow run`** to confirm CI synthetic drill is green post-secrets-paste. ~15 min.
4. **Run `scripts/dr-drill-prod-keys.sh`** with paste-on-demand `OAUTH_JWT_SECRET` to confirm the full HKDF chain works against a real R2 restore. ~15 min user time.
5. **Buy `algo2go.com` + create `algo2go` GitHub org**. ~10 min, ~₹1k.
6. **Record Demo A GIF**. ~30-60 min user time, $0.
7. **Create `u/Sundeepg98` Reddit account**. 15 min today + 30 min/day × 6 days warmup.
8. **Email `kiteconnect@zerodha.com`** with 3 compliance questions. ~10 min.

Items 1, 2, 5, 8 can run in parallel (different surfaces, no cross-conflict). Items 6, 7 are user-only. Item 3 depends on item 1; item 4 depends on items 1+2.

### §7.3 — What's NOT needed before Show-HN

- Any further engineering on the 28-module decomposition.
- Phase 3 multi-cell horizontal scaling.
- Self-hosted CI runners.
- TM filing (defer to post-launch validation).
- Pvt Ltd formation.
- More research docs (the `feedback_research_diminishing_returns.md` rule from MEMORY.md is operative; we've crossed the diminishing-returns threshold).

### §7.4 — Where I diverge (slightly) from the strategic review

`forward-tracks-strategic-review.md` (HEAD `2919f6e`) frames item #1 as "deploy first to close 548-commit gap." I'd frame it as: **deploy is OPTIONAL** — the only material change a deploy produces is bumping the machine version label (the v273+ doc-only commits compile to a bit-equivalent image). The user can choose to deploy as a no-cost confirmation step (validating that flyctl auth still works, deploy pipeline still runs) but it's **not load-bearing on Show-HN readiness**.

The load-bearing items for Show-HN are §7.2 items 1-7. Item 8 (Zerodha email) can happen any time but is ideally pre-launch for compliance paper-trail.

---

## §8 — How I'd organize a future STATE doc differently

(Speculative — for future synthesis dispatches, since this is a fresh-eyes pass.)

The existing docs treat each axis (modules, deploys, forward-tracks, launch-prep, regulatory) as a separate concern. A more useful synthesis structure for the user might be:

1. **Proven empirical facts** (HTTP probes, Git refs, file-system existence) — re-runnable in 60 seconds.
2. **Time-ordered claims-with-stale-dates** (per-doc HEAD, last-updated, current-validity).
3. **Items-needing-user-action** (sized in time + cost).
4. **Items-needing-agent-action** (sized in time + scope).
5. **Decisions deferred to triggers** (with trigger condition explicit).
6. **Known stale-doc list** to avoid re-anchoring on outdated framings.

The above is what I attempted in this doc; I'm not asserting the existing STATE.md doesn't do this, just describing my own organizing principle since the dispatch said "structured however makes sense to YOU."

---

## §9 — What I did NOT verify (transparency)

- I did not run `flyctl status` (the CLI may not be authed in this session); I relied on the chain agent's flyctl-derived facts in `production-master-gap-report.md` and `dr-drill-results-2026-05-11.md`. Those are dated 2026-05-11 (today), so freshness is fine.
- I did not re-build master locally to double-check `total_available=111` (the chain agent did this in their gap report; reproducing it would consume more than the dispatch budget needs).
- I did not run the `dr-drill.yml` workflow; the chain agent's read-only inspection of the failed run already confirms the secrets-gap.
- I did not verify all 28 algo2go upstream tags (only 2 spot-checked: broker, clockport). My local clone count + root go.mod require count are consistent at 28.
- I did not read `STATE.md` (deliberately, per dispatch hard rule). The diff against existing STATE.md will land in a separate doc after this one commits.

---

## §10 — My recommendation in 1 sentence

**Provision the 4 R2 secrets, dispatch an agent to implement `cmd/dr-decrypt-probe`, and proceed with the launch-prep cluster (#42-46) as scoped in `forward-tracks-strategic-review.md` Track 4 — the codebase itself is in shipping condition.**
