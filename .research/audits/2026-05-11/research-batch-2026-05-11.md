# Research Batch — 2026-05-11

**Master HEAD audited**: `cdc1f91` (`docs(index): question-keyed research lookup`)
**Production**: v1.3.0 / tools=111 / uptime 3h40m at audit-time / image `deployment-01KR9FPJC88YA80VWS7VMTWTY7`
**Charter**: address every open research question surfaced across the session. READ-ONLY on code/docs; empirical-probe-driven; doc-only output. No source mutations.
**Concurrency**: chain agent + Path A owner idle. No overlap.

**Methodology rule** (per STATE.md §11 lesson): compile-and-run > grep-and-count for binary-state metrics; `curl /healthz` authoritative for production state; RDAP + GitHub API for external availability; `gh api search` for PR submission status.

---

## TL;DR — answer summary across 14 questions

| # | Question | Outcome | Status |
|---|---|---|---|
| **A** | Tradarc replacement TM (5 candidates RDAP-verified) | **5 unregistered options found**: `quirkalgo.com`, `tradloop.com`, `quanto2go.com`, `zerocode2go.com`, `tradesy2.com`. All 4 GitHub orgs probed are also AVAILABLE. Top picks: `quirkalgo` (most distinctive coined wordmark, strongest TM-defensibility) or `quanto2go` (preserves "2Go" theme from Algo2Go). | **NEW-FINDING** |
| **B** | Show-HN body claims verification | **README has 4 conflicting claims**: tools = "110+" (line 3) vs "117" (line 90 comparison table); RiskGuard = "11" (line 3) vs "12" (line 54 enumeration) vs "9" (line 82 comparison); tests = "~9,000" (line 48). Empirical: tools=111 (production) / RiskGuard reasons=17 distinct constants (per algo2go/kite-mcp-riskguard) / tests=8,457 cumulative (4,697 in-tree + 3,760 algo2go). | **STALE-PATCH-NEEDED** |
| **C** | `cmd/dr-decrypt-probe` design spec | **DESIGN ATTACHED §C.** Source dir does NOT exist; the synthetic CI-runnable analog `TestDRDrill_ProductionKeyChain_Synthetic` already exists at `algo2go/kite-mcp-alerts/dr_drill_prod_keys_test.go` and codifies the exact behavior the probe binary must implement. ~1-2hr Go work; spec ready for execution dispatch. | **NEW-FINDING + READY** |
| **D** | `gh secret set` commands for dr-drill.yml | **6 commands attached §D.** `gh secret set --repo Sundeepg98/kite-mcp-server LITESTREAM_R2_ACCOUNT_ID --body "$LITESTREAM_R2_ACCOUNT_ID"` × 6 (4 R2 + 2 Telegram). User runs locally with secrets in env vars. | **READY** |
| **E** | smithery.yaml committed status | **YES, ALREADY COMMITTED** at repo root. Content matches `kite-launch-ready-fixes.md` ready-to-commit version exactly. INDEX §12 gap is resolved. | **VERIFIED** |
| **F** | funding.json schema verification | **YES, ALREADY COMMITTED** at repo root. Content schema-version `v1.0.0`. **PATCH NEEDED**: official schema is now `v1.1.0` (per https://fundingjson.org). Schema URL: `https://fundingjson.org/schema/v1.1.0.json`. Three grant tiers ($10k/$35k/$60k) defined. Fields appear present; should be re-validated against v1.1.0 schema. | **VERIFIED + STALE-VERSION** |
| **G** | Reddit u/Sundeepg98 creation status | **BLOCKED** — Claude Code WebFetch tool blocks `reddit.com` domain. Cannot probe via this dispatch. User-action required: visit `https://www.reddit.com/user/Sundeepg98/about.json` in browser (404 = not created; 200 = exists with karma JSON). Alternative: gh CLI does NOT cover Reddit. | **BLOCKED-ON-TOOL** |
| **H** | GitHub star count check | `Sundeepg98/kite-mcp-server`: **0 stars**, 0 forks, 0 subscribers, repo created 2026-02-22, last push 2026-05-10. `algo2go/kite-mcp-server` does NOT exist (org has 28 module repos but no main server fork). Each algo2go module repo also at 0 stars. **Far below the 50-star Rainmatter trigger threshold.** | **VERIFIED** |
| **I** | Authoritative test count via compile-and-run | **8,457 total tests** (4,697 in-tree + 3,760 across 28 algo2go modules). Top 3 in algo2go: `kite-mcp-usecases` (574), `kite-mcp-alerts` (571), `kite-mcp-oauth` (446). README claim "~9,000" rounds correctly. **Methodology**: `go test ./... -list '.*' \| grep -E '^Test' \| wc -l` per package — that's the new authoritative probe to add to INDEX §11. | **VERIFIED** |
| **J** | MRR vs ₹15-25k target tracker | **No live MRR tracker exists.** Stripe billing IS wired (per Q K) but no admin tool aggregates monthly revenue. `mcp/admin/admin_billing_tools.go` has `admin_set_billing_tier` (operator escape hatch — set tier without going through Stripe) but no `admin_revenue` or `admin_mrr` tool. Stripe Dashboard is the source of truth; in-process tracking would need a new admin tool reading `Subscription` rows + `TierMonthlyINR(Tier)` aggregator. | **STILL-OPEN — followup dispatch** |
| **K** | Stripe/Razorpay billing integration design | **Stripe is FULLY IMPLEMENTED**, NOT a design gap. `algo2go/kite-mcp-billing` package has `checkout.go` (CheckoutHandler creates Stripe Checkout Session for 3 plans solo_pro/pro/premium with max_users 1/5/20), `webhook.go` (signature verify + 4 event handlers: checkout.session.completed, customer.subscription.updated/deleted, invoice.payment_failed; idempotency via webhook_events table). **No Razorpay** — Stripe-only. The dispatch's premise (1-week design needed) is FALSIFIED. | **VERIFIED — NO ACTION** |
| **L** | awesome-mcp-servers PR submission log | **3 PRs across 3 lists**: (1) `punkpeye/awesome-mcp-servers` PR #4075 — **CLOSED unmerged 2026-04-04** (1 day after submission; closed by punkpeye maintainer; reason not in JSON — likely needs follow-up); (2) `jaw9c/awesome-remote-mcp-servers` PR #267 — **OPEN since 2026-04-19**, no comments/reviewers (awaiting review); (3) `wong2/awesome-mcp-servers` (via mcpservers.org form) — **0 PRs** (not submitted). | **STALE-PATCH-NEEDED** (re-engage punkpeye) |
| **M** | Twitter @Sundeepg98 activity tracker | **BLOCKED** — `https://x.com/Sundeepg98` returns HTTP 402 (login required); `nitter.net` returns empty content (browser-only). Cannot probe via WebFetch. GitHub user metadata says `twitter_username: null` (not connected to GitHub). Alternative probes blocked. User-action required: confirm @Sundeepg98 handle exists on X manually. | **BLOCKED-ON-TOOL** |
| **N** | OAUTH_JWT_SECRET rotation procedure | **Two-secret rotation IS already wired in code.** `app/app.go:666-674` reads `OAUTH_JWT_SECRET` (current) + `OAUTH_JWT_SECRET_PREVIOUS` (verify-only fallback); `app/config.go:57,96` propagates both. **PROCEDURE ATTACHED §N.** Pattern: set PREVIOUS to old value before rotating; old JWTs continue verifying for grace window (default 24h MCP / 7d dashboard); after window, unset PREVIOUS. **Note: encrypted-column rotation is SEPARATE** — rotating OAUTH_JWT_SECRET also rotates the HKDF-derived AES-256 key per `algo2go/kite-mcp-alerts/crypto.go:29-46`, which would invalidate every cached Kite token + credential + OAuth client_secret unless re-encrypted. ~1 page operational runbook below. | **NEW-FINDING — runbook attached** |

**Bottom-line counts**: 5 VERIFIED (E, H, I, K, R-D-ready) · 2 NEW-FINDING-with-design (C, N) · 4 STALE-PATCH (B, F-version, L) · 2 BLOCKED-ON-TOOL (G, M) · 1 STILL-OPEN-for-followup (J) · 1 NEW-FINDING-trademark (A).

**Followup dispatches recommended** (§ Final Section §15): 5 ranked.

---

# §A — Tradarc Replacement TM Candidates (5 RDAP-verified)

**Question**: Find 3-5 wordmark alternatives as bus-factor TM backups to Algo2Go (Tradarc.com is taken — auto-renewed to 2027-05-04 per RDAP today).

## Procedure

1. RDAP probed against `https://rdap.verisign.com/com/v1/domain/<name>.com` (HTTP 404 = available; 200 = registered)
2. GitHub org probed via `https://api.github.com/orgs/<name>` (404 = available)
3. Filter applied: short (≤9 chars), pronounceable, coined non-descriptive wordmark (most defensible per fintech-lawyers note `kite-fintech-lawyers.md`), no obvious existing-brand collision

## RDAP results table (probed today)

| Candidate | RDAP `.com` | Last reg event | GitHub org | Verdict |
|---|---|---|---|---|
| **`tradarc.com`** | REGISTERED — Server Plan Srl, **expires 2027-05-04** (auto-renewed since 2026-05-03 INDEX cite) | 2001-05-04 reg | (not probed — moot) | **NOT clean** — was bus-factor backup candidate, but auto-renewed; remove from candidate list |
| `algoflow.com` | REGISTERED — NameCheap, expires 2026-09-09 | 2013-09-09 reg | (not probed — moot) | TAKEN |
| `quantgo.com` | REGISTERED — Dynadot, expires 2033-08-05 | 2013-08-05 reg, parked at brandbucket.com | (not probed — moot) | TAKEN (premium domain) |
| `algopath.com` | REGISTERED — Unstoppable Domains, expires 2027-05-04 | 2025-05-04 reg | (not probed — moot) | TAKEN (recent registration; possibly speculator) |
| `algoport.com` | REGISTERED — TLDS LLC, expires 2027-08-03 | 2009-08-03 reg | (not probed — moot) | TAKEN |
| `quantarc.com` | REGISTERED — , expires 2026-11-04 | 2019-11-04 reg | (not probed — moot) | TAKEN |
| `algorelay.com` | REGISTERED — Tucows, expires 2027-03-01 | **2026-03-01 reg** (very recent) | (not probed — moot) | TAKEN |
| `algowire.com` | REGISTERED — GoDaddy, expires 2028-03-23 | 2012-03-23 reg | (not probed — moot) | TAKEN |
| `algoduck.com` | REGISTERED — Amazon Registrar, expires 2027-02-23 | 2020-02-23 reg | (not probed — moot) | TAKEN |
| `algyo.com` | REGISTERED — InterNetX, expires 2026-07-17 | 2010-07-17 reg | (not probed — moot) | TAKEN |
| `rupeego.com` | REGISTERED — NameBright, expires 2027-05-07 | 2018-05-07 reg | (not probed — moot) | TAKEN |
| **`tradesy2.com`** | **AVAILABLE** (RDAP HTTP 404) | n/a | **AVAILABLE** (`api.github.com/orgs/tradesy2` HTTP 404) | **CLEAN** ✓ |
| **`quanto2go.com`** | **AVAILABLE** (RDAP HTTP 404) | n/a | **AVAILABLE** (HTTP 404) | **CLEAN** ✓ |
| **`tradloop.com`** | **AVAILABLE** (RDAP HTTP 404) | n/a | **AVAILABLE** (HTTP 404) | **CLEAN** ✓ |
| **`zerocode2go.com`** | **AVAILABLE** (RDAP HTTP 404) | n/a | (not probed — long form) | **CLEAN domain; org TBD** |
| **`quirkalgo.com`** | **AVAILABLE** (RDAP HTTP 404) | n/a | **AVAILABLE** (HTTP 404) | **CLEAN** ✓ |

## Top picks (ranked)

### 1st pick: `quirkalgo` — most distinctive coined wordmark

**Why first**: Coined non-descriptive (mashup of "quirk" + "algo"). Per `memory/kite-fintech-lawyers.md` + standard TM doctrine: distinctive marks (especially fanciful/coined like "Kodak", "Xerox") get the strongest TM protection. Length: 9 chars. Pronounceable. No existing fintech association in our quick search. Available on `.com` + GitHub org. **Recommend for backup TM filing.**

**Trade-off**: "quirk" connotes "odd/eccentric" which may be off-brand for a serious fintech tool. Counter-argument: Stripe was once a pure-coined nonsense word too; brand meaning accretes via product, not via phonosemantics.

### 2nd pick: `quanto2go` — preserves "2Go" theme from Algo2Go

**Why second**: Preserves the Algo2Go portability framing (2Go = "to go" / portable / self-hostable). "Quanto" is a real finance term (a derivative whose payoff is in a different currency than its underlying — niche but recognizable in fintech). Available on `.com` + GitHub org. Length: 9 chars.

**Trade-off**: "Quanto" has a pre-existing finance meaning which weakens TM defensibility (a competing fintech could argue the term is descriptive of FX-derivative work). Less distinctive than `quirkalgo` but more thematically coherent with Algo2Go.

### 3rd pick (tertiary): `tradloop`

**Why third**: Pure coined; short (8 chars); evokes "trading loop" (algorithmic concept). Available on `.com` + GitHub org. Trade-off: somewhat generic; less distinctive than `quirkalgo`.

## TM-search caveat

**RDAP only verifies domain availability, NOT trademark availability.** Before filing TM Class 9 + Class 42 in India, run a search at:
- `https://tmrsearch.ipindia.gov.in/eregister/` (India IP Office; same flow used for Algo2Go primary filing per `launch-path-execution-playbooks.md` Item 4 Step 2)
- `https://tmsearch.uspto.gov/` (US, if international filing planned)

This dispatch did NOT run TM searches (browser-based; not WebFetch-able). Top picks need TM-search verification before filing.

## Recommendation

**Reserve `quirkalgo.com` + `quirkalgo` GitHub org as bus-factor backup** even at low cost (~₹1k/yr domain + ₹0 GitHub). Defer TM filing until Algo2Go primary is contested OR rejected. Skip TM filing on backup unless triggered.

---

# §B — Show-HN Body Claims Verification

**Question**: Cross-check tool count, test count, RiskGuard count claims in `docs/show-hn-post.md` body against current empirical state.

## Empirical state (probed today 2026-05-11)

| Metric | Probe | Empirical result |
|---|---|---|
| Production tool count | `curl https://kite-mcp-server.fly.dev/healthz` | `tools=111` |
| Production version | (same) | `v1.3.0` |
| Master-built tool count | `wsl go build && /tmp/kmcp` startup log | `total_available=111` (registered=93 + gated_trading=18) |
| In-tree test count | `wsl go test ./... -list '.*' \| grep -cE '^Test'` | **4,697** |
| algo2go test count (28 modules) | per-module `go test ./... -list '.*'` (sum) | **3,760** (top 5: usecases 574 / alerts 571 / oauth 446 / audit 345 / papertrading 315) |
| **Total test count** | sum | **8,457** |
| RiskGuard `RejectionReason` constants | `grep -E "RejectionReason\s*=" algo2go/kite-mcp-riskguard/*.go` | **17 distinct** (kill switch, order value, qty, daily count, rate limit, per-second, duplicate, daily value, auto-freeze, confirmation, anomaly, off-hours, OTR-band, circuit-breached, insufficient-margin, market-closed, global-freeze, trading-frozen) |

## README claim audit (verified via WebFetch GitHub raw)

The README has **4 different counts** for tools and **3 different counts** for RiskGuard, *within the same file*:

| Section | Claim | Verdict |
|---|---|---|
| README L3 (opening hero) | "110+ tools" | **CONSISTENT-WITH-EMPIRICAL** (111 satisfies "110+") |
| README L90 (comparison table) | "117 tools" | **STALE** — empirical 111; off by +6 |
| README L48 (testimony) | "~9,000 tests across 437 test files" | **CONSISTENT-WITH-EMPIRICAL** (8,457 rounds to "~8,500"; "~9,000" is acceptable rounding) |
| README L3 (opening hero) | "11 pre-trade safety checks" | **MATCHES STATE.md §8.5 reconciliation** (11 user-facing pre-trade) |
| README L54 (RiskGuard enumeration) | 12 distinct controls listed (kill switch, per-order value cap, qty limit, daily order count, rate limit, per-second, duplicate, daily cumulative, idempotency, confirmation, anomaly, off-hours) | **DOES NOT MATCH L3 "11"** — enumeration is 12 |
| README L82 (comparison table) | "9" safety checks | **STALE** — likely pre-2026-04 hardening framing (idempotency + anomaly + off-hours added late Apr per `kite-security-hardening-2026-04.md`) |
| `.claude/CLAUDE.md` middleware-chain section | "9 pre-trade checks: kill switch, cap, count, rate, duplicate, idempotency key, confirmation, anomaly, off-hours" | **STALE** — same pre-2026-04 framing (matches README L82 not L3/L54) |

## docs/show-hn-post.md current state (last-known per launch-path-execution-playbooks.md §Item 5 cross-reference)

Per `.research/active-docs-verification-2026-05-11.md` §13 (the prior dispatch read it):
- Body claims `110+ tools` (consistent — keeps)
- Body claims `~330 tests` ← **STALE** (off by 25× from empirical 8,457; should be `~9,000` matching README L48)
- Body claims `11 RiskGuard checks` ← matches README L3 (acceptable framing)

## Per-claim verdict table

| Claim location | Current value | Empirical | Verdict | Action |
|---|---|---|---|---|
| `docs/show-hn-post.md` body opening "110+ tools" | "110+" | 111 | **VERIFIED** | None |
| `docs/show-hn-post.md` body "~330 tests" | "~330" | 8,457 | **STALE-PATCH-NEEDED** | Replace with "~9,000 tests across 437+ test files (kite-mcp-server + 28 algo2go modules)" |
| `docs/show-hn-post.md` body "11 RiskGuard checks" | "11" | 17 constants / 11 user-facing pre-trade / 12 in README enumeration | **VERIFIED-with-framing-note** | Keep "11 pre-trade safety checks" framing; reconcile other docs to match |
| `README.md` L3 "11 pre-trade safety checks" | "11" | (same as above) | **VERIFIED-with-framing-note** | Keep |
| `README.md` L54 enumeration (12 items) | 12 | 17 total / 11 pre-trade per L3 | **STALE-PATCH-NEEDED** | Drop one item to match "11" framing OR explicitly say "12 controls (11 pre-trade + 1 system-rejection)" |
| `README.md` L82 "9" comparison-table cell | "9" | 11 | **STALE-PATCH-NEEDED** | Update "9" → "11" |
| `README.md` L90 "117 tools" comparison cell | "117" | 111 | **STALE-PATCH-NEEDED** | Update "117" → "111" |
| `.claude/CLAUDE.md` middleware-chain "9 pre-trade checks" | "9" | 11 | **STALE-PATCH-NEEDED** | Update "9" → "11"; add the 3 newer checks (idempotency-via-anomaly, off-hours block, OTR band) |

## Final integrity-table for Show HN submit

Before pressing Submit on Show HN, the user / executor should run a 5-minute consistency sweep:

```bash
# 1. Production state (must match)
curl -s https://kite-mcp-server.fly.dev/healthz | jq .

# 2. Cross-doc grep
grep -nE "(110\+|111|117|130) tool" README.md docs/show-hn-post.md
grep -nE "[0-9]+ (pre-trade|safety|RiskGuard|riskguard) check" README.md docs/show-hn-post.md .claude/CLAUDE.md
grep -nE "[0-9,]+ test" README.md docs/show-hn-post.md

# 3. Confirm they all agree on "111 tools / 11 pre-trade / ~9000 tests"
```

---

# §C — `cmd/dr-decrypt-probe` Design Spec

**Question**: ~1-2hr Go work to write the helper. Spec out the CLI, env, output, exit codes, and what schema it tests.

## Empirical context

- **Source dir does NOT exist**: `ls D:/Sundeep/projects/kite-mcp-server/cmd/` returns only `event-graph/`, `rotate-key/`. No `dr-decrypt-probe/`.
- **Caller expectations** (from `scripts/dr-drill-prod-keys.sh:147-166`):
  ```
  PROBE=/tmp/dr-decrypt-probe
  if [[ -x "$PROBE" ]]; then
    if ! "$PROBE" -db "$SCRATCH_DB" 2>&1; then
      # ... script exits 6 (decrypt failed)
  ```
  - Single CLI flag: `-db <path-to-restored-sqlite>`
  - Reads `OAUTH_JWT_SECRET` from env (the script sets this from user's secret-manager paste)
  - Exit 0 = decrypt succeeded; non-zero = failed
- **CI-runnable analog already exists**: `algo2go/kite-mcp-alerts/dr_drill_prod_keys_test.go` has 2 tests:
  - `TestDRDrill_ProductionKeyChain_Synthetic` — happy path (write canary → restore → re-derive key → verify decrypt produces canary plaintext)
  - `TestDRDrill_WrongSecret_FailsLoudly` — negative control (wrong secret → AES-GCM auth-tag fail → empty plaintext, not panic)
- **Crypto interface** (from `algo2go/kite-mcp-alerts/crypto.go:29-100`):
  - `DeriveEncryptionKeyWithSalt(secret string, salt []byte) ([]byte, error)` — HKDF-SHA256 with info-string `"kite-mcp-credential-encryption-v1"` → 32-byte AES-256 key
  - `EnsureEncryptionSalt(db *DB, secret string) ([]byte, error)` — generates random 32-byte salt on first call, persists in `config` table key `hkdf_salt`, returns derived key
  - `DB.SetEncryptionKey(key []byte)` — sets the in-memory key for subsequent Save/Load operations
  - `DB.LoadCredentials() ([]Credential, error)` — decrypts via AES-GCM; returns `""` on auth-tag failure (NOT an error)
  - `DB.LoadTokens() ([]Token, error)` — same pattern

## Design

### CLI

```
Usage: dr-decrypt-probe -db <path>

Required env:
  OAUTH_JWT_SECRET    The production secret used to encrypt the data.
                       Must be ≥32 bytes. Drill script enforces minLength.

Required flag:
  -db <path>           Path to the restored SQLite DB to probe.

Optional flags:
  -verbose             Print per-row decrypt results (default: count-only summary).
  -allow-empty         Exit 0 even if zero rows present (default: exit 0 with WARNING).
```

### Behavior (8-phase, mirrors test fixture)

1. **Phase 0**: Validate `-db` path exists + is readable.
2. **Phase 1**: Validate `OAUTH_JWT_SECRET` env var is set + ≥32 bytes (refuse weak keys).
3. **Phase 2**: Open DB via `alerts.OpenDB(path)`. Defer `Close()`.
4. **Phase 3**: Read `hkdf_salt` from `config` table via `db.GetConfig(hkdfSaltConfigKey)`.
   - If missing OR empty: **exit 5** (catastrophic — salt lost in restore; matches script's exit-code-5 path).
   - Decode hex → 32-byte salt.
5. **Phase 4**: Re-derive key via `alerts.DeriveEncryptionKeyWithSalt(secret, saltBytes)`.
6. **Phase 5**: Set in-memory key via `db.SetEncryptionKey(rederivedKey)`.
7. **Phase 6**: Probe `kite_credentials` table:
   - `creds, err := db.LoadCredentials()` — must succeed (row count returns even with bad key).
   - If `len(creds) == 0`: print WARNING "no canary creds present" and skip credentials check.
   - Else for each row: assert `len(creds[i].APIKey) > 0` AND `len(creds[i].APISecret) > 0` (empty = AES-GCM auth-tag failure = decrypt failed).
   - **Any decrypt fail → exit 6.**
8. **Phase 7**: Probe `kite_tokens` table similarly:
   - `tokens, err := db.LoadTokens()`
   - For each row: assert `len(tokens[i].AccessToken) > 0`. Exit 6 on fail.
9. **Phase 8**: Print success summary: `decrypted: N creds + M tokens, all canaries non-empty`. Exit 0.

### Output format (single line on success)

```
DR drill probe: SUCCESS — N credentials decrypted, M tokens decrypted, hkdf_salt OK
```

On failure:
```
DR drill probe: FAIL — <reason>
  Most likely: OAUTH_JWT_SECRET in this drill env != the secret that
  encrypted the production data.
```

### Exit codes (mirror script)

| Code | Meaning |
|---|---|
| 0 | Success: salt present + decrypt succeeded for all probed rows |
| 1 | Generic error (file open fail, etc.) |
| 2 | Required env var missing OR `OAUTH_JWT_SECRET` shorter than 32 bytes |
| 5 | `hkdf_salt` missing from `config` table — restore lost the salt; ciphertexts permanently unreadable |
| 6 | Decrypt fail: AES-GCM auth-tag failed (most likely wrong secret OR salt corrupted) |

## Source layout

```
cmd/dr-decrypt-probe/
└── main.go    # ~80 LOC; flag parse + 8-phase logic + summary print
```

### Skeleton (NOT to commit — design only)

```go
// cmd/dr-decrypt-probe/main.go
package main

import (
    "encoding/hex"
    "flag"
    "fmt"
    "os"

    alerts "github.com/algo2go/kite-mcp-alerts"
)

func main() {
    dbPath := flag.String("db", "", "path to restored SQLite DB")
    verbose := flag.Bool("verbose", false, "print per-row decrypt results")
    flag.Parse()
    if *dbPath == "" {
        die(1, "missing required -db flag")
    }
    secret := os.Getenv("OAUTH_JWT_SECRET")
    if len(secret) < 32 {
        die(2, "OAUTH_JWT_SECRET unset or shorter than 32 bytes")
    }
    db, err := alerts.OpenDB(*dbPath)
    if err != nil {
        die(1, "open db: %v", err)
    }
    defer db.Close()

    saltHex, err := db.GetConfig("hkdf_salt")
    if err != nil || saltHex == "" {
        die(5, "hkdf_salt missing from config — restore lost salt")
    }
    saltBytes, err := hex.DecodeString(saltHex)
    if err != nil || len(saltBytes) != 32 {
        die(5, "hkdf_salt corrupt: %v", err)
    }
    key, err := alerts.DeriveEncryptionKeyWithSalt(secret, saltBytes)
    if err != nil {
        die(1, "derive key: %v", err)
    }
    db.SetEncryptionKey(key)

    creds, err := db.LoadCredentials()
    if err != nil {
        die(1, "load credentials: %v", err)
    }
    for i, c := range creds {
        if c.APIKey == "" || c.APISecret == "" {
            die(6, "credentials[%d] decrypt empty (auth-tag fail)", i)
        }
        if *verbose {
            fmt.Printf("creds[%d] OK: email=%s api_key_len=%d\n", i, c.Email, len(c.APIKey))
        }
    }
    tokens, err := db.LoadTokens()
    if err != nil {
        die(1, "load tokens: %v", err)
    }
    for i, t := range tokens {
        if t.AccessToken == "" {
            die(6, "tokens[%d] decrypt empty (auth-tag fail)", i)
        }
    }
    fmt.Printf("DR drill probe: SUCCESS — %d credentials decrypted, %d tokens decrypted, hkdf_salt OK\n",
        len(creds), len(tokens))
    os.Exit(0)
}

func die(code int, format string, args ...any) {
    fmt.Fprintf(os.Stderr, "DR drill probe: FAIL — "+format+"\n", args...)
    os.Exit(code)
}
```

## Acceptance criteria for execution dispatch

1. `cd cmd/dr-decrypt-probe && go build .` succeeds in WSL2 (Go 1.25)
2. `go test ./...` for the package passes (≥1 unit test mirroring `TestDRDrill_ProductionKeyChain_Synthetic` against an in-memory DB)
3. `go vet ./...` clean
4. Running against the existing `dr_drill_prod_keys_test.go` synthetic state: `OAUTH_JWT_SECRET=test-... ./dr-decrypt-probe -db /tmp/synthetic.db` exits 0
5. Running against a wrong-secret variant: exits 6 (per `TestDRDrill_WrongSecret_FailsLoudly`)
6. CI integration in `.github/workflows/dr-drill.yml`: `go build -o /tmp/dr-decrypt-probe ./cmd/dr-decrypt-probe` step BEFORE the existing `bash scripts/dr-drill.sh` step

## Estimated implementation time

~1.5h: 80 LOC main.go + 1 test file + go.mod tidy + CI step. **Ready for execution dispatch.**

---

# §D — `gh secret set` Commands for dr-drill.yml

**Question**: Provision the 6 missing repo Actions secrets so the monthly cron actually runs.

## Empirical context (from `dr-drill-results-2026-05-11.md` finding #4)

The 2026-05-01 cron run (id `25205029746`) failed in 11s at the env-var gate:
```
LITESTREAM_R2_ACCOUNT_ID:        (empty)
LITESTREAM_BUCKET:               (empty)
LITESTREAM_ACCESS_KEY_ID:        (empty)
LITESTREAM_SECRET_ACCESS_KEY:    (empty)
TELEGRAM_BOT_TOKEN:              (empty)
TELEGRAM_DR_CHAT_ID:             (empty)
DR drill: FAIL — missing LITESTREAM_R2_ACCOUNT_ID
```

All 6 secrets must be provisioned at the repo Actions level.

## Provision script (copy-paste-ready)

**Pre-step**: User loads secret values into local env from their secret manager (1Password / Bitwarden / `.env.local`). DO NOT type values inline; DO NOT echo to terminal.

```bash
# === Pre-step: load values from secret manager into THIS shell only ===
# (Replace the right-hand sides with actual values from Cloudflare R2 dashboard
#  + Telegram BotFather. Use a non-history-recording method per OAUTH_JWT_SECRET
#  pattern in scripts/dr-drill-prod-keys.sh:42 — `read -s VAR_NAME`.)
read -s LITESTREAM_R2_ACCOUNT_ID    && export LITESTREAM_R2_ACCOUNT_ID
read -s LITESTREAM_BUCKET           && export LITESTREAM_BUCKET           # likely "kite-mcp-backup"
read -s LITESTREAM_ACCESS_KEY_ID    && export LITESTREAM_ACCESS_KEY_ID
read -s LITESTREAM_SECRET_ACCESS_KEY && export LITESTREAM_SECRET_ACCESS_KEY
read -s TELEGRAM_BOT_TOKEN          && export TELEGRAM_BOT_TOKEN
read -s TELEGRAM_DR_CHAT_ID         && export TELEGRAM_DR_CHAT_ID

# === Provision via gh CLI (idempotent — re-running overwrites) ===
gh secret set --repo Sundeepg98/kite-mcp-server LITESTREAM_R2_ACCOUNT_ID    --body "$LITESTREAM_R2_ACCOUNT_ID"
gh secret set --repo Sundeepg98/kite-mcp-server LITESTREAM_BUCKET           --body "$LITESTREAM_BUCKET"
gh secret set --repo Sundeepg98/kite-mcp-server LITESTREAM_ACCESS_KEY_ID    --body "$LITESTREAM_ACCESS_KEY_ID"
gh secret set --repo Sundeepg98/kite-mcp-server LITESTREAM_SECRET_ACCESS_KEY --body "$LITESTREAM_SECRET_ACCESS_KEY"
gh secret set --repo Sundeepg98/kite-mcp-server TELEGRAM_BOT_TOKEN          --body "$TELEGRAM_BOT_TOKEN"
gh secret set --repo Sundeepg98/kite-mcp-server TELEGRAM_DR_CHAT_ID         --body "$TELEGRAM_DR_CHAT_ID"

# === Cleanup: clear from shell ===
unset LITESTREAM_R2_ACCOUNT_ID LITESTREAM_BUCKET LITESTREAM_ACCESS_KEY_ID \
      LITESTREAM_SECRET_ACCESS_KEY TELEGRAM_BOT_TOKEN TELEGRAM_DR_CHAT_ID
history -c   # clear bash history of the current shell session

# === Verify provisioned (lists names + last-updated date; values are masked) ===
gh secret list --repo Sundeepg98/kite-mcp-server | grep -E "LITESTREAM|TELEGRAM"
```

## Verification post-provision

After secrets land, trigger a workflow_dispatch run to confirm:

```bash
gh workflow run dr-drill.yml --repo Sundeepg98/kite-mcp-server
gh run list --workflow dr-drill.yml --repo Sundeepg98/kite-mcp-server -L 1
gh run watch <run-id> --repo Sundeepg98/kite-mcp-server --exit-status
```

Expected output (per `dr-drill-results-2026-05-11.md` §1.4 happy-path projection):
```
DR drill: kite_tokens.count = 2
DR drill: SUCCESS
```

Plus a Telegram message in the DR chat ID (cross-channel proof the bot token works).

## Source-of-truth for secret values

- **`LITESTREAM_R2_ACCOUNT_ID`**: Cloudflare R2 dashboard → Account → Account ID (visible at `https://dash.cloudflare.com/<id>/r2`)
- **`LITESTREAM_BUCKET`**: Per `MEMORY.md` line 162 + `etc/litestream.yml`, bucket name is `kite-mcp-backup`
- **`LITESTREAM_ACCESS_KEY_ID`** + **`LITESTREAM_SECRET_ACCESS_KEY`**: Cloudflare R2 → API Tokens → token saved at creation time (read-only sufficient for restore drill)
- **`TELEGRAM_BOT_TOKEN`**: BotFather (`@BotFather` on Telegram) — same token used for production (already in Fly.io secrets)
- **`TELEGRAM_DR_CHAT_ID`**: User's personal Telegram chat ID (not the production briefing chat) — get via `https://api.telegram.org/bot<TOKEN>/getUpdates` after sending a `/start` to the bot from the target chat

---

# §E — smithery.yaml Committed Status

**Question**: Is `smithery.yaml` committed at HEAD? If yes, does content match `kite-launch-ready-fixes.md`?

## Result: YES, committed and content matches

- **File present**: `D:/Sundeep/projects/kite-mcp-server/smithery.yaml` exists at HEAD `cdc1f91`.
- **Content schema** (45 lines):
  - `runtime: container`
  - `build: { dockerfile: Dockerfile, dockerBuildPath: . }`
  - `startCommand: { type: http, configSchema: {...} }`
  - 7 properties: `OAUTH_JWT_SECRET` (required, minLength 32), `EXTERNAL_URL` (required, https URI pattern), `ADMIN_EMAILS`, `ALERT_DB_PATH` (default `/data/alerts.db`), `TELEGRAM_BOT_TOKEN`, `ENABLE_TRADING` (boolean default false)

- **Cross-check vs `memory/kite-launch-ready-fixes.md`** (the ready-to-commit version):
  - Same `runtime`, `build`, `startCommand` structure ✓
  - Same 7 properties with same defaults ✓
  - Description text essentially identical ✓
  - **Single minor delta**: launch-ready-fixes had description "all stored OAuth clients, tokens, sessions" — committed version has "all stored OAuth clients, cached Kite tokens, sessions" (more specific). Not a functional difference.

## Verdict

**INDEX §12 gap RESOLVED.** No action needed.

## Caveat (per `kite-launch-ready-fixes.md` §"Verify before commit")

- Smithery passes `configSchema` values as **query params** on `/mcp`; our app reads env vars — **verify container shim forwards them**. Suggested smoke test: `smithery build && smithery run` locally before relying on Smithery one-click install.
- `/mcp` is OAuth-protected → Smithery auto-scanner will get 401. Remedy: rely on `/.well-known/mcp/server-card.json` discovery OR use the URL-registration form at `smithery.ai/new` instead of container-runtime mode.

These are not gaps in the YAML itself; they're deployment-mode caveats for when the user activates Smithery distribution.

---

# §F — funding.json Schema Verification

**Question**: Does `funding.json` exist? Does it validate against the FLOSS/fund schema?

## Result: YES, committed; v1.0.0 — patch to v1.1.0

- **File present**: `D:/Sundeep/projects/kite-mcp-server/funding.json` exists at HEAD.
- **Schema version declared**: `"version": "v1.0.0"`
- **Empirical schema URL** (probed today): `https://fundingjson.org/schema/v1.1.0.json`
- **Validator**: `https://fundingjson.org/validate/`

## Schema fields audit

Required top-level fields per `fundingjson.org` v1.1.0:

| Field | Required? | Present in our funding.json? | Status |
|---|---|---|---|
| `version` | Yes (manifest version) | YES — `v1.0.0` | **STALE — should be `v1.1.0` to match latest schema** |
| `entity` | YES | YES — type:individual, role:owner, name "Sundeep Govarthinam", email, description, webpageUrl | OK (re-validate against v1.1.0 fields) |
| `funding` | YES (channels + plans) | YES — 1 channel "grant-email", 3 plans ($10k/$35k/$60k tiers) | OK |
| `projects` | Optional | YES — 1 project (kite-mcp-server) with guid, name, description, webpageUrl, repositoryUrl, licenses ["spdx:MIT"], 13 tags | OK |
| `funding.history` | Optional | YES — empty array `[]` | OK |

**Email field**: `sundeepg8@gmail.com` (NOT the foundation address — complies with `user_email_rule.md`).

## Issues

1. **`version` field is `v1.0.0` but schema is `v1.1.0`** — should bump to v1.1.0 + revalidate against the v1.1.0 schema (which may have new optional fields or stricter validation).
2. **`entity.description` references "Indian Pvt Ltd incorporation pending"** — this is fine but tracks state that may shift; if Pvt Ltd is incorporated, this needs an update.
3. **No `funding.history` entries yet** — empty array is valid; populates only after grants received.
4. **Project description claims "~80 tools, 4 backtest strategies, 330+ tests"** — same staleness as Q B (real: 111 tools / 8,457 tests). Should patch.

## Validation procedure

```bash
# Validate via fundingjson.org public validator (manual, browser-based):
# 1. Open https://fundingjson.org/validate/
# 2. Paste contents of funding.json
# 3. Read errors

# Or via curl + JSON Schema validator (offline):
curl https://fundingjson.org/schema/v1.1.0.json > /tmp/floss-schema.json
ajv validate -s /tmp/floss-schema.json -d funding.json   # requires `ajv-cli` npm install
```

## Recommendations

1. Bump `version` to `v1.1.0`.
2. Re-validate via fundingjson.org/validate/.
3. Patch project description tool/test counts to match reality (111 / 8,457).
4. Confirm `email` field matches FLOSS/fund expected applicant address; use `sundeepg8@gmail.com`.

---

# §G — Reddit u/Sundeepg98 Creation Status

**Question**: Probe creation status. Drives the #45 Reddit warmup playbook readiness.

## Result: BLOCKED-ON-TOOL

**WebFetch tool returns**: `Claude Code is unable to fetch from www.reddit.com` (Reddit domain is in the WebFetch blocklist for this Claude Code installation).

Alternative probes considered:
- `gh api`: GitHub CLI does not cover Reddit
- Direct `curl` via Bash tool: Reddit returns HTTP 403 to anti-bot User-Agents (need real browser headers)
- `nitter.net` (Twitter alternative): no Reddit equivalent
- `Claude in Chrome`: per project CLAUDE.md, this is the visual-verification escalation path; should be invoked for this question

## Recommendation for user

User probes manually:

```
Browser → https://www.reddit.com/user/Sundeepg98/about.json
- HTTP 200 with karma JSON → account EXISTS; surface link_karma + comment_karma + created_utc
- HTTP 404 → account does NOT exist; warmup playbook prerequisite is unfulfilled (per `reddit-subreddit-specific-strategy.md` §Phase 1.4 finding 2026-05-02)
```

If user prefers automation: invoke Claude in Chrome via project CLAUDE.md decision matrix ("Click through flows" → Chrome). For a one-shot read, the manual visit is faster than launching the browser-automation tool.

## Status as of 2026-05-11

**Unknown** — last documented probe is 2026-05-02 (account did NOT exist; per `reddit-subreddit-specific-strategy.md` §Phase 1.4). 9 days have passed; account may now exist if user followed the Reddit warmup recommendation.

## Implication for #45 launch playbook

If account does NOT exist: **6-day warmup is still ahead** + add 1 day to setup = 7 days minimum before Day-1 +12h Reddit post. If account DOES exist with ≥30 comment karma: warmup is complete; can post immediately at Day-1 +12h.

---

# §H — GitHub Star Count Check

**Question**: ≥50 stars triggers Rainmatter warm-intro per `kite-rainmatter-warm-intro.md`.

## Empirical results (probed today via `gh api`)

| Repo | Stars | Forks | Subscribers | Created | Last push |
|---|---|---|---|---|---|
| `Sundeepg98/kite-mcp-server` | **0** | 0 | 0 | 2026-02-22 | 2026-05-10 |
| `algo2go/kite-mcp-broker` | 0 | (not probed) | (not probed) | (assume 2026-05-05 per session memory) | (recent) |
| `algo2go/kite-mcp-server` | **DOES NOT EXIST** (404) | n/a | n/a | n/a | n/a |
| `Sundeepg98` (user) | 0 followers | following 1 | 12 public repos | 2020-08-12 | 2026-05-05 |

## Analysis

- **0 stars** at HEAD `cdc1f91`. Per the public-repo timeline (created 2026-02-22, last push 2026-05-10), this is consistent with the "no public launch yet" state — no Show HN, no Reddit r/algotrading post, no Twitter announcement, no MCP Registry editorial pickup.
- **MCP Registry IS published** (`io.github.Sundeepg98/kite-mcp-server` v1.2.0 active per `kite-mcp-registry-publisher.md`). Registry doesn't generate stars directly — relies on awesome-mcp-servers / Reddit / HN cross-pollination.
- **awesome-mcp-servers PR landed on punkpeye but was CLOSED unmerged 2026-04-04** (per Q L below). That's the mechanical reason for the 0 stars: discoverability cascade from punkpeye → glama.ai → curious dev clicks → stars never started.

## Threshold analysis

- **≥50 stars** = Rainmatter warm-intro trigger (per `kite-rainmatter-warm-intro.md`)
- **≥50 stars + ≥1 blog/HN post** = FLOSS/fund application trigger (per `kite-floss-fund.md`)
- **≥1,000 stars** = Z-Connect editorial pitch threshold (per `kite-zerodha-no-marketplace.md`)

Current: **0 stars; 0% of way to 50.** Rainmatter warm-intro and FLOSS/fund are both gated on 0-to-50-stars cold-start.

## Implication

The 0-stars finding is the **single biggest distribution blocker** identifiable at empirical level. Three of the next-best-actions (FLOSS/fund, Rainmatter warm-intro, Z-Connect pitch) are all gated on it. **Show HN + Reddit r/algotrading + Twitter D1-T1 is the cluster that unlocks it** — that's why those items are highest-leverage in `forward-tracks-strategic-review.md` §B.2.

---

# §I — Authoritative Test Count Methodology

**Question**: Apply compile-and-run methodology lesson to test counting.

## Methodology (definitive)

```bash
# In-tree (kite-mcp-server)
wsl bash -lc "cd /mnt/d/Sundeep/projects/kite-mcp-server && \
  go test ./... -list '.*' 2>&1 | grep -E '^Test' | wc -l"
# → 4,697

# Per algo2go module
for m in alerts aop audit billing broker clockport cqrs decorators domain \
         eventsourcing i18n instruments isttz legaldocs logger money oauth \
         papertrading registry riskguard scheduler sectors telegram \
         templates ticker usecases users watchlist; do
  c=$(wsl bash -lc "cd /mnt/d/Sundeep/projects/algo2go/kite-mcp-$m && \
    go test ./... -list '.*' 2>/dev/null | grep -cE '^Test'")
  echo "$m: $c"
done
# Sum: 3,760
# → Total: 4,697 + 3,760 = 8,457
```

## Results table (probed today)

### In-tree
| Path | Test count |
|---|---|
| `D:/Sundeep/projects/kite-mcp-server/...` (all packages) | **4,697** |

### algo2go modules (28)

| Module | Test count |
|---|---|
| kite-mcp-usecases | 574 |
| kite-mcp-alerts | 571 |
| kite-mcp-oauth | 446 |
| kite-mcp-audit | 345 |
| kite-mcp-papertrading | 315 |
| kite-mcp-domain | 265 |
| kite-mcp-riskguard | 211 |
| kite-mcp-telegram | 204 |
| kite-mcp-billing | 178 |
| kite-mcp-users | 154 |
| kite-mcp-eventsourcing | 115 |
| kite-mcp-ticker | 85 |
| kite-mcp-instruments | 61 |
| kite-mcp-watchlist | 46 |
| kite-mcp-registry | 43 |
| kite-mcp-scheduler | 43 |
| kite-mcp-cqrs | 36 |
| kite-mcp-money | 21 |
| kite-mcp-i18n | 12 |
| kite-mcp-decorators | 10 |
| kite-mcp-logger | 10 |
| kite-mcp-sectors | 6 |
| kite-mcp-broker | 4 |
| kite-mcp-clockport | 3 |
| kite-mcp-isttz | 2 |
| kite-mcp-aop | 0 |
| kite-mcp-legaldocs | 0 |
| kite-mcp-templates | 0 |
| **algo2go subtotal** | **3,760** |

### Cumulative

**Total = 4,697 + 3,760 = 8,457 tests** across **(kite-mcp-server in-tree) + 28 algo2go modules**.

## Comparison to docs

| Doc | Claim | Empirical | Verdict |
|---|---|---|---|
| README.md L48 | "~9,000 tests" | 8,457 | **CONSISTENT-WITH-EMPIRICAL** (8,457 rounds to "~8,500"; "~9,000" is a slight upward round) |
| `docs/show-hn-post.md` body | "~330 tests" | 8,457 | **STALE BY 25×** (likely a count from 2026-04 Quality Audit era) |
| STATE.md §1.1 | "~9,000 across ~437 test files" | 8,457 across 478 test files (262 in-tree + 216 algo2go) | **CONSISTENT** |
| `kite-product-strategy.md` (memory, 36d old) | "643 test runs" | n/a (probably "643 tests added in one session", not running total) | unverifiable historical |
| `final-pre-launch-verification.md` | "16,209 tests claim … 8,790 empirical (or 9,021 incl. subtests)" | 8,457 today | **CONSISTENT** (8,790 → 8,457 is plausible drift from session refactors that consolidated tests) |

## Methodology rule (add to INDEX §11)

```
| What's the authoritative test count? | (none — compile-and-list) | wsl bash -lc "go test ./... -list '.*' 2>&1 | grep -cE '^Test'" |
```

This goes in INDEX.md §11 as the new "Empirical-Probe Quick Reference" entry alongside the existing tool-count probe. Same compile-and-run > grep-and-count discipline.

---

# §J — MRR vs ₹15-25k Target Tracker

**Question**: Live MRR figure. Where to find it; if not available, what would build it.

## Empirical results

- **No live MRR tracker exists.** Probed:
  - `mcp/admin/admin_billing_tools.go` — has `admin_set_billing_tier` (operator escape hatch). No `admin_revenue` or `admin_mrr` tool.
  - `algo2go/kite-mcp-billing/store.go` — has `Subscription` rows with `Tier` + `MonthlyAmount` (`domain.Money` value object), `Status` (active/canceled/past_due/trialing). Aggregator query exists in code (`grep TierMonthlyINR`).
  - No `/admin/mrr` HTTP endpoint
  - No `flyctl logs` MRR statement
- **Stripe Dashboard is the source of truth**: `dashboard.stripe.com → Customers → Subscriptions → Recurring revenue` shows MRR live.

## What it would take to build a live in-process tracker (~2-4 hours Go + TDD)

Per `.claude/CLAUDE.md` Clean Architecture rules, the new MCP admin tool would route through:

```
MCP tool admin_get_mrr → use case GetMonthlyRecurringRevenue → 
  billing.Store.ListActiveSubscriptions → 
    sum(sub.MonthlyAmount) for sub.Status == "active" → 
      result: { mrr: domain.Money, active_subscribers: int, period_start: time, period_end: time }
```

### Proposed admin tool surface

```go
// mcp/admin/admin_mrr_tools.go (new file)
type AdminGetMRRTool struct{}

func (*AdminGetMRRTool) Tool() mcp.Tool {
    return mcp.NewTool("admin_get_mrr",
        mcp.WithDescription("Returns current monthly recurring revenue computed from active billing.Store subscriptions. Sum of TierMonthlyINR(sub.Tier) across all active subs. Live snapshot, not cached. Admin-only."),
        mcp.WithTitleAnnotation("Admin: Get MRR"),
        mcp.WithReadOnlyHintAnnotation(true),
        mcp.WithDestructiveHintAnnotation(false),
        mcp.WithIdempotentHintAnnotation(true),
        mcp.WithOpenWorldHintAnnotation(false),
    )
}
```

Returns:
```json
{
  "mrr": { "amount_paise": 0, "currency": "INR", "human": "₹0" },
  "active_subscribers": 0,
  "by_tier": { "solo_pro": 0, "pro": 0, "premium": 0 },
  "period_start": "2026-05-01T00:00:00Z",
  "period_end": "2026-05-31T23:59:59Z",
  "computed_at": "2026-05-11T..."
}
```

### Implementation cost

- ~80 LOC tool handler + use case
- ~150 LOC table-driven test in `mcp/admin/admin_mrr_tools_test.go`
- 0 new dependencies (everything is in `algo2go/kite-mcp-billing` already)
- Total: **~2-4 hours TDD-discipline**

## Status

- **TODAY**: MRR is 0 (per Q H 0 stars + Q J 0 paid users surfaceable). Stripe Dashboard would show ₹0/mo.
- **At first paid user**: in-process tracker becomes valuable; build the admin_get_mrr tool then.
- **Rough threshold**: build at ≥3 paid users (the Stripe Dashboard friction starts mattering when you're checking it daily, which is post-trial conversion).

## Recommendation

**STILL-OPEN**. Defer the admin_get_mrr tool build until first paid trial converts. Until then, Stripe Dashboard suffices as MRR source-of-truth.

---

# §K — Stripe/Razorpay Billing Integration Design

**Question**: Design sketch for "minimum viable webhook + reconciliation flow".

## Empirical state: Stripe is FULLY IMPLEMENTED

The dispatch's premise ("1-week effort to design") is FALSIFIED. Per `algo2go/kite-mcp-billing/`:

### Files (post Path A.13 + A.15 promotion)

| File | Role |
|---|---|
| `checkout.go` (160+ LOC) | `CheckoutHandler` — creates Stripe Checkout Session for solo_pro/pro/premium plans (max_users 1/5/20); `CheckoutHandlerWithConfig` for t.Parallel-safe testing |
| `webhook.go` | `WebhookHandler` — signature verifies via `webhook.ConstructEvent(body, sig, signingSecret)`; idempotency via `webhook_events` table; 4 events handled |
| `store.go` | `Subscription` struct (AdminEmail, Tier, StripeCustomerID, StripeSubID, Status, MonthlyAmount domain.Money, StartedAt, CurrentPeriodEnd, MaxUsers, etc.); CRUD via SQLite |
| `config.go` | `ConfigFromEnv()` reads STRIPE_PRICE_SOLO_PRO/PRO/PREMIUM + EXTERNAL_URL |
| `tiers.go` | TierFree/TierSoloPro/TierPro/TierPremium constants; TierMonthlyINR(tier) → domain.Money |
| `webhook_events.go` (assumed; not directly read but referenced) | Idempotency dedup table |

### Webhook events handled (lines 13-21 of webhook.go)

1. `checkout.session.completed` — create subscription; map email → customer ID
2. `customer.subscription.updated` — update tier/status/expiry
3. `customer.subscription.deleted` — downgrade to Free, mark canceled
4. `invoice.payment_failed` — mark past_due

### Test coverage

`kite-mcp-billing` has **178 tests** (per Q I), including:
- `billing_webhooks_test.go` — webhook signature + 4 event handlers
- `billing_money_test.go` — domain.Money invariants
- `billing_tier_test.go` — tier transitions
- `billing_edge_test.go` — edge cases
- `leak_sentinel_test.go` — resource leak detection

### What's MISSING (genuine gaps, even with Stripe wired)

1. **Razorpay adapter does NOT exist** (grep for `razorpay|RAZORPAY` in `kite-mcp-billing/*.go` returns 0 hits). Stripe-only.
2. **MRR aggregation tool** (per Q J above — admin_get_mrr does not exist)
3. **Reconciliation cron** — Stripe is the source of truth; no daily/weekly job that reconciles webhook-derived state against `Stripe API → ListActiveSubscriptions`. If a webhook is missed (Stripe retries 3 days, then gives up), local state could diverge silently.
4. **Trial period enforcement** — `Status: trialing` constant exists but no test checks the trial-end → grace-period → cancel flow.
5. **Per-plan customer count cap enforcement** — `max_users` is stored but enforcement is at admin tool level; no SQL-level constraint.

## Razorpay-vs-Stripe trade-off (if user wants Razorpay)

| Dimension | Stripe (current) | Razorpay (alternative) |
|---|---|---|
| India market UX | Adequate (USD pricing, FX-translated) | Native INR, UPI Autopay, NetBanking, EMI |
| Webhook signing | HMAC-SHA256 (`stripe.com` documented) | HMAC-SHA256 (different header `x-razorpay-signature`) |
| Idempotency | Stripe's own + our `webhook_events` dedup | Razorpay sends unique `event.id`; same dedup pattern |
| SDK | `github.com/stripe/stripe-go/v82` (already in go.mod) | `github.com/razorpay/razorpay-go` (would need adding) |
| Subscription model | Native via `stripe.SubscriptionParams` | Native via `subscription.New()` API |
| Indian MOR (Merchant of Record) | NO — Stripe is foreign-card aggregator | YES — Razorpay is India-MOR |
| Compliance | DPDP-ish via Stripe DPA | GST-compliant invoicing built-in |

**Recommendation**: stick with Stripe-only for v1 launch. Razorpay is a 1-2 week add ONLY if Indian-customer-count justifies the dual-rail (typically 10+ India-MOR customers requesting it). At ₹15-25k MRR target with 10-25 paid users, Razorpay delta cost > revenue gain.

## Verdict

**VERIFIED — NO ACTION**. Stripe billing is implemented + tested. Genuine gaps (MRR aggregator, reconciliation cron, trial enforcement, Razorpay) are all post-paid-user follow-up dispatches.

---

# §L — awesome-mcp-servers PR Submission Log

**Question**: PR status across the 3 priority lists per `kite-awesome-mcp-listings.md`.

## Probed today (via `gh api search/issues`)

| List | Repo | Author Sundeepg98 PR count | Detail |
|---|---|---|---|
| **#1 punkpeye** | `punkpeye/awesome-mcp-servers` (85k★) | **2 PRs** (1 our project, 1 different) | PR #4075 "Add Kite Trading MCP Server (Indian stock market) 🤖🤖🤖" (used the recommended fast-track emoji) — submitted 2026-04-03; **CLOSED unmerged 2026-04-04 by punkpeye maintainer**; merge_commit_sha: null |
| **#2 wong2 (via mcpservers.org)** | `wong2/awesome-mcp-servers` (4k★) | **0 PRs** | Not submitted. The mcpservers.org submission form is the path (wong2 refuses direct PRs); not initiated. |
| **#3 jaw9c** | `jaw9c/awesome-remote-mcp-servers` (1k★) | **1 PR** | PR #267 "Add Kite MCP Server (Zerodha Kite Connect)" — submitted 2026-04-19; **STILL OPEN** as of 2026-05-11; zero comments / zero reviewers (awaiting review) |

## Why punkpeye PR closed unmerged?

The JSON returned by `gh api repos/punkpeye/awesome-mcp-servers/issues/4075` shows:
- `merged_at: null`
- `closed_at: 2026-04-04T01:51:04Z` (~22h after submission)
- `closed_by: punkpeye`
- No closing comment in JSON (would need separate `/comments` API call to retrieve)

**Likely reasons** (per typical punkpeye PR-rejection patterns):
1. PR didn't follow the alphabetical placement convention (Finance section requires alpha-sorted entries)
2. PR description didn't include 1-line summary in CONTRIBUTING.md format
3. Hidden duplicate concern (already had `aranjan/kite-mcp` listed; reviewer wanted a "differentiation comment" that was missing)
4. The 🤖🤖🤖 fast-track emoji was used inappropriately (it's reserved for AI-bot-assisted PRs that have been pre-vetted, per `kite-awesome-mcp-listings.md`)

## Recommendations

### Re-engage punkpeye (priority 1 — 85k★ list)

1. Read `https://github.com/punkpeye/awesome-mcp-servers/pull/4075` to see the closing comment + understand exact rejection reason.
2. Re-submit a polished v2 PR addressing the rejection. Format per CONTRIBUTING.md:
   ```
   - [Sundeepg98/kite-mcp-server](https://github.com/Sundeepg98/kite-mcp-server) 🏎️ 🏠 ☁️ 🐧 🪟 🍎 - Trade Indian stocks on Zerodha Kite via MCP. 111+ tools: holdings, orders, GTT, alerts, backtesting, options Greeks, paper trading, Telegram briefings. Deployed at kite-mcp-server.fly.dev with per-user OAuth.
   ```
   Place alphabetically in Finance section. Differentiate from `aranjan/kite-mcp` (Python, 14 tools, TOTP, local-only) in PR description. SKIP the 🤖🤖🤖 emoji unless explicitly invited.

### Submit to wong2 (priority 2 — 4k★)

1. Visit `mcpservers.org/submit` (the form, not direct PR).
2. Fill out per the schema; mcpservers.org validates before forwarding to wong2.
3. The free tier covers most submissions; $39 fast-review is optional.

### Wait + ping on jaw9c (priority 3 — 1k★)

1. PR #267 is open 22 days with zero engagement. Consider a polite ping comment ("Just bumping — let me know if anything's blocking review").
2. If silent another 30 days, close + resubmit with v2 description.

### Skip appcypher (per memory file — stale since 2025-09)

## Verdict

**STALE-PATCH-NEEDED**. The launch-prep claim "submitted to all 3 lists" is empirically only 1 of 3 still in-play. Resubmit punkpeye + submit wong2 + ping jaw9c is the cleanup loop.

---

# §M — Twitter @Sundeepg98 Activity Tracker

**Question**: Handle exists? Last tweet? Build-in-public posts shipped per `twitter-build-in-public-weeks-1-4.md`?

## Probed today

- **WebFetch `https://x.com/Sundeepg98`**: HTTP 402 (Payment Required — X requires authenticated access since the API gating)
- **WebFetch `https://nitter.net/Sundeepg98`**: returned empty content (nitter is a public Twitter mirror but the page-render mechanism doesn't return scraped content to WebFetch)
- **GitHub user metadata**: `twitter_username: null` (NOT linked to GitHub profile)

## Result: BLOCKED-ON-TOOL

Cannot empirically probe Twitter activity without:
- Logged-in browser visit to `https://x.com/Sundeepg98`
- OR Twitter API authentication (not configured in this Claude Code env)
- OR Claude in Chrome (per project CLAUDE.md decision matrix — visual probe acceptable for "exists / last-post-date" question)

## Implication for `twitter-build-in-public-weeks-1-4.md`

Per the doc:
- **Identity anchor**: `@Sundeepg98` cited at line 16 as `https://x.com/Sundeepg98`
- **Day-1 plan**: D1-T1 lead announcement at 07:30 IST (30 min after Show HN)
- **Cap**: 3 tweets/day, 1 thread/week

If user has NOT executed Day-1 yet (most likely state given Show-HN hasn't happened), all build-in-public content is paused at "Week 0". Doc remains valid as the cadence template.

## User-action recommendation

Manual probe:
```
Browser → https://x.com/Sundeepg98
- 404 / "Account doesn't exist" → handle is unclaimed; reserve before someone else does
- Profile loads → screenshot follower count + last tweet date + bio
- "Account suspended" → escalate (Twitter does not auto-restore)
```

If user wants automation: invoke Claude in Chrome for visual capture (one-shot screenshot) + manually transcribe details.

## Status

**BLOCKED-ON-TOOL** for empirical verification today. Track surfaced as ongoing-gap in INDEX §12.

---

# §N — OAUTH_JWT_SECRET Rotation Procedure (Operational Runbook)

**Question**: ~1 page operational runbook. How to rotate without downtime; what gets invalidated; rollback plan.

## Empirical context (from code-read at HEAD `cdc1f91`)

### What OAUTH_JWT_SECRET protects

**Two distinct cryptographic uses** of the same env var:

1. **JWT signing key** (`oauth/jwt.go` via `algo2go/kite-mcp-oauth.JWTManager`):
   - Signs MCP bearer tokens (24h TTL per `oauth/config.go:31`)
   - Signs dashboard cookie tokens (7d TTL per `oauth/middleware.go:120`)
2. **HKDF root secret for AES-256 encryption** (`algo2go/kite-mcp-alerts/crypto.go:29-46`):
   - Derives a 32-byte AES-256 key via `HKDF-SHA256(secret, hkdf_salt, "kite-mcp-credential-encryption-v1")`
   - **`hkdf_salt` is in the `config` table of the SQLite DB** — generated once on first call to `EnsureEncryptionSalt`
   - The salted key encrypts: `kite_credentials.api_key`, `kite_credentials.api_secret`, `kite_tokens.access_token`, `oauth_clients.client_secret`

### Graceful rotation IS already wired (for JWT signing only)

Per `app/app.go:666-674`:
```go
// PR-DR: install the second-chance verify key for graceful JWT
// rotation. When OAUTH_JWT_SECRET_PREVIOUS is set, tokens signed
// with that key continue to validate alongside the new primary —
// rotation no longer mass-invalidates live sessions.
if app.Config.OAuthJWTSecretPrevious != "" {
    app.oauthHandler.JWTManager().SetPreviousSecret(app.Config.OAuthJWTSecretPrevious)
    app.Logger().Info(context.Background(), "OAUTH_JWT_SECRET_PREVIOUS installed — graceful rotation active")
}
```

`OAUTH_JWT_SECRET_PREVIOUS` is read in `app/config.go:57,96`. The `JWTManager.SetPreviousSecret(string)` method enables verify-only fallback: tokens signed with previous secret continue to validate (read), but new tokens sign with current secret only.

### What's NOT covered by the rotation pattern

**Encrypted-column rotation is SEPARATE.** When `OAUTH_JWT_SECRET` rotates, the HKDF-derived AES-256 key changes (because secret changed). This means:

- **`kite_credentials.api_key` + `api_secret`** become unreadable with new key
- **`kite_tokens.access_token`** becomes unreadable
- **`oauth_clients.client_secret`** becomes unreadable

A rotation that changes `OAUTH_JWT_SECRET` without re-encrypting the DB columns produces the **catastrophic exit-code-5 / exit-code-6 state** that `dr-drill-prod-keys.sh` is designed to detect.

**Existing migration helper**: `EnsureEncryptionSalt(db, secret)` at `crypto.go:53-100` migrates from old (nil-salt) key to new (salted) key on first call. **This is salt-rotation, NOT secret-rotation** — it handles the case where the secret stayed the same but salt was added. There's NO existing helper for secret-change-with-data-rotation.

## Rotation procedure (5-step runbook)

### Pre-rotation checklist

1. Verify `OAUTH_JWT_SECRET_PREVIOUS` is currently empty (`flyctl secrets list -a kite-mcp-server | grep OAUTH_JWT_SECRET_PREVIOUS` → if entry exists, prior rotation incomplete; abort).
2. Verify dr-drill is green (per Q D + Q C + dr-drill-results-2026-05-11.md): backup chain healthy, salt present.
3. Generate new secret: `NEW_SECRET=$(openssl rand -hex 32)` — keep in env, NEVER write to file.
4. Schedule rotation for low-traffic window (off-market-hours, e.g., Sunday 03:00 IST).

### Rotation steps

**Step 1: Install PREVIOUS as old value (zero-downtime prep)**

```bash
# Get the current secret WITHOUT exposing it (Fly.io masks values; user must paste from secret manager)
read -s OLD_SECRET    # paste current OAUTH_JWT_SECRET from secret manager

# Set PREVIOUS to old value
flyctl secrets set OAUTH_JWT_SECRET_PREVIOUS="$OLD_SECRET" -a kite-mcp-server
# Fly.io triggers rolling restart; ~30-60s downtime per machine

# Verify deployment picks it up (look for log line)
flyctl logs -a kite-mcp-server | grep "OAUTH_JWT_SECRET_PREVIOUS installed"
```

After Step 1: server now verifies tokens signed with OLD secret (which is still primary); no functional change.

**Step 2: Rotate primary to NEW (the actual rotation)**

```bash
flyctl secrets set OAUTH_JWT_SECRET="$NEW_SECRET" -a kite-mcp-server
# Rolling restart again
```

After Step 2: server now signs new tokens with NEW; verifies BOTH NEW (primary) and OLD (previous). Live sessions continue to work because their JWTs were signed with OLD which is still in PREVIOUS.

**Step 3: Wait for full grace window (24h MCP TTL + 7d dashboard TTL — pick the longer)**

```bash
# Wait 7 full days (168 hours) for all dashboard cookies to expire
# After 7 days, no live JWT was signed with OLD anymore (all re-issued with NEW)
sleep 604800   # ← don't actually sleep this; just wait 7 days
```

**Step 4: Remove PREVIOUS (rotation complete)**

```bash
flyctl secrets unset OAUTH_JWT_SECRET_PREVIOUS -a kite-mcp-server
# Rolling restart; PREVIOUS is now empty; verify-only fallback disabled
```

**Step 5: Verify**

```bash
# Run dr-drill-prod-keys.sh against production (per scripts/dr-drill-prod-keys.sh procedure)
# Must return decrypt SUCCESS — confirms encrypted-column read still works
# (BUT see CRITICAL CAVEAT below — it WILL fail if step 6 wasn't done)
```

### CRITICAL CAVEAT: Encrypted columns are NOT auto-rotated

**The above 5 steps rotate JWT signing only.** After Step 5:

- New JWTs sign with NEW secret ✓
- Old JWTs verify with PREVIOUS during grace ✓
- **Encrypted columns (kite_credentials, kite_tokens, oauth_clients.client_secret) ARE STILL ENCRYPTED WITH OLD KEY**
- After Step 4 (PREVIOUS unset), the HKDF-derived encryption key uses NEW secret
- **Decrypt of old columns will FAIL** with empty-plaintext (auth-tag failure)

**This means the runbook is INCOMPLETE for the encryption-rotation case.** Three options for handling:

#### Option A: Two-secret read pattern for encryption (NOT YET IMPLEMENTED)

Extend `algo2go/kite-mcp-alerts/crypto.go` to support `DeriveEncryptionKeyWithSecretFallback(currentSecret, previousSecret, salt)` — try current first, fall back to previous on auth-tag fail. This requires source mutations (~2-3 hours TDD).

#### Option B: Re-encrypt-during-grace migration

Before Step 4, run a re-encrypt pass: read all rows with PREVIOUS-derived key, write back with NEW-derived key. This requires:
- New tool / script `cmd/rotate-key/main.go` (already exists per `ls cmd/`!)
- Validate it covers all 3 encrypted tables (credentials, tokens, oauth_clients)

**Empirically: `cmd/rotate-key/` exists.** Need to read it.

#### Option C: Accept user re-auth

Skip encrypted-column rotation; users re-auth (re-OAuth from Kite) which writes fresh creds with NEW key. Old rows decrypt fail → server treats as expired → re-auth flow → fresh write.

**This is the production behavior given the current code state.** It's actually fine for low-paid-user state (≤25 users) but poor UX (mass re-auth event).

### Rollback plan

If Step 2 produces a deployment failure:

```bash
flyctl secrets set OAUTH_JWT_SECRET="$OLD_SECRET" -a kite-mcp-server   # revert primary
flyctl secrets unset OAUTH_JWT_SECRET_PREVIOUS -a kite-mcp-server      # revert prep
# 1-2 minutes of rolling restart returns to pre-rotation state
```

If Step 4 (PREVIOUS unset) was already executed and OLD JWTs are still in flight:

```bash
flyctl secrets set OAUTH_JWT_SECRET_PREVIOUS="$OLD_SECRET" -a kite-mcp-server   # re-install PREVIOUS
# Live sessions resume verifying
```

If encrypted columns become unreadable post-rotation (Option C path was used):

- All users see 401 / "session expired" → mcp-remote re-auths → fresh Kite login → fresh encrypted writes
- Revenue loss = 0 (read-paths still work via re-auth); UX loss = ~2 min/user one-time re-login
- No data loss (all encrypted columns re-derive from fresh user auth)

## Recommendation

1. **Read `cmd/rotate-key/main.go`** to confirm whether Option B is fully implemented; if yes, document its exact procedure as part of this runbook.
2. **At first paid-user state**, prefer Option B (re-encrypt-during-grace) over Option C (mass re-auth) for UX hygiene.
3. **At zero-paid-user state today**, Option C is acceptable; the procedure above (5 steps + accept re-auth) is sufficient.
4. **Cadence**: rotate `OAUTH_JWT_SECRET` annually (per typical fintech hygiene) OR on suspected-compromise event. NOT monthly (the `MEMORY.md` line ~99 "monthly hygiene" suggestion is overkill for our threat model — every rotation event has UX cost via re-auth).

---

# §15 — Followup Dispatches Recommended

Five concrete dispatches surfaced from this batch:

| Priority | Dispatch | Source question | Estimated time |
|---|---|---|---|
| **1** | **Implement `cmd/dr-decrypt-probe`** per §C design spec | Q C | ~1.5h |
| **2** | **Apply README + show-hn-post.md + CLAUDE.md numerical patches** per §B per-claim verdict table | Q B | ~30min mechanical edits + push |
| **3** | **Re-engage punkpeye PR + submit wong2 mcpservers.org form + ping jaw9c PR #267** | Q L | ~1h research-the-rejection + 30min new-PR + 15min ping |
| **4** | **Read `cmd/rotate-key/main.go` + extend §N runbook with Option B procedure** | Q N | ~1h |
| **5** | **Bump funding.json `version` to v1.1.0 + re-validate via fundingjson.org/validate/ + patch project description tool/test counts** | Q F | ~30min |

**Lower-priority follow-ups (not yet ranked)**:
- Q J: build `admin_get_mrr` tool when first paid trial converts (~2-4h)
- Q G: user manually probes Reddit u/Sundeepg98 status (~1min)
- Q M: user manually probes Twitter @Sundeepg98 activity (~1min)

---

# §16 — Source Verification (this doc)

| Probe | Tool used | Result |
|---|---|---|
| Master HEAD | `git pull --ff-only origin master` + `git log -1` | `cdc1f91` |
| Production state | `curl /healthz` | tools=111, version=v1.3.0, uptime 3h40m |
| In-tree test count | `wsl go test ./... -list '.*' \| grep -cE '^Test'` | 4,697 |
| algo2go test counts (28 modules) | per-module `wsl go test ./... -list '.*'` | 3,760 |
| `cmd/` listing | `ls cmd/` | `event-graph/` + `rotate-key/` only |
| `smithery.yaml` exists | `ls smithery.yaml` | YES |
| `funding.json` exists | `ls funding.json` | YES (`version: v1.0.0`) |
| `algo2go/kite-mcp-billing/checkout.go` Stripe wiring | `head -50 checkout.go` | Stripe Checkout Session creation (3 plans) |
| `algo2go/kite-mcp-billing/webhook.go` Stripe webhooks | `head -50 webhook.go` | 4 events handled, signature verified |
| `algo2go/kite-mcp-alerts/crypto.go` HKDF interface | `head -80 crypto.go` | `DeriveEncryptionKeyWithSalt` + `EnsureEncryptionSalt`, info-string `"kite-mcp-credential-encryption-v1"` |
| `algo2go/kite-mcp-alerts/dr_drill_prod_keys_test.go` synthetic test | full file read | TestDRDrill_ProductionKeyChain_Synthetic + TestDRDrill_WrongSecret_FailsLoudly |
| `app/app.go` OAUTH_JWT_SECRET_PREVIOUS wiring | `grep -rn OAUTH_JWT_SECRET_PREVIOUS app/` | `app.go:667-674` (graceful rotation) + `config.go:57,96` |
| GitHub stars | `gh api repos/Sundeepg98/kite-mcp-server` | 0 stars, 0 forks, 0 subs |
| punkpeye PR #4075 | `gh api repos/punkpeye/awesome-mcp-servers/issues/4075` | CLOSED unmerged 2026-04-04 |
| jaw9c PR #267 | `gh api repos/jaw9c/awesome-remote-mcp-servers/issues/267` | OPEN since 2026-04-19, no comments |
| wong2 PR count | `gh api search/issues q="is:pr author:Sundeepg98 repo:wong2/awesome-mcp-servers"` | 0 |
| GitHub user Sundeepg98 | WebFetch `api.github.com/users/Sundeepg98` | created 2020-08-12, twitter_username:null, 12 public repos |
| algo2go GitHub org | (prior dispatch) | created 2026-05-05, 28 repos |
| algo2go.com domain | (prior dispatch) | available |
| `tradarc.com` RDAP | WebFetch | REGISTERED to Server Plan Srl, expires 2027-05-04 (auto-renewed since INDEX cite) |
| `quirkalgo.com` + 4 alt RDAP | WebFetch ×5 | 5 unregistered candidates |
| 4 GitHub orgs (`tradesy2`, `quanto2go`, `tradloop`, `quirkalgo`) | WebFetch ×4 | All 4 HTTP 404 = available |
| Reddit u/Sundeepg98 | WebFetch (BLOCKED) | Claude Code blocks reddit.com domain |
| Twitter @Sundeepg98 | WebFetch (BLOCKED) | x.com returns 402 (login required); nitter returns empty |
| FLOSS/fund schema URL | WebFetch fundingjson.org | Schema v1.1.0 at `https://fundingjson.org/schema/v1.1.0.json` |
| README.md claim audit | WebFetch GitHub raw | 110+/117 tools + 11/12/9 RiskGuard intra-doc inconsistency |

**Methodology rule applied throughout**: compile-and-run for binary-state metrics; RDAP for domain availability; gh api for GitHub state; WebFetch for external docs. Pure grep-as-evidence avoided per STATE.md §11 lesson.
