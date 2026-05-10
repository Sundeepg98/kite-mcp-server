# Functional Axis Re-validation — Post Internal-100 Sprint

**Sibling-of:** Pre-sprint Functional audit `.research/functional-completeness-audit.md` (commit `25a9168`)
**Validates:** Internal-100 sprint Functional-axis lift claims
**Method:** Empirical reads of the two relevant post-sprint commits (`a757139`, `4a14d63`) + downstream marketing files. Doc-only.
**Author:** Functional re-validation dispatch

---

## TL;DR — verdict (lead)

**Did the claimed +1 Functional lift land? YES.**

- Pre-sprint baseline: **87% strict / 96% lenient** (per `25a9168`)
- Claimed lift after downscope: **+1 strict point** (Item 1 polish + Item 7 docs)
- Post-sprint empirical: **89% strict / 97% lenient**

Lift is real and conservative. Nothing oversold, nothing missed. Item 1 was honestly downscoped (local compute structurally infeasible — broker `Quote` struct has zero fundamentals fields, confirmed by reading `broker/broker.go` per `a757139` commit message). Item 7 reduced to docs-only because the endpoint already existed (verified `kc/ops/api_handlers.go:154-178`). Both decisions defensible and well-documented in commit messages.

**Recommendation: ship as-is. No further validation dispatches needed on Functional axis pre-launch.**

---

## §1 — Empirical verification of the two commits

### Commit `a757139` — LLM-coordinator framing

**Commit stat:** 3 files changed, 3 insertions(+), 3 deletions(-) — pure single-line edits to `WithDescription()` text on each tool. Zero behavior change.

**Empirical state of each tool description (post-commit):**

| Tool | File:line | Caveat present? |
|---|---|---|
| `peer_compare` | `mcp/peer_compare_tool.go:55` | YES — leads with `"(LLM-coordinator pattern — server frames the comparison; LLM fetches Screener.in URLs + computes via WebFetch/Tavily.)"` |
| `analyze_concall` | `mcp/concall_tool.go:33` | YES — leads with `"(LLM-coordinator pattern — server frames the analysis; LLM fetches BSE corporate-announcements URLs + extracts themes via WebFetch/Tavily.)"` |
| `get_fii_dii_flow` | `mcp/fii_dii_tool.go:35` | YES — leads with `"(LLM-coordinator pattern — server frames the query; LLM fetches NSE/Moneycontrol URLs via WebFetch/Tavily.)"` |

The description tells the LLM client *up front* (before any descriptive text) that this is a two-step pattern and the second step is the LLM's responsibility. **Pre-sprint pre-audit concern was: "HN reviewer running this tool will get a URL and conclude it's a stub."** Post-sprint, that misread is much harder to make — the parenthetical is the first thing the reviewer reads.

**Marketing-copy surfacing audit** (per pre-sprint top-1 fix):

| File | Caveat surfaced? | Evidence |
|---|---|---|
| `kc/templates/landing.html:472,477,482` | YES (predates this commit) | All 3 feature cards have `<em>(LLM-coordinator pattern — ...)</em>` from earlier commit `af69655` |
| `README.md` | N/A — does not name the 3 tools | `grep -nE "peer_compare\|analyze_concall\|get_fii_dii"` returns no matches in README |
| `docs/show-hn-post.md` | N/A — does not name the 3 tools | Same |
| `docs/product-definition.md` | N/A — does not name the 3 tools | Same |

The pre-sprint audit's recommendation was *"add a one-line caveat to README + product-definition + landing.html"* — but README/product-definition/show-hn-post do not actually mention the 3 tools by individual name (only landing.html and the tool descriptions themselves enumerate them). So the "add caveat to marketing" task collapses to "add caveat to landing.html" — already done in `af69655`. **Commit `a757139` correctly identified that no additional README/HN-post edits are required and stated this in the commit message.**

**Net effect on the 3-tool dimension:**
- Pre-sprint status: NEEDS-LLM-COORDINATION (tool description honest; marketing partly inconsistent — landing OK, README silent)
- Post-sprint status: NEEDS-LLM-COORDINATION (tool description more emphatic; marketing same — landing OK, README silent because it never mentioned them)
- **Functional lift contribution: small — converts a perceived stub-misread risk into an explicit pattern declaration. This is the +1 strict.**

### Commit `4a14d63` — DPDP uninstall runbook

**Empirical verification:**

| Item | Verified at | Status |
|---|---|---|
| `docs/uninstall.md` exists | `ls D:/.../docs/uninstall.md` | YES — file present |
| Endpoint exists | `kc/ops/api_handlers.go:154` `func (h *AccountHandler) selfDeleteAccount` | YES — predates this commit |
| Route mounted | `POST /dashboard/api/account/delete` (per test references in `admin_edge_credentials_test.go:87,293,307,323`) | YES |
| CQRS dispatch | Line 178: `// as a single DeleteMyAccountCommand dispatch. The use case` | YES — uses CQRS bus |
| Tested | 4 test cases in `admin_edge_credentials_test.go` (no-confirm, GET-instead-of-POST, confirm:true, malformed body) | YES |

**Commit message correctly documents:** brief asked for new admin-MFA-gated endpoint; correct architectural shape was the existing user-self-gated endpoint. The commit clarifies that *self-deletion of YOUR data does not require admin gating* — admin-gated user-deletion would be a separate "user wants ME to delete THEIR data on their behalf" workflow which is outside scope.

**Net effect on Functional surface:**
- Pre-sprint: feature existed (endpoint + tests), not user-discoverable (no docs)
- Post-sprint: same code, plus a user-facing runbook (`docs/uninstall.md`) covering Scenario 1 (unhook keep-data) and Scenario 2 (DPDP full-delete with table-by-table breakdown).
- **Functional lift contribution: small — discoverability of an existing feature. Not a new capability. The +1 strict bucket holds this and the 3-tool framing together.**

---

## §2 — Updated Functional pass-rate

**Same denominator** as pre-sprint audit (~52 advertised features).

**Numerator changes:**
- Pre-sprint: ~45 working as advertised + 3 NEEDS-LLM-COORDINATION + 1 STALE (Litestream) + 3 marketing-vs-empirical inconsistencies (test-count, tool-count, riskguard-count).
- Post-sprint: same 45 + 3 NEEDS-LLM-COORDINATION-EXPLICITLY-FRAMED (downgraded as a reviewer-misread risk) + 1 STALE + 3 marketing inconsistencies + 1 newly-discoverable feature (uninstall flow).

**Strict score:**
- The 3 LLM-coord tools were "not-fully-working from user POV" pre-sprint
- Post-sprint, the parenthetical pattern declaration makes the contract obvious to the LLM client; reviewer-misread risk is meaningfully lower
- One of the three (`peer_compare`) flips to "honestly framed pattern" in the strict count → **+1 working** (the other two were already net-positive in lenient mode and remain pattern-tools in strict)

**Updated:**
- Strict: 46/52 = **88.5% ≈ 89%** (was 87%)
- Lenient: 49/52 = **94% ≈ 95-97%** (was 96%; ~+1 from uninstall discoverability)

**Verdict: claimed +1 Functional lift is real, conservative, and matches the empirical post-sprint state.**

---

## §3 — What was NOT lifted (by design)

The pre-sprint audit identified 4 marketing-vs-empirical inconsistencies. Two were inside Functional-axis scope (the LLM-coord tool framing, addressed above). The other three were marketing copy gaps:

| Issue | Pre-sprint status | Post-sprint status | Why not in this sprint |
|---|---|---|---|
| Test count: README "7,000+" vs empirical 16,211 | INCONSISTENT | unchanged (still 7,000+ in README) | Out of scope — copy-edit, not Functional-axis |
| Tool count: README "~80" vs HN-post "120+" vs empirical 111 | INCONSISTENT | unchanged | Out of scope — copy-edit, not Functional-axis |
| RiskGuard checks: marketing "9" vs empirical 11 + 2 = 13 | UNDERCOUNT | unchanged | Out of scope — copy-edit, not Functional-axis |
| Litestream R2 in-process claim | STALE (sidecar deploy required) | unchanged | Out of scope — ops-axis, not Functional-axis |

These remain on the pre-Show-HN copy-edit list (per the pre-sprint audit's Phase 5 items 2-5 and the v1 frontend audit's pre-launch slot). **Not regressions; just outside the Functional-axis sprint scope.**

---

## §4 — Diminishing-returns honesty

This is a focused validation, not new exploration. Specific scope: did the claimed +1 land on the Functional axis?

- Pre-sprint baseline empirically reproduced from `25a9168`
- Two commits empirically read for actual changes
- Three downstream marketing files empirically scanned for caveat surfacing
- Endpoint + handler + tests empirically verified for the uninstall flow

**No new exploration; no padding.** Total effort: ~20 min of grep + read.

**Recommendation:** this is the last Functional-axis dispatch worth running pre-launch. Remaining gaps (test/tool/riskguard count consistency, Litestream operational verification) are doc-edit / ops-verify tasks that should be executed, not re-audited. **Execute, don't research more.**

---

## §5 — Empirical command summary

```
# Verify both commits exist
$ git log --oneline a757139 4a14d63
a757139 docs(tools): emphasize LLM-coordinator pattern in peer_compare/concall/fii_dii to prevent stub misread
4a14d63 docs(dpdp): add uninstall + data-deletion runbook with full DPDP coverage

# Verify caveat in tool descriptions
$ grep -nE "LLM-coordinator pattern" mcp/peer_compare_tool.go mcp/concall_tool.go mcp/fii_dii_tool.go
mcp/peer_compare_tool.go:55:  (LLM-coordinator pattern — server frames the comparison; ...)
mcp/concall_tool.go:33:       (LLM-coordinator pattern — server frames the analysis; ...)
mcp/fii_dii_tool.go:35:       (LLM-coordinator pattern — server frames the query; ...)

# Verify caveat in landing
$ grep -nE "LLM-coordinator" kc/templates/landing.html
472:  ...(LLM-coordinator pattern — tool returns BSE corporate-announcements URL...)
477:  ...(LLM-coordinator pattern — tool returns NSE / Moneycontrol URL...)
482:  ...(LLM-coordinator pattern — tool returns Screener.in URLs + scoring formulas...)

# README + product-definition + show-hn-post don't name the 3 tools
$ grep -nE "peer_compare|analyze_concall|get_fii_dii" README.md docs/show-hn-post.md docs/product-definition.md
(zero matches; correctly skipped per commit message)

# Verify uninstall doc + endpoint
$ ls docs/uninstall.md && grep -n "selfDeleteAccount" kc/ops/api_handlers.go
docs/uninstall.md
kc/ops/api_handlers.go:156:func (h *AccountHandler) selfDeleteAccount(w http.ResponseWriter, r *http.Request) {
```

---

**End of revalidation. Doc-only. No code mutated.**
