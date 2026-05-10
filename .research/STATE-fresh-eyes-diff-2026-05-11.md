# STATE-v2 vs STATE.md — Fresh-Eyes Diff Report

**Date**: 2026-05-11 IST.
**Authored by**: same #C fresh-eyes agent that wrote `STATE-v2-fresh-eyes.md` at commit `4e73521`.
**Method**: I authored `STATE-v2-fresh-eyes.md` BEFORE reading `.research/STATE.md` (per dispatch hard rule). Now that v2 is committed, I read STATE.md and produce this diff.

---

## §0 — Bottom line up front

**The two docs converge on the substantive empirical state**: tools=111 in production AND in master-built binary; no deploy-pipeline gap; the launch-blocker is operational (R2 secrets unset, `cmd/dr-decrypt-probe` missing) not technical; 28 algo2go modules external; Path A inauguration COMPLETE.

**Both docs make the same headline call**: don't deploy out of fear of staleness; focus on launch-prep operations.

**Where they differ is in framing-and-organization, not in facts.** I found ZERO substantive empirical disagreements between v2 and STATE.md. **No critical contradiction surfaced.** No launch-pause needed.

The high-value deltas are:

1. **STATE.md is more thorough on conflict-resolution history** (§8 documents 6 resolved conflicts with timestamps). v2 doesn't have this section.
2. **STATE.md has explicit gaps-needing-user-verification list** (§9, 6 entries). v2 mentioned this in passing in §9 but didn't enumerate. **STATE.md wins here.**
3. **v2 has a cleaner "today/this week" actionable section** (§7.2, 8 ranked items). STATE.md fragments this across §2.2, §4, §6 launch-execution table. **v2 wins here for orchestrator readability.**
4. **STATE.md has comprehensive archive index** (§7, 80 archived docs in 5 categories with rationale). v2 doesn't even mention the archive. **STATE.md wins here for historical traceability.**
5. **v2 explicitly flags `final-pre-launch-verification.md` as itself-stale and `agent-domain-map.md` as having stale "Recent context" sections** (v2 §6.1, §6.2). STATE.md doesn't surface these meta-claims. **v2 wins here.** STATE.md treats `final-pre-launch-verification.md` as still load-bearing without flagging that its 2026-05-03 framing is outdated.

---

## §1 — Claim-by-claim diff matrix

| Claim domain | STATE.md says | STATE-v2 says | Verdict |
|---|---|---|---|
| Production /healthz | tools=111, v1.3.0 (2026-05-10 + re-verified 2026-05-11) | tools=111, v1.3.0 (2026-05-11 today, two probes 3-min apart) | **Agree.** v2 has a slightly fresher set of probes. |
| Master HEAD | `bc5043e` (the deploy commit) — STATE.md notes 1-2 commits ahead all `.research/`-only | `25b201a` (today's HEAD; v2 explicit). | **Agree on substance**: STATE.md was authored at HEAD `1e80930` (the commit before the gap-report); 2 newer commits (`bea1e11`, `25b201a`) have landed since STATE.md was written. v2 is fresher. |
| 28 algo2go modules external | YES (alphabetical list) | YES (count match; not enumerated) | **Agree.** |
| In-tree workspace members | 4 (root + plugins + testutil + app/providers) | 4 (same) | **Agree.** |
| Tools=130 mistake provenance | YES — explicitly documented at §5.6 + §8.6 with cost-of-error (~6 hours) note | YES — documented at v2 §2 with same provenance + same correction commit (`bea1e11`) | **Agree.** Both docs treat this as resolved. |
| Tier 1 closure-DI | 3 facades migrated (brokers + eventing + scheduling); 2 deferred (StoreRegistry + SessionLifecycleService) | Reference only at v2 §3 ("3 facade back-pointers eliminated"); does NOT mention deferred 2 facades | **STATE.md wins on completeness.** v2 omitted the deferred facades. Not a contradiction; v2 is just less detailed. |
| Tier 2 pure-function registrars | 8 total (1 pre-existing + 7 extracted); C3 unit tests added at `1c54773` | Reference only ("6 sub-registrar pure-function extractions in kc/manager_commands_admin.go have direct unit-test coverage"); doesn't count the OAuth registrar (Tier 2.2) separately | **STATE.md wins on count accuracy** — 8 vs 6+1 (oauth) +1 (precedent) is the same arithmetic but framed differently. v2 should have said 7 extracted + 1 precedent = 8 to match STATE.md. |
| Phase 2.6 (Turso/libSQL) | Path 6 adopted Steps 1-3; production stays SQLite; libsql-client-go is right choice despite deprecation banner | Same: "shipped but not used"; ALERT_DB_DRIVER unset; SQLite default | **Agree.** |
| Two real launch-blockers (R2 secrets + dr-decrypt-probe) | NOT explicit in STATE.md (STATE.md predates the dr-drill-results-2026-05-11.md doc by ~half a day) | EXPLICIT at v2 §4 (top-tier finding) | **v2 wins** — these are the most actionable findings of the day and v2 surfaces them prominently. STATE.md should incorporate them on next refresh. |
| `forward-tracks-strategic-review.md` "deploy first" recommendation status | STATE.md §8.1 explicitly FALSIFIES it: "the 'production deploy is recommendation #1' call in `forward-tracks-strategic-review.md` is FALSIFIED. Surface this back to the strategic-review doc + playbook in next synthesis pass." | v2 §6.5 same conclusion: "deploy is OPTIONAL — not load-bearing on Show-HN readiness" | **Agree.** Both docs explicitly call out this falsification. |
| `final-pre-launch-verification.md` staleness | STATE.md treats it as "still load-bearing" (§6 active cross-references list) | v2 §6.1 explicitly flags it as "itself stale" (authored 2026-05-03; subsequent deploys invalidate the "548 commits stale" framing) | **v2 wins.** STATE.md doesn't flag the recursive staleness problem. |
| `agent-domain-map.md` "tools=130 invariant" rule | STATE.md §6 lists agent-domain-map.md as active without flagging the stale invariant | v2 §6.2 explicitly flags: rule should read "tools=111 invariant" | **v2 wins** — STATE.md should note this when next refreshed. |
| Conflicts surfaced and resolutions | STATE.md §8 has 6 documented conflicts with resolutions (numbered 8.1-8.6 — note 8.1 + 8.6 cover the tools=130 saga and the version-string-vs-deploy-state confusion) | v2 doesn't have this section | **STATE.md wins.** This is high-signal historical record that orchestrator can lean on. |
| Identified gaps needing user verification | STATE.md §9 has 6 explicit entries (Whitelisted-IPs cap, WS connection limit, static IP `209.71.68.157`, OAuth JWT rotation, Kite Connect pricing, daily token expiry) | v2 §9 mentions "I did not run flyctl status" + "did not verify all 28 upstream tags" but doesn't surface the broader user-verification gaps | **STATE.md wins.** This is decision-relevant information v2 omitted. |
| Archive index | STATE.md §7 documents 80 archived docs in 5 categories | v2 doesn't reference the archive at all | **STATE.md wins** for historical traceability. v2 was authored without considering the archive's value. |
| Maintenance protocol | STATE.md §10 has explicit "when to update / when not to update" + archive workflow | v2 doesn't have this | **STATE.md wins.** This is operational discipline. |
| Source verification methodology | STATE.md §11 explicitly mandates compile-and-run > grep-and-count and explains the methodology fix | v2 §1 + §2 implicit but not codified as explicit "future synthesis MUST do this" rule | **STATE.md wins** — STATE.md frames it as a durable methodology rule. v2 just narrates the historical mistake. |
| Production deploy cadence claim | STATE.md says "~84 consecutive (per dispatch metadata)" | v2 says "86-deploy streak" | **Both approximately correct.** Difference reflects post-STATE.md cleanup-track deploys (v273, v274). v2 number is fresher. |
| Show-HN sequencing | STATE.md §4 has dispatch-authorization table + "7-9 days end-to-end" gate | v2 §7.2 has 8-item priority queue + "~3-4 hours focused user-time" estimate | **Agree on substance**, different framing. STATE.md emphasizes calendar gating; v2 emphasizes user-time block. Both useful. |
| TM filing cost | STATE.md §8.3: ₹9k direct (recommended) vs ₹19-22k via Vakilsearch | v2 references "~₹19-23k TM filing" without surfacing the ₹9k direct alternative | **STATE.md wins** — v2 quoted the higher-cost framing without the empirical correction. |
| 11/9/8 RiskGuard checks reconciliation | STATE.md §8.5: 11 is current; 9 is older memory; 8 is oldest | v2 doesn't reconcile this | **STATE.md wins** — useful for any Show-HN body claim integrity. |
| `algo2go.com` availability | STATE.md §2.3: AVAILABLE as of 2026-05-03 | v2 mentions in §5.2: "Buy `algo2go.com` + create `algo2go` GitHub org" assumed available | **Both correct.** STATE.md cites the verification date. |
| Tradarc backup name | STATE.md §8.4: NOT clean (registered to Server Plan Srl) | v2 doesn't mention | **STATE.md wins** — important for any "if Algo2Go gets contested" branch. |

---

## §2 — Disagreements: zero substantive contradictions

I cross-checked every empirical claim that appears in BOTH docs:

| Empirical claim | STATE.md value | v2 value | Match? |
|---|---|---|---|
| Production tool count | 111 | 111 | ✓ |
| Master-built binary tool count | 111 | 111 (chain agent's measurement, cited verbatim) | ✓ |
| Production version | v1.3.0 | v1.3.0 | ✓ |
| In-tree workspace members | 4 | 4 | ✓ |
| External algo2go modules | 28 | 28 | ✓ |
| Path A inauguration status | COMPLETE (kc/sectors A.26 + clockport A.27) | COMPLETE (same) | ✓ |
| Tier 1 facades migrated | 3 (brokers/eventing/scheduling) | 3 (same) | ✓ |
| Tier 2 pure-function registrars | 8 (1 precedent + 7 extracted) | "8 command registrars" referenced | ✓ |
| Phase 2.6 production state | SQLite (Driver unset); Turso path shipped not active | Same | ✓ |
| Litestream → R2 backup | Working (per dr-drill) | Working (per dr-drill — same source) | ✓ |
| `cmd/dr-decrypt-probe` exists? | NOT explicit in STATE.md (predates dr-drill report by half a day) | NO (verified by `ls cmd/`) | v2 has the empirical check; not a disagreement |
| GitHub Actions R2 secrets configured? | NOT explicit | NO (chain agent's dr-drill log evidence) | v2 has the empirical check; not a disagreement |

**Zero disagreements where both docs make a load-bearing claim.** The only deltas are: STATE.md was authored at HEAD `1e80930` before the gap-report was written; the gap-report findings are reflected in STATE.md §5.6 and §8.6 explicitly.

---

## §3 — Existing-only claims: should they be in v2?

These claims appear in STATE.md but NOT in v2. My judgment on each:

### 3.1 — Conflict resolution log (STATE.md §8)

**STATE.md content**: 6 historical conflicts with empirical resolutions (deploy-streak vs version-string, tools=130 vs tools=111, TM filing cost, Tradarc backup, RiskGuard count, version-string-vs-deploy-state).

**My judgment**: **YES, v2 should incorporate this.** It's high-signal historical record. The orchestrator and future synthesis dispatches benefit from "here's how we resolved this contradiction" context.

### 3.2 — User-verification gaps (STATE.md §9)

**STATE.md content**: 6 specific claims that need empirical verification (Whitelisted-IPs cap, Kite WS connection limit, static IP 209.71.68.157, OAuth JWT rotation cadence, Kite Connect pricing, daily token expiry).

**My judgment**: **YES, v2 should incorporate this.** These are the "items not verified anywhere; user must verify before relying on." Decision-relevant.

### 3.3 — Archive index (STATE.md §7)

**STATE.md content**: 80 archived docs across 5 categories with 1-line role descriptions.

**My judgment**: **MAYBE.** The archive is reference material, not active strategic input. STATE.md's value-add is the categorized index that helps future agents navigate the historical record. v2 could reference it by URL rather than re-enumerating. **Compromise: v2 should mention the archive's existence + key categories without re-listing all 80 docs.**

### 3.4 — Maintenance protocol (STATE.md §10)

**STATE.md content**: explicit "when to update / when not to update / archive workflow" rules.

**My judgment**: **YES, v2 should incorporate this** as a meta-doc. Operational discipline matters when a STATE doc has multi-agent maintainers.

### 3.5 — Source verification methodology rule (STATE.md §11 + §5.6)

**STATE.md content**: explicit rule that "compile-and-run > grep-and-count" with the historical cost-of-error footnote.

**My judgment**: **YES, v2 should incorporate this.** This is a durable methodology lesson, not a one-off finding. Future synthesis dispatches need this guardrail.

---

## §4 — V2-only claims: are they actually missing from STATE.md?

These claims appear in v2 but NOT in STATE.md. My judgment on each:

### 4.1 — `final-pre-launch-verification.md` is itself stale (v2 §6.1)

**v2 content**: the doc was authored 2026-05-03; its "548 commits stale" framing is no longer true after subsequent v228+ deploys. Downstream docs that cite it inherit the stale framing.

**Is this in STATE.md?** **NO.** STATE.md §6 lists `final-pre-launch-verification.md` as active without staleness warning.

**Should it be?** **YES.** This is exactly the kind of recursive-staleness problem a STATE doc should surface. **Recommend: add staleness flag + date when STATE.md is next refreshed.**

### 4.2 — `agent-domain-map.md` "tools=130 invariant" rule needs correction (v2 §6.2)

**v2 content**: agent-domain-map.md hard-rules list includes "tools=130 invariant"; the actual production invariant is tools=111.

**Is this in STATE.md?** **NO.** Implicit in STATE.md §1.1 row "MCP tools (production-registered): 111" but not flagged as a doc-rule that needs updating.

**Should it be?** **YES.** Same recursive-staleness pattern. **Recommend: add to STATE.md §6 cross-references with "rule needs correction: tools=130 → tools=111".**

### 4.3 — Two real launch-blockers from chain agent's dr-drill (v2 §4)

**v2 content**: GitHub Actions R2 secrets unset; `cmd/dr-decrypt-probe` doesn't exist; both are blockers for Show-HN launch.

**Is this in STATE.md?** **NO** (STATE.md was written before dr-drill report).

**Should it be?** **YES, urgently.** This is the most actionable finding in the corpus today. **Recommend: surface to STATE.md TL;DR §3 + §4 as critical pre-launch action items.**

### 4.4 — "Today/this week" priority queue (v2 §7.2)

**v2 content**: 8-item ranked list of pre-Show-HN actions with time estimates.

**Is this in STATE.md?** **PARTIALLY.** STATE.md §4 has an authorization table but it's framed as dispatch-routing, not user-action priority.

**Should it be?** **YES.** A prioritized user-action queue is a common artifact orchestrators consult. **Recommend: STATE.md §4 could be reformatted as a priority queue alongside the dispatch-authorization view.**

### 4.5 — Phase 2.6 Turso path "shipped-but-not-active" framing (v2 §6.4)

**v2 content**: explicit framing that Turso integration is "production-ready, not production-active."

**Is this in STATE.md?** **PARTIALLY** at §1.3: "Production stays on SQLite (`Driver` unset → default branch)" and §3.x not explicit.

**Should it be?** **MARGINALLY.** STATE.md mentions the env-var-flip readiness but doesn't frame as "we have optionality but haven't exercised it in production." v2's framing is slightly stronger. **Recommend: minor refinement only.**

---

## §5 — Recommendations for next STATE.md refresh

Based on the diff, here's the priority-ordered list of edits I'd make to STATE.md:

### Critical (do this in next refresh)

1. **Surface dr-drill findings**: incorporate v2 §4 launch-blockers (R2 secrets + dr-decrypt-probe) into STATE.md TL;DR §3 + §4 + §5.
2. **Update HEAD references**: STATE.md §1 cites HEAD `bc5043e`; current is `25b201a` (or successor by next refresh). Cross-reference to chain agent's gap-report (commit `21d5684`) and dr-drill-results (commit `25b201a`) is missing from STATE.md.
3. **Flag `final-pre-launch-verification.md` as itself-stale**: STATE.md §6 cross-references list should annotate this doc with its 2026-05-03 authorship date and the stale 548-commits-gap framing.
4. **Flag `agent-domain-map.md` rule needs correction**: STATE.md §6 should note that the doc's "tools=130 invariant" rule is one of the inherited grep-error claims.

### Important (next refresh or two)

5. **Forward-tracks strategic review needs an update or annotation**: STATE.md acknowledges the falsification (§8.1 + §8.6) but doesn't surface a "the strategic review doc itself needs a refresh pass" item. **Recommend**: add a §X "downstream-doc refresh queue" listing forward-tracks-strategic-review.md, agent-domain-map.md, final-pre-launch-verification.md as needing per-claim re-validation.
6. **Add the priority-queue framing to §4**: turn the dispatch-authorization table into a user-action priority queue (8 items per v2 §7.2).

### Nice-to-have (when time permits)

7. **Trim §7 archive index**: 80-doc enumeration is long; categorize-and-summarize would be lighter without losing traceability.
8. **Reconcile "84-deploy streak" → "86 deploys" or whatever current count is** at next refresh; update §1.1.

---

## §6 — Net assessment

**STATE.md is the better single source-of-truth document overall.** It has:
- The conflict resolution log (§8) that v2 lacks.
- The user-verification gaps list (§9) that v2 lacks.
- The maintenance protocol (§10) that v2 lacks.
- The source-verification methodology rule (§11) that v2 lacks.
- The archive index (§7) that v2 lacks.

**v2 surfaces some important meta-staleness findings that STATE.md misses**:
- `final-pre-launch-verification.md` is itself stale.
- `agent-domain-map.md` has a stale "tools=130 invariant" rule.
- The dr-drill launch-blockers are the day's most actionable finding.

**No critical empirical disagreement exists between the two docs.** Show-HN should NOT be paused based on this diff. The user can proceed with the launch-prep cluster (#42-46) as planned, with the dr-drill remediation (R2 secrets + dr-decrypt-probe) as the highest-priority pre-launch task.

**My recommendation for the user**: keep STATE.md as the canonical doc; merge the 3 critical v2-only findings into STATE.md at next refresh; archive `STATE-v2-fresh-eyes.md` and this diff doc to `.research/archive/state-verification/` once the user has read both.

---

## §7 — Process notes (for future fresh-eyes dispatches)

1. **The "do not read STATE.md until v2 is committed" hard rule worked.** I had no anchoring bias from STATE.md; my organizing principle in v2 ("60-second snapshot → empirical baseline → tools=130 mistake → 28-module map → launch blockers → forward-track cluster → readiness verdict") emerged from the underlying source docs, not from STATE.md's structure.
2. **The two docs converge on substance** — which is the goal. If they had diverged on empirical facts, that would have been a critical finding warranting launch-pause. They don't.
3. **The diff exposes meta-claims STATE.md lacks** (recursive staleness flags) — which is the value-add of fresh-eyes synthesis. The blind-set member catches things the original author can't see because they're in their own framing.
4. **Empirical probes are fast and cheap.** I ran `curl /healthz` twice + 2 `git ls-remote --tags` queries + 1 `ls cmd/` check. Total wall-time: <2 minutes. Should be the default for any future state-verification dispatch.

---

## §8 — Final synthesis verdict

**No critical contradiction.** **No launch pause needed.** **STATE.md is the better composite doc; v2 contributes a few important findings that should land in next STATE.md refresh.** **The actionable next step is independent of which doc the orchestrator uses**: provision R2 secrets, implement `cmd/dr-decrypt-probe`, proceed with launch-prep cluster #42-46.

Time used: ~3.5 hours of read + synthesis work; well inside the 6-hour halt rule. Cumulative for the dispatch (v2 + diff): ~3.5 hours.
