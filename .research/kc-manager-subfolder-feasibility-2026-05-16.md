<!-- secret-scan-allow: research-doc-with-file-line-cites -->
---
title: kc/manager_*.go subfolder feasibility (transcript persistence)
as-of: 2026-05-16
re-verify-by: 2026-08-16
master-head-at-write: kite-mcp-kc 04b27f0 → 3def64c (v0.1.1)
scope: READ-ONLY feasibility study captured from transcript; Shape 1 execution shipped at kc v0.1.1
note: this doc captures the feasibility study + Shape 1 execution outcome. The execution result is documented inline at end (kc/ root: 58 → 56 files; v0.1.1 shipped).
---

# kc/manager_*.go subfolder feasibility (transcript persistence)

## INPUTS — load-bearing facts probed `2026-05-16`

| # | Claim | Probe | Verified |
|---|---|---|---|
| 1 | kc/ extracted to external `algo2go/kite-mcp-kc v0.1.0` mid-research (Phase 1 Phase A) | `git log` in kite-mcp-bootstrap shows commit `3328c14` | 2026-05-16 |
| 2 | **58 non-test .go files at kite-mcp-kc/ root** (matches user's empirical observation about manager-sprawl) | `ls *.go \| grep -v _test.go \| wc -l` | 2026-05-16 |
| 3 | 26,622 total non-test LOC across 58 root files | aggregated `wc -l` | 2026-05-16 |
| 4 | Already-subfoldered: `kc/ops/`, `kc/ports/` (matches user observation) | `ls -d */` | 2026-05-16 |
| 5 | **128 Manager methods total** (90 public Capital + 38 private lowercase) on `*Manager` receiver | per-mod `grep -oE '^func \(m \*Manager\)'` | 2026-05-16 |
| 6 | Manager struct has ~50 fields (all lowercase = private) | `grep -E '^\s+[a-z][a-zA-Z]+' manager_struct.go` | 2026-05-16 |
| 7 | 33 of 58 files reference `m.<private-field>` (Manager-receiver methods); 25 files have zero `m.X` refs | per-file `grep -cE '\bm\.[a-z]'` | 2026-05-16 |
| 8 | Top-3 private-field-touchers: `manager_commands_account.go` (67 m.X refs), `store_registry.go` (44), `manager_use_cases.go` (41) — PEAK encapsulation-walled | sorted grep counts | 2026-05-16 |
| 9 | 134 bootstrap files import `algo2go/kite-mcp-kc` post-Phase-1 | `grep -rl '"github.com/algo2go/kite-mcp-kc'` | 2026-05-16 |
| 10 | **Sprint 2-4 wall** (memory `session_2026-05-16_decomposition-arc-complete.md` lines 78-82): "subpackage extraction blocked by unexported-field encapsulation (25 fields cross package boundary)" — file-split within same package is the only viable mechanical decomposition | memory file | 2026-05-16 |

## Concern grouping (per-file classification)

| Bucket | Files | LOC subtotal |
|---|---|---|
| **A. Manager struct + lifecycle** | manager.go, manager_struct.go, manager_init.go + 5 splits, manager_lifecycle.go, manager_accessors.go, manager_interfaces.go, manager_orders_fallback.go, options.go, config.go, config_manager.go, reconstitution.go | ~2,650 |
| **B. Command registrars (CQRS)** | manager_cqrs_register.go, manager_commands_account.go, manager_commands_admin.go + 7 splits, manager_commands_exit/oauth/orders/setup.go, manager_queries_remaining/escapes.go, manager_use_cases.go | ~3,200 |
| **C. Services (Manager-receiver bound)** | alert_service, broker_services, credential_service, eventing_service, family_service, fill_watcher, order_service, portfolio_service, scheduling_service, session_lifecycle_service, session_service, session_svc | ~2,500 |
| **D. Stores (own struct receivers)** | token_store, credential_store, store_registry | ~595 |
| **E. Session subsystem** | session.go, session_signing.go | ~830 |
| **F. Kite SDK wrappers** | kite_client, kite_connect, callback_handler | ~150 |
| **G. Interfaces + ports declarations** | interfaces.go, manager_interfaces.go | ~792 |
| **H. Utilities (no Manager touch)** | broker_context, client_hint_detect, client_hint_resolver, expiry, timezone, util | ~600 |

## Encapsulation analysis (empirical)

**Population 1 — Manager-method files (33 files, encapsulation-walled)**
- 33 of 58 files have ≥1 `m.<private>` ref; total ~770 such refs
- Moving these to a sub-package requires exporting every touched Manager field (breaks god-object contract per Sprint 2-4 wall)
- **HARD-walled** per memory's Provider-Interface Preservation Lesson

**Population 2 — Self-contained files (25 files)**
- 25 files have zero `m.<private>` refs
- BUT empirical re-verification at HEAD `04b27f0` showed: **most of these export symbols consumed by 134 bootstrap files** OR declare types bound to Manager-struct fields

**Quantitative summary**:
| Wall classification | File count | Subfolder feasibility |
|---|---|---|
| HARD-walled (m.X refs) | 33 | Move requires Manager field exports |
| SOFT-walled (types Manager-field-bound OR bootstrap-consumed) | 23 | Move requires bootstrap-side rewrites (out of scope) |
| TRULY mobile (no external consumption, no Manager binding) | 2 | **`util.go` + `broker_context.go`** |

## Candidate subfolder shapes evaluated

### Shape 1 — "Minimal-touch utility subfolder" (RECOMMENDED, EXECUTED)
**Cost**: ~5-8 files into `kc/internal/<subpkg>`. Manager.go updates ~10-15 imports.
**Encapsulation impact**: ZERO new public API. Go's internal-package rule blocks external import.
**Status post-execution**: 2 files moved (util.go → internal/util/; broker_context.go deleted as Wave-D-dead-doc).

### Shape 2 — "Aggressive concern subfolder" (REJECTED)
Per-concern sub-packages (commands/, init/, services/, stores/) would require 25-30 Manager field exports. **Replays Sprint 2 wall.**

### Shape 3 — "Per-aggregate hexagonal" (REJECTED)
Domain-level split already done at module level (28 algo2go modules); duplicating inside kc/ wastes work.

### Shape 4 — "File-only resorting" (WEAK alternative)
Pure rename. ~30% benefit at ~10% effort. Doesn't address "subfolders" framing.

## Sprint 1-4 wall analysis

Per memory `session_2026-05-16_decomposition-arc-complete.md` lines 78-82, **6 empirical halts** converged on:

> **Sprint 2 halt** — subpackage extraction blocked by unexported-field encapsulation (25 fields cross package boundary)
> **Sprint 3 pre-check halt** — same blocker at 5x scale; only file-split viable
> **Sprint 4 pre-check halt** — 0 truly-drainable fields; 19 are Provider contracts, 23 are correctly-encapsulated, 11 already exported

**Empirical re-verification at HEAD `04b27f0`**: 33 Manager-receiver files at kc/ root collectively reference `m.<private-field>` 770 times. Moving ANY to a sub-package requires exporting referenced fields. The Provider-Interface contract holds.

**Conclusion**: the wall is real and has not weakened with kc-as-its-own-module. Module extraction moved the boundary OUT; sub-package extraction would create a NEW boundary INSIDE kc/ and the same 25-field problem applies.

## Recommendation (executed)

**Shape 1 — Minimal-touch utility subfolder — executed at kc v0.1.1.** Falsifiable claim:

1. Reduce kc/ root file count from 58 to 56 ✓ (delta -2)
2. Not require ANY Manager field exports ✓
3. Not break the Provider-Interface Preservation pattern ✓
4. Cost ~30-60min agent time ✓ (actual: ~50min)
5. Reverse-import scope bounded: ~3 callsite edits (credential_service.go + manager_config_test.go + 2 comment-only manager.go references), zero bootstrap consumer changes ✓

**The remaining 33 Manager-method files at root are the empirical god-object boundary** — they cannot subfolder without breaking encapsulation. Per Provider-Interface Preservation Lesson, this is structurally CORRECT, not a defect.

## Execution outcome (kc v0.1.1)

| Step | Result |
|---|---|
| Move util.go → kc/internal/util/util.go | ✓ |
| Rename truncKey → Trunc (export) | ✓ |
| Update 2 callsites (credential_service.go, manager_config_test.go) | ✓ |
| Update 2 comments in manager.go | ✓ |
| Delete broker_context.go (Wave-D dead-doc, all refs are comments) | ✓ |
| WSL2 go build ./... | exit 0 |
| WSL2 go vet ./... | exit 0 |
| WSL2 go test -count=1 -short ./... | exit 0 (32.0s) |
| WSL2 go test -count=1 ./... (full) | exit 0 (35.9s) |
| Commit + push + tag v0.1.1 | ✓ commit 3def64c |
| GOPROXY fetch verification | ✓ resolved cleanly |
| Encapsulation invariant (no new Manager field exports) | ✓ verified via git diff v0.1.0..v0.1.1 -- manager_struct.go empty |

**Public API unchanged**: bootstrap consumers do not need to update import paths. v0.1.1 is a patch release; v0.1.0 callers continue to work.

## Empirical surprises

1. **Phase 1 Phase A landed mid-research** — bootstrap HEAD advanced from `f500ee0` → `3328c14` between dispatch start and Shape 1 execution. The framing changed from "kc is bootstrap-internal" to "kc is its own external module" but the encapsulation wall reapplied at sub-package boundary.

2. **Truly-mobile set was 2 files, not 19-25** as the prior research framing suggested. Empirical re-verification showed most Population 2 files export symbols consumed by 134 bootstrap files OR declare types Manager-field-bound. The conservative Path R was the empirically-honest minimal scope.

3. **`kc/internal/<subpkg>` is the right shape, not `kc/<subpkg>`** — Go's internal-package rule provides equivalent-to-private for sub-packages. Moves utility files to `kc/internal/util/`, etc.; blocks bootstrap from importing them even though kc-the-module is publicly imported.

4. **Sprint 1-3 file-splits (manager_init_* × 5, manager_commands_admin_* × 7) are SAME-package splits** — they didn't introduce sub-packages, just split single files into multiple files of `package kc`. This is the ONLY decomposition Go's encapsulation rule permits for Manager-receiver files. The pattern is empirically correct, not a workaround.

5. **The user's observation is empirically valid** — `kc/ops/` and `kc/ports/` have proper subfolders because they declare Manager-independent concerns. kc/ root sprawl exists because the Manager struct is intentionally a single-file-receiver-set held together by Provider-interface discipline; this is the architecture, not a defect.

## What's been done since (Path A's Tier B work)

After Shape 1 (kc v0.1.1) landed, Path A continued internal Manager decomposition WITHOUT subfolder moves:

- v0.1.2: AuditStoreConcreteProvider + SessionRegistryProvider ports added (Audit's work)
- v0.1.3: CI workflow added
- v0.1.4+: Tier B Step 2 — folded 13 Wave D use-case fields into OrderService; Tier B Step 3 — folded 6 raw alert subsystem fields into AlertService

These are STILL same-package refactors (per Sprint 2-4 wall). Path A is correctly NOT attempting sub-package extraction. They're reducing the 50-field Manager struct via service-aggregation, which IS the right direction within the wall.

## Sources

- Memory `session_2026-05-16_decomposition-arc-complete.md` (Provider-Interface Preservation Lesson, lines 78-82 + 134-136)
- Empirical re-probes at HEAD `04b27f0` (kite-mcp-kc init commit)
- Execution outcome at commit `3def64c` (v0.1.1)
- Path A's subsequent Tier B work (commits `aff935b`, `0534edd`, etc.)

---

*Transcript-persisted 2026-05-16 evening. Captures the feasibility study + Shape 1 execution outcome. Path A's Tier B work continues the in-package decomposition without violating Sprint 2-4 wall.*
