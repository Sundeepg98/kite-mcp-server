# Incident Response Runbook (Extended)

*Last reviewed: 2026-04-26*
*Maps to NIST CSF 2.0: RS.MA (Incident management), RS.AN (Analysis), RS.MI (Mitigation), RS.CO (Communication), RC.RP (Recovery planning), RC.IM (Improvements).*
*Companion to: [`incident-response.md`](incident-response.md) (scenario playbooks), [`recovery-plan.md`](recovery-plan.md) (RTO/RPO + DR drills), [`continuous-monitoring.md`](continuous-monitoring.md) (detection sources), [`vendor-management.md`](vendor-management.md) (vendor contacts).*

This document EXTENDS [`incident-response.md`](incident-response.md). The base file holds the four scenario-driven playbooks (PR, API, Security, Legal). This file adds the cross-cutting structure: **response phases**, **escalation tree**, **communication templates**, **roles & decision authorities**, and **post-incident review process**. Use both together.

---

## 1. Response phases (NIST CSF RS.MA-1)

Every incident — regardless of class — runs through six phases. The phase boundaries are decision gates: do not progress until the gate criteria hold.

```
T-0      Detection
  |
  v
Phase 1: Triage (15 min)        --- Gate: incident class declared, severity rated
  |
  v
Phase 2: Containment (1 hour)   --- Gate: blast radius bounded, attacker locked out
  |
  v
Phase 3: Eradication (24 hours) --- Gate: root cause removed, fix verified
  |
  v
Phase 4: Recovery (72 hours)    --- Gate: service restored, monitoring confirms stable
  |
  v
Phase 5: Notification (T+72h)   --- Gate: regulators / users notified per legal SLA
  |
  v
Phase 6: Post-mortem (30 days)  --- Gate: root cause documented, threat model updated
```

### Phase 1 — Triage (15 min)

**Goal**: classify the incident and rate severity. Pick a scenario from [`incident-response.md`](incident-response.md) §"Decision triage."

| Question | Source |
|---|---|
| Is this real or a false positive? | `flyctl logs -a kite-mcp-server`; `/healthz?format=json`; user report cross-check |
| What class? (PR / API / Security / Legal) | [`incident-response.md`](incident-response.md) §Decision triage |
| What severity? (Critical / High / Medium / Low) | §"Severity rating" below |
| Is data affected? | If yes — DPDP/CERT-In clock starts immediately |
| Is upstream (Kite) involved? | Affects communication template |

**Output**: incident declared in `docs/evidence/incident-YYYY-MM-DD/timeline.md`. First three lines:

```markdown
# Incident YYYY-MM-DD
**Detected:** YYYY-MM-DD HH:MM IST
**Class:** [PR | API | Security | Legal]
**Severity:** [Critical | High | Medium | Low]
**Initial responder:** Sundeep Govarthinam
```

### Phase 2 — Containment (1 hour)

**Goal**: bound the blast radius. Stop the bleeding.

| Action | Tool | When |
|---|---|---|
| Engage kill switch | `admin_set_kill_switch --enabled=true` | Active write-path attack |
| Disable trading globally | `flyctl secrets set ENABLE_TRADING=false` | Suspected algo-trading violation |
| Freeze a specific user | `admin_freeze_user` | Targeted account compromise |
| Rotate `OAUTH_JWT_SECRET` | `flyctl secrets set OAUTH_JWT_SECRET=$(openssl rand -hex 32)` | Suspected JWT signing key compromise |
| Revoke all sessions | `sqlite3 $ALERT_DB_PATH "DELETE FROM mcp_sessions;"` | Lateral movement suspected |
| Take service offline | `flyctl scale count 0 -a kite-mcp-server` | Active data exfiltration in progress |

**Pre-containment evidence preservation**: BEFORE any state change, snapshot:

```bash
flyctl ssh sftp get /data/alerts.db ./evidence/alerts.db.preimage
sha256sum ./evidence/alerts.db.preimage  > ./evidence/alerts.db.preimage.sha256
```

The hash makes the snapshot immutable evidence. Without it, post-incident forensics cannot prove the timeline.

### Phase 3 — Eradication (24 hours)

**Goal**: root cause identified and removed.

- **Code-cause**: identify the commit that introduced the vulnerability (`git log --grep=<term>`, `git blame`); revert or patch.
- **Config-cause**: identify the env-var or fly.toml change that caused it; rollback per [`change-management.md`](change-management.md) §5.2.
- **Credential-cause**: rotate the credential and verify no other systems share it.
- **Infrastructure-cause**: file with vendor (Fly.io, Cloudflare, Stripe, Telegram); document their reference number in the timeline.

**Verification gate**: the same exploit must NOT reproduce against the patched binary. Write a regression test that fails on the pre-fix binary and passes on the post-fix one — store the test in the codebase permanently.

### Phase 4 — Recovery (72 hours)

**Goal**: service fully restored; monitoring confirms stable operation.

- Re-enable killed paths in reverse order of kill: secrets → trading flag → user freezes → kill switch.
- Watch `/healthz?format=json` for 30 min post-recovery; expect green status, zero `dropped_count`, zero `auto_freeze` events.
- Re-validate the audit hash chain: `auditStore.VerifyChain(...)` returns success.
- Confirm Litestream replication is current: WAL freshness <1 minute (`/healthz?level=deep` `litestream` component).

**Recovery is NOT complete** until [`recovery-plan.md`](recovery-plan.md) §"Recovery validation checklist" passes.

### Phase 5 — Notification (T+72h)

**Goal**: meet all legal notification SLAs.

| Recipient | SLA | Channel | Template |
|---|---|---|---|
| CERT-In (data breach) | T+6h | Online portal `cert-in.org.in` | [`incident-response.md`](incident-response.md) §"Template: CERT-In incident notification" |
| Data Protection Board (DPB) | T+24h initial, T+72h detailed | Portal (when live) | [`incident-response.md`](incident-response.md) §"T+24h" / §"T+72h" |
| Affected users | T+72h | Email from grievance officer | [`incident-response.md`](incident-response.md) §"User notification template" |
| Zerodha (`kiteconnect@zerodha.com`) | T+72h if Kite credentials affected | Email | [`incident-response.md`](incident-response.md) §"Parallel — Zerodha notification" |
| Stripe (if billing affected) | Per Stripe T&Cs | Stripe support dashboard | Per Stripe SLA |
| Cloudflare R2 (if backup affected) | Per Cloudflare T&Cs | Dashboard ticket | Per Cloudflare SLA |

The 72-hour clock starts at **detection**, not at the moment of compromise. Document both timestamps. See [`incident-response.md`](incident-response.md) §"Data breach playbook" for full DPDP detail.

### Phase 6 — Post-mortem (30 days)

**Goal**: incident is documented, learned from, and the lessons feed forward.

Output document at `docs/post-mortems/YYYY-MM-DD-<slug>.md`. Required sections:

1. **Executive summary** (3 sentences): what happened, blast radius, current status.
2. **Timeline** (verbatim from `evidence/incident-YYYY-MM-DD/timeline.md`).
3. **Root cause** (the commit / config / credential / infra failure that started it).
4. **Detection** (what surfaced it — and what didn't).
5. **Containment effectiveness** (what worked, what didn't).
6. **What we changed** (code diffs, config diffs, doc updates, threat-model updates).
7. **Independent review** (external security engineer's writeup; budget ₹15-25k for 4-8 hours per [`incident-response.md`](incident-response.md)).
8. **Lessons learned** (numbered list; each lesson maps to a control improvement or a documentation update).

Public post-mortem published at the GitHub repo (or personal blog) within 30 days. Specificity rebuilds trust; vagueness erodes it.

---

## 2. Severity rating

Used in Phase 1 to classify. Severity drives SLA urgency and notification scope.

| Severity | Trigger conditions (any one) | Notification | Response intensity |
|---|---|---|---|
| **Critical** | Active data exfiltration; PII / credentials confirmed compromised; broker-credential leak; pre-auth RCE | All Phase 5 recipients; CERT-In within 6h | Full team, 24×7 until contained |
| **High** | Service-wide outage >30 min; post-auth privilege escalation; encryption-at-rest bypass; financial loss for a user | Affected users + Zerodha (if applicable) | Full team during business hours; on-call after-hours |
| **Medium** | Multi-user impact <30 min; auth bypass requiring user interaction; audit-log integrity loss | Status page update; affected users if specific | Same-day response |
| **Low** | Single-user impact; documentation gap; informational scanner finding; minor functionality bug | Internal triage only | Next-business-day |

If undecided between two severities, choose the higher one. Erring on the side of overreaction is cheap; under-classification is not.

---

## 3. Escalation tree

Single-maintainer reality: the tree has one node today. Designed for the future team structure.

```
                    ┌─────────────────────┐
                    │   Maintainer        │
                    │   (Sundeep G.)      │
                    │   sundeepg8@gmail.com │
                    │   <phone>           │
                    └──────┬──────────────┘
                           │
        ┌──────────────────┼──────────────────────────┐
        │                  │                          │
        v                  v                          v
┌────────────────┐  ┌──────────────┐    ┌──────────────────────┐
│ Vendor         │  │ Legal        │    │ Regulator            │
│ contacts       │  │ counsel      │    │ contacts             │
│                │  │              │    │                      │
│ Fly.io support │  │ Spice Route  │    │ CERT-In              │
│ Cloudflare R2  │  │ Legal        │    │ DPB India            │
│ Stripe support │  │ Finsec Law   │    │ SEBI                 │
│ Zerodha        │  │              │    │ NSE                  │
└────────────────┘  └──────────────┘    └──────────────────────┘
```

Full contact directory: [`incident-response.md`](incident-response.md) §"Contact directory."

### When to escalate to legal counsel

- Anything from SEBI, NSE, DPB, or a lawyer letter — engage legal first per [`incident-response.md`](incident-response.md) §Scenario 4.
- Threatened litigation (formal C&D, "demand letter").
- DPDP §13 grievance from a user (30-day reply window).
- Any communication where the wrong word becomes Exhibit A.

### When to escalate to regulator

- Data breach: CERT-In within 6h; DPB within 72h. AUTOMATIC — no judgment call.
- SEBI inquiry response: through legal counsel. Never reply directly.
- Trademark / IP claim: through legal counsel.

### When to escalate to vendor

- API rate-limit / suspension (Zerodha): per [`incident-response.md`](incident-response.md) §Scenario 2.
- Infrastructure outage suspected upstream of our code (Fly.io, Cloudflare R2): vendor support.
- Stripe webhook signature failures: Stripe support.

---

## 4. Roles & decision authorities

| Decision | Authority | Notes |
|---|---|---|
| Declare incident | Anyone who notices it | Better one false positive than one missed real |
| Engage kill switch | Maintainer | 5-second decision; reversible |
| Take service offline | Maintainer | Reversible but user-visible |
| Rotate `OAUTH_JWT_SECRET` | Maintainer | Invalidates ALL T1 records — see [`SECURITY_POSTURE.md`](SECURITY_POSTURE.md) §4.2 |
| Send public communication | Maintainer + (if available) legal counsel | Public post = permanent |
| Reply to regulator | Legal counsel only | Maintainer drafts evidence; lawyer drafts reply |
| File CERT-In report | Maintainer | Time-critical (6h); template pre-drafted |
| Notify affected users | Maintainer | Through grievance officer email; not personal Gmail |
| Pay external auditor | Maintainer | Budget ₹15-25k for post-incident review |
| Refund users | Maintainer | Pro-rata via billing tools (auditable trail) |

Single-maintainer means every decision routes to one person. As scale grows, decisions split per role; until then, named-authority discipline keeps the responder from second-guessing under stress.

---

## 5. Communication templates

These are skeleton templates. The full pre-drafted body for each is in [`incident-response.md`](incident-response.md). Listed here for orientation.

### 5.1 Public post (Twitter / Z-Connect / GitHub)

Use Scenario 1 template from [`incident-response.md`](incident-response.md). Format: 1 sentence, factual, link to changelog. NEVER thread.

### 5.2 User breach notification email

Use [`incident-response.md`](incident-response.md) §"Template: user breach notification email." Sent from grievance officer address (not personal Gmail). Plain text, no tracking pixels, no marketing.

### 5.3 CERT-In notification

Use [`incident-response.md`](incident-response.md) §"Template: CERT-In incident notification form fields." Pre-drafted to fit the 6-hour SLA — fill in 4 fields and submit.

### 5.4 Zerodha contact (`kiteconnect@zerodha.com`)

Per [`incident-response.md`](incident-response.md) §Scenario 2 / §"Parallel — Zerodha notification." Factual, short, includes our static egress IP for their lookup.

### 5.5 Status page update

Single-line update on `/dashboard` injected via server-side template:

```
[BANNER] Service incident YYYY-MM-DD HH:MM IST. Investigating <symptom>.
Updates: <link>. — Sundeep
```

Banner rendered until status is `Resolved`.

### 5.6 Internal post-mortem opener

Email to maintainer's own address (creates an audit trail for the post-mortem):

```
Subject: [INCIDENT POST-MORTEM] YYYY-MM-DD-<slug>

Detected: YYYY-MM-DD HH:MM IST
Class: <PR | API | Security | Legal>
Severity: <Critical | High | Medium | Low>
Status: <Open | Contained | Eradicated | Recovered | Closed>

Timeline starts at: docs/evidence/incident-YYYY-MM-DD/timeline.md
Post-mortem due: YYYY-MM-DD (T+30 days)

Triage notes:
- ...
```

---

## 6. Tabletop exercises

To stress-test the runbook before a real incident hits.

### 6.1 Quarterly tabletop

Quarterly: pick one scenario from [`incident-response.md`](incident-response.md) §"Decision triage" and walk through Phases 1-3 against current production state. Goal: identify gaps in the runbook BEFORE they bite.

| Quarter | Scenario | Output |
|---|---|---|
| 2026-Q2 | Data breach (Scenario 3) | DPDP+CERT-In templates current? Test send-and-revoke procedure works? |
| 2026-Q3 | Public criticism (Scenario 1) | Email templates current? Public-post draft current? |
| 2026-Q4 | API rate-limit / suspension (Scenario 2) | Zerodha contact thread current? |
| 2027-Q1 | Regulatory inquiry (Scenario 4) | Lawyer contact list current? Evidence package complete? |

After each tabletop: update this runbook + [`incident-response.md`](incident-response.md) with any gaps found.

### 6.2 Annual full-DR tabletop

Annual: simulate a complete data-restore from Litestream + R2 with `scripts/dr-drill.sh` AND walk through Phase 4 of an incident. See [`recovery-plan.md`](recovery-plan.md) §"DR tabletop."

---

## 7. Detection sources mapped to scenarios

Cross-link from [`continuous-monitoring.md`](continuous-monitoring.md) detection signals to incident scenarios. Helps the responder map "I see X alert" to "I should run scenario Y."

| Signal | Likely scenario | First-action runbook |
|---|---|---|
| `/healthz?format=json` `audit.dropped_count > 100` | API or Security | [`operator-playbook.md`](operator-playbook.md) §1.3, then [`incident-response.md`](incident-response.md) §Scenario 3 if data-write affected |
| `auto_freeze` event in audit log | Security (Adversary B/F) | [`incident-response.md`](incident-response.md) §Scenario 3; check audit trail for affected user |
| Hash chain verify failure | Security (tampering) | [`incident-response.md`](incident-response.md) §Scenario 3; preserve forensic snapshot before any change |
| Rate-limit 429 spike | API | [`incident-response.md`](incident-response.md) §Scenario 2; check audit for top-user |
| Stripe webhook signature failure spike | Security | Suspected secret leak; rotate `STRIPE_WEBHOOK_SECRET` |
| Public criticism on Twitter / Z-Connect | PR / Reputation | [`incident-response.md`](incident-response.md) §Scenario 1 |
| Cease-and-desist letter | Legal | [`incident-response.md`](incident-response.md) §Scenario 4 |
| Litestream WAL freshness `>10 min` | API (infra) | Check Cloudflare R2 status; if persisting, escalate to Cloudflare support |
| Memory >80% sustained | Infra | [`operator-playbook.md`](operator-playbook.md) §7 — scale-up signal |
| Sudden 10x spike in `place_order` for one user | Security (Adversary F or stolen credentials) | [`incident-response.md`](incident-response.md) §Scenario 3; freeze user immediately |

---

## 8. Evidence preservation

Every incident MUST produce these artefacts, all under `docs/evidence/incident-YYYY-MM-DD/`:

| Artefact | Source | When |
|---|---|---|
| `timeline.md` | Maintainer journal | Phase 1 onwards |
| `alerts.db.preimage` + sha256 | `flyctl ssh sftp get` | Phase 2 (BEFORE any change) |
| `flyctl-logs-<window>.log` | `flyctl logs --since YYYY-MM-DDTHH:MM:SS` | Phase 2 |
| `audit-export-<window>.csv` | Dashboard `/dashboard/activity?export=csv&from=...` | Phase 2 |
| `cert-in-form-YYYY-MM-DD.pdf` | CERT-In portal screenshot | Phase 5 |
| `dpb-draft.md` | Maintainer draft per DPDP §8(5) | Phase 5 |
| `lawyer-thread.mbox` | Gmail label export | Phase 5 |
| `postmortem.md` | Maintainer | Phase 6 |
| `independent-review.md` | External security engineer | Phase 6 |

Storage: archived as `docs/evidence/pack-YYYY-MM-incident-<slug>.zip` after closure. Retained indefinitely (regulatory subpoena defence).

---

## 9. Continuous improvement

Each incident closes the loop on the threat model and risk register.

| Output | Action | Document |
|---|---|---|
| Lesson 1: detection gap | Add monitoring signal | [`continuous-monitoring.md`](continuous-monitoring.md) |
| Lesson 2: threat model gap | Add adversary / surface row | [`threat-model-extended.md`](threat-model-extended.md) §1 / §2 |
| Lesson 3: control gap | Add mitigation; update [`SECURITY_POSTURE.md`](SECURITY_POSTURE.md) §3 |
| Lesson 4: process gap | Update this runbook | This file |
| Lesson 5: vendor failure | Update vendor risk tier | [`vendor-management.md`](vendor-management.md) |

Annual review of all post-mortems: identify systemic patterns. If 3+ post-mortems share a class of root cause (e.g. "audit chain wasn't enabled"), elevate to a quarterly-review topic and remediate at the root.

---

## 10. Cross-references

- [`incident-response.md`](incident-response.md) — scenario-driven playbooks (Scenarios 1-4 + Data breach)
- [`recovery-plan.md`](recovery-plan.md) — RTO/RPO, DR drills
- [`continuous-monitoring.md`](continuous-monitoring.md) — detection sources and alert thresholds
- [`vendor-management.md`](vendor-management.md) — vendor contacts and escalation paths
- [`operator-playbook.md`](operator-playbook.md) — day-2 ops decision tree
- [`change-management.md`](change-management.md) §6 — emergency change protocol
- [`SECURITY_POSTURE.md`](SECURITY_POSTURE.md) — control posture
- [`threat-model-extended.md`](threat-model-extended.md) — adversary categories + attack surfaces
- [`risk-register.md`](risk-register.md) — operational risks
- [`access-control.md`](access-control.md) — RBAC / admin gating
