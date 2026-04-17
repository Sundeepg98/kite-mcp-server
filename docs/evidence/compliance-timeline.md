# Compliance Timeline

Reverse-chronological log of outreach, filings, and compliance touchpoints. Keep factual — no editorialising.

Format: `YYYY-MM-DD — counterparty — action`

---

## 2026-04-XX — kiteconnect@zerodha.com — voluntary disclosure

- **Status:** Pending send
- **Type:** Proactive compliance disclosure
- **Purpose:** Inform Zerodha Kite Connect team that we operate a self-hosted MCP bridge using their developer API; describe our BYO-app model and risk controls
- **Draft location:** `docs/drafts/zerodha-email.md` (if drafted)
- **Expected response window:** 5-10 business days based on kiteconnect@zerodha.com published SLA
- **Owner:** Sundeep (g.karthick.renusharmafoundation@gmail.com)

## 2026-04-XX — Spice Route Legal — consultation

- **Status:** Not yet booked
- **Type:** 1-hour paid legal consult
- **Purpose:** Validate TERMS/PRIVACY draft, DPDP exposure analysis, SEBI investment adviser boundary, broker redistribution concerns
- **Estimated cost:** ₹20-30k for initial consult
- **Owner:** Sundeep
- **Follow-up:** Incorporate feedback into TERMS.md / PRIVACY.md (currently marked DRAFT per commit `18aa136`)

## 2026-04-XX — SEBI — (no contact to date)

- **Status:** No direct outreach
- **Reasoning:** We are not an SEBI-regulated entity today. Server is a UX layer over user's own broker relationship; no funds touched; no advisory claims (see commit `78301d6`). Path-2 posture (`04f4b18` `ENABLE_TRADING` env gate) keeps the default-off surface minimal.
- **Trigger for direct outreach:** Only if counsel advises, or if a Zerodha response indicates SEBI notification is expected

---

## Historical milestones (development-side, not counterparty outreach)

These are internal milestones relevant to a compliance story — they sit here so a regulator reading chronologically sees the diligence arc.

- **2026-02 — Security audit:** 27-pass manual analysis, 181 findings documented in `SECURITY_AUDIT_REPORT.md`
- **2026-03 — Security audit remediation:** All 181 findings closed (153 fixed, 28 accepted risk). Deployed Fly.io v43 on 2026-03-01
- **2026-03 — Quality audit:** 3-agent parallel review + review-of-reviews. 34 findings total, all addressed. 257+ tests
- **2026-04-XX — Incident-response runbook** (commit `2c72647`): Crisis playbook with regulator timelines and escalation paths
- **2026-04-XX — TERMS/PRIVACY marked DRAFT** (commit `18aa136`): Explicit acknowledgement that legal review is pending, to mitigate DPDP liability drift
- **2026-04-XX — Path-2 compliance** (commit `04f4b18`): `ENABLE_TRADING` env gate, order-placement tools default-off for new deployments
- **2026-04-XX — Riskguard tightening** (commit `7cd7b35`): Default-on order confirmation + lower default caps specifically to mitigate prompt-injection-driven orders
- **2026-04-XX — SEBI-disclaimer on Telegram** (commit `3879aba`): Every outbound message prefixed with disclaimer + `/disclaimer` command, pre-empting advisory classification drift

---

## Template for future entries

```
## YYYY-MM-DD — [counterparty name] — [action type]

- **Status:** [Sent / Pending / Responded / Closed]
- **Type:** [Disclosure / Filing / Consult / Response to inquiry / ...]
- **Purpose:** [One sentence]
- **Draft or thread location:** [Path / URL]
- **Response timeline:** [Days to reply, or "no response yet as of DATE"]
- **Owner:** [Name + email]
- **Follow-up action:** [What we do next, if anything]
```
