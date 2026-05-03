# Compliance Emails — Outreach Log

Append-only log of every email sent to regulators, exchange / broker compliance teams, legal counsel, or other counterparties in a compliance capacity.

## Log

| Date | To | Subject | Response received? | Link to thread |
|------|----|---------|--------------------|----------------|
| (none yet) | | | | |

---

## Log format (per entry)

When you send an email, record it below with this shape:

```
### YYYY-MM-DD — [recipient email address + name if known]

- **Subject:** [Exact subject line of the email]
- **Summary (2 sentences max):** [Why you sent it + what you asked / disclosed]
- **Response timeline:** [Days to reply — or "no response as of YYYY-MM-DD"]
- **Outcome:** [Acknowledgement / answer / escalation / closed with action]
- **Link to original (sent items) + response:** [Gmail thread URL, Jira ticket, or similar]
- **Attachments sent:** [List any — e.g. architecture.md, SECURITY_AUDIT_REPORT.md]
```

---

## Known future counterparties

Pre-populated for reference; move into the log above when an actual email goes out.

- **kiteconnect@zerodha.com** — Zerodha Kite Connect compliance / developer support
- **helpdesk@sebi.gov.in** — SEBI (use only on counsel's advice)
- **support@spiceroutelegal.com** / direct counsel — Legal advisory (booking required)
- **ciso@cert-in.org.in** / `incident@cert-in.org.in` — CERT-In (only if we reach a Category I/II incident as defined in `docs/incident-response.md`)
- **grievances@nsdl.co.in** — NSDL (depositary; unlikely to be relevant unless a securities-data issue arises)
- **dp-grievances@bseindia.com** / **investorhelp@nse.co.in** — Exchange investor relations (unlikely — we don't interact with exchange directly)

## Hygiene rules

1. **Append-only.** Never delete a log entry. If facts change, add a follow-up entry.
2. **Screenshot or PDF the response.** Emails can be lost / inboxes wiped; keep a local record.
3. **Keep 2-sentence summaries honest.** If it was a friendly ack with no substance, say so.
4. **If no response after 10 business days on a disclosure:** escalate per `docs/incident-response.md`.
5. **Never send legal / compliance email from a non-project address.** Sundeep's product email (not the foundation-context address) is the canonical project contact. Previous entries that cite the foundation-context address predate the 2026-04-18 rule clarification and should be read as "personal email at the time of the note", not as the canonical contact. The foundation-context Gmail address is foundation-only and must never appear on product communications.

## Example filled entry (fictional — do not confuse with real data)

```
### 2026-05-15 — kiteconnect@zerodha.com (Zerodha Compliance)

- **Subject:** Voluntary disclosure — kite-mcp-server self-hosted MCP bridge for Kite Connect
- **Summary:** Informed Kite Connect team we operate a self-hosted MCP bridge using per-user BYO developer apps with layered risk controls; attached architecture doc + security audit summary; asked if any formal acknowledgement process exists.
- **Response timeline:** Replied 2026-05-19 (4 business days)
- **Outcome:** Acknowledged receipt; confirmed no formal programme but our BYO model is consistent with Kite Connect terms; no action required from us at this time.
- **Link to original + response:** [Gmail thread URL here]
- **Attachments sent:** docs/evidence/architecture.md (PDF), SECURITY_AUDIT_REPORT.md (PDF)
```
