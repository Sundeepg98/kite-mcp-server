# Incident Response Runbook

**Last updated:** 2026-04-17
**Owner:** Sundeep Govarthinam (current single operator)

## Purpose

Pre-drafted response scripts for 4 incident classes. Follow the matching
script when an incident occurs; do NOT improvise under pressure.

The goal: cut response latency from hours to minutes by executing from
script rather than drafting fresh under stress. Read this file *before*
an incident. Keep `docs/evidence/` populated so the "pre-built evidence
package" section has real artifacts to hand over.

Sibling runbooks:
- Day-2 ops: [operator-playbook.md](operator-playbook.md)
- Security posture reference: [SECURITY_POSTURE.md](SECURITY_POSTURE.md)
- Legal index: [legal-notes.md](legal-notes.md)

---

## Decision triage

When an incident hits, the first question is **which bucket**. Pick one,
then jump to that scenario. Do not start doing things before picking a
bucket.

- **PR/reputation** — public criticism from Nithin, media, influencer,
  or a viral negative thread. Go to **Scenario 1**.
- **API** — Zerodha rate-limits, throttles, or revokes Kite Connect
  access; 429s across the board; suspension email. Go to **Scenario 2**.
- **Security** — vulnerability disclosed, breach suspected, user
  complaint of unauthorized orders, secrets leaked. Go to **Scenario 3**.
- **Legal** — SEBI / NSE inquiry, cease-and-desist, trademark claim,
  DPDP complaint, lawyer letter. Go to **Scenario 4**.

If you're unsure whether it's "PR" or "Legal" (e.g., a Zerodha legal
post on Twitter), treat as **Legal** — the higher-formality playbook
covers both.

---

## Scenario 1: Public criticism (e.g., Nithin disapproves)

The working example: Nithin Kamath (Zerodha CEO) publicly criticises
`kite-mcp-server` on X / Z-Connect / LinkedIn. Same script applies for
any public figure with >10k followers in the Indian fintech space.

### Hour 0–2: STOP

- [ ] Screenshot the criticism (full thread + any replies) and archive
      to `docs/evidence/incident-YYYY-MM-DD/`. Timestamp matters for
      later timeline reconstruction.
- [ ] Do **NOT** tweet, do NOT reply, do NOT DM supporters. Do not
      "soft" defend in private — anything you send to anyone becomes
      public if forwarded.
- [ ] Re-read Agent 53's full Nithin-disapproval playbook (session
      memory / `.research/` if archived).
- [ ] Breathe. Two hours of silence is better than two minutes of the
      wrong reply.

### Hour 2–6: Private email

Send to Nithin's publicly-known email (check Z-Connect profile,
LinkedIn). CC Kailash Nadh (CTO). CC kiteconnect@zerodha.com (ecosystem
team — keeps it on the support record).

Pre-drafted template (~150 words, adjust the square brackets only):

> **Subject:** Your [DATE] concern about kite-mcp-server
>
> Nithin,
>
> Saw your [tweet / Z-Connect post / LinkedIn note] today. Taking it
> seriously and responding in private first.
>
> Facts on `kite-mcp-server`: it is a fork of your own open-source repo
> under MIT. All authentication is per-user OAuth; there are no pooled
> API keys, no shared tokens, and no performance claims. Every tool is
> explicitly disclaimed as non-advisory.
>
> Happy to remove anything you flag, join a call at any time, or shut
> down the hosted instance (`kite-mcp-server.fly.dev`) today pending
> review. Logs and audit trail are at [short link to evidence pack].
>
> What would be most useful — a call, a written response, or just a
> shutdown? I will action whichever you choose within 24 hours.
>
> — Sundeep
> [phone] | <grievance officer email>

**Do NOT** in this email: defend the project, offer counter-arguments,
cite SEBI regulations, claim compliance wins, reference community
support, or mention fundraising / revenue.

**Do** in this email: acknowledge, state facts (not spin), offer
concrete options, provide a link to evidence. Three sentences of fact
beats three paragraphs of defence.

### Hour 6–24: One factual public post

Only after sending the private email. Post once, from your personal
handle (not a project handle):

- Thank Zerodha by name ("Thanks to Zerodha for the feedback on ...").
- State what is changing ("Disabling trading tools on the hosted
  instance effective immediately while we align with Zerodha's
  feedback.").
- Link a changelog PR that is **already merged** showing the fix.
- One sentence only. No threads. No tagged defenders. No replies to
  any criticism thread.

Pre-drafted template:

> Thanks to @Nithin0dha and the Zerodha team for feedback on
> kite-mcp-server. Effective today: trading tools disabled on the
> hosted instance pending their review; read-only data tools remain
> for self-hosted users. Changelog: [link]. Happy to take this
> offline — <grievance officer email>.

If supporters pile on in the thread, do not reply to any of them, not
even to thank them. Every reply you make becomes a new attack surface.

### Week 1 decision tree

By end of week 1, the criticism has usually resolved into one of three
concrete asks. Execute the matching branch.

**Scenario A — Kite Connect key revoked:**

- [ ] Kill Fly.io instance within 2 hours:
      `flyctl scale count 0 -a kite-mcp-server`
- [ ] Pivot to self-hosted-only. Publish migration guide linking
      [byo-api-key.md](byo-api-key.md) and
      [client-examples.md](client-examples.md).
- [ ] Pro-rata refund any paying users (manual list from billing
      store — use admin tools, not a script, for auditability).
- [ ] Communicate openly on kite.trade/forum ("Connect tier revoked;
      project now self-hosted only. Here is the migration guide.").

**Scenario B — Trademark "Kite" objection:**

- [ ] Execute the `Algo2Go` rename within 72 hours (placeholder name;
      confirm non-conflicting at rename time).
- [ ] 301 redirect the old GitHub repo to the new one.
- [ ] Publish a rename note in CHANGELOG.md and on project site.
- [ ] Update all references in code, docs, marketing, landing page.
      Grep for `Kite` in user-facing strings, rename only the ones
      that refer to our project (not the Zerodha API — that stays
      "Kite Connect").

**Scenario C — "Unregistered algo provider" objection:**

- [ ] Flip `ENABLE_TRADING=false` on the hosted instance (env var
      flip on fly.io — 5 minutes:
      `flyctl secrets set ENABLE_TRADING=false -a kite-mcp-server`).
- [ ] Keep data/read-only tools available. Update landing page copy
      to reflect "data-only hosted instance, trading via self-host".
- [ ] Re-engage `kiteconnect@zerodha.com` with revised architecture
      ("Trading disabled. Data pass-through only. Confirms we are
      not acting as an unregistered provider.").
- [ ] Publish SEBI framework compliance note referencing
      `SECURITY_POSTURE.md` §7.

---

## Scenario 2: API rate-limit / throttle / ban

### Symptoms

- HTTP 429 from `api.kite.trade` on all egress from
  `209.71.68.157` (our Fly.io bom static IP).
- Email from `kiteconnect@zerodha.com` citing §9a of the Kite Connect
  terms (10-day cure notice).
- Cloudflare IP ban at the Zerodha edge (different signature — 403 or
  connection reset rather than 429).
- User reports: "user not enabled on app" — usually means the user's
  own Kite developer app is misconfigured, not ours. Verify in audit
  log before escalating.

### First hour

- [ ] Check audit log for a sudden rate spike in the last 24 hours:
      `sqlite3 $ALERT_DB_PATH "SELECT user_email, COUNT(*), DATE(ts) \
        FROM tool_calls WHERE ts > datetime('now','-1 day') \
        GROUP BY user_email ORDER BY 2 DESC LIMIT 20;"`
      Identify the top user — if one user is >10× the median, they
      caused it.
- [ ] Post to kite.trade/forum asking for clarification on the throttle
      (keeps a public trail — Zerodha support reads the forum).
- [ ] Email `kiteconnect@zerodha.com` with a factual note:
      > Seeing 429s from our egress IP 209.71.68.157 starting [timestamp].
      > Investigating internally. Rate limit config attached.
      > Please confirm whether this is deliberate on your side or we
      > should treat as our own issue.
- [ ] If self-caused, reduce in-process rate limits (`app/ratelimit.go`).
      Do not redeploy until you've confirmed the cause — a change-under-
      pressure deploy risks making it worse.
- [ ] If a §9a 10-day cure notice: open a GitHub issue titled
      `[INCIDENT] Zerodha §9a cure notice YYYY-MM-DD`, fix within 5
      days (half the window), and confirm with Zerodha in writing
      before the 10-day bell.

### What to NOT do

- Do not retry the same request type faster "to see if it recovers".
- Do not rotate to a second Fly.io region to get a fresh IP — their
  contract is tied to the registered static IP.
- Do not assume "they'll fix it" — acknowledge in writing within 24h
  or Zerodha's terms presume silence = agreement.

---

## Scenario 3: Security vulnerability

### Symptoms

- CVE reported against `gokiteconnect`, `mcp-go`, or our own code
  (GitHub security advisory, email to `security@`).
- User reports unauthorized orders, missing holdings, or PII leak.
- Fly.io or Cloudflare R2 compromise suspected (unexpected login,
  unknown API key activity).
- Secrets found in a public commit (rotate immediately regardless of
  severity).

### First 72 hours — DPDP Breach Notification Rule 7

India's Digital Personal Data Protection Act imposes a staged
notification:

- [ ] **T+1 hour — triage & contain.** Freeze affected accounts
      (admin tool: `admin_freeze_user`). Rotate any suspected
      compromised secret (`OAUTH_JWT_SECRET`, Kite keys, R2 credentials).
      Preserve logs — do NOT delete.
- [ ] **T+24h — initial intimation to Data Protection Board of India**
      via portal. Required fields: nature, extent (approximate user
      count), timing, likely impact. Vagueness is acceptable at T+24h;
      accuracy matters more than completeness.
- [ ] **T+72h — detailed report to DPB.** Must include: facts,
      root cause, mitigation taken, party responsible (our side vs
      upstream), prevention measures. This is the report that gets
      scrutinised — attach logs, commit SHAs, audit trail export.
- [ ] **Parallel — notify affected users** via the email on file
      (`kc/credstore/` has the per-user email). Use a pre-drafted
      notification template (see below).
- [ ] Do NOT delete audit logs, `tool_calls` rows, or encrypted
      credential rows under any circumstance — DPB may subpoena.
- [ ] If you can't meet T+72h, request DPB extension in writing
      before the deadline (not after).

### User notification template

> **Subject:** Security incident affecting your kite-mcp-server account
>
> On [date], we identified [brief description]. Your account may be
> affected because [specific reason]. We have [mitigation taken].
>
> What you should do:
> 1. Log in to Kite and review orders and positions from [date range].
> 2. Revoke our app at kite.trade > API Console > Revoke if you want
>    to be cautious.
> 3. Reply to this email with any unauthorised activity.
>
> We have reported this to the Data Protection Board of India as
> required under DPDP Rule 7. Full timeline and technical details:
> [link].

### After containment

- [ ] Post-mortem in `docs/evidence/incident-YYYY-MM-DD/postmortem.md`.
- [ ] Third-party review within 30 days (at minimum: pay a freelance
      security engineer for 4 hours of independent audit).
- [ ] CVE published if our code caused it, with credit to reporter.
- [ ] Update `THREAT_MODEL.md` with the class of vuln so it's covered
      next time.

---

## Scenario 4: Regulatory inquiry / C&D / DPDP complaint

### If from SEBI

- [ ] Do NOT respond on your own. Engage a fintech lawyer first.
      Primary: Spice Route Legal — `info@spiceroutelegal.com` (budget
      ₹20–30k for a 1-hour consult). Alt: Finsec Law (Mumbai) —
      `info@finseclaw.com`.
- [ ] Acknowledge receipt within 24 hours of the inquiry. A three-line
      acknowledgement is fine — the lawyer drafts the substantive
      reply.
- [ ] Compile the evidence package (see section below) in parallel
      while the lawyer drafts.
- [ ] Full written response within 30 days (standard SEBI timeline).
      If more time is needed, the lawyer requests an extension in
      writing — do not let the window lapse silently.
- [ ] Every email in/out goes into `docs/evidence/incident-YYYY-MM-DD/`.
      Don't rely on Gmail retention.

### If from Zerodha / NSE (cease-and-desist)

- [ ] Same drill — lawyer first. Even a "friendly" Zerodha legal note
      is a formal communication.
- [ ] Comply with specific asks (e.g., "stop using the name X") while
      seeking clarification on ambiguous ones.
- [ ] Do NOT threaten counter-legal-action. Do NOT attempt to "wait
      it out" or ignore.
- [ ] Do NOT publicly discuss the C&D until the lawyer says it's
      safe (usually after the reply window closes).

### If DPDP complaint (user files with DPB)

- [ ] Our DPO / Grievance Officer (currently Sundeep — update TERMS.md
      when this changes) must reply within 30 days of receipt (DPDP
      §13, confirmed against the CPA 2019 Rule cadence).
- [ ] Contact info for DPB India: per the official portal at
      [to be filled once portal publishes a stable URL].
- [ ] Cooperative stance. Offer to meet, walk through the audit trail,
      and fix whatever the complaint surfaces. Hostile DPDP responses
      escalate to regulator sanctions fast.

---

## Data breach playbook

A dedicated playbook for confirmed data breaches. Cross-cuts Scenario 3
(security vulnerability) and Scenario 4 (DPDP complaint) — use this
section whenever personal data has been (or is suspected to have been)
accessed, exfiltrated, or disclosed without authorization.

Written for the current operating reality: solo operator, pre-LLP,
fewer than 50 users. Scale assumptions will change once the entity
incorporates or paid user count crosses 200.

### Scope

Any unauthorized access, exfiltration, or disclosure of user personal
data falls into this scope. Specifically:

- Kite API credentials (API key + secret stored encrypted in
  `KiteCredentialStore`)
- Kite access tokens (encrypted in `KiteTokenStore`, refreshed daily)
- User email addresses (from OAuth sign-in + billing)
- Tool-call audit logs (`tool_calls` table — contains redacted
  parameters but user-attributable)
- Telegram chat IDs (linked to email in the Telegram binding store)
- OAuth client registrations (client_secret encrypted)

Any of the above leaving our control — via server compromise, SQLite
exfiltration, Cloudflare R2 backup exposure, a rogue dependency, or a
config accident — triggers this playbook.

### Timelines (legally bounded — meet all of these)

These are cumulative legal obligations; missing any one is a separate
violation independent of the breach itself.

- **T+0 to T+6h — CERT-In notification.** Mandatory under the CERT-In
  Directions dated April 28, 2022 (issued under §70B(6) of the IT Act).
  Submit via https://www.cert-in.org.in (incident reporting form) or
  email `incident@cert-in.org.in` with the form attached. Use the
  template below. The 6-hour clock starts at the moment of *detection*,
  not the moment of breach — document both timestamps.
- **T+0 to T+72h — Data Protection Board of India (DPB) notification.**
  Required under §8(5) of the DPDP Act 2023. Form and exact fields
  pending final DPDP Rules; draft using §8(5) requirements (nature,
  extent, timing, consequences, mitigation). Submit when the DPB
  portal is live; until then, keep the draft under
  `docs/evidence/incident-YYYY-MM-DD/dpb-draft.md` so the audit trail
  shows the 72-hour draft was prepared on time.
- **T+0 to T+72h — affected-user notification.** Email every affected
  user via the address on file in `KiteCredentialStore`. Simultaneously
  display an in-app banner on `/dashboard` (inject via the server-side
  template — do NOT rely on users logging in within 72h).
- **Parallel — Zerodha notification.** If Kite API credentials or
  developer-app secrets were exposed, email `kiteconnect@zerodha.com`
  within the same 72h window. They may rotate developer-app secrets
  on their side, which breaks every user's active session — they need
  to know first.

### Decision tree (first 60 minutes)

The first hour determines whether the next 72 are manageable or
catastrophic. Follow this order; do not skip.

**0–5 min — confirm the breach is real.**

- [ ] Is this a test, a false positive, or a genuine event? Check
      `fly logs -a kite-mcp-server` for the trigger.
- [ ] Verify audit-trail hash-chain integrity (`admin_list_anomaly_flags`
      + manual `tool_calls` hash walk).
- [ ] Cross-check with Cloudflare R2 access logs (unexpected download
      = exfiltration).
- [ ] If still uncertain after 5 minutes: treat as real and continue.
      False positive during containment is cheap; missed real breach
      is not.

**5–15 min — scope assessment.**

- [ ] How many users affected? (`SELECT COUNT(DISTINCT user_email) FROM
      tool_calls WHERE ts BETWEEN ? AND ?`)
- [ ] What data categories? Map to DPDP §8(5) terminology:
      credentials, tokens, emails, audit logs, or combinations.
- [ ] Is this ongoing (attacker still has access) or past (window
      closed)? Ongoing = containment is priority 1; past = evidence
      preservation is priority 1.

**15–30 min — containment.**

- [ ] Freeze the kill switch:
      `admin_set_kill_switch --enabled=true --reason="data breach
      incident YYYY-MM-DD"`. This halts all write paths immediately.
- [ ] Rotate `OAUTH_JWT_SECRET`:
      `flyctl secrets set OAUTH_JWT_SECRET=$(openssl rand -hex 32)
      -a kite-mcp-server`. Invalidates all MCP bearer JWTs; forces
      every user to re-authenticate. This also rotates the HKDF salt
      for AES-256-GCM credential encryption — see credstore notes
      below before flipping.
- [ ] If credential-store encryption key was exposed: rotate the
      derived key and re-encrypt the table in-place. Procedure in
      `kc/credstore/README.md` — test in staging first if time allows.
- [ ] Revoke all active MCP sessions (`SessionRegistry` table purge):
      `sqlite3 $ALERT_DB_PATH "DELETE FROM sessions;"`. Users will
      reconnect via mcp-remote automatically.
- [ ] Preserve a forensic snapshot BEFORE any of the above:
      `flyctl ssh sftp get /data/alerts.db ./evidence/alerts.db.preimage`
      and hash it (`sha256sum`) so the forensic timeline has a
      known-good starting point.

**30–60 min — draft notifications.**

- [ ] Fill out the CERT-In template (below) and submit. The 6-hour
      deadline is the tightest — prioritise this over DPB.
- [ ] Draft the user-notification email (template below) but do NOT
      send yet. Check with the lawyer first if one is engaged.
- [ ] Open `docs/evidence/incident-YYYY-MM-DD/timeline.md` and start
      logging timestamped events. Every action goes in.

### Template: CERT-In incident notification form fields

Pre-fill these so the form can be submitted in ≤15 minutes under
pressure. The form is at https://www.cert-in.org.in under "Report an
Incident".

```
Type of incident: Data breach / Unauthorized access
Date and time of occurrence: YYYY-MM-DD HH:MM IST
Date and time of detection: YYYY-MM-DD HH:MM IST

Incident description (1 paragraph, ≤500 chars):
On <date>, unauthorized access to <component> was detected. The
incident resulted in <exposure summary>. Root cause is <known /
under investigation>. The service was placed in kill-switch mode at
<time>; all active sessions revoked at <time>. Forensic snapshot
preserved at <hash>.

Number of affected users: <exact count or "approximately N">
Category of data exposed (DPDP Act §8(5) terminology):
  - Authentication credentials (encrypted at rest)
  - Session tokens (encrypted at rest)
  - Contact identifiers (email addresses)
  - Audit / transaction logs (PII-redacted)
  - <any other category that applies>

Actions taken:
  - Kill switch engaged at <time>
  - Rotated OAUTH_JWT_SECRET and credential-store key at <time>
  - Revoked all active sessions at <time>
  - Forensic snapshot preserved (SHA256: <hash>)
  - Affected users notified at <time> (or: draft ready; send
    scheduled for <time> pending lawyer review)
  - DPB notification drafted; submission pending portal activation
    (DPDP Rules not yet notified)

Contact person:
  Name: Sundeep Govarthinam
  Role: Grievance Officer (solo operator; entity incorporation pending)
  Email: <grievance officer email>
  Phone: <phone>
```

### Template: user breach notification email

Send from the grievance officer address (NOT a personal Gmail).
Plain text. No tracking pixels. No marketing content.

```
Subject: Important security notice about your kite-mcp-server account

Hello,

On <date> we detected <brief factual description of the incident>.
Your account is affected because <specific reason — do not
generalise>.

What data was involved:
  - <specific category 1>
  - <specific category 2>
  (We have NOT found evidence that <category not affected> was
   accessed. We will update you if that changes.)

What we did:
  - Engaged the server kill switch at <time>, halting all writes
  - Rotated the encryption key protecting stored credentials
  - Revoked all active sessions — you will need to sign in again
  - Preserved forensic evidence and notified CERT-In within 6 hours
  - Filed a draft notification with the Data Protection Board of
    India (pending portal activation)

What you should do:
  1. Rotate your Kite developer-app credentials immediately:
     a. Log in to https://developers.kite.trade
     b. Revoke the existing app ("Revoke" button on the app page)
     c. Create a new app with the same redirect URI
     d. Re-upload the new API key + secret via our dashboard at
        https://kite-mcp-server.fly.dev/dashboard
  2. Log in to https://kite.zerodha.com and review all orders and
     positions between <start date> and now. Flag anything unfamiliar
     to Zerodha support.
  3. If you used the same password anywhere else, change it (this
     incident does not involve passwords, but basic hygiene applies).

Timeline:
  <date> <time> — Incident occurred (best estimate)
  <date> <time> — Incident detected
  <date> <time> — Containment actions completed
  <date> <time> — CERT-In notified
  <date> <time> — This notice sent

Questions: reply to this email. I respond personally within 24 hours
as the sole operator. Formal grievance channel:
  Grievance Officer: Sundeep Govarthinam
  Email: <grievance officer email>

The full technical post-mortem will be published at
<docs/post-mortems/YYYY-MM-DD-<slug>.md> within 30 days of this
notice.

— Sundeep
  <grievance officer email>
```

### Credential compromise — Kite API key/secret

A sub-case of the broader data-breach playbook, specific to exposure
of Kite developer-app credentials. Handle slightly differently because
the rotation burden falls on the user, not the server.

**Single-user compromise (one user's credentials leaked):**

- [ ] Mark that user's row in `KiteCredentialStore` as
      `status=revoked` (admin SQL or future admin tool). Subsequent
      tool calls for this user return 401 until they re-upload.
- [ ] Email the user specifically (template above, scoped to one
      account). Do NOT broadcast — it unnecessarily alarms unaffected
      users.
- [ ] User action required: they log in to
      https://developers.kite.trade, revoke their existing app, create
      a new one with the same redirect URI, and re-upload the new
      credentials via `/dashboard`.
- [ ] Server action: once they re-upload, the new row replaces the
      revoked one. No action needed on the old `kite_access_tokens`
      row — the revoked credentials can no longer mint tokens against
      it.

**Server-side compromise (credential-store encryption key exposed —
all users affected):**

- [ ] Mark all rows in `KiteCredentialStore` as `status=revoked`
      simultaneously (admin SQL: `UPDATE kite_credentials SET
      status='revoked' WHERE status='active';`).
- [ ] Email all users simultaneously via a bulk send from the
      grievance officer address. Template above, addressed generically.
- [ ] Provide a 7-day grace window before hard-disabling the
      revoked credentials (just in case a user's email bounces and
      they need to be reached via Telegram or another channel).
- [ ] Rotate the credential-store encryption key (HKDF salt stored
      in `OAUTH_JWT_SECRET` — rotating the JWT secret forces
      key re-derivation on next write).
- [ ] Post a public incident notice on the landing page + GitHub
      README within 24 hours. Silent server-side compromises that
      users discover via media become DPDP-violation compounders.

### Post-breach

The 72 hours are survival. The 30 days afterward determine whether
users and regulators trust you again.

- [ ] Forensic review — hire an independent security engineer for
      4–8 hours (budget ₹15–25k). They review the exfil path and
      the fix; their writeup becomes an appendix to the post-mortem.
- [ ] Update `THREAT_MODEL.md` with the vulnerability class so the
      threat model covers it next time (not "this specific bug" —
      the class it belongs to).
- [ ] File the post-mortem under
      `docs/post-mortems/YYYY-MM-DD-<incident-slug>.md`. Must include:
      timeline, root cause, diff that caused it, diff that fixed it,
      independent-review appendix, and what changed in the threat
      model.
- [ ] Publish the post-mortem publicly within 30 days. Specificity
      rebuilds trust; vagueness erodes it.
- [ ] Re-submit to CERT-In a "closure report" confirming the incident
      is resolved (form on the CERT-In portal).
- [ ] If DPB was notified: file the follow-up report with DPB once the
      portal accepts follow-ups (§8(5) DPDP requires closure
      notification when mitigation is complete).

---

## Contact directory

Keep this list current. If a contact changes, the wrong address in a
regulator reply is its own incident.

- **Zerodha Kite Connect compliance:** kiteconnect@zerodha.com
- **Rainmatter ecosystem (for PR-related outreach):** talk@rainmatter.com
- **SEBI inquiry contact:** contact@sebi.gov.in (office inbox; specific
  divisions have their own — the formal notice will name one)
- **NSE:** nnfreg@nse.co.in
- **DPB India:** [to be filled once portal live]
- **Lawyer (first call):** Spice Route Legal — info@spiceroutelegal.com
- **Alt lawyer:** Finsec Law (Mumbai) — info@finseclaw.com
- **Fly.io support (infra):** `flyctl support` or
  https://community.fly.io (our paying tier)
- **Cloudflare R2 support:** via dashboard ticket

---

## Things to NEVER do

Ordered by how much damage each has caused in other founder post-mortems.

1. **Threaten legal action in the first response.** It locks the other
   side into an adversarial posture before either of you understands
   the facts.
2. **Rage-delete the repo or lock GitHub issues.** Looks like a
   cover-up. Everything on GitHub is archived by third parties anyway.
3. **Mobilise Twitter defenders or reply-attack critics.** One
   defensive reply from you legitimises a hundred pile-on replies
   from both sides.
4. **Delete audit logs, `tool_calls` rows, or credential store rows.**
   Both a SEBI and a DPDP violation on its own, independent of the
   original incident.
5. **Respond to SEBI without a lawyer.** Even an innocuous email can
   be quoted back. Let the lawyer draft.
6. **Admit guilt publicly before the lawyer consults.** "Sorry, we
   were wrong" in a tweet becomes Exhibit A.
7. **Push a code fix under pressure without tests.** You are far more
   likely to break something than to fix the original issue. If a fix
   is urgent, the `ENABLE_TRADING=false` env flip is your panic
   button.

---

## Pre-built evidence package

Keep these artifacts current at `docs/evidence/` so they are available
within 5 minutes of an incident. Refresh monthly.

- [ ] Architecture diagram (current version from `ARCHITECTURE.md`)
- [ ] Audit log export, last 30 days, PII-redacted
      (`sqlite3 $ALERT_DB_PATH "SELECT ... FROM tool_calls ..."`)
- [ ] Commit history showing security diligence (tag `v1.0.0` onwards)
- [ ] `TERMS.md` + `PRIVACY.md` current signed copies
- [ ] User count (from admin dashboard; approximate is fine)
- [ ] Revenue (from billing store, if billing activated)
- [ ] Email threads with Zerodha (kiteconnect@zerodha.com) — export
      the Gmail label to mbox
- [ ] SEBI framework compliance note (`SECURITY_POSTURE.md` §7)
- [ ] Threat model (`THREAT_MODEL.md`)
- [ ] Security audit reports (`SECURITY_AUDIT_REPORT.md`,
      `SECURITY_PENTEST_RESULTS.md`)

Store as `docs/evidence/pack-YYYY-MM.zip` so "which version" is never
ambiguous when a regulator asks for it six months later.

---

## Post-incident: Recovery timeline

Don't skip this. Post-incident is when most founders go quiet and the
narrative calcifies against them.

- **Week 2–4:** Post-mortem blog on personal site + GitHub. Include
  the real timeline, the diff that caused it (if code), the diff
  that fixed it, and a link to a third-party review. Specificity
  builds trust back faster than vague apologies.
- **Month 2–3:** Re-submit FLOSS / Rainmatter fund applications citing
  the feedback verbatim and what changed. Regulators and funders
  respect engineers who close the loop; they distrust silent ones.
- **Month 4–6:** Re-approach Rainmatter via warm intro (FOSS United
  member or Rainmatter portfolio founder). A cold email 30 days
  after incident won't land; a warm intro at 4 months will.
- **Month 6–12:** Reputation rebuild. Target: a neutral Zerodha
  mention (e.g., a Kailash Nadh retweet of a changelog) or a
  positive Indian-fintech-press quote. No pushing — the recovery
  comes from shipping visibly, not pitching.

---

## Changelog

- 2026-04-17: Initial version. Pre-drafted from Agent 53's crisis
  playbook. Untested in a live incident (good problem to have).
- 2026-04-18: Added dedicated "Data breach playbook" section covering
  CERT-In 6-hour notification (IT Act §70B(6), April 2022 Directions),
  DPDP Act 2023 §8(5) 72-hour DPB notification, decision tree for the
  first 60 minutes, pre-filled CERT-In form template, user-breach
  notification email template, and the Kite API credential-compromise
  sub-playbook (single-user vs server-side). Replaced Foundation email
  references with `<grievance officer email>` placeholder.
