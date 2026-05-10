# Launch Path Execution Playbooks

**Date**: 2026-05-10
**HEAD audited**: `bcbe9f0` (Path A's C1 cleanup — `chore(deps): bump audit/users/watchlist v0.1.0 → v0.2.0`)
**Predecessor**: `4f0d021 docs(forward-tracks): strategic review + 5-track survey for next-30d`
**Charter**: research-only execution playbooks. Doc-only. NO code changes. Per-item: dispatch procedure + halts + credentials + success criteria + cleanup.
**Concurrency**: Path A owner in flight on C1+C2+C3 cleanup chain (disjoint scope). All other agents idle.

**Production state at audit-time**:
- Master HEAD: `bcbe9f0`
- Production: v1.3.0 / tools=111 (550+ commits stale per `forward-tracks-strategic-review.md`)
- 28 algo2go external modules
- Active recommendation from predecessor: deploy current master FIRST, then execute the 5 actions in this playbook

---

## TL;DR — dispatch order

Five items, ranked by user-time-to-decision:

| # | Item | Agent time | User time | $ cost | Halts | Recommendation |
|---|---|---|---|---|---|---|
| 1 | **#43 R2 dr-drill (synthetic, no prod keys)** | ~15 min | ~5 min review | $0 | 1 (gh workflow trigger) | **Dispatch first.** Validates backup chain. Uses repo-stored secrets only. |
| 2 | **#43-prod R2 dr-drill (full HKDF chain)** | ~15 min | ~5 min secret-paste | $0 | 1 (paste OAUTH_JWT_SECRET into agent terminal) | **Dispatch second.** Validates encrypted-column decryption end-to-end. Highest confidence boost. |
| 3 | **#44 Demo A GIF recording** | N/A — agent CANNOT do this | ~30-60 min user | $0 | full user-execute (Playwright MCP can't do widget render + Telegram cross-window in one capture) | **User-execute task.** Playbook is recipe + tooling list. |
| 4 | **#42 Algo2Go TM filing** | ~50-75 min agent | ~15-30 min user | ₹4,500/class × 2 classes = ₹9,000 | 4-5 user halts (PAN, address, OTP, payment, DSC) | **Dispatch fourth.** Defer the ₹19-22k full-service-via-Vakilsearch path; do direct ipindiaonline.gov.in filing for ₹9k. |
| 5 | **#46 Show HN submit** | ~10 min agent prep | ~3 hours active triage | $0 | 1 (final submit click) | **Dispatch last** (after #1-#4 complete + Path A C1+C2+C3 lands + master deployed). |
| 5b | **#45 Reddit warmup research** | ~30 min agent | 6 days × 30 min/day | $0 | 0 agent halts (research only) | **Dispatch parallel with #1-#4.** Output is subreddit list + topic ideas + cadence; user executes the 6-day warmup. |

**Critical sequencing constraint**: Items #1, #2, #4, #5b can dispatch in parallel today. Item #3 (Demo A GIF) is fully user-executed. Item #5 (Show HN submit) MUST wait for: master deployed to Fly.io + dr-drill green + demo GIF embedded in README + 6-day Reddit warmup complete. **End-to-end calendar from today to Show HN: 7-9 days.**

---

# Item 1 — R2 dr-drill against synthetic test data (~15 min agent, $0)

## What it actually verifies

The repo has TWO dr-drill scripts:

### `scripts/dr-drill.sh` (basic — recommended for first dispatch)

Per `scripts/dr-drill.sh:1-77`:

1. Validates 4 R2 env vars present (`LITESTREAM_R2_ACCOUNT_ID`, `LITESTREAM_BUCKET`, `LITESTREAM_ACCESS_KEY_ID`, `LITESTREAM_SECRET_ACCESS_KEY`).
2. Calls `litestream restore -if-replica-exists -config etc/litestream.yml /data/alerts.db -o /tmp/dr-drill-<timestamp>.db`.
3. Asserts the restored file is non-empty (`stat` returns >0 bytes).
4. Runs `sqlite3 <restored.db> "SELECT count(*) FROM kite_tokens"` — schema parseable + count returnable.
5. Exits 0 on success; pings Telegram if `TELEGRAM_BOT_TOKEN` + `TELEGRAM_DR_CHAT_ID` set.
6. `cleanup()` trap deletes scratch DB on every exit path.

**What it does NOT verify**: that encrypted columns (`kite_tokens.token`, `kite_credentials.api_secret`, `oauth_clients.client_secret`) actually decrypt. The script comments warn explicitly: *"the existing drill verifies the SQLite file restores and is parseable, but only runs SELECT count(*) FROM kite_tokens — which silently passes even when every encrypted column is permanently unreadable."*

### `.github/workflows/dr-drill.yml` (CI-driven)

Schedule: `cron: '30 3 1 * *'` (1st of each month, 09:00 IST). Also `workflow_dispatch` for manual trigger. Uses repo-level R2 + Telegram secrets. Skipped on forks.

## Agent procedure

```
Step 1 (no halt): orient
  - cd D:/Sundeep/projects/kite-mcp-server
  - cat scripts/dr-drill.sh (already-read; 77 lines)
  - cat .github/workflows/dr-drill.yml (already-read; 47 lines)

Step 2 (no halt): trigger workflow via gh CLI
  - gh workflow run dr-drill.yml -R Sundeepg98/kite-mcp-server
  - Returns: "Run created" with run-id

Step 3 (no halt, ~5-10 min wait): poll for completion
  - gh run watch <run-id> -R Sundeepg98/kite-mcp-server --exit-status
  - OR gh run list --workflow dr-drill.yml -L 1 (poll every 30s until status=completed)

Step 4 (no halt): read result
  - gh run view <run-id> --log
  - Look for: "DR drill: SUCCESS" line + "kite_tokens.count = N" line + exit-code 0

Step 5 (no halt): validate Telegram side-channel (if expected)
  - User reports: did Telegram DR channel receive a SUCCESS ping?
  - If yes: end-to-end side-channel works.
  - If no: TELEGRAM_DR_CHAT_ID secret may be unset on the repo (not blocker for drill itself).
```

## Credentials needed from user

**None.** All 4 R2 secrets (`LITESTREAM_R2_ACCOUNT_ID`, `LITESTREAM_BUCKET`, `LITESTREAM_ACCESS_KEY_ID`, `LITESTREAM_SECRET_ACCESS_KEY`) are already stored at GitHub repo Actions secrets level. `gh workflow run` triggers a CI job which has access; the agent's local terminal never sees the secrets.

## Halts

**1 halt**: at workflow trigger time, agent confirms with user "I'm about to trigger `dr-drill.yml` via gh CLI on `Sundeepg98/kite-mcp-server` master — proceed?" before the irreversible-but-trivial action of consuming ~2-3 min of GitHub-hosted CI minutes.

## Success criterion

`gh run view <run-id>` exit-code 0 + log shows:
- `DR drill: kite_tokens.count = <N>` where N≥1
- `DR drill: SUCCESS`
- Telegram DR ping received (if configured) OR confirmation that Telegram DR is unconfigured

## Cleanup

None — script self-cleans via `trap cleanup EXIT`. CI runner is ephemeral. Telegram message is intentional (audit evidence).

## Risk

**Minimal**. Worst case: the CI run fails due to (a) Litestream replica is empty (legitimate on fresh deployment, exits 0 gracefully), (b) R2 secret rotated and CI secret stale (visible failure; user knows to fix). No production state is touched.

## Estimated agent time

~15 min total (mostly waiting on CI).

---

# Item 2 — R2 dr-drill with full HKDF→AES-256-GCM decryption chain (~15 min agent + 5 min user, $0)

## What it actually verifies

Per `scripts/dr-drill-prod-keys.sh:1-178`:

This is the **stronger** drill. After the basic restore, it derives the AES-256 key from `OAUTH_JWT_SECRET + hkdf_salt` (stored in the `config` table) and attempts to decrypt one row from `kite_credentials`. AES-GCM Decrypt returns empty string on auth-tag failure, so success means **the full HKDF→AES-256-GCM chain works end-to-end**.

Phases:
1. Phase 0: Gate inputs (refuses to run if `OAUTH_JWT_SECRET` shorter than 32 chars).
2. Phase 1: Litestream restore (same as basic drill).
3. Phase 2: Verify `hkdf_salt` survived restore (`SELECT value FROM config WHERE key='hkdf_salt'`). **Exit code 5** if salt missing — catastrophic; ciphertexts unrecoverable.
4. Phase 3: Count canary rows (`kite_credentials.count`, `kite_tokens.count`). If both 0 (fresh deployment, no users): exit 0 with WARNING.
5. Phase 4: Run `/tmp/dr-decrypt-probe` (Go binary at `cmd/dr-decrypt-probe`) to actually decrypt one canary row. **Exit code 6** if decrypt fails — most likely cause: `OAUTH_JWT_SECRET` mismatch with what production used.

Safety gates (per the script's header comments):
- Restores to `/tmp/dr-drill-prod-${TIMESTAMP}.db`, NEVER `/data/alerts.db`.
- Reads `OAUTH_JWT_SECRET` from env once, never logs it.
- Read-only: no INSERTs/UPDATEs, no R2 writes.
- `cleanup()` trap deletes scratch DB on every exit path AND `unset OAUTH_JWT_SECRET` to prevent leak via later `history`/`env` calls.

## Agent procedure

```
Step 1 (no halt): orient
  - cd D:/Sundeep/projects/kite-mcp-server
  - cat scripts/dr-drill-prod-keys.sh (already-read; 178 lines)
  - Confirm cmd/dr-decrypt-probe exists: ls cmd/dr-decrypt-probe/
    (if missing: build via go build -o /tmp/dr-decrypt-probe ./cmd/dr-decrypt-probe)

Step 2 (HALT): request user paste secrets

  Agent says to user:
    "I need to run dr-drill-prod-keys.sh which requires:
     (a) 4 R2 env vars: LITESTREAM_R2_ACCOUNT_ID, LITESTREAM_BUCKET,
         LITESTREAM_ACCESS_KEY_ID, LITESTREAM_SECRET_ACCESS_KEY
     (b) OAUTH_JWT_SECRET (min 32 chars; from `flyctl secrets list` masks
         the value, so paste from your secret-manager)

     Please paste 5 lines below (or 'cancel' to abort):
       export LITESTREAM_R2_ACCOUNT_ID=<your value>
       export LITESTREAM_BUCKET=<your value>
       export LITESTREAM_ACCESS_KEY_ID=<your value>
       export LITESTREAM_SECRET_ACCESS_KEY=<your value>
       export OAUTH_JWT_SECRET=<your value>"

  User pastes (one-shot, agent does not echo).
  Agent runs `export` commands in WSL2 bash subshell (NOT logged to ~/.bash_history; use `set +o history` first).

Step 3 (no halt): build helper if needed
  - if [[ ! -x /tmp/dr-decrypt-probe ]]; then
       go build -o /tmp/dr-decrypt-probe ./cmd/dr-decrypt-probe
    fi

Step 4 (no halt): run drill
  - bash scripts/dr-drill-prod-keys.sh
  - Capture stdout + stderr + exit code

Step 5 (no halt): validate
  - Exit code 0 = full success (or PARTIAL SUCCESS if probe binary missing)
  - Exit code 2 = env var missing (user needs to re-paste)
  - Exit code 3 = restore failed (R2 secret wrong OR R2 outage)
  - Exit code 4 = restored file empty (litestream replica empty — likely first-deploy)
  - Exit code 5 = hkdf_salt missing (CATASTROPHIC — escalate immediately)
  - Exit code 6 = decrypt failed (OAUTH_JWT_SECRET mismatch — escalate)

Step 6 (no halt): cleanup
  - unset OAUTH_JWT_SECRET LITESTREAM_R2_ACCOUNT_ID LITESTREAM_BUCKET \
          LITESTREAM_ACCESS_KEY_ID LITESTREAM_SECRET_ACCESS_KEY
  - history -c (clear current session bash history)
  - rm -f /tmp/dr-drill-prod-*.db (the script's trap should already do this; double-check)
  - Report exit code + summary lines back to orchestrator
  - DO NOT report the secret values back; ONLY exit code + count + size + status lines
```

## Credentials needed from user

5 secrets, all pasted in one halt:
1. `LITESTREAM_R2_ACCOUNT_ID` — Cloudflare R2 account ID. Visible at https://dash.cloudflare.com/<account>/r2 → Account ID.
2. `LITESTREAM_BUCKET` — bucket name (likely `kite-mcp-backup` per `MEMORY.md`).
3. `LITESTREAM_ACCESS_KEY_ID` — R2 API token (read-only suffices for restore; user generated this when setting up Litestream).
4. `LITESTREAM_SECRET_ACCESS_KEY` — paired secret for the access key.
5. `OAUTH_JWT_SECRET` — from user's secret manager (1Password/Bitwarden). Verifiable via `flyctl secrets list -a kite-mcp-server | grep OAUTH_JWT_SECRET` (shows hash digest, not value, but user can confirm presence).

**Critical secret-handling rules**:
- Agent uses `set +o history` BEFORE the export, so secrets don't enter `~/.bash_history`.
- Agent NEVER echoes the secret back. Agent NEVER writes the secret to a file (not even tmp).
- Agent's `cleanup()` block runs `unset` + `history -c` after the drill completes.
- Agent's report to orchestrator contains: exit code + restored file size + row counts + "decrypt SUCCESS" string. **NEVER the secret values, NEVER ciphertext hex.**

## Halts

**1 halt**: secret paste. User pastes once; agent doesn't ask follow-up questions.

## Success criterion

Exit code 0 + log line: `DR drill (prod keys): decrypt probe SUCCESS — full HKDF→AES-256-GCM chain verified.` AND `kite_credentials.count > 0` (otherwise PARTIAL SUCCESS warning).

## Cleanup procedure

Mandatory (in order):
1. `bash` `trap` already runs `cleanup()` which unsets OAUTH_JWT_SECRET + deletes scratch DB.
2. Agent additionally runs `history -c` + `unset` for all 5 vars in agent's parent shell.
3. Agent verifies cleanup with: `env | grep -iE 'litestream|oauth_jwt' || echo "clean"`.
4. Agent verifies `/tmp/dr-drill-prod-*.db` not present: `ls /tmp/dr-drill-prod-*.db 2>/dev/null || echo "no scratch dbs"`.
5. Agent reports cleanup status to orchestrator.

## Risk

**Low if cleanup runs cleanly**. Risks:
- (a) Agent log buffer / orchestrator transcript could capture secret if user pastes inside an Agent message (orchestrator-mediated dispatch). **Mitigation**: agent should ask user to paste to a *terminal directly accessible by the agent process via WSL2*, not via the chat transcript. If user can't do this, defer the prod-keys drill until user can run it themselves with the agent watching script execution.
- (b) Cleanup `trap` could be bypassed by a SIGKILL mid-drill. **Mitigation**: secondary `unset` in agent's outer shell.
- (c) `OAUTH_JWT_SECRET` rotation between user's paste and prod's actual current value would yield exit-code 6. Annoying but not a security incident.

**Recommendation**: Item 2 should run on USER's machine with the agent dispatching commands and reading output, NOT in a Claude Code agent's worktree. The secret-handling boundary is that user controls the keystrokes; agent observes results.

## Estimated agent time

~15 min agent (excluding the 5 min user secret-paste + cleanup verification).

---

# Item 3 — Demo A GIF recording (~30-60 min, FULLY user-executed)

## Why agent cannot do this

Demo A scenario per `.research/demo-recording-production-guide.md` requires:
- Claude Desktop window open with active MCP session
- User typing at human pace (`Show my Zerodha portfolio.` → `Set an alert for RELIANCE at 2 percent drop.`)
- MCP-Apps inline widget rendered (depends on Claude client UI)
- Cut to Telegram desktop showing notification (cross-window, cross-process)
- ScreenToGif recording entire interaction at 10 fps, 1280x720
- Manual editing: trim leading/trailing dead frames in ScreenToGif editor

**Playwright MCP can capture browser-only video**, but Demo A is intentionally a desktop-app demo (Claude Desktop + Telegram desktop), not a browser demo. Playwright cannot record desktop windows outside the browser.

**Alternative considered**: Demo using Claude.ai web instead of Claude Desktop, with Telegram Web in a second tab — Playwright COULD capture this. **Rejected** because:
1. Web-Claude doesn't render MCP-Apps widgets identically to Desktop Claude (verified empirically per `MEMORY.md kite-mcp-server` widgets section).
2. The widget render is the visceral wow-moment of Demo A.
3. Browser-only loses the "this is real desktop integration" framing.

## Agent's contribution to this item

The playbook (this section) IS the agent's contribution. User executes; agent doesn't dispatch.

## User procedure (full recipe from `demo-recording-production-guide.md`)

### Step 1 — Install ScreenToGif (3 min)

```powershell
winget install --id NickeManarin.ScreenToGif --source winget
```

Or signed installer at https://www.screentogif.com/.

### Step 2 — Pre-flight setup (5 min)

In Claude Desktop:
```
paper_trading_toggle enabled=true initial_cash=10000000
```

This enables paper-trading mode — no real Kite data appears in the recording.

Verify the Claude Desktop session email is **NOT** the user's foundation-context email per `MEMORY.md user_email_rule.md`. Use a generic test session.

### Step 3 — Window cleanup (3 min)

- Close Slack / Discord / Outlook / Teams / Telegram phone-mirror
- Windows Settings → Notifications → Focus Assist: Priority Only
- Browser zoom 125% (legibility on HN/Reddit thumbnails)

### Step 4 — Recording (5-10 min including 2 retakes)

ScreenToGif → *Recorder*:
- Frame: ≤1280×720 around Claude Desktop window
- FPS: 10
- Cursor capture: ON
- Click *Record*

Run the 30-second scenario:
1. (0-2s) Static frame: Claude Desktop, last assistant turn shows "✓ Connected to kite-mcp-server"
2. (2-6s) Type: `Show my Zerodha portfolio.`
3. (6-9s) Send → Claude renders thinking spinner → "→ get_holdings" tool-call panel
4. (9-14s) MCP-Apps widget renders: portfolio table with 5-7 paper holdings (RELIANCE, INFY, TCS, HDFC, ITC mocked)
5. (14-16s) Brief pause (let viewer read the table)
6. (16-21s) Type: `Set an alert for RELIANCE at 2 percent drop.`
7. (21-25s) Send → Claude renders → "→ create_alert" → "✓ Alert created" widget
8. (25-30s) Cut to Telegram desktop in second window: notification appears: "📊 Kite Alert created: RELIANCE drop 2% from ₹1,420"

Click *Stop*.

### Step 5 — Editing (5 min)

ScreenToGif's editor:
1. Trim leading dead frames (anything before first keystroke)
2. Trim trailing dead frames (anything after Telegram notification)
3. *File → Save as → GIF (FFmpeg)*, quality 80, lossy compression
4. Target output: ≤4MB (Twitter native upload limit)

### Step 6 — Save canonical path

```
D:\Sundeep\projects\kite-mcp-server\docs\assets\demo-portfolio-alert.gif
```

This path is referenced by ALL 5 embedding slots.

### Step 7 — Embed in 5 places

| # | Channel | Embed action |
|---|---|---|
| 1 | GitHub README hero | `![demo](docs/assets/demo-portfolio-alert.gif)` directly above install code block |
| 2 | Twitter Day-1 thread T1 | Native upload via twitter web composer |
| 3 | Reddit r/algotrading post | `![](https://raw.githubusercontent.com/Sundeepg98/kite-mcp-server/master/docs/assets/demo-portfolio-alert.gif)` |
| 4 | Show HN body | One-line: `Demo: <github-raw-url>` at bottom |
| 5 | Landing page hero | `<img src="/static/demo-portfolio-alert.gif" alt="demo" loading="lazy" style="max-width:720px">` after `.hero p` in `kc/templates/landing.html` |

After embedding (1) and (5), commit + push:
```
git add docs/assets/demo-portfolio-alert.gif README.md kc/templates/landing.html
git commit -m "feat(demo): add Demo A GIF — portfolio + alert flow"
git push origin master
```

### Step 8 — Re-deploy (after commit)

```
flyctl deploy -a kite-mcp-server --remote-only
```

Validates GIF is fetchable at `/static/demo-portfolio-alert.gif` post-deploy.

## Halts

**0 agent halts.** Full-user-execute.

## Success criterion

User-judged: "Does the GIF look professional + tell the story in 30s?" + technical: file ≤4MB + embedded in all 5 slots + post-deploy fetch returns 200 OK.

## Risk

User-time-only: ~30-60 min. If recording fails 3+ retakes, defer to a different recording session (don't perfectionist-loop). Demo A is "minimum viable" — 80% quality is launch-ready per `demo-recording-production-guide.md` Demo-B-and-C-skip recommendation.

## Common pitfalls (from `demo-recording-production-guide.md`)

1. Cursor blink artifacts: turn off Windows text-cursor blink (Settings → Accessibility → Text Cursor → Indicator: Off).
2. High-DPI display: set system scaling to 100% during recording (otherwise blurry on consumer screens).
3. Telegram cross-window: pre-position Telegram desktop window so the cut-to-notification at 25s is in the same recording region; otherwise ScreenToGif misses the notification.

---

# Item 4 — Algo2Go Trademark filing direct via ipindiaonline.gov.in (~50-75 min agent + 15-30 min user, ₹9,000)

## Important reframe

Per `MEMORY.md kite-algo2go-rename.md` and `algo2go-reservation-runbook.md`, the prior cost estimate was ₹19-22k via **Vakilsearch / LegalWiz / Mytrademarkguide** style services (which charge ₹9-11k/class on top of the ₹4,500 govt fee). 

**Direct filing via ipindiaonline.gov.in is ₹4,500/class for individuals, MSMEs, or recognized startups.** Two classes (9 + 42) = **₹9,000 total**. **₹10-13k savings** vs Vakilsearch. The trade-off is user does the form-filling work themselves (~30-45 min) instead of paying a service to do it.

The agent CAN drive most of the form-filling via the IPIndia portal (form has typed fields; Playwright MCP can fill text). But several steps require irreducibly-user-action: PAN card upload, OTP, payment via UPI/netbanking. So this is a multi-halt agent dispatch.

## What it actually does

Files Form TM-A on ipindiaonline.gov.in for:
- **Mark**: ALGO2GO (wordmark, plain text — no logo)
- **Class 9**: Computer software (downloadable + recorded)
- **Class 42**: Software as a Service (SaaS); Cloud computing services
- **Applicant**: Sundeep Gupta (individual) — eligibility for ₹4,500/class fee
- **Use claim**: "Proposed to be used" (we haven't shipped at scale yet; this preserves all dates)
- **Goods/services description**: precise wording matters for opposition-resistance — see Step 4 below

## Agent procedure

```
Step 1 (HALT for user authorization): scope confirmation
  Agent says:
    "I'm about to drive the trademark filing for ALGO2GO at ipindiaonline.gov.in:
     - Class 9 (software): ₹4,500 govt fee
     - Class 42 (SaaS): ₹4,500 govt fee
     - Total: ₹9,000 paid by you via UPI / netbanking at end
     - User-action steps: ~5 halts (login, OTP, PAN upload, address confirm, final
       payment click). Each halt waits for you.
     - Total wall-clock: 50-75 min agent + ~15-30 min user
     OK to proceed? [yes / cancel]"
  
  If user cancels: end. Else:

Step 2 (no halt): trademark search (saves ₹9k if mark is taken)
  Use Playwright MCP to navigate to:
    https://tmrsearch.ipindia.gov.in/eregister/
  Search:
    - Mark: ALGO2GO (exact match)
    - Wordmark search type: "starts with"
    - Class: 9 + 42 (run twice, once per class)
  Capture screenshot of search results.
  
  EXPECTED RESULT: zero matches in both classes.
  IF MATCHES FOUND: report to user, halt with message
    "Found existing mark <mark name> in Class <N>. Filing as ALGO2GO would risk
     opposition. Recommend (a) re-research naming, (b) consult Spice Route Legal
     before filing." Do NOT proceed.

Step 3 (HALT): user logs into ipindiaonline.gov.in
  Agent navigates Playwright to:
    https://ipindiaonline.gov.in/eregister/
  Asks user:
    "Please log in with your IP-India user account. If no account: register at
     https://ipindiaonline.gov.in/eregister/registration.aspx — requires PAN,
     mobile number for OTP, email. Once logged in, return here and confirm with
     'logged in'."
  Wait for user confirmation.

Step 4 (no halt): pre-fill TM-A form
  Agent uses Playwright to navigate to: 
    File New Application → Form TM-A
  
  Fills:
    - Applicant Type: Individual (cheaper fee)
    - Applicant Name: <user provided>
    - Address for service in India: <user provided; must be Indian address>
    - Nationality: Indian
    - Trademark: ALGO2GO
    - Mark Type: Word
    - Mark Description: "ALGO2GO" (typed in text — no font / no color claim)
    - Use claim: "Proposed to be used" (radio button)
    - Class 9 selected
    - Class 9 description (recommended exact wording, 200-char limit):
      "Computer software for algorithmic trading; downloadable software for
       managing securities trading; computer programs for financial analysis;
       application programming interface (API) software for connecting to
       brokerage services."
    - Add another class: Class 42
    - Class 42 description:
      "Software as a service (SaaS) featuring software for algorithmic trading;
       cloud computing services featuring software for portfolio analysis;
       hosting of online trading platforms; software development services for
       financial technology."

Step 5 (HALT): user reviews pre-filled form
  Agent says:
    "Form is pre-filled. Please review at the browser tab for:
     (a) Applicant Name spelled correctly
     (b) Address looks right
     (c) Class 9 + Class 42 descriptions accurate
     (d) Mark = ALGO2GO (capitalization)
     Confirm 'looks good' or specify edits."
  Wait for user.

Step 6 (HALT): user uploads PAN card scan
  Agent says:
    "Please upload your PAN card scan via the form's 'Upload Identity Proof'
     field. Accepted formats: PDF or JPG, ≤2MB. Confirm with 'uploaded'."
  Wait for user. (Cannot agent-drive: file upload requires user to pick file
  from local OS file dialog.)

Step 7 (HALT): user signs digitally OR via affidavit
  Two options for individual filers:
    (A) Class 3 Digital Signature Certificate (DSC): user inserts USB token,
        clicks 'Sign'. If user has DSC: ~2 min step.
    (B) Affidavit upload: user prints, signs in ink, scans, uploads. ~30 min
        step (but doesn't need DSC).
  Agent says:
    "How will you sign? [DSC / affidavit]"
  Wait for user choice; if DSC: prompt user to insert token + click Sign in
  the form. If affidavit: pause for user to print + sign + scan + upload (this
  could be hours; agent should release the dispatch and re-engage when user
  reports back).

Step 8 (HALT): payment
  Agent navigates to payment page in form.
  Agent says:
    "₹9,000 due (₹4,500 × 2 classes). Payment options:
     (a) Net banking (preferred — instant)
     (b) UPI
     (c) Credit/debit card
     Please complete payment in the open tab. Confirm with 'paid' once IPIndia
     shows 'Payment Successful'."
  Wait for user.

Step 9 (no halt): capture acknowledgment
  After payment, IPIndia shows:
    - Application number (e.g. 7654321)
    - Acknowledgment receipt PDF (downloadable)
    - Filing date
  Agent uses Playwright to:
    - Screenshot the acknowledgment page
    - Download the PDF to D:/Sundeep/projects/kite-mcp-server/.research/tm-acknowledgment-<timestamp>.pdf
  Agent reports back: "Application number <N> filed at <timestamp>. PDF saved
  to <path>."

Step 10 (no halt): cleanup
  - Close Playwright browser
  - Confirm acknowledgment PDF saved
  - Report to orchestrator
```

## Credentials needed from user

1. IPIndia user account login (preferably created in advance; otherwise inline registration adds ~10 min).
2. PAN card scan (PDF or JPG, ≤2MB).
3. Address-for-service-in-India (any Indian postal address).
4. (Either) Class 3 DSC USB token + PIN, OR willingness to do affidavit (print + sign + scan).
5. Payment method (₹9,000 via net-banking / UPI / card).

## Halts

**5 user halts**: scope confirmation → IPIndia login → form review → PAN upload → DSC-or-affidavit → payment. Plus optional 6th if scope-rerouted post-search.

## Success criterion

IPIndia shows "Application Number assigned" + downloadable acknowledgment PDF + payment receipt + email/SMS confirmation to user's registered address.

## Cleanup

- Acknowledgment PDF saved to `.research/`
- Browser closed
- No secrets persisted

## Risks

1. **Wrong applicant type (Pvt Ltd instead of Individual)**: doubles fee to ₹18,000. Mitigation: confirm "Individual" in Step 4 pre-fill.
2. **Goods/services description too narrow**: oppositions can claim our use exceeds the description. Mitigation: agent uses the broad recommended wording in Step 4 above.
3. **Mark search misses an existing similar mark**: agent only searches exact spelling; ipindiaonline portal also offers "phonetic" search. Mitigation: agent runs both exact AND phonetic searches in Step 2.
4. **DSC token issues**: user's DSC PIN forgotten / token expired. Mitigation: pre-flight check before Step 1.
5. **₹9k payment fails / refunded**: govt fees are non-refundable EXCEPT in payment-gateway failure cases. Mitigation: user uses net-banking (instant) not card (sometimes delayed).
6. **₹4,500/class fee rate changes**: as of 2026 Q1, rate is stable; verify on ipindiaonline.gov.in/forms-and-fees page just before Step 4.

## Estimated agent time

50-75 min agent + 15-30 min user (excluding affidavit branch which adds 30-60 min user offline time).

## Trade-off vs Vakilsearch / LegalWiz

| Path | Total cost | Agent time | User time | When to choose |
|---|---|---|---|---|
| **Direct via ipindiaonline.gov.in** (this playbook) | ₹9,000 | 50-75 min | 15-30 min | Default. User comfortable with online forms. |
| Vakilsearch / LegalWiz / Mytrademarkguide | ₹19,000-22,000 | ~5 min (just authorize) | 10-15 min over 2-3 days | User wants hand-holding, agent dispatch lifecycle constraint, OR there's a complication (logo not just wordmark, opposition concern, NRI applicant). |

**Recommendation**: Direct path. ₹10-13k savings + filing date is identical (ipindiaonline.gov.in is the canonical filer; Vakilsearch just submits on user's behalf to the same portal).

---

# Item 5 — Show HN submit (~10 min agent prep + 3 hours active triage, $0)

## Pre-flight blockers (must all be green BEFORE submit)

Per `final-pre-launch-verification.md` + `day-1-launch-ops-runbook.md`:

| # | Blocker | Verification |
|---|---|---|
| 1 | Master deployed to Fly.io | `curl /healthz` shows `tools=130+` (NOT 111) AND `version` newer than v1.3.0 |
| 2 | `og-image.png` returns 200 | `curl -sIo /dev/null -w "%{http_code}" https://kite-mcp-server.fly.dev/og-image.png` returns `200` |
| 3 | dr-drill green (Item 1 above) | `gh run list --workflow dr-drill.yml -L 1` shows status=success |
| 4 | Demo A GIF embedded (Item 3) | README hero has `<img>` tag pointing to `docs/assets/demo-portfolio-alert.gif`, file size ≤4MB, file fetchable on Fly.io at `/static/demo-portfolio-alert.gif` returns 200 |
| 5 | Reddit account warmed (Item 5b) | `u/Sundeepg98` exists with ≥30 comment karma + ≥7 days age |
| 6 | Tool count consistent | README claim matches `/healthz tools=N` (avoid the current 117/111/122 inconsistency flagged in `final-pre-launch-verification.md`) |
| 7 | Test count consistent | README claim matches actual `find -name '*_test.go' \| xargs grep -c '^func Test'` empirical |
| 8 | Show HN body finalized | `docs/show-hn-post.md` reviewed for stale numbers (current draft says "11 checks ₹50k cap" — confirm matches deployed) |
| 9 | Static IP whitelisted on user's Kite app | `flyctl ips list -a kite-mcp-server` shows current static IP IS whitelisted in user's Kite developer console |
| 10 | flyctl auth fresh | `flyctl auth whoami` returns user email (not "no auth") |
| 11 | Pre-staged second `bom` machine | `flyctl machines list -a kite-mcp-server` shows count=2 |

If ANY blocker is red: defer launch.

## Optimal title (per HN guidelines + show-hn-post.md analysis)

Show HN guidelines (per https://news.ycombinator.com/showhn.html):
- Begin title with `Show HN:`
- Be **boring in the best sense**: clear, neutral, no uppercase, no exclamation, no praise, no editorialized claims
- No "first/the only" framing

Recommended title (verbatim from `docs/show-hn-post.md` option #1):

> **Show HN: kite-mcp-server – Self-hosted MCP for Zerodha Kite, with riskguards**

Length: 73 chars (under HN's 80-char limit). Hits HN reader patterns:
- "Self-hosted" — local-first signal
- "Zerodha Kite" — broker name recognizable to the audience that matters
- "with riskguards" — pre-empts "AI YOLOs real money" worst-case in the title itself

**Alternative** (if user wants Algo2Go branding): 
> **Show HN: Algo2Go – Self-hosted MCP for Zerodha Kite (Go, MIT, 130 tools)**

The "kite-mcp-server" version is preferred for the launch — it leads with the function (MCP+Zerodha) over the brand (Algo2Go), and the latter is unestablished. Once the brand is recognizable (post-launch), Algo2Go branding can lead.

## Body (per `docs/show-hn-post.md` — already drafted, ~500 words)

The full body is in `docs/show-hn-post.md` lines 14-43. Structure:
1. Opening (~95 words): what it is + the Indian-broker-MCP space context
2. What's inside (~120 words): tool count, OAuth, RiskGuard chain, audit log, deployment
3. Regulatory wrinkle (~90 words): SEBI tool-not-service framing, April 2026 IP mandate
4. Honest limitations (~100 words): not on registry, paper-trading naive, SQLite not Postgres
5. Why HN (~80 words): want critique on security model + architecture

**Pre-submit edits required** to match deployed state:
- Update tool count claim from "110+ tools" to match actual deployed `tools=N`
- Update test count from "~9,000" to actual `grep -c '^func Test'` empirical
- Update RiskGuard count claim — current draft says "11 checks", code may have evolved; verify
- Update IP `209.71.68.157` if Fly.io egress IP rotated since 2026-04

## URL

**Project URL**: `https://github.com/Sundeepg98/kite-mcp-server`

NOT the landing page — HN crowd prefers source repo over marketing pages. The repo URL doubles as the project landing for HN; the README already has CTAs for "Try the hosted demo" + "Self-host in 60 seconds".

## Optimal timing

Per HN data + `day-1-launch-ops-runbook.md`:

**Tuesday or Wednesday, 06:30-08:30 PT** (= 19:00-20:30 IST evening). 

Rationale (per WebSearch results):
- Tuesday-Thursday 08:00-11:00 ET is the canonical "best time" window
- 06:30-08:30 PT = 09:30-11:30 ET — front of US tech crowd's morning
- 19:00-20:30 IST = post-work, pre-dinner — Indian dev crowd is in second-wind engagement
- Avoid Mondays (algorithmic catch-up from weekend) and Fridays (low engagement)

**Specific recommendation**: **Tuesday 06:45 PT** — early enough to catch US morning engagement, late enough that the post isn't drowned by other 06:30 submissions.

## Agent procedure

```
Step 1 (no halt): pre-flight verification
  - cd D:/Sundeep/projects/kite-mcp-server
  - Run all 11 blockers (Items above). Report status to user.
  - If any RED: report blocker + halt. Do NOT proceed.
  - If all GREEN: proceed.

Step 2 (no halt): final body edits
  - Read docs/show-hn-post.md
  - Update tool count, test count, RiskGuard count, static IP to match
    deployed empirical (verified in Step 1).
  - Save updated draft to .research/show-hn-post-final-<timestamp>.md
    (do NOT modify docs/show-hn-post.md — that's the launch-prep template;
    the timestamped copy is the actual submission text)

Step 3 (HALT): user reviews body
  Agent says:
    "Show HN submission preview:
     
     TITLE: Show HN: kite-mcp-server – Self-hosted MCP for Zerodha Kite,
            with riskguards
     URL:   https://github.com/Sundeepg98/kite-mcp-server
     BODY:  <attached at .research/show-hn-post-final-<ts>.md>
     
     Optimal submit window: TUE 2026-MM-DD 06:45 PT (= 19:15 IST)
     Current time: <now>
     Time until submit window: <delta>
     
     Pre-stage second bom machine? Need to do before submit:
       flyctl machines clone <id> --region bom -a kite-mcp-server
     
     Confirm to proceed: [yes-pre-stage / yes-no-prestage / cancel]"
  Wait for user.

Step 4 (HALT): pre-stage second machine (if user authorized)
  - flyctl machines clone <bom-id> --region bom -a kite-mcp-server
  - flyctl machines list -a kite-mcp-server | should show count=2
  - User confirms second machine is healthy via flyctl status
  
Step 5 (HALT — final, irreversible): user clicks Submit
  Agent navigates Playwright to: https://news.ycombinator.com/submit
  Agent fills:
    - Title: <as above>
    - URL: https://github.com/Sundeepg98/kite-mcp-server
    - Text: leave EMPTY (HN convention: URL submissions DO NOT use Text;
      the body goes as the FIRST COMMENT)
  
  Agent says:
    "Form filled. Title and URL set. Text field is EMPTY (intentional —
     HN convention: body goes as first comment).
     
     IMPORTANT: do NOT click Submit yet. After clicking Submit, agent will
     immediately add the body as the FIRST COMMENT. The title-and-URL-only
     submission stays clean; the comment thread starts with the launcher's
     own context-setting comment.
     
     Pull the trigger? [click-submit-now / cancel]"
  Wait for user.

Step 6 (no halt — automatic upon user submit): post the first comment
  After user clicks Submit, HN redirects to the post page.
  Agent extracts the post URL + HN item ID.
  Agent navigates to the comment box.
  Agent fills the comment box with the body from .research/show-hn-post-final-<ts>.md
  Agent says:
    "Body comment ready to post. Click [Add comment] to post the first comment.
     This is your context-setting message."
  User clicks.

Step 7 (no halt): activate Day-1 monitoring
  Per day-1-launch-ops-runbook.md Phase 2 (Minute 0-15):
    - Agent: "Submission live. Post URL: <url>. HN item: <id>."
    - Agent: "Activating triage workflow per day-1-launch-ops-runbook.md.
              Will NOT respond to anything for first 15 min."
    - Agent monitors:
      * /healthz (every 60s; alert if status != ok)
      * gh run watch on smoke-canary workflow
      * HN front page rank (refresh every 60s)
    - At minute 15: agent returns triage candidates from Phase 2 of runbook.
```

## Halts

**4 halts**: pre-flight blocker results (auto-halt-if-red), body review, pre-stage decision, **final submit click** (the trigger).

## Should agent halt before final submit?

**Yes — explicitly.** The Submit button click is a publish-to-the-world action. Even with full pre-staging, the user pulls the trigger. Agent fills the form via Playwright; user clicks the actual button. This preserves user-as-decider for the irreversible action.

## Success criterion

- Post live at https://news.ycombinator.com/item?id=<id>
- First comment posted with body
- /healthz still green at minute 15
- HN front-page rank visible (regardless of whether high enough to actually FRONT-PAGE)

## Cleanup

- Playwright session left OPEN for user to engage with comments
- Day-1 monitoring active for 90+ min (Phases 2-6 of runbook)
- Ops sticky-note kept visible (last good Fly.io release ID + Docker tag)

## Risk

- **Master vs deployed mismatch**: pre-flight blocker #1 catches this. Mitigation: deploy first.
- **Demo GIF 404 on Fly.io**: pre-flight blocker #4 catches this. Mitigation: post-deploy fetch.
- **HN guidelines violation**: title format check via WebFetch news.ycombinator.com/showhn.html in pre-flight.
- **HN downvote-bomb in first 5 min**: only mitigation is the body quality (already drafted) + good first reply.
- **CI flake during launch window**: pre-flight blocker requires green smoke-canary; agent re-runs if first attempt flakes.

## Estimated agent time

~10 min agent prep + form-fill. User time: ~3 hours active triage post-submit (Phases 2-6 of `day-1-launch-ops-runbook.md`).

---

# Item 5b — Reddit warmup research (parallel-dispatch with #1-#4, ~30 min agent)

## Why this is research-only

Per `MEMORY.md user_email_rule.md` + general account-hygiene rules, agent CANNOT post on Reddit on user's behalf. Reddit accounts are user-identity-linked.

Agent's contribution: research output that compresses 6 days of warmup into a 30-min prep document.

## Output

Subreddit-by-subreddit, per-day cadence + topic ideas. Already extensively covered in `.research/reddit-subreddit-specific-strategy.md` (which I read in the predecessor `forward-tracks-strategic-review.md` work). The agent for Item 5b dispatches:

```
Step 1 (no halt): orient
  - cat .research/reddit-subreddit-specific-strategy.md
  - Identify subreddits already covered:
    * r/algotrading (1.86M subs, primary launch channel)
    * r/IndianStockMarket (1.31M subs, AI-content rule constraint)
    * r/Zerodha (350 subs, restricted — DROP)
    * r/IndianStreetBets (alternative Indian audience)
    * r/programming (DROP per rules)
    * r/golang (viable secondary)

Step 2 (no halt): research subreddit RECENT (last 30d) top posts
  - For each surviving subreddit (r/algotrading, r/IndianStockMarket,
    r/IndianStreetBets, r/golang, r/SideProject):
    Use WebFetch on `reddit.com/r/<sub>/top/?t=month` to capture recent
    successful post patterns. Output: 3-5 top posts per sub with
    title pattern + body length + comment count.

Step 3 (no halt): synthesize topic ideas for 6-day warmup
  Per day, suggest 1-2 lurk-and-comment opportunities:
    Day -6: r/algotrading: comment on a backtesting / data-quality post
    Day -5: r/golang: comment on a CLI / single-binary deployment post
    Day -4: r/algotrading: comment on a SEBI / regulatory post (highly
            relevant; user's deep knowledge here is differentiated value)
    Day -3: r/SideProject: comment on a side-project launch with helpful
            engineering feedback
    Day -2: r/IndianStockMarket: comment on a portfolio / personal-finance
            post (PF angle, not tech)
    Day -1: r/algotrading: COMMENT on the post most-likely to be active
            during the user's launch window (so the user has visibility
            in r/algotrading recent-comments at launch time)

Step 4 (no halt): output single-doc playbook
  Write .research/reddit-warmup-playbook.md with:
    - 6-day calendar
    - Per-day: subreddit + topic + suggested comment-prompt
    - Karma growth target: ≥30 comment karma, ≥0 negative downvote ratio
    - Day-0 (launch day): primary post in r/algotrading at +12h after
      Show HN
    - Verbatim post body for r/algotrading per .research/reddit-subreddit-
      specific-strategy.md §A.1
```

## Halts

**0 agent halts.** Pure research output.

## Success criterion

`.research/reddit-warmup-playbook.md` exists with:
- 6-day calendar
- Per-day comment-target identified
- Karma growth target stated
- Day-0 verbatim post body included

## Risk

User reads playbook then doesn't follow it = wasted 30 min of agent time. Mitigation: orchestrator confirms with user "you have ≥30 min/day for 6 days?" BEFORE dispatching this item.

---

# Cross-cutting: ordering + sequencing

## Recommended dispatch sequence

```
TODAY:
  → Item 1 (R2 dr-drill basic)        [agent dispatch, 15 min]
  → Item 5b (Reddit warmup research)  [agent dispatch, 30 min, parallel]

DAY +1 (after Item 1 green):
  → Item 2 (R2 dr-drill prod-keys)    [agent dispatch, 15 min + user 5 min]
  → Item 3 (Demo A GIF)               [USER-execute, 30-60 min]
  → User: deploy current master to Fly.io (~30 min, prerequisite for Item 5)

DAY +2 to +6 (parallel Reddit warmup):
  → User: 30 min/day Reddit comments per Item 5b output

DAY +7 (Tue or Wed PT optimal):
  → Item 4 (TM filing) — can run any day Day +1 to +6, no launch dependency
  → Item 5 (Show HN submit) — at 06:45 PT
```

## What blocks what

| Item | Blocks |
|---|---|
| Item 1 | Item 5 (need dr-drill green before launch) |
| Item 2 | Nothing critical (additional confidence; not launch-blocker) |
| Item 3 | Item 5 (need GIF embedded for blocker #4) |
| Item 4 | Nothing (TM filing is parallel; legally-prudent but not launch-blocker) |
| Item 5b | Item 5 (need Reddit account warmed) |
| Master deploy | Item 5 (production must match master) |

**Critical path to Show HN**: Master deploy → Items 1+3+5b → Item 5. ~7-9 days end-to-end.

## What can be skipped if user wants Show HN sooner

- **Item 2** (prod-keys drill): nice-to-have, not launch-blocking. Skip if user has confidence in the basic Item 1 result.
- **Item 4** (TM filing): legally-prudent but Show HN can launch without it. Filing is post-validation per `forward-tracks-strategic-review.md` recommendation #5.

What CANNOT be skipped: master deploy + Item 1 + Item 3 + Item 5b (Reddit warmup is nontrivial; without it, primary distribution channel is shadowbanned).

---

# Cross-cutting: credentials inventory (one-page reference)

| Item | Secret/credential | Where to source | Format | Sensitivity |
|---|---|---|---|---|
| Item 1 | (none — uses repo-stored CI secrets) | n/a | n/a | n/a |
| Item 2 | LITESTREAM_R2_ACCOUNT_ID | Cloudflare R2 dashboard | UUID-ish | medium (read-only access to backup bucket) |
| Item 2 | LITESTREAM_BUCKET | Same | string | low |
| Item 2 | LITESTREAM_ACCESS_KEY_ID | Cloudflare R2 → API tokens | string | medium |
| Item 2 | LITESTREAM_SECRET_ACCESS_KEY | Same (saved at token-creation time only) | string ≥40 chars | HIGH |
| Item 2 | OAUTH_JWT_SECRET | User's secret manager (1Password/Bitwarden) | string ≥32 chars | CRITICAL |
| Item 3 | (no secrets — local recording) | n/a | n/a | n/a |
| Item 4 | IPIndia portal user account login | Created at https://ipindiaonline.gov.in registration | username + password | medium |
| Item 4 | OTP for IPIndia login | SMS to registered mobile | 6-digit | low (one-time) |
| Item 4 | PAN card scan | User's identity documents | PDF/JPG ≤2MB | medium (PII) |
| Item 4 | Class 3 DSC PIN | DSC USB token | 6-12 chars | HIGH |
| Item 4 | Bank/UPI for ₹9,000 payment | User's payment method | n/a | one-time auth |
| Item 5 | HN account login | https://news.ycombinator.com/login (Sundeepg98) | username + password | medium |
| Item 5 | flyctl auth | https://fly.io/dashboard | token (refreshes via Playwright) | medium |
| Item 5b | (no secrets — research only) | n/a | n/a | n/a |

**HIGH/CRITICAL secret-handling rule**: Item 2 OAUTH_JWT_SECRET pasting requires user to use a TERMINAL DIRECTLY accessed by the agent process (e.g., the agent's WSL2 bash where the `read -s` happens). It must NOT be pasted into a Claude chat transcript / orchestrator-mediated message — the secret would persist in conversation history.

---

# Closing recommendation

**Dispatch Item 1 (basic dr-drill) and Item 5b (Reddit warmup research) in parallel TODAY.** Both are zero-secret-paste, low-risk, low-time. They produce green-signal artifacts that unblock the rest of the sequence.

**Items 2, 4 require user secret-paste OR PII** — dispatch only after Item 1 is green AND user has set aside the user-time block for the halts.

**Item 3 (Demo A GIF) is fully user-executed** — orchestrator surfaces the recipe; user-time gates this; no agent dispatch.

**Item 5 (Show HN submit) is the FINAL action** — must wait for master deploy + Items 1, 3, 5b complete. Estimated calendar to launch: 7-9 days from today.

---

## Sources of evidence

- `scripts/dr-drill.sh` (full read; 77 lines)
- `scripts/dr-drill-prod-keys.sh` (full read; 178 lines)
- `.github/workflows/dr-drill.yml` (full read; 47 lines)
- `docs/show-hn-post.md` (full read; 79 lines — title options + body + 12 prepared replies)
- `.research/demo-recording-production-guide.md` (read 280+ lines — Demo A scenario + ScreenToGif recipe)
- `.research/reddit-subreddit-specific-strategy.md` (read 100+ lines — per-sub rules + draft posts)
- `.research/day-1-launch-ops-runbook.md` (predecessor read in `forward-tracks-strategic-review.md` work)
- `.research/final-pre-launch-verification.md` (predecessor read in `forward-tracks-strategic-review.md` work)
- `.research/forward-tracks-strategic-review.md` (this dispatch's predecessor at `4f0d021`)
- `.research/algo2go-reservation-runbook.md` (reservation-only-not-filing scope; this playbook extends with direct-filing path)
- `MEMORY.md` (`kite-algo2go-rename.md`, `kite-mrr-reality.md`, `user_email_rule.md`)
- HN guidelines: https://news.ycombinator.com/showhn.html (WebFetched 2026-05-10)
- IPIndia fees 2026: https://www.intepat.com/blog/trademark-registration-fees-india (₹4,500/class for individuals/MSMEs/startups)
- IPIndia portal: https://ipindiaonline.gov.in/eregister/
- Show HN timing data: WebSearch 2026-05-10
- Live verification: `curl https://kite-mcp-server.fly.dev/healthz` (v1.3.0/tools=111 confirmed)
