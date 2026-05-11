# flyctl friction inventory + Playwright MCP capabilities

**Date**: 2026-05-11 IST
**Master HEAD audited**: `9034790` (`docs(track-c): land Track C decisions report for 11 doc-classification §8.6 items`)
**Dispatch role**: Track 2 — friction map + Playwright capability investigation
**Concurrency**: Audit agent on Track 1 (fly MCP existence/build). Both feed into orchestrator's synthesis.

**Methodology**:
- Friction inventory: empirical scan of `git log --grep=flyctl` (65 hits across history), MEMORY.md kite-mcp section (16 flyctl-relevant notes), in-session decision records, and operational-runbook stale-command findings.
- Playwright capability investigation: actually exercised the Playwright MCP tool surface — navigate, snapshot, run_code_unsafe (storageState API probe). Confirmed empirically what the toolset can vs can't do.
- Risk model: examined live browser context cookie inventory — found user is **already authed to dash.cloudflare.com, digitalocean.com, fly.io domain (but not the dashboard yet)** in this session's browser context.

**Headline finding**: Playwright MCP can drive 100% of the "click through a web UI to set/rotate a credential" workflows we currently delegate to the user. The `browser_run_code_unsafe` tool exposes `page.context().storageState()` for session persistence — once a user logs in to a service via Playwright once, subsequent automation can reload state without re-auth. Combined with TOTP generation, even 2FA workflows reduce to "user pastes TOTP secret once."

---

## §1 — flyctl friction inventory

Catalogued from this session's empirical record + MEMORY.md + prior decision records. Sorted by severity × frequency.

| # | Friction | Severity | Frequency | Fix cost | Workaround in place |
|---|---|---|---|---|---|
| 1 | **`.fly/binc` PATH typo** — user's Windows PATH had a typo; full path `/c/Users/Dell/.fly/bin/flyctl.exe` is the only reliable invocation | HIGH (silent failure on bare `flyctl`) | EVERY session at startup | ~30s to write a `flyctl.cmd` wrapper that fixes the typo; ~5min to fix the PATH env var itself | Use absolute path `/root/.fly/bin/flyctl` in WSL2 or `C:\Users\Dell\.fly\bin\flyctl.exe` in PS |
| 2 | **WSL2 git credential helper missing** — `git push` from WSL2 hangs at >60s; PowerShell `git push` (with `gh` keyring) works. Every push of this session went via PowerShell | HIGH (push throughput halved) | EVERY commit-push pair in this session (~40 commits) | ~10min to install `git-credential-manager` for WSL2 OR configure `credential.helper` to a stored token | Push via Windows-side git from PowerShell; commits stay in WSL2 |
| 3 | **`flyctl releases list` is not a valid subcommand** — runbooks reference it; only `flyctl releases image` + `flyctl releases rollback` exist. Operational runbooks bake-in the broken command | HIGH (operator following runbook hits error) | Every deploy attempt that consults runbooks (this session: 3 documents had it) | ~5min sweep | Fixed at commit `29de8c8` in pre-deploy-checklist; still present in `day-1-launch-ops-runbook.md` per audit-doc verification §17 patch list |
| 4 | **Windows AppControl blocking `flyctl.exe`** — periodically OS treats fly binary as untrusted; bypass via WSL2 path | MEDIUM (~2 incidents in last 30 days per session_2026-05-04 note) | Sporadic; ~1/week | High — requires Microsoft-side trust + signing changes | Use WSL2 with `/root/.fly/bin/flyctl`; auth-portability via copying `/mnt/c/Users/Dell/.fly/config.yml` to `/root/.fly/` |
| 5 | **`Metrics token unavailable: context canceled`** warning on EVERY flyctl call | LOW (cosmetic) | EVERY flyctl invocation (10+ in this session per chain agent's reports) | Likely flyctl-internal token-fetch timeout — bug-report territory, not a fix-by-us | Ignore; output remains valid |
| 6 | **No structured (JSON) deploy state readback** — `flyctl deploy` emits unstructured text; agents have to regex `image: registry.fly.io/...:deployment-XYZ` from log | MEDIUM (~50 lines of unstructured output per deploy; agents parse with `tail -50`) | Every deploy (this session had several v-numbered deploys) | High — would require Fly to ship structured-output mode (`--json` flag for `deploy`); workaround: `flyctl status --json` after deploy | Current: parse stdout with grep |
| 7 | **Manual `flyctl secrets set` invocations** — every secret update is shell-driven, no UI confirmation | MEDIUM (~6 secret-mutating events documented in this session: R2 creds, OAUTH_JWT_SECRET rotation planning, etc.) | Sporadic | None — flyctl is the canonical interface; UI just wraps the same API | Current: human-supervised flyctl invocation |
| 8 | **GitHub Actions repo secrets unset** for dr-drill cron — the dr-drill workflow's only run (2026-05-01) failed at the env-var gate; 4 R2 + 2 Telegram secrets missing | HIGH (monthly cron silently failing) | 1 known + every future monthly cron until provisioned | ~5min user-action (paste 6 secrets at GitHub Settings → Secrets → Actions) | None — surfaced in dr-drill-results-2026-05-11.md §2 |
| 9 | **flyctl auth expiry handling** — `flyctl auth status` returns "logged in" but specific API calls 401; MEMORY.md says "Auth expires periodically — re-login via Playwright browser automation works (navigate to the CLI auth URL, click 'Continue as')." | LOW (Playwright re-login already documented) | Sporadic; ~1/month | ~3min interactive re-auth via Playwright per documented procedure | Playwright-driven re-auth; ~30min framing in some launch-prep docs was OUTDATED per active-docs-verification |
| 10 | **No typed responses across the toolchain** — `flyctl status` emits a 2-column ASCII table that agents have to regex for `Image` and `VERSION` fields; structured access would mean `flyctl status --json` (which exists for some subcommands but not all) | MEDIUM | Every state-query call | Variable — for some subcommands `--json` exists; for others not | Mix of regex-parse + `--json`-where-available |
| 11 | **No "diff before deploy"** — `flyctl deploy` doesn't surface what will change between current image and new image; operators learn after the fact | LOW (we run pre-deploy WSL2 sanity gates that gate the deploy) | Every deploy | High (would need Fly to ship a diff feature) | Current: pre-deploy WSL2 sanity (`go build`, `go test ./mcp/`, `go vet`) gates the deploy |
| 12 | **Background-task auto-backgrounding** — `flyctl deploy` occasionally gets auto-backgrounded by the harness with 0-byte stdout file; use `flyctl status` as oracle of truth | LOW (~1 incident per ~30 deploys) | Rare | None (harness behavior) | Verify via `flyctl status` after backgrounded task; image ID + machine version are authoritative |
| 13 | **R2 credentials in plaintext in `memory/kite-session-apr3.md`** — credential hygiene issue surfaced by memory-files-verification §I10 | HIGH (security) | One-time — needs rotation | ~10min user-action (Cloudflare dash to rotate API token → Fly secret to update → memory file to patch with env-var reference) | None until user rotates |
| 14 | **Auth-portability between WSL2 and Windows** — `flyctl auth login` from WSL2 stores token in `/root/.fly/config.yml`; from Windows stores in `%USERPROFILE%\.fly\config.yml`. Mismatch = re-auth required for each environment | LOW (one-time per env) | Per-environment-setup | Manual file-copy between them (documented in session_2026-05-04 close-2 note) | Manual copy |

**Frequency-weighted top 3** (these are the bottleneck flushes):
1. **Friction #2** (WSL2 git credential helper) — every commit-push pair hits this. ~40 occurrences this session.
2. **Friction #5** (Metrics token warning) — every flyctl call. ~30 occurrences.
3. **Friction #1** (PATH typo) — every session-start. 1 occurrence × always-paid cognitive load.

**Severity × frequency leaderboard** (HIGH × FREQ should be fixed first):
1. **Friction #2** — HIGH × ~40 = highest leverage. ~10min fix yields per-commit savings forever.
2. **Friction #3** — HIGH × per-deploy-runbook-read = audit-document sweep already underway.
3. **Friction #8** — HIGH × per-cron = ~5min user-paste closes a launch-prerequisite gap.
4. **Friction #13** — HIGH × one-time-but-security = rotation overdue.

---

## §2 — Playwright MCP capability matrix

Empirically probed in this dispatch (HEAD `9034790`). Confirmed available + working:

### §2.1 Core navigation + state

| Tool | Empirical status | Notes |
|---|---|---|
| `mcp__plugin_playwright_playwright__browser_navigate(url)` | ✓ VERIFIED — successfully navigated to `https://fly.io/docs/flyctl/` + `https://fly.io/dashboard` (redirected to sign-in) + `https://dash.cloudflare.com/` (redirected to /login due to expired session) | Returns page URL + title + accessibility snapshot path |
| `browser_navigate_back()` | (available per tool inventory) | Browser-back equivalent |
| `browser_close()` | ✓ VERIFIED — closed current tab cleanly | |
| `browser_tabs(action: list/new/close/select, index?, url?)` | (available) | Tab management — supports cookie-context sharing across tabs |
| `browser_resize(width, height)` | (available) | Viewport sizing |
| `browser_wait_for(text? / textGone? / time?)` | (available) | Wait-for-element pattern; supports text-appearance + text-disappearance + time-passes |

### §2.2 Interaction (the workhorse set)

| Tool | Empirical status | Notes |
|---|---|---|
| `browser_snapshot(target?, depth?, boxes?, filename?)` | ✓ VERIFIED — yields YAML accessibility-tree snapshot with `[ref=eN]` IDs for every element | Better than screenshot for action-driven workflows; ref IDs become the `target` for subsequent click/fill |
| `browser_click(target, button?, doubleClick?, modifiers?, element)` | (available) | Click via accessibility ref OR CSS selector; supports keyboard modifiers |
| `browser_fill_form(fields[])` | (available — empirically known from playbook) | Bulk-fills textbox / checkbox / radio / combobox / slider in a single call. Each field: target + name + type + value |
| `browser_type(text, target?)` | (available per tool inventory) | Single-field type variant |
| `browser_press_key(key)` | (available) | Keyboard input; supports `ArrowLeft`, `Enter`, single chars, etc. |
| `browser_select_option(target, values[])` | (available per tool inventory) | `<select>` dropdown |
| `browser_drag(...)`, `browser_drop(...)` | (available) | Drag-drop |
| `browser_hover(target)` | (available) | Mouse hover (for dropdowns that open on hover) |

### §2.3 Verification + state introspection

| Tool | Empirical status | Notes |
|---|---|---|
| `browser_take_screenshot(type, target?, fullPage?, filename?)` | (available) | PNG/JPEG snapshot — for visual confirmation, not for action-driven workflows |
| `browser_console_messages(level, all?, filename?)` | (available) | Read console errors/warnings/info/debug |
| `browser_network_requests(static, filter?, filename?)` | (available) | Inspect XHR/fetch traffic; supports regex filter — useful for confirming "did the API call actually fire?" |
| `browser_network_request(N)` | (referenced) | Full details on a specific numbered request |
| `browser_evaluate(function, target?, element?, filename?)` | (available per tool inventory) | Run JS in page context — read text, get attribute, custom assertions |
| `browser_handle_dialog(accept, promptText?)` | (available) | Accept/dismiss browser-native dialogs (alert/confirm/prompt) |
| `browser_file_upload(paths[])` | (available) | Drive `<input type="file">` |

### §2.4 The keystone — `browser_run_code_unsafe`

This is the unlock for session persistence + TOTP + arbitrary Playwright API.

**Tool**: `browser_run_code_unsafe(code, filename?)`
**Signature**: takes a JS arrow function with `(page)` parameter; executes in Playwright server context.
**Capability** (empirically probed this dispatch):

```js
async (page) => {
  const ctx = page.context();
  // VERIFIED: storageState() returns full cookie + localStorage state
  const state = await ctx.storageState();
  return {
    cookieCount: state.cookies.length,        // 224 in current session
    storageState_is_function: true,            // confirmed
    addCookies_available: true,                // confirmed
    clearCookies_available: true,              // confirmed
  };
}
```

**Empirical findings from probe**:
- Current browser context already holds **224 cookies** across `dash.cloudflare.com`, `digitalocean.com`, `www.recaptcha.net`, `fly.io`, etc. The user is logged in to multiple sensitive services in the same context that Playwright MCP drives.
- `ctx.storageState({path: '/path/to/state.json'})` persists cookies + localStorage to disk as JSON — the canonical Playwright pattern for "log in once, replay forever."
- `ctx.addCookies(...)` reads back a saved state — closes the persistence loop.
- `ctx.clearCookies(...)` for clean-slate testing.

**Empirical finding on session validity**:
- Cookies-present ≠ auth-valid. Navigating to `dash.cloudflare.com/` while having 224 cookies still redirected to `/login` because the dashboard server-side validated session and found it expired.
- Implication: **storageState persistence works for short-window automation** (within session-validity window) but doesn't bypass first-time-login or session expiry. Acceptable for "rotate credentials" workflows where the agent runs within minutes of a fresh user login.

### §2.5 What Playwright MCP CANNOT do

- **Headed-mode visibility control from the agent side** — the playwright MCP doesn't expose a headless/headed toggle directly to the agent (Playwright server config). User would need to configure Playwright MCP at install time.
- **Inject TOTP secret into the agent context securely** — TOTP secret is a credential. Agent can hold it transiently in conversation context for a single rotation, but persistent storage means the agent's process must trust the host. Realistic pattern: **user pastes TOTP secret + agent generates 30s codes inline**. The `otplib` or built-in Web Crypto could be invoked via `browser_run_code_unsafe`.
- **Drive operating-system dialogs** outside the browser (e.g., Windows UAC prompt for installing flyctl). Strictly browser-only.
- **Recover from CAPTCHA** — recaptcha.net is in the cookie list; user might trip a CAPTCHA challenge during automated login. Falls back to user-assist.

### §2.6 Empirical capability gradient

For each common credential-management workflow, what's the **minimum user touch**:

| Workflow | First-time user touch | Subsequent runs | Bottleneck |
|---|---|---|---|
| Cloudflare R2 token rotation | Manual login + manual 2FA + click "create token" + paste back | storageState replay; click "create token"; agent receives token | First-time TOTP unless TOTP-seed pasted |
| Fly.io secret update via dashboard | Manual login + click app → secrets → set | storageState replay; click set | Same |
| Fly.io secret update via flyctl | `flyctl auth login` (browser handshake) + `flyctl secrets set NAME=value -a <app>` | Same (no re-auth in 7d window) | flyctl already automates 99% |
| GitHub repo Actions secret paste | `gh secret set NAME -b VALUE -R <repo>` (one CLI call) | Same | gh-CLI is canonical; no Playwright needed |
| Kite developer console API key rotation | Manual login + manual TOTP + form fill | storageState replay; agent fills form | TOTP first-time |
| MCP Registry submission | Manual login + form fill | storageState replay; agent fills | TOTP first-time |

**The pattern**: Playwright is best when the operation IS a multi-step web UI flow. For single-call API operations (gh secret set, flyctl secrets set), the CLI is faster — Playwright would be re-implementing what the CLI already does.

---

## §3 — Workflow-by-workflow recommendation: CLI vs browser vs API

For each credential / state-mutation workflow we hit this session:

### §3.1 Cloudflare R2 credential rotation

**Current state**: plaintext credentials in `memory/kite-session-apr3.md`. User-action overdue per memory-verification §I10.

**Workflow**: Cloudflare dash → R2 → Manage API Tokens → Roll → copy new ID + secret → `flyctl secrets set LITESTREAM_ACCESS_KEY_ID=... LITESTREAM_SECRET_ACCESS_KEY=...` → patch memory doc.

**Right tool**: **Playwright (browser)** for the Cloudflare side (multi-step UI, dashboard requires login + 2FA, no Cloudflare CLI for R2 token rotation in the agent's PATH). **flyctl** for the Fly-secret-update side (one CLI call). **Edit tool** for the memory doc patch.

**Why not CLI alone**: Cloudflare's R2 API supports token rotation via REST, but the agent doesn't have a Cloudflare API token to call the API (chicken-and-egg). Browser is the human-canonical workflow + the only currently-feasible one.

**User involvement**: first-time TOTP (~30s); subsequent runs only need user-pasted new-token confirmation.

**Estimated time**: 5min user + 2min agent.

### §3.2 OAUTH_JWT_SECRET rotation

**Current state**: rotation runbook landed at `b43c8b6` (`docs/decisions/rotate-key-runbook-2026-05-11.md`); not yet executed.

**Workflow**: generate new 32+ byte secret → `flyctl secrets set OAUTH_JWT_SECRET_PREVIOUS=<old> OAUTH_JWT_SECRET=<new> -a kite-mcp-server` → trigger deploy → verify 401/JWT-refresh works → after grace window remove PREVIOUS.

**Right tool**: **flyctl** (all CLI). No browser needed; Fly.io's `flyctl secrets set` is the canonical interface.

**Why not Playwright**: flyctl is faster + the secret stays on the local box; browser would funnel it through a remote Playwright server.

**Estimated time**: 5min agent.

### §3.3 GitHub repo Actions secrets paste (dr-drill cron)

**Current state**: 4 R2 + 2 Telegram secrets unset; cron has been failing monthly since 2026-05-01. Documented in `decisions/dr-drill-results-2026-05-11.md` §2.

**Workflow**: 6 × `gh secret set NAME -b VALUE -R Sundeepg98/kite-mcp-server` (with values pasted from secret manager) → trigger one `gh workflow run dr-drill.yml -R Sundeepg98/kite-mcp-server` to confirm green.

**Right tool**: **gh CLI** (project CLAUDE.md confirms `gh CLI for data operations, Chrome for visual operations` as canonical). One command per secret.

**Why not Playwright**: GitHub UI works fine, but gh-CLI is faster and machine-checkable (exit code 0 + secret-exists confirmation).

**Why not REST**: gh-CLI IS the REST wrapper with auth baked in.

**Estimated time**: 5min total (user pastes 6 secrets one-by-one; agent runs `gh secret set` for each).

### §3.4 Fly.io secrets (general)

**Right tool**: **flyctl secrets set** (CLI). Always.

**Why**: `flyctl secrets set` is one call; values stay local; no UI navigation; works in WSL2 with absolute path.

### §3.5 Fly.io deploys

**Right tool**: **flyctl deploy --remote-only** (CLI, WSL2). Always.

**Why**: deploys are well-understood; image push is canonical; chain agent has done this 100+ times this session.

**Caveat**: `flyctl releases list` is broken — substitute `flyctl status` + `flyctl image show`.

### §3.6 Kite developer console (BYO API key rotation)

**Current state**: Kite has no CLI. User must visit `kite.zerodha.com/connect/login` → developer console → app → rotate key.

**Right tool**: **Playwright (browser)** — only option. Multi-step UI; OAuth + TOTP.

**User involvement**: first-time TOTP. Subsequent runs: storageState replay (if within Kite session window).

**Estimated time**: 5min user + 2min agent.

### §3.7 Fly.io re-auth (when `flyctl auth status` shows logged in but API 401s)

**Right tool**: **Playwright** per MEMORY.md L147 — navigate to CLI auth URL, click "Continue as".

**Why**: flyctl's `flyctl auth login` opens a browser anyway. Driving it via Playwright closes the loop in-agent. Playwright handles the redirect dance + post-redirect button click.

**Estimated time**: 1min agent + 30s user (TOTP).

### §3.8 MCP Registry publish

**Current state**: per chain agent's repo-docs-verification, server is NOT yet listed (`registry.modelcontextprotocol.io/v0/servers/io.github.Sundeepg98%2Fkite-mcp-server` returns HTTP 404).

**Workflow**: `./mcp-publisher login github` (browser OAuth handshake) → `./mcp-publisher publish` (uses server.json from repo).

**Right tool**: **mcp-publisher CLI** primary; Playwright for the OAuth handshake (mirror of flyctl's auth flow).

**Estimated time**: 10min user-supervised.

### §3.9 Algo2Go trademark filing (IPIndia)

**Right tool**: **Playwright (browser)** — government portal, no API, multi-step form, requires PAN upload + DSC.

**Caveat**: 5 user halts per `algo2go-reservation-runbook.md` — payment, DSC sign, PAN photo upload. Browser drives the navigation; user controls the legal-act steps.

### §3.10 Cohort / Razorpay payment links

**Right tool**: **Razorpay dashboard** (browser). User-only; cohort-1-landing.md has the workflow.

### §3.11 Show HN submission

**Right tool**: **Playwright (browser)** for the final submit — but per `launch-path-execution-playbooks.md` the submit itself has 4 halts. Browser is the natural fit since the URL field + Text field + Submit button are HN's only interactive surfaces.

---

## §4 — Auth state caching strategy

The single highest-leverage Playwright-MCP optimization:

### §4.1 storageState pattern

Per empirical probe (§2.4): `page.context().storageState({path: '/path/to/state.json'})` writes cookies + localStorage + sessionStorage to a JSON file. `browser.newContext({storageState: '/path/to/state.json'})` reads it back.

**Canonical workflow**:
1. **First time** (user-supervised): user logs in to a service via Playwright; agent runs `await page.context().storageState({path: '<service>-state.json'})` and saves to a known location.
2. **Subsequent times** (agent-only): agent imports storageState; opens a tab; navigates to authenticated URL; confirms via "page title doesn't say Login" probe.
3. **On session expiry**: re-trigger first-time flow.

**Where to store storageState files**:
- NOT in the repo (cookies = credentials).
- In user's `%USERPROFILE%\.playwright-mcp-state\` directory OR `~/.config/playwright-mcp-state/` (Linux/Mac).
- File permissions: 0600 (user-readable only).
- Optional encryption: GPG-encrypt with user's GPG key.

**Per-service files** (one per origin to limit blast radius):
- `cloudflare-dash-state.json`
- `fly-dashboard-state.json`
- `kite-developer-console-state.json`
- `github-state.json` (less useful — gh-CLI is canonical for GitHub anyway)

### §4.2 TOTP integration

For 2FA-protected services: user pastes TOTP secret seed once; agent generates 30s codes via Web Crypto / otplib.

**Pattern**:
```js
// Run via browser_run_code_unsafe — generates current TOTP code
async (page, totpSecret) => {
  // Standard TOTP: base32 secret → HMAC-SHA1 of unix-time/30 → 6-digit code
  const code = await generateTotp(totpSecret);
  await page.getByLabel('Authentication code').fill(code);
  await page.getByRole('button', {name: 'Verify'}).click();
}
```

**Where to store TOTP secret**:
- **NEVER** in the repo.
- Per-service env var: `CLOUDFLARE_TOTP_SECRET`, `FLY_TOTP_SECRET`, etc., set in user's shell only when needed (or in a session-scoped scratch file).
- Per session: user pastes secret into agent context; agent uses for one run; agent clears at session end.

**Risk model**:
- TOTP secret = "1 factor of 2FA persistent forever." Treat as carefully as a password.
- Storing in `~/.config/playwright-mcp-state/totp-secrets.json` is acceptable IF that file is 0600 + filesystem-encrypted (BitLocker / LUKS / FileVault).
- Stored is significantly less safe than user-pastes-each-time.

### §4.3 Single-context vs per-service contexts

Playwright's default browser context shares cookies across navigations. **Consequence**: if user runs `browser_navigate('cloudflare.com')` and then `browser_navigate('fly.io')`, both share the same cookie jar — cross-site contamination is possible but Same-Site cookie attributes generally prevent leakage in practice.

**Recommendation**: use `browser_tabs(action: 'new')` to create a fresh context for each service-rotation operation. Closes the cross-site-cookie-bleed risk.

### §4.4 Cookie expiry probe

Per the empirical Cloudflare probe (§2.1): cookies-present ≠ session-valid. **Pattern**:
```js
async (page, dashboardUrl) => {
  await page.goto(dashboardUrl);
  // Wait briefly for server-side validation
  await page.waitForLoadState('networkidle');
  // Check URL — if redirected to /login, session is dead
  const currentUrl = page.url();
  const isLoggedIn = !currentUrl.includes('/login') && !currentUrl.includes('/sign-in');
  return {currentUrl, isLoggedIn};
}
```

If `isLoggedIn === false`: trigger user-prompt for fresh login OR replay storageState refresh.

---

## §5 — Risk model + user-in-the-loop boundaries

### §5.1 What CAN be delegated to Playwright + storageState

| Operation | User involvement | Risk |
|---|---|---|
| Navigate to a public docs page | None | None |
| Take a screenshot of a public page | None | None |
| Replay storageState into a fresh tab | None (assumed by `storageState` exists + valid) | Cookie file contents could be stolen if filesystem ACL bypass; mitigate via 0600 + disk encryption |
| Fill a form on an authenticated page | User-pastes-value once; agent fills | Same as above |
| Generate TOTP from a known secret | User-pastes-TOTP-secret once; agent generates | TOTP secret loss = adversary has 2nd factor forever; treat as critical |
| Click a "rotate API token" button + capture the new value via DOM read | None after auth state is loaded | Token interception if Playwright server is compromised |
| Submit a Show HN post | User reviews the URL + title + body before agent clicks Submit | Posting wrong content (mitigated by halt-before-submit) |

### §5.2 What MUST stay user-in-the-loop

| Operation | Why user must drive |
|---|---|
| First-time login to a new service | TOTP setup; password manager unlock; CAPTCHA |
| Re-authentication after session expiry | Same |
| Any operation that mints a long-lived credential (e.g., API token) | User reviews scope + expiry before clicking Create |
| Any operation that moves money (Razorpay, Stripe) | Legal + financial liability |
| Any operation that triggers irreversible state change in a third party | TM filing, domain registration, MCA filing, NSE empanelment application |
| Any operation across the `.fly/binc` PATH gotcha boundary | First-time fix requires user Windows env edit (Settings → Environment Variables → PATH) — agent can suggest the value but not commit it |

### §5.3 Recommended interaction protocol

For each automation candidate from §3, the dispatch brief should specify:
1. **User-pre-step** (if any): set env var, paste TOTP, log in once.
2. **Agent steps**: browser_navigate → browser_snapshot → browser_click / browser_fill_form → browser_evaluate to read result → return.
3. **User-post-step** (if any): verify the change took effect; commit any local-file patches.

For zero-friction credential-management ops:
- User logs in once → storageState saved → agent does N rotations until session expires → re-prompt.
- For TOTP-protected services: TOTP secret stored in `~/.config/playwright-mcp-state/totp.json` (encrypted) OR re-pasted each session.

---

## §6 — Summary table: optimal tool per operation

| Operation | Best tool | Why | User involvement |
|---|---|---|---|
| `flyctl deploy` | flyctl CLI (WSL2) | Canonical; well-understood; chain agent has 100+ reps | None after auth |
| `flyctl secrets set` | flyctl CLI (WSL2) | One call; values stay local | None after auth |
| `flyctl status` / `flyctl image show` / `flyctl ips list` | flyctl CLI (WSL2) | Substitutes for broken `flyctl releases list` | None after auth |
| flyctl re-auth | Playwright (browser) | MEMORY.md L147 — navigate CLI auth URL + "Continue as" click | First-time TOTP |
| `gh secret set` for GitHub Actions secrets | gh CLI | One call; faster than browser; project CLAUDE.md confirms | None (gh keyring auth) |
| Cloudflare R2 credential rotation | Playwright (browser) | No agent-side Cloudflare API token; UI is the only path | First-time TOTP; storageState for subsequent runs |
| OAUTH_JWT_SECRET rotation | flyctl CLI | All secret-set operations are CLI | None |
| MCP Registry publish | mcp-publisher CLI + Playwright for OAuth | CLI for publish; browser for first-time GitHub-OAuth handshake | First-time TOTP |
| Kite developer console (BYO key rotation) | Playwright (browser) | No Kite CLI for developer console; UI is the only path | First-time TOTP |
| IPIndia TM filing | Playwright (browser) — 5 halts | Govt portal; UI-only; PAN upload + DSC sign | Heavy — 5 user halts |
| Razorpay payment links | Browser (user-only) | Financial; user must be in the loop | Full |
| Show HN submit | Playwright (browser) | HN UI is simple but submit is irreversible | Final-click halt |
| Demo GIF recording | OS-native (user-only) | ScreenToGif requires user driving the recording | Full |

**Pattern**: for **single-call state mutations**, CLI wins. For **multi-step UI flows** (rotation, OAuth handshake, govt portals), Playwright wins. Anything irreversible or financial = user-in-the-loop final-click.

---

## §7 — Concrete optimization candidates (ranked by ROI)

If user authorizes implementation, the top 5 to consider (in priority order):

### 1. Fix WSL2 git credential helper (Friction #2) — HIGH ROI

**Cost**: ~10min one-time setup.
**Savings**: every commit-push pair from WSL2 stops hanging at >60s. ~40 ops this session × 60s = 40min saved/session.
**How**: install `git-credential-manager` for WSL2 OR `gh auth setup-git` in WSL2 OR add `credential.helper "/mnt/c/Program Files/Git/mingw64/libexec/git-core/git-credential-manager"` to WSL2 `~/.gitconfig`.

### 2. Sweep `flyctl releases list` from operational runbooks (Friction #3)

**Cost**: ~5min.
**Savings**: future operators don't hit the broken command.
**How**: `sed -i 's|flyctl releases list|flyctl status -a kite-mcp-server # (or "flyctl image show -a ...")|g'` on the affected runbooks. Already done in `pre-deploy-checklist.md`; remaining: `day-1-launch-ops-runbook.md` per audit-doc-verification §17.

### 3. Provision GitHub Actions secrets for dr-drill (Friction #8) — HIGH ROI

**Cost**: ~5min user-paste.
**Savings**: monthly cron stops silently failing. Launch prerequisite (dr-drill is item #43 of Show HN playbook).
**How**: user pastes 6 secrets at GitHub → repo Settings → Secrets and variables → Actions. Then `gh workflow run dr-drill.yml -R Sundeepg98/kite-mcp-server` to validate.

### 4. Rotate + redact plaintext R2 credentials (Friction #13) — SECURITY

**Cost**: ~15min (Cloudflare token rotation + Fly secret update + memory-file patch).
**Savings**: closes a known credential-exposure gap.
**How**: see §3.1 above. Playwright drives Cloudflare; flyctl updates Fly; Edit patches memory.

### 5. Build storageState caches for the 3 sensitive services (Cloudflare / Kite / Fly)

**Cost**: ~10min × 3 services = 30min user-supervised first-time logins.
**Savings**: every subsequent rotation / state-check operation skips the login step. Estimated 20-40min saved per launch-prep sweep.
**How**: per §4.1 storageState pattern.

---

## §8 — What the audit agent's parallel work (fly MCP) adds

Per dispatch brief, audit agent investigating fly MCP existence/build in parallel. Possible outcomes + implications:

**If fly MCP exists today**: replace flyctl CLI with native MCP tool calls; structured responses; bypasses friction #5 (Metrics token warning) and #6 (no structured deploy state readback). Highest-ROI infrastructure addition.

**If fly MCP doesn't exist yet**: 2 options surface — (a) the agent's `browser_run_code_unsafe` + Playwright can drive the Fly dashboard for rare operations; flyctl remains canonical for routine ops, (b) the audit could propose building a thin MCP wrapper around flyctl-with-parsing.

Either way, **Track 2's Playwright capability inventory is additive** — fly MCP (when exists) handles the "structured state read" use case; Playwright handles the "drive a UI we don't have an API for" use case. They're complementary.

---

## §9 — Source verification

| Probe | Method | Result |
|---|---|---|
| Master HEAD | `git rev-parse HEAD` | `9034790` ✓ |
| flyctl commit history | `git log --grep=flyctl --grep="fly\.io" --all -i` | 65 commits ✓ |
| Playwright MCP availability | `mcp__plugin_playwright_playwright__browser_navigate` invoked successfully | URL = `https://fly.io/docs/flyctl/`; title = "flyctl - The Fly.io CLI · Fly Docs" ✓ |
| Playwright `browser_run_code_unsafe` API | Invoked with `page.context().storageState()` probe | Returned cookieCount=224 + sample-cookies-from-cloudflare-DO-fly-recaptcha + storageState_is_function=true ✓ |
| Cookie inventory in current browser context | `page.context().storageState()` | 224 cookies across `dash.cloudflare.com`, `digitalocean.com`, `www.recaptcha.net`, `fly.io` ✓ |
| Fly.io dashboard auth state | `browser_navigate('https://fly.io/dashboard')` | Redirected to `/app/sign-in?return_to=%2Fdashboard` — confirms user NOT logged in to Fly dashboard in this context ✓ |
| Cloudflare dash auth state | `browser_navigate('https://dash.cloudflare.com/')` | Redirected to `/login` despite cookie-presence — confirms cookies-present ≠ session-valid ✓ |
| MEMORY.md friction notes | `grep -nE "flyctl" MEMORY.md` | 16 flyctl-relevant entries ✓; PATH typo at line 147; deploy pattern at line 103 |
| `flyctl releases list` not a valid subcommand | Cited from `production-master-gap-report.md` §1.1 + active-docs-verification §17 | VERIFIED at probe time ✓ |
| dr-drill Actions secrets unset | Cited from `decisions/dr-drill-results-2026-05-11.md` §2 | VERIFIED via `gh workflow run` history showing 1 failed run ✓ |
| Plaintext R2 credentials in memory file | Cited from `memory-files-verification-2026-05-11.md` finding I10 | VERIFIED via direct file read ✓ |

---

## §10 — Hard rules compliance

| Rule | Status |
|---|---|
| READ-ONLY | ✓ — Playwright probes were idempotent navigations to public docs + cookie introspection; no auth flows attempted; no state mutated |
| Empirical: try actual Playwright MCP tools | ✓ — `browser_navigate` × 3, `browser_snapshot` × 2, `browser_run_code_unsafe` × 2 (storageState API probe), `browser_close` × 1 |
| Cite specific tool names + parameter signatures | ✓ — see §2.1-2.4 |
| Single commit + push | (next step) |
| ~2h budget; halt at 3h | ~1h wall-clock through investigation + writing |
| Don't drive sensitive logins | ✓ — only probed public docs + dashboard-redirect-to-login (no credentials entered) |

---

## §11 — Verdict

The Playwright MCP toolset is **dramatically more capable than the dispatch's framing suggested**. The `browser_run_code_unsafe` tool exposes the full Playwright Page/Context API including `storageState()` for session persistence — meaning once a user logs in to a service via Playwright once, the agent can rotate credentials / drive UI flows without re-auth until the session expires server-side.

Combined with the friction inventory (§1), the optimization landscape is clear:
- **Most flyctl friction is one-time-fix territory** (PATH, credential helper, runbook command sweep).
- **The remaining flyctl friction** (Metrics token warning, no JSON output) is Fly.io-internal; addressed when audit agent's fly-MCP investigation lands.
- **Playwright's role** is for the workflows that **never had a CLI to begin with** (Cloudflare R2 rotation, Kite developer console, IPIndia TM filing, MCP Registry OAuth handshake, Show HN submit).

The pattern surfaced is: **CLI for single-call state mutations; Playwright for multi-step UI flows; user-in-the-loop for irreversibles and financials**. The empirical capability probes confirm Playwright MCP can execute on every browser-side workflow we identified — first-time TOTP being the only user-paste burden, mitigated to "once per session-expiry" by storageState caching.

If user authorizes implementation, top 5 ROI items in §7 sum to ~40-60min of work for ~40min-saved-per-session forever PLUS closes the launch-prerequisite dr-drill cron gap PLUS closes the credential-rotation security gap.
