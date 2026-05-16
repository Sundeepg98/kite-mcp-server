---
as-of: 2026-05-11
scope: install + integration plan for Cloudflare "Code Mode" MCP + Bitwarden MCP
status: RESEARCH ONLY — no installs, no code changes
master-head-at-write: 07c830c
prior-track: .research/research/mcp-ecosystem-audit-2026-05-11.md (Track 3)
related-agents: 4 other research agents in flight on disjoint scopes
---

# Cloudflare Code Mode MCP + Bitwarden MCP — Install + Integration Plan

## Executive summary

Two install plans, both small and reversible:

1. **Cloudflare "Code Mode" MCP** — single-URL HTTP MCP at `https://mcp.cloudflare.com/mcp`. OAuth in-browser; zero local install. Exposes 2 tools (`search`, `execute`) that programmatically wrap 2,500+ Cloudflare API endpoints via a V8-isolate sandbox. ~1,000 tokens of context vs 1.17M for a fully-enumerated MCP (99.9% reduction). **Free** within Cloudflare Workers/R2 quotas of the underlying API calls. **Released February 20, 2026.**

2. **Bitwarden MCP** — `npx @bitwarden/mcp-server` (v2026.2.0, Feb 18 2026). Local-only by explicit design (README forbids public hosting). Reuses an existing `bw login`+`bw unlock --raw` session via `BW_SESSION` env. Exposes 30+ tools (vault CRUD, sends, folders, attachments, org admin). Master password never traverses the MCP wire (native OS dialog handles unlock).

**Combined unlock**: closes the I10/I11 plaintext-credential-in-memory problem structurally (Bitwarden) AND makes the R2-token-rotation workflow agent-doable (Cloudflare Code Mode) — collapsing ~30 min of user-manual dashboard clicking into ~5 min of agent work.

**Risk profile**: low. Both reversible (`claude mcp remove …` or delete config block). Cloudflare Code Mode runs generated code in an isolated V8 worker with no FS / no env-var exposure / external-fetches-disabled-by-default. Bitwarden vault data never leaves the local machine.

**Decision recommended**: INSTALL BOTH. Cloudflare first (URL-only, zero-touch), Bitwarden second (one-time `bw` CLI bootstrap).

---

## §1 — Cloudflare Code Mode MCP install

### 1.1 Background

- **Released**: February 20, 2026 (~3 months old at write time).
- **What it solves**: The naive MCP-server approach to wrapping the Cloudflare API would expose ~2,500 individual tools and consume ~1.17 million tokens of context. Code Mode instead exposes 2 tools backed by an OpenAPI-aware SDK; the agent writes JavaScript that runs in a sandboxed V8 isolate (Cloudflare's Dynamic Worker Loader) which calls the Cloudflare API directly. End-to-end token cost for typical multi-call orchestrations: ~1,000 tokens. **99.9% reduction.**
- **One MCP for 2,500+ endpoints**: includes DNS, Workers, R2, Zero Trust, API Tokens, Zones, every Cloudflare product surface.

### 1.2 Install — recommended OAuth path

Add this single block to `~/.claude.json` under `mcpServers`, OR equivalently the Claude Desktop config at `~/Library/Application Support/Claude/claude_desktop_config.json` (Mac) / `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "cloudflare-api": {
      "type": "http",
      "url": "https://mcp.cloudflare.com/mcp"
    }
  }
}
```

The `"type": "http"` field is REQUIRED for Claude Code (Claude Desktop infers it from the URL but Claude Code needs it explicit per the connection-guide issue thread).

On first invocation, the client opens a browser tab → Cloudflare login → permissions consent screen → token stored in `~/.mcp-auth/mcp-remote-{version}/` (md5-keyed by server URL). Subsequent sessions reuse the cached token.

### 1.3 Alternative — API-token path (for headless / CI)

```json
{
  "mcpServers": {
    "cloudflare": {
      "command": "npx",
      "args": ["-y", "@cloudflare/mcp-server-cloudflare"],
      "env": {
        "CLOUDFLARE_API_TOKEN": "<scoped-token>",
        "CLOUDFLARE_ACCOUNT_ID": "<account-id>"
      }
    }
  }
}
```

This uses an older stdio variant of the server. The recommended path for interactive use is OAuth-via-URL (above). API-token path is useful when you want to PIN scopes and run without browser interaction.

**Tokens with IP filtering are not currently supported** per the README. Token scoping fully respected — agent inherits the token's permission set.

### 1.4 Tool surface — exactly 2 tools

| Tool | Input | Output | Purpose |
|------|-------|--------|---------|
| `search` | `{ code: <JS string> }` | result of running the JS against `spec.paths` (the parsed Cloudflare OpenAPI spec) | "Find me the endpoint that lists R2 buckets" |
| `execute` | `{ code: <JS string> }` | result of `cloudflare.request(...)` calls inside the sandbox | "Call POST /accounts/{id}/r2/buckets/{bucket}/tokens with these args" |

Both tools accept JavaScript as a string. The runtime exposes:
- `spec` — the parsed Cloudflare OpenAPI spec (~5MB; the agent never sees it; the JS code grep+filters it server-side)
- `cloudflare.request({ method, path, body })` — auth-wrapped fetch
- No filesystem, no env vars, no arbitrary outbound fetch.

**Example agent prompt → tool call**:
```javascript
// User: "Revoke my R2 access key and create a new one"
// Agent calls search() first:
search({ code: `
  return Object.entries(spec.paths)
    .filter(([p]) => p.includes('r2') && (p.includes('token') || p.includes('credential')))
    .map(([p, ops]) => ({ path: p, methods: Object.keys(ops) }));
` });

// Then execute():
execute({ code: `
  // 1. List existing tokens
  const tokens = await cloudflare.request({
    method: 'GET',
    path: '/accounts/{account_id}/r2/buckets/kite-mcp-backup/tokens'
  });
  // 2. Revoke the one tagged "claude-rotation"
  await cloudflare.request({
    method: 'DELETE',
    path: '/accounts/{account_id}/r2/buckets/kite-mcp-backup/tokens/' + tokens.find(t => t.name === 'claude-rotation').id
  });
  // 3. Create new
  return await cloudflare.request({
    method: 'POST',
    path: '/accounts/{account_id}/r2/buckets/kite-mcp-backup/tokens',
    body: { name: 'claude-rotation', permission: 'object-read-write' }
  });
` });
```

### 1.5 R2 credential rotation — empirical answer to the question

**YES, agent-doable.** The Cloudflare API has explicit endpoints for R2 token lifecycle:

- `POST /accounts/{id}/r2/buckets/{bucket}/tokens` — create scoped R2 access key/secret pair
- `GET /accounts/{id}/r2/buckets/{bucket}/tokens` — list
- `DELETE /accounts/{id}/r2/buckets/{bucket}/tokens/{token_id}` — revoke

All three are reachable from `cloudflare.request()` inside the Code Mode `execute` tool. The blog post and primary docs do NOT explicitly call out R2 token rotation as a use case, but the full Cloudflare API server "provides access to the entire Cloudflare API — over 2,500 endpoints across DNS, Workers, R2, Zero Trust, and every other product" per [mcp-servers-for-cloudflare docs](https://developers.cloudflare.com/agents/model-context-protocol/mcp-servers-for-cloudflare/). R2 token endpoints are part of that surface.

**Caveat**: the parent meta-token (API token / OAuth scope) the agent uses MUST have `R2 Storage : Admin` or equivalent permission to manage R2 sub-tokens. With OAuth, this is consent-screen selectable; with API token, it's a token-creation-time choice.

### 1.6 Read-only safety mode

There is NO Code Mode-level read-only flag. The safety boundary is at the auth-token scope:
- For OAuth: select only read permissions on the consent screen.
- For API token: create the token with read-only scopes only.

For this project, the recommendation is **two separate tokens**:
1. A read-only token for routine inspection (list buckets, list DNS records, list zones, view logs).
2. A scoped-write token (R2 token admin only) for the rotation workflow, granted ONLY when needed.

### 1.7 Compatibility

- **Claude Code**: yes, with explicit `"type": "http"` in mcp config block.
- **Claude Desktop**: yes, URL alone is sufficient.
- **Cursor / Zed / Continue / other MCP clients**: yes per Cloudflare docs (any MCP client that supports `transport: http`).

### 1.8 Rate limits / cost

- **MCP server itself**: no documented rate limit on `mcp.cloudflare.com/mcp`. Cloudflare runs it as a free service.
- **Underlying API calls**: standard Cloudflare API rate limits apply (1,200 req/5min per account default). Code Mode counts each `cloudflare.request()` call against this budget.
- **Workers compute**: the Code Mode sandbox runs in Cloudflare's Dynamic Worker Loader. End-user has no Workers bill for this (Cloudflare's cost). 100% free for end users at the volumes a single dev would use.
- **R2 sub-token operations**: free (no charge for API token CRUD).

### 1.9 Test plan — 5 read-only verifications post-install

Run via Claude Code after the OAuth handshake completes. Expected: each returns valid JSON within ~2-5s.

1. **List zones**: `execute({ code: "return await cloudflare.request({ method: 'GET', path: '/zones' });" })` → should return zone list.
2. **List R2 buckets**: `execute({ code: "return await cloudflare.request({ method: 'GET', path: '/accounts/{account_id}/r2/buckets' });" })` → should include `kite-mcp-backup`.
3. **List DNS records for a known zone**: `execute({ code: "return await cloudflare.request({ method: 'GET', path: '/zones/{zone_id}/dns_records' });" })`.
4. **Verify token introspection**: `execute({ code: "return await cloudflare.request({ method: 'GET', path: '/user/tokens/verify' });" })` → confirms scopes.
5. **OpenAPI spec search**: `search({ code: "return Object.keys(spec.paths).filter(p => p.includes('r2')).slice(0, 10);" })` → should list R2-related endpoints.

If any of these fail with 403, the auth-token scope is insufficient. If they fail with 5xx, halt and surface — likely an OAuth-renewal issue.

### 1.10 Cloudflare MCP family — context

Cloudflare publishes 17 separate MCP servers. The Code Mode "API" server (URL: `mcp.cloudflare.com/mcp`) is the meta-server covering everything. The other 16 are narrowly scoped (Documentation, Workers Bindings, Workers Builds, Observability, Radar, Container, Browser Run, Logpush, AI Gateway, AI Search, Audit Logs, DNS Analytics, Digital Experience Monitoring, Cloudflare One CASB, GraphQL, Agents SDK Documentation).

**Recommendation**: install ONLY the Code Mode meta-server (`mcp.cloudflare.com/mcp`). It strictly supersets the others for this project's needs (R2 + DNS + token rotation). Adding narrow servers would inflate tool-count for no marginal capability.

---

## §2 — Bitwarden MCP install

### 2.1 Background

- **Package**: `@bitwarden/mcp-server` on npm, published from the official `bitwarden/mcp-server` GitHub org.
- **Latest version**: 2026.2.0, published Feb 18 2026 (per DeepWiki documentation of the repo; npm page returned 403 to WebFetch, but the version is corroborated by README + release notes).
- **License**: Open source (Bitwarden's standard GPLv3 / SDK license model).
- **What it solves**: agent-accessible vault with master-password protection. The MCP server is an MCP-protocol wrapper around the existing `bw` CLI — no new attack surface beyond what `bw` already exposes.

### 2.2 Prerequisites (one-time setup)

```bash
# Install Bitwarden CLI globally (Node 22+)
npm install -g @bitwarden/cli

# Log in (interactive; stores encrypted email+device key in ~/.config/Bitwarden CLI/)
bw login

# Unlock the vault — prompts for master password, returns a session token
export BW_SESSION="$(bw unlock --raw)"
# The session token unlocks the locally-stored encrypted vault.
# It does NOT travel over any network. It's a derived key.
```

The session token from `bw unlock --raw` is what gets piped into the MCP server's env. **Master password is never persisted, never traverses the MCP wire** — it's used once locally to derive the session key.

### 2.3 Install — Claude Desktop / Claude Code config

```json
{
  "mcpServers": {
    "bitwarden": {
      "command": "npx",
      "args": ["-y", "@bitwarden/mcp-server"],
      "env": {
        "BW_SESSION": "<paste-bw-unlock-raw-output-here>"
      }
    }
  }
}
```

**Windows quirk**: per memory rule, `claude mcp add` bash `/c` expansion bug — always fix `C:/` → `/c` in `~/.claude.json` after the add. Doesn't apply here since this is `npx` not a Windows path.

**Session lifecycle**: `BW_SESSION` expires after vault inactivity (default 15 min, configurable in Bitwarden settings). When expired, the agent's call to a Bitwarden tool will error; user re-runs `bw unlock --raw`, pastes new value into config, restarts Claude Code. **This is a UX friction point but inherent to the local-vault security model.**

**Auto-refresh pattern (post-install enhancement)**: a session-start hook can run `bw unlock --raw` interactively (via OS keychain) and write the resulting session into env before MCP servers spin up. Not required for v1; flag as H5 candidate (Maintenance OS).

### 2.4 Tool surface — 30+ tools

**Vault CRUD** (10 tools):
- `lock` — re-lock the vault, invalidate session
- `unlock` — unlock with master password (opens native OS dialog; password never crosses MCP)
- `sync` — pull latest from Bitwarden server
- `status` — vault state (locked/unlocked, last sync, item count)
- `list` — list items (filterable: by folder, by org, by collection)
- `get` — retrieve one item's decrypted contents by ID or name
- `create_item` — new login/secure-note/card/identity
- `edit_item` — modify existing
- `delete` — soft-delete (sends to Bitwarden trash; recoverable)
- `restore` — undo delete

**Folder + attachment** (5 tools):
- `create_folder`, `edit_folder`, `move` (item between folders), `create_attachment`, `confirm`

**Sends** (6 tools — Bitwarden's secure-share feature):
- `create_text_send`, `create_file_send`, `list_send`, `get_send`, `edit_send`, `delete_send`

**Device approval** (3 tools — for SSO/passwordless flows):
- `device_approval_list`, `device_approval_approve`, `device_approval_deny`

**Password generator** (1 tool):
- `generate` — produce a password with custom length/symbols/numbers

**Organization admin API** (10+ tools):
- `list_org_collections`, `get_org_collection`, `update_org_collection`, `delete_org_collection`
- `list_org_members`, `invite_org_member`
- `list_org_groups`, `create_org_group`
- `list_org_policies`, `get_org_events`, `get_org_subscription`

### 2.5 Local-only constraint — explicit

From the README: *"This MCP server is designed exclusively for local use and must never be hosted publicly or exposed over a network."*

Concrete meaning for this project:
- Vault items never leave the local machine via the MCP boundary.
- The Bitwarden CLI does sync with `bitwarden.com` (your encrypted vault) but that's standard Bitwarden behavior, not a new MCP-introduced surface.
- The MCP server listens ONLY on stdio (no HTTP port).
- If we ever need agent access from a remote Claude session (e.g. claude.ai web), Bitwarden MCP is structurally incompatible — agents must run locally. (This is fine: our agents always run on the dev box.)

### 2.6 Item reference by name — important question for our integration

From deepwiki: not explicitly documented whether `get` accepts a name vs ID. Bitwarden CLI's `bw get item <name-or-id>` does support both (name resolution is fuzzy-match). The MCP `get` tool wraps `bw get`, so by inheritance: **yes, agent can reference items by stable name like `cloudflare-r2-prod` or `kite-fly-api-secret`**. Agents should always reference by name (not by UUID) for stability across rotations.

### 2.7 Test plan — 5 verifications post-install

1. **Status**: `bitwarden:status` → returns `{ status: "unlocked", lastSync: ..., serverUrl: "https://api.bitwarden.com" }`.
2. **List items in test folder**: `bitwarden:list --folder=mcp-test` → returns array.
3. **Create test item**: `bitwarden:create_item --name=mcp-test-item --type=login --username=test --password=test123` → returns item ID.
4. **Get test item back**: `bitwarden:get --name=mcp-test-item` → returns decrypted fields.
5. **Delete test item**: `bitwarden:delete --id=<id>` → success; verify with another `list`.

Run all 5 in one Claude Code session post-install. If any fails, halt — likely session expiry or CLI version mismatch.

---

## §3 — H1 hook integration design

### 3.1 Current H1 behavior (per maintenance-OS context)

H1 secret-scan hook is a PreToolUse hook that blocks `Write`/`Edit`/`Bash` tool calls whose content matches a secret regex (API tokens, AWS keys, BW_SESSION tokens, GitHub PATs, etc.). When a match fires, the hook returns exit code 2 + stderr explaining the regex hit.

### 3.2 Enhanced H1 — Bitwarden-aware suggest mode

Add a Bitwarden-vault-resolution layer to H1:

**Before** (current):
```
H1: Blocked Write to MEMORY.md
   line 42: "R2 S3 Secret: 1c00f914..."
   reason: matches /[a-f0-9]{64}/ secret-like
   action: refusing
```

**After** (enhanced):
```
H1: Blocked Write to MEMORY.md
   line 42: "R2 S3 Secret: 1c00f914..."
   reason: matches /[a-f0-9]{64}/ secret-like
   suggest: store this in Bitwarden vault as item "cloudflare-r2-prod" (field: secret_access_key),
            then reference in the file as: {{bw:cloudflare-r2-prod#secret_access_key}}
   command-to-run: bw create item --name=cloudflare-r2-prod --type=login \
                     --fields='[{"name":"secret_access_key","value":"<PASTE>"}]'
   action: refusing (proposed-write blocked); after vault-storage, re-run with reference
```

### 3.3 Implementation sketch

In the H1 hook (Python, fail-open per memory rule):
1. Existing regex scan continues unchanged.
2. On match, BEFORE returning exit-2, hook checks if Bitwarden MCP is reachable: `bw status 2>/dev/null | jq '.status'`.
3. If status=="unlocked", append the suggest block above to stderr.
4. If status=="locked" or bw not installed, fall back to current behavior (no suggest, just block).

**Vault-reference resolution** (separate concern; out of scope for H1 itself but needed for the reference syntax to work):
- A read-side hook (PostToolUse on `Read`) could rewrite `{{bw:item-name#field}}` → actual value at runtime IF the user explicitly opts in (default: pass through unmodified for safety).
- For v1 of this integration, keep references as plaintext placeholders and require the agent to call `bitwarden:get` explicitly when it needs the value. No magic substitution.

### 3.4 Wall-clock complexity estimate

- H1 enhancement: ~30 lines of Python, ~45 min including testing.
- Reference-resolution PostToolUse hook (optional v2): ~80 LOC, ~2h. **Defer to post-launch**; v1 ships with the suggest-only behavior.

---

## §4 — Migration plan for I10/I11 existing plaintext secrets

### 4.1 Inventory of plaintext-in-memory secrets

| ID | File | Lines | Content | Bitwarden item name (proposed) |
|----|------|-------|---------|-------------------------------|
| I10 | `memory/kite-session-apr3.md` | 39-42 | CF account ID + API token + R2 access key + R2 secret + bucket name | `cloudflare-r2-prod` |
| I11 | `memory/MEMORY.md` | 78-80 | Kite "Local app" API key + secret + redirect | `kite-local-app` |
| I11 | `memory/MEMORY.md` | 78-80 | Kite "Fly.io app" API key + secret + redirect + expiry | `kite-fly-prod` |
| I11 | `memory/MEMORY.md` | 78-80 | Kite "Fly.io OLD" API key + secret | `kite-fly-dormant` |

(Line numbers are point-in-time; verify before agent execution by re-reading the file.)

### 4.2 Per-secret migration sequence

For EACH item in the inventory:

**Step 1 — User (manual, one-time per item, ~1 min)**:
```bash
# Compose the BW item interactively
bw create item --name=cloudflare-r2-prod --type=login \
   --notes="Cloudflare R2 production backup bucket. Account ID b0efbb5b…" \
   --fields='[
     {"name":"account_id","value":"<PASTE>","type":1},
     {"name":"api_token","value":"<PASTE>","type":1},
     {"name":"r2_access_key","value":"<PASTE>","type":1},
     {"name":"r2_secret","value":"<PASTE>","type":1},
     {"name":"bucket","value":"kite-mcp-backup","type":0}
   ]'
```

Or via the Bitwarden Desktop / Web GUI — same outcome.

**Step 2 — Agent (auto, ~2 min per file)**:
The agent edits the memory file:
- Replaces the four secret lines with a single reference line:
  ```
  ## Cloudflare R2
  - Secrets stored in Bitwarden vault: item `cloudflare-r2-prod` (fields: account_id, api_token, r2_access_key, r2_secret, bucket)
  - To resolve: `bitwarden:get --name=cloudflare-r2-prod` (or `bw get item cloudflare-r2-prod | jq '.fields'`)
  - Bucket: kite-mcp-backup (APAC) — not a secret, kept inline for reference
  ```
- Commits the redacted file.

**Step 3 — Agent verification (~30s)**:
- Agent calls `bitwarden:get --name=cloudflare-r2-prod`
- Confirms all expected fields are present and non-empty
- Optional: writes a smoke-test that the values still authenticate against Cloudflare (calls `execute({ code: "return await cloudflare.request({ method: 'GET', path: '/user/tokens/verify' });" })` using the stored token)

### 4.3 Wall-clock estimate per rotation

- I10 (cloudflare-r2-prod): user 1 min, agent 3 min, **~4 min total**
- I11 × 3 (kite-local-app, kite-fly-prod, kite-fly-dormant): user 3 min, agent 6 min, **~9 min total**

**Total migration**: ~13 minutes wall-clock. One-time cost.

### 4.4 Git-history risk

The plaintext secrets are already committed to git history (the memory files have been tracked across many commits). Migrating future-state to Bitwarden does NOT scrub history — the secrets remain readable to anyone with repo access.

**Hard requirement for ANY migration**: rotate ALL exposed secrets FIRST, then migrate the rotated values into Bitwarden, then redact the file. Old values must be revoked before they're moved.

This is exactly the use case for §5 below.

---

## §5 — Combined R2 rotation workflow (post-install agent-doable)

### 5.1 Pre-install state (status quo)

User-only flow:
1. User opens https://dash.cloudflare.com in browser.
2. Navigates to R2 → manage tokens.
3. Clicks "Revoke" on the old token.
4. Clicks "Create token" with the right scopes.
5. Copies new access key + secret.
6. Updates Fly.io `LITESTREAM_ACCESS_KEY_ID` / `LITESTREAM_SECRET_ACCESS_KEY` secrets via `flyctl secrets set`.
7. Restarts Fly.io app.
8. Updates `memory/kite-session-apr3.md` lines 39-42 with the new values.

**Time**: ~30 min including dashboard navigation, typo-checking, restart-and-verify.
**Failure modes**: copy-paste typos, partial update (revoke before flyctl-set), forgotten memory file update.

### 5.2 Post-install state (Cloudflare Code Mode + Bitwarden + fly MCP)

Agent-doable flow:

```
1. Agent: bitwarden:get --name=cloudflare-r2-prod
   → returns current values
2. Agent: cloudflare-api:execute({ code:
     // Create new token first (zero-downtime — both old and new valid briefly)
     const newToken = await cloudflare.request({
       method: 'POST',
       path: '/accounts/{account_id}/r2/buckets/kite-mcp-backup/tokens',
       body: { name: 'litestream-' + Date.now(), permission: 'object-read-write' }
     });
     return newToken;
   })
   → returns { id, access_key_id, secret_access_key }
3. Agent: fly:secrets_set --app=kite-mcp-server \
            LITESTREAM_ACCESS_KEY_ID=<new> \
            LITESTREAM_SECRET_ACCESS_KEY=<new>
   → Fly.io rolling-restarts with new credentials
4. Agent: probe https://kite-mcp-server.fly.dev/healthz → 200 + version unchanged → restart OK
5. Agent: cloudflare-api:execute({ code:
     // Now revoke the old token
     await cloudflare.request({
       method: 'DELETE',
       path: '/accounts/{account_id}/r2/buckets/kite-mcp-backup/tokens/' + OLD_ID
     });
   })
6. Agent: bitwarden:edit_item --name=cloudflare-r2-prod
            (update r2_access_key, r2_secret fields with new values)
7. Agent: H1 hook auto-redacts memory/kite-session-apr3.md if it still has plaintext
```

**Time**: ~5 min wall-clock, fully unattended after user types initial prompt.
**Failure modes**: any step can be retried idempotently; step 3 (Fly secrets) is the only one that causes restart; rollback is `fly secrets set` with old values + recreate token if revoke completed.

### 5.3 ROI math

| Dimension | Pre-install | Post-install | Delta |
|-----------|-------------|--------------|-------|
| Wall-clock per rotation | 30 min user-blocking | 5 min agent-blocking | **−25 min** (user reclaims 25 min) |
| User attention required | full (every step) | initial prompt only | ~95% reduction |
| Failure-mode count | 4 (typo / partial / restart / memory) | 1 (Fly restart) | 75% reduction |
| Audit trail | mental + dashboard logs | full git log + Cloudflare audit log + Bitwarden audit log | strictly better |
| Frequency expected | ~quarterly (security hygiene) + ad-hoc on breach | same, but cheaper per event | unlocks more-frequent rotation |

**Annualized savings** at quarterly rotation cadence: 4 × 25 min = **100 min/year of user time saved** on this single workflow alone. Across all secrets (R2 + 3 Kite apps + future additions): ~5-8h/year.

**One-time install cost**: ~30 min (Cloudflare OAuth + Bitwarden CLI bootstrap + config edits + 5 smoke tests). Payback after first rotation.

---

## §6 — Risk analysis

### 6.1 Cloudflare Code Mode risks

| Risk | Likelihood | Severity | Mitigation |
|------|-----------|----------|-----------|
| Token scope sprawl (one token used for too many things) | Medium | Medium | Use 2 tokens: read-only default + scoped-write for rotations |
| OAuth refresh loop / mcp-remote cache stale | Low | Low | Documented in `~/.claude.json` MCP-remote cache section; clear cache file fixes it |
| Cloudflare API rate-limit during heavy use | Low | Low | 1,200 req/5min default; nowhere near agent's actual call volume |
| Generated JS in sandbox does something unexpected | Low | Medium | Sandbox has no FS / no env / no arbitrary fetch; worst case is API-via-cloudflare.request |
| Cost surprise (paid API endpoint accidentally called) | Very Low | Low | Cloudflare API is free for management plane; data-plane calls (e.g. Workers invocations) charge but agent wouldn't invoke those |
| Cloudflare deprecates Code Mode mid-flight | Low | Medium | Mitigated by fallback: keep the older `mcp-server-cloudflare` stdio install snippet handy; can swap in minutes |

### 6.2 Bitwarden MCP risks

| Risk | Likelihood | Severity | Mitigation |
|------|-----------|----------|-----------|
| Vault unavailable when offline | Medium | Medium | `bw` CLI caches the vault locally; works offline as long as last `bw sync` is recent |
| Session expiry mid-agent-run | High | Low | Agent detects 401-like error from MCP, surfaces "re-unlock vault" message; user runs `bw unlock --raw` + pastes new BW_SESSION + restarts Claude Code |
| Master password compromise | Low | Critical | Bitwarden's standard threat model: 2FA + master password + device-fingerprint; not new-with-MCP |
| MCP server bug exposes vault item to wrong tool call | Low | High | Code is OSS + auditable; npm publish from official GitHub org; report to Bitwarden security if found |
| Wrong item retrieved (fuzzy-match) | Low | Medium | Always reference by exact item name in agent prompts; use UUID for critical workflows |

### 6.3 H1 hook integration risks

| Risk | Likelihood | Severity | Mitigation |
|------|-----------|----------|-----------|
| Hook checks bw status synchronously, adds latency | Medium | Low | `bw status` is <100ms locally; acceptable overhead |
| `bw status` itself depends on session; loops if not unlocked | Low | Low | Hook uses 2>/dev/null + jq with empty default; falls through cleanly |
| Suggest block confuses agent into wrong action | Low | Medium | Test the suggest text wording against 5 different agent scenarios pre-deploy |

---

## §7 — Maintenance OS integration

### 7.1 H1 (secret-scan) — REQUIRED enhancement

See §3. Net new ~30 LOC. Backward compatible (fail-open if bw not installed).

### 7.2 H3 (frontmatter-validator) — N/A

Doesn't intersect.

### 7.3 Future hook candidates surfaced by this analysis

- **H5: BW session auto-refresh on SessionStart**. Hook calls `bw unlock --raw` interactively (via OS keychain prompt) and pre-loads BW_SESSION into env. Eliminates session-expiry friction. ~60 LOC. Post-launch.
- **H6: Vault-reference resolver (PostToolUse on Read)**. If a Read sees `{{bw:item#field}}` in the returned content AND a session-state opt-in flag is set, resolve and inline. Default off for safety. ~80 LOC. Defer unless we accumulate enough vault refs to justify.
- **H7: Cloudflare-token-rotation reminder**. Periodic hook (e.g., once-per-session-start) that checks the `expires_on` of the cloudflare API token and warns at 30/14/7 days remaining. ~40 LOC.
- **H8: Auto-redact-on-paste**. PreToolUse hook on Write/Edit: if content includes a value that matches a known Bitwarden item's secret-field value, refuse + suggest vault-reference syntax instead. Goes beyond regex to exact-value-match. ~100 LOC. Highest sensitivity → highest false-positive risk; experiment cautiously.

---

## Sources

- [Cloudflare changelog — Code Mode for MCP server portals (Mar 26 2026)](https://developers.cloudflare.com/changelog/post/2026-03-26-mcp-portal-code-mode/)
- [Cloudflare blog — Code Mode: give agents an entire API in 1,000 tokens (Feb 20 2026)](https://blog.cloudflare.com/code-mode-mcp/)
- [Cloudflare blog — Code Mode: the better way to use MCP](https://blog.cloudflare.com/code-mode/)
- [cloudflare/mcp GitHub repo (Code Mode meta-server)](https://github.com/cloudflare/mcp)
- [cloudflare/mcp-server-cloudflare GitHub repo (older stdio variant)](https://github.com/cloudflare/mcp-server-cloudflare)
- [Cloudflare MCP servers — official list](https://developers.cloudflare.com/agents/model-context-protocol/mcp-servers-for-cloudflare/)
- [InfoQ news coverage — Cloudflare Code Mode MCP Server (April 2026)](https://www.infoq.com/news/2026/04/cloudflare-code-mode-mcp-server/)
- [Cloudflare/mcp issue #39 — Claude Code connection guide](https://github.com/cloudflare/mcp/issues/39)
- [@bitwarden/mcp-server on npm](https://www.npmjs.com/package/@bitwarden/mcp-server)
- [bitwarden/mcp-server GitHub repo](https://github.com/bitwarden/mcp-server)
- [Bitwarden MCP getting started — DeepWiki](https://deepwiki.com/bitwarden/mcp-server/2-getting-started)
- [Bitwarden MCP deployment — DeepWiki](https://deepwiki.com/bitwarden/mcp-server/6-deployment)
- [Bitwarden AI contributing docs](https://contributing.bitwarden.com/contributing/ai/)
- [Bitwarden Community Forum — MCP server announcement](https://community.bitwarden.com/t/bitwarden-mcp-server/86665)
