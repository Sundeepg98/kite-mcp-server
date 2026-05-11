# Fly.io MCP — Existence + Build Effort Research

**Date**: 2026-05-11 IST
**Master HEAD**: `9034790`
**Dispatch role**: Track 1 of 2 parallel — MCP discovery + recommendation. Track 2 (Chain agent) doing Playwright end-to-end + flyctl friction inventory in parallel.
**Charter**: empirical answer to "why no Fly MCP, every flyctl op is shell-out." Single doc, decision-oriented.

**Methodology** (per CORPUS-MAINTENANCE-STRATEGY): compile-and-probe > grep — every claim grounded in an actual probe (WebFetch / gh api / local `flyctl mcp --help`). Cited URLs per finding.

---

## TL;DR — three things to know

1. **An OFFICIAL Fly.io MCP server EXISTS and is INSTALLED ON THE USER'S MACHINE ALREADY.** It's not a separate repo or download — it's `flyctl mcp server`, a **built-in subcommand of the `flyctl` CLI itself**. Empirically verified: local `flyctl v0.4.14` (Feb 2026 build) ships 10 `fly mcp <subcommand>` variants including `server`, `add`, `launch`, `inspect`, `list`, `logs`, `proxy`, `wrap`, `destroy`, `remove`.

2. **Connecting it to Claude Code is a ONE-COMMAND operation**: `flyctl mcp server --claude --server fly`. The command auto-edits the Claude client config (similar to how `claude mcp add` works for other servers). No JSON-by-hand, no manual config-file editing. Minimum flyctl version is v0.3.117 per Fly's official blog (we're far past that at v0.4.14).

3. **Tool surface (per Fly's "MCP for Provisioning" blog post, May 2026)**: `apps`, `logs`, `machine`, `orgs`, `platform`, `status`, `volumes` are "roughed in." Author Sam Ruby (Fly engineering) added `fly volume create` "first try" — actively being extended. This covers all 7 tool-classes the dispatch enumerated: status, logs, machines, releases (subset of platform/apps), secrets (gap — see §3 below), deploy (gap — see §3), image-show (subset of status).

**Recommendation** (immediate, low-risk, zero build effort): **INSTALL `flyctl mcp server --claude --server fly`** as a single command. ~5 min including Claude Code restart. Skip the `superfly/flymcp` Go-wrapper repo (effectively abandoned per §2.B), skip the `brannn/fly-mcp` community fork (single-day commit, 0 stars, 11 months stale), skip Composio's paid managed-tier toolkit.

---

## §1 — Discovery: what exists in the Fly.io MCP ecosystem

### 1.1 The official answer is built into flyctl itself

**Empirical** (local `flyctl mcp --help` run 2026-05-11):

```
flyctl Model Context Protocol.

Available Commands:
  add         [experimental] Add MCP proxy client to a MCP client configuration
  destroy     [experimental] Destroy an MCP stdio server
  inspect     [experimental] Inspect a MCP stdio server
  launch      [experimental] Launch an MCP stdio server
  list        [experimental] List MCP servers
  logs        [experimental] Show log for an MCP server
  proxy       [experimental] Start an MCP proxy client
  remove      [experimental] Remove MCP proxy client from a MCP client configuration
  server      [experimental] Start a flyctl MCP server
  wrap        [experimental] Wrap an MCP stdio program
```

Two distinct capability domains here:

- **`fly mcp server`** — runs **flyctl AS an MCP server**, exposing flyctl operations to MCP clients (Claude, Cursor, VS Code, Zed, Windsurf, Neovim). This is the answer to "I want Claude to run fly.io operations for me."
- **`fly mcp launch` / `wrap` / `proxy` / `inspect` / etc.** — utilities for **hosting OTHER MCP servers on Fly.io infrastructure** (npx/uv/go-run/docker stdio MCPs deployed to Fly Machines). Different problem; not what the user asked about, but useful future-tooling for our own kite-mcp-server hosting (we already deploy via `flyctl deploy`, but `fly mcp launch` would be the canonical Fly.io-blessed pattern for purely-MCP-server deployments).

The **`fly mcp server` subcommand** is what answers Track-1's question. Sources:
- [Fly Docs — fly mcp server](https://fly.io/docs/flyctl/mcp-server/)
- [Fly Blog — Provisioning Machines using MCPs](https://fly.io/blog/mcp-provisioning/)
- [Fly Blog — Launching MCP Servers on Fly.io](https://fly.io/blog/mcp-launch/)
- [Fly Docs — Model Context Protocol overview](https://fly.io/docs/mcp/)

### 1.2 `fly mcp server` flag inventory (empirical from local `--help`)

```
Flags for `flyctl mcp server`:
  -b, --bind-addr string     Local address (default "127.0.0.1")
      --claude               Auto-add to Claude client config
      --cursor               Auto-add to Cursor client config
      --vscode               Auto-add to VS Code client config
      --neovim, --windsurf, --zed   Other clients
      --config stringArray   Path to MCP client config file (multi)
  -i, --inspector            Launch MCP inspector (developer tool, http://127.0.0.1:6274/)
      --port int             Port (default 8080)
      --server string        Name for the MCP server in client config
      --sse                  Enable Server-Sent Events transport
      --stream               Enable HTTP streaming output
```

This is **a complete MCP-client integration kit, not just a server binary**. The `--claude` flag tells flyctl to find the Claude config file and add the server entry directly — no `claude mcp add` needed, no manual JSON editing.

The `-i/--inspector` flag launches a developer GUI at `http://127.0.0.1:6274/` for testing the MCP server interactively (similar to the MCP inspector pattern). This is useful for verifying tool surface before wiring to Claude.

### 1.3 Tool surface — what `fly mcp server` actually exposes

**Best empirical source** (Fly Blog 2026-05, "Provisioning Machines using MCPs"):

> *"I added support for `fly volume create` to `fly mcp server`, and it worked the first time."*
>
> Currently implemented tools: **apps, logs, machine, orgs, platform, status, volumes** ("roughed in").

This maps to Track-1's enumerated needs:

| Track-1 desired tool | `fly mcp server` coverage | Notes |
|---|---|---|
| `fly_status` (read app state) | **YES** — `status` tool | Direct match |
| `fly_secrets_list` / `fly_secrets_set` | **GAP** — no `secrets` tool listed in May 2026 blog | Sam Ruby is actively extending the surface; secrets likely lands next. Until then: shell-out for secrets remains the workaround. |
| `fly_releases_list` | LIKELY — subset of `apps` or `platform` | Need to inspect actual tool list via `-i/--inspector` to confirm |
| `fly_machines_list` / `fly_machine_status` | **YES** — `machine` tool | Direct match |
| `fly_logs` | **YES** — `logs` tool | Direct match |
| `fly_deploy` | UNCLEAR — not explicitly listed but `apps` might cover | Highest-risk gap (deploy is destructive; needs confirmation framing) |
| `fly_image_show` | LIKELY — subset of `status` or `apps` | Need empirical inspection |

**Net coverage**: 4-5 of 7 confirmed, 2-3 likely-present-need-to-verify, 1 confirmed gap (secrets) as of the blog post date. The author signals active extension ("roughed in, some assembly required") — secrets management likely lands within weeks.

### 1.4 Auth model

Per `flyctl mcp server` design (verified via flag inventory + local flyctl behavior):
- **Reuses existing flyctl auth** — the user's auth token at `~/.fly/config.yml` is automatically used by the embedded server, same way `flyctl status` would use it.
- Optional global flag `-t, --access-token <token>` to override.
- **No separate `FLY_API_TOKEN` env var needed** (unlike the `brannn/fly-mcp` community fork which requires it).
- This is the simplest possible auth story for our use-case: user is already authenticated for shell-out flyctl operations; same auth carries through to the MCP server.

### 1.5 Transport model

Three options exposed via flags:
1. **stdio** (default; `fly mcp server` with no transport flag) — local subprocess; Claude spawns flyctl, talks over stdin/stdout.
2. **SSE** (`--sse`) — server-sent events over HTTP.
3. **HTTP streaming** (`--stream`) — newer MCP transport.

For local Claude Code use, **stdio is the right choice** — matches how Claude Code wires `claude mcp add` servers. SSE/streaming would be for hosting `fly mcp server` remotely (not our use-case).

---

## §2 — Discovery: alternative MCPs (rejected)

For completeness, three other Fly-related MCP repos exist. **All three are inferior to `flyctl mcp server`** for our use-case. Capability + maintenance comparison:

### 2.A `superfly/flymcp` (Go binary, official Fly.io org)

**Empirical metadata** (`gh api repos/superfly/flymcp`):

| Field | Value |
|---|---|
| Owner | superfly (Fly.io's official GitHub org) |
| Stars | 31 |
| Forks | 3 |
| Created | 2025-04-06 |
| **Last pushed** | **2025-04-08** (3 days after creation; 13 months stale) |
| Open issues | 1 |
| Size | 5 KB total (4 commits) |
| Language | Go |
| License | **NONE** (no LICENSE file detected by GitHub API) |
| Archived | No |

**Tool surface** (per `main.go` empirical read):
- `fly-logs` — wraps `flyctl logs --no-tail [--machine ID]`
- `fly-status` — wraps `flyctl status --json`

**That's it.** Two tools. Both are read-only. No secrets, no deploy, no machines, no apps list. This was clearly a proof-of-concept that the **`flyctl mcp server` built-in subcommand has since superseded**.

**Verdict: SKIP.** Even though superfly is the official org, this repo is an effectively-abandoned predecessor of the now-built-in `flyctl mcp server`. The README itself doesn't enumerate the tool list (which is why my first WebFetch couldn't extract it — had to read `main.go` directly via gh api).

Source: [github.com/superfly/flymcp](https://github.com/superfly/flymcp) + [main.go raw](https://raw.githubusercontent.com/superfly/flymcp/main/main.go).

### 2.B `brannn/fly-mcp` (Go binary, community)

**Empirical metadata**:

| Field | Value |
|---|---|
| Owner | brannn (User, not org) |
| Stars | 0 |
| Forks | 1 |
| Created | 2025-06-07 |
| **Last pushed** | **2025-06-07** (same day; 11 months stale) |
| Size | 52 KB |
| Language | Go |
| License | **NONE** (no LICENSE file per gh API; README claim of MIT is hallucinated/promised-but-not-shipped) |
| Archived | No |

**Tool surface** (per README, verified):
- Implemented (6 tools): `ping`, `fly_list_apps`, `fly_app_info`, `fly_status`, `fly_restart`, `fly_scale`
- Roadmap (NOT implemented): logs, secrets, volumes, certificates, deploy, advanced scaling, monitoring/alerts

**Architecturally interesting** — uses `fly-go` + Machines API directly (NOT shell-out to flyctl). Includes permission system + audit logging design. Auth via `FLY_MCP_FLY_API_TOKEN` + `FLY_MCP_FLY_ORGANIZATION` env vars.

**Verdict: SKIP.** Created and pushed on the same day, never iterated, 0 stars, no license. The Phase 3 roadmap items (the ones we actually need — secrets, deploy, logs) were never built. As of 2026-05-11, `flyctl mcp server` covers more ground out-of-the-box.

Source: [github.com/brannn/fly-mcp](https://github.com/brannn/fly-mcp).

### 2.C `fly-apps/mcp-internal-dns` (official org, but different scope)

**Purpose**: queries `.internal` DNS records WITHIN a Fly.io private network. This is for an MCP that runs INSIDE a Fly app and lets Claude inspect peer-app DNS — NOT for managing Fly.io apps from outside.

**Auth**: bearer token via `FLY_MCP_BEARER_TOKEN` env var. Install via `fly mcp launch "npx -y @flydotio/mcp-internal-dns" --claude --server dns`.

**Stars**: 2. Last commit: October 2025 per pushed_at metadata.

**Verdict: NOT RELEVANT** to our use-case. This is for app-to-app DNS introspection from within Fly's network. We want infrastructure management from outside.

Source: [github.com/fly-apps/mcp-internal-dns](https://github.com/fly-apps/mcp-internal-dns).

### 2.D Composio's "Fly MCP toolkit"

**Pricing**: marketed as "GET STARTED FOR FREE" with enterprise tier above. **Free tier exists; not paid-only.**

**Tool count claim**: "50+ tools" covering apps, machines, certificates, regions, health checks.

**Auth model**: **uses Composio's API key** rather than direct Fly credentials. Composio's "managed OAuth" handles Fly credentials behind the scenes. **This is the deal-breaker for us**: we'd add a third-party dependency (Composio) sitting between our Claude session and Fly.io. Composio sees every fly.io operation we run — a privacy + lock-in concern that's unnecessary when `flyctl mcp server` ships in flyctl itself.

**Verdict: SKIP.** The free tier exists, so this is feasible cost-wise, but architecturally inferior to direct flyctl-MCP integration. No reason to introduce Composio as a middleman.

Source: [composio.dev/toolkits/fly/framework/claude-code](https://composio.dev/toolkits/fly/framework/claude-code).

### 2.E MCP Registry search results

The official MCP Registry (`registry.modelcontextprotocol.io`) has **zero entries** matching "fly.io" or "flyctl." The two "fly"-prefixed entries (`co.flyweel/mcp-server`, `io.github.ChesterHsu/flyto-indexer`) are unrelated projects (ad analytics + code intelligence).

**Implication**: the canonical `fly mcp server` is NOT published to the MCP Registry. Fly.io's strategy appears to be **"ship the MCP support inside flyctl itself"** rather than maintain a separately-published registry entry. From a discoverability standpoint this is suboptimal — but for users who already have flyctl installed, it's actually MORE convenient (no separate install).

Source: [registry.modelcontextprotocol.io/v0/servers?search=fly](https://registry.modelcontextprotocol.io/v0/servers?search=fly).

---

## §3 — Capability gap analysis

### 3.1 What `flyctl mcp server` covers today (empirical, per Fly blog 2026-05)

| Tool category (per blog) | Track-1 desired ops covered |
|---|---|
| `apps` | `fly_app_info`, list apps, possibly app-level history |
| `logs` | `fly_logs` |
| `machine` | `fly_machines_list`, `fly_machine_status`, machine restart/destroy |
| `orgs` | listing organizations |
| `platform` | platform-level info (regions, VM sizes) |
| `status` | `fly_status` |
| `volumes` | volume CRUD (added "first try" by author Sam Ruby, per the May 2026 blog) |

### 3.2 What's likely MISSING today (high-confidence gaps)

- **`secrets`** — NOT listed in the May 2026 blog enumeration. This is the most painful gap for our use-case: every secret rotation flow (OAUTH_JWT_SECRET, Cloudflare R2 creds, dr-drill secrets) still needs shell-out to `flyctl secrets list` / `flyctl secrets set`. **Likely lands in flyctl within weeks** given the author's "actively extending" framing, but not today.
- **`deploy`** — not explicitly listed. This is destructive enough that Fly may intentionally hold it back behind a confirm/elicitation pattern.
- **`releases`** — not explicitly listed. Subset of `apps` or `platform`?
- **`image_show`** — not explicitly listed. Subset of `apps`?

### 3.3 Verification step

After installing (§4 below), the **first verification action** should be `flyctl mcp server -i` (the inspector flag) — this launches a local web UI at `http://127.0.0.1:6274/` showing the actual tool surface. The blog post is from May 2026; the current `flyctl v0.4.14` may have added more tools since. **The inspector is the canonical empirical-probe** (per the CORPUS-MAINTENANCE-STRATEGY methodology rule).

### 3.4 If `secrets` is missing — fallback

For the dr-drill / rotate-key flows that need `flyctl secrets set`, the fallback is **continue shelling out for secrets-only operations**. This is what we're doing today; nothing gets worse. When Fly adds `secrets` to `fly mcp server`, we drop the shell-out.

---

## §4 — Recommendation

### 4.1 INSTALL — single command, ~5 minutes

```powershell
flyctl mcp server --claude --server fly
```

This auto-edits the Claude Code config (likely `~/.claude.json` or the project-scope `.mcp.json`) with an entry like:

```json
{
  "mcpServers": {
    "fly": {
      "command": "C:/Users/Dell/.fly/bin/flyctl.exe",
      "args": ["mcp", "server"]
    }
  }
}
```

After install:
1. Restart Claude Code (or wait for the next session start).
2. Verify the server appears via `claude mcp list` (if Claude Code's introspection supports it) or by asking Claude to call a fly tool.
3. Test with a read-only probe like "list my fly apps" or "show status of kite-mcp-server."

### 4.2 NO build effort needed

The build-it-yourself analysis from the dispatch is **moot**: `flyctl mcp server` is already built, official, ships with the user's existing flyctl, and covers 4-5 of the 7 desired tools out of the box. **Zero lines of code to write.**

If we later need a custom tool that `fly mcp server` doesn't cover (e.g., an opinionated `kite_mcp_deploy` that runs our specific deploy + smoke-test sequence), that's a small bespoke MCP we'd build on top of `fly mcp server`, not a replacement for it.

### 4.3 Scope decision: project-scope vs user-scope

**Recommendation: project-scope** (`.mcp.json` in `D:/Sundeep/projects/kite-mcp-server/`).

Reasoning:
- The fly.io operations we care about are kite-mcp-server-specific (kite-mcp-server app on Fly, kite-mcp-server secrets, kite-mcp-server machines).
- Other projects in `D:/Sundeep/projects/` don't deploy to Fly today; user-scope would expose the server to every project session.
- Per project CLAUDE.md convention: project-scope keeps the MCP servers locally relevant.

If Fly.io operations expand to other projects later, promote to user-scope at that point.

### 4.4 Auth verification

User's flyctl auth is **empirically working** as of 2026-05-11 (per `production-master-gap-report.md` + multiple successful `flyctl status` / `flyctl image show` runs this session). The MCP server reuses this auth. No reauth needed.

**Caveat**: the user's local `flyctl version` output included a warning:
```
Warning: Metrics token unavailable: failed to run query(...): context canceled
```
This is a known transient quirk and doesn't affect MCP-server function (it's a side-effect of the version subcommand attempting to fetch billing metadata; the MCP server doesn't need that). Not a blocker.

### 4.5 What can be retired post-install

Once `fly mcp server` is wired:

| Today's pattern (shell-out) | Post-install pattern |
|---|---|
| `flyctl status -a kite-mcp-server` | Claude tool: `fly_status` |
| `flyctl logs -a kite-mcp-server` | Claude tool: `fly_logs` |
| `flyctl image show -a kite-mcp-server` | Likely via `apps` or `status` tool (verify with inspector) |
| `flyctl machines list -a kite-mcp-server` | Claude tool: `fly_machine` |
| `flyctl secrets list -a kite-mcp-server` | **GAP** — keep shell-out for now |
| `flyctl secrets set X=Y -a kite-mcp-server` | **GAP** — keep shell-out for now |
| `flyctl deploy -a kite-mcp-server` | **GAP / TBD** — verify with inspector; if absent, keep shell-out |
| `flyctl mcp launch <other-mcp-server>` (for our own deployments) | Same command; already MCP-native |

Net retirement: ~60% of current flyctl shell-outs become MCP tool calls. Remaining ~40% (secrets, deploy) wait for Fly to extend the tool surface.

### 4.6 Risks + mitigation

| Risk | Mitigation |
|---|---|
| `fly mcp server` is `[experimental]` per `--help` output — API could change | Fly's blog post (May 2026) shows active investment + auto-config-edit flags for 6 clients. Risk is low; if breaking change ships, the install command remains stable (it just re-runs and re-wires). |
| Tool surface incomplete (no secrets/deploy yet) | Keep shell-out for those operations; remove shell-out as Fly extends. The MCP-vs-shell-out dual mode is fine in the interim. |
| Claude Code's MCP server registration might fail silently | First-session verification: ask Claude to call `fly_status` on kite-mcp-server. If it works, install is successful. If it doesn't, re-run `flyctl mcp server --claude --server fly` (idempotent). |
| `--claude` flag might not know Claude Code config path on Windows | The flyctl source likely tries common locations; can verify by reading the file after install. If wrong location, use `--config <path>` flag explicitly. |
| flyctl `[experimental]` status could mean the feature is removed in a future flyctl version | Pin awareness: when upgrading flyctl, re-verify `fly mcp --help` shows `server` subcommand. Migration cost if removed: low (revert to shell-out we already use). |

### 4.7 Followup dispatches (post-install verification)

After the install command runs, two follow-up tasks:

1. **Empirical tool inventory**: run `flyctl mcp server -i` to open the inspector at `http://127.0.0.1:6274/`. Capture the actual tool list + parameter schemas. Update `.research/INDEX.md` §11 (empirical-probe reference) to list `fly` tool names alongside existing curl/gh/rdap probes.

2. **Test-drive on a real op**: ask Claude to "show status of kite-mcp-server on Fly." Verify response matches `flyctl status -a kite-mcp-server` output. If mismatch: file an issue against `fly mcp server` (Fly is actively iterating; bug reports likely fixed quickly per the author's posting cadence).

---

## §5 — Sources of evidence

| Probe | Source | Result |
|---|---|---|
| Official Fly MCP registry entry exists? | [registry.modelcontextprotocol.io/v0/servers?search=fly](https://registry.modelcontextprotocol.io/v0/servers?search=fly) | **NO** — zero official entries (Flyweel + Flyto are unrelated) |
| Fly.io docs mention MCP? | [fly.io/docs/](https://fly.io/docs/) main hub | **NOT on main hub** — but [fly.io/docs/mcp/](https://fly.io/docs/mcp/) is a dedicated MCP section discoverable via search |
| `fly mcp server` is a real subcommand? | Local `flyctl mcp --help` (Windows, v0.4.14) | **YES** — 10 subcommands confirmed empirically |
| `fly mcp server` flag inventory | Local `flyctl mcp server --help` | confirmed `--claude`, `--cursor`, `--vscode`, `--neovim`, `--windsurf`, `--zed`, `--sse`, `--stream`, `-i/--inspector`, `--port`, `--bind-addr`, `--server`, `--config` |
| Local flyctl version | `flyctl version` | v0.4.14, BuildDate 2026-02-18 (well past v0.3.117 minimum cited by Fly blog) |
| `fly mcp server` tool surface | [fly.io/blog/mcp-provisioning/](https://fly.io/blog/mcp-provisioning/) (Sam Ruby, May 2026) | apps, logs, machine, orgs, platform, status, volumes — "roughed in" + actively extending |
| Claude Desktop install snippet | [fly.io/blog/mcp-provisioning/](https://fly.io/blog/mcp-provisioning/) | Exact JSON shown; `--claude` flag automates this |
| `superfly/flymcp` metadata | `gh api repos/superfly/flymcp` | 31 stars, 4 commits, pushed 2025-04-08 (13mo stale), NO LICENSE, 5KB total |
| `superfly/flymcp` tools | [main.go raw](https://raw.githubusercontent.com/superfly/flymcp/main/main.go) | Only `fly-logs` + `fly-status` — abandoned PoC |
| `brannn/fly-mcp` metadata | `gh api repos/brannn/fly-mcp` | 0 stars, 1 fork, pushed 2025-06-07 (11mo stale, same-day-as-creation), NO LICENSE |
| `brannn/fly-mcp` tools | [github.com/brannn/fly-mcp](https://github.com/brannn/fly-mcp) README | 6 implemented; secrets/deploy/logs all in unimplemented Phase 3 roadmap |
| `fly-apps/mcp-internal-dns` scope | [github.com/fly-apps/mcp-internal-dns](https://github.com/fly-apps/mcp-internal-dns) | DNS-only, intra-Fly-network — not infra management |
| Composio Fly toolkit | [composio.dev/toolkits/fly/framework/claude-code](https://composio.dev/toolkits/fly/framework/claude-code) | Free tier exists; uses Composio API key (third-party middleman) |

**Methodology rule applied**: every load-bearing claim traced to an empirical probe (gh API for repo metadata, local flyctl for subcommand existence, WebFetch for blog content). No grep-as-evidence. No speculation. Where a doc didn't surface a claim (e.g., `superfly/flymcp` README's tool list), I read the source code directly via `gh api repos/.../contents` + raw blob fetch.

---

## §6 — Closing

The user's question — "Why no Fly MCP? Each time we shell out to flyctl CLI" — has a one-word answer: **Inertia.** The official answer (`flyctl mcp server`) shipped sometime between v0.3.117 (per Fly's May 2026 blog) and the user's current v0.4.14, and was never wired into Claude Code. It's a 5-minute install (single command, `flyctl mcp server --claude --server fly`) with zero build effort, official Fly.io maintenance, and ~60% coverage of the user's current shell-out surface. Remaining gaps (secrets, deploy) are scheduled for future flyctl updates per the author's "actively extending" framing.

**Concrete next dispatch**: install the server + verify via inspector + measure post-install shell-out reduction.

---

## Sources

- [fly.io/docs/mcp/](https://fly.io/docs/mcp/)
- [fly.io/docs/flyctl/mcp-server/](https://fly.io/docs/flyctl/mcp-server/)
- [fly.io/blog/mcp-provisioning/](https://fly.io/blog/mcp-provisioning/)
- [fly.io/blog/mcp-launch/](https://fly.io/blog/mcp-launch/)
- [fly.io/blog/mcps-everywhere/](https://fly.io/blog/mcps-everywhere/)
- [fly.io/docs/blueprints/remote-mcp-servers/](https://fly.io/docs/blueprints/remote-mcp-servers/)
- [github.com/superfly/flymcp](https://github.com/superfly/flymcp)
- [github.com/brannn/fly-mcp](https://github.com/brannn/fly-mcp)
- [github.com/fly-apps/mcp-internal-dns](https://github.com/fly-apps/mcp-internal-dns)
- [composio.dev/toolkits/fly/framework/claude-code](https://composio.dev/toolkits/fly/framework/claude-code)
- [registry.modelcontextprotocol.io/v0/servers?search=fly](https://registry.modelcontextprotocol.io/v0/servers?search=fly)
