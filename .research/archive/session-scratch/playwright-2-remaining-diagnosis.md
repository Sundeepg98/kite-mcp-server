# Playwright E2E — Remaining 2 Failures Diagnosis

**HEAD**: `017366f` (fix(e2e): /auth/login skip when OAuth unconfigured)
**Date**: 2026-05-02
**Scope**: Diagnosis-only. No code or test edits. Per-failure verdict + recommended action.

## TL;DR

| # | Failure | Verdict | Action | Pre/Post launch |
|---|---------|---------|--------|-----------------|
| 1 | server-card identity field | **MCP SPEC AMBIGUITY** — handler is SEP-1649-correct (nested `serverInfo.name`); test was written for SEP-2127-style flat `name`. Both interpretations are defensible. | **STALE TEST** — relax assertion to also accept `body.serverInfo?.name`. ~5 min fix in test only. | Post-launch (defer with TODO) |
| 2 | `/mcp` POST `tools/list` returns 404 | **TRANSPORT SHAPE** — `/mcp` is a streamable-HTTP MCP endpoint that REQUIRES the `initialize` handshake first. The 404 (`"Invalid session ID"`) is upstream mcp-go library behavior at `streamable_http.go:389`, NOT a bug or auth gate. Test sends a single `tools/list` POST without prior `initialize` — that can never succeed against a session-based transport. | **STALE TEST** — rewrite test to do `initialize` → capture `Mcp-Session-Id` header → `notifications/initialized` → `tools/list`. ~30-45 min. Or `test.fixme` with TODO. | Post-launch (defer with TODO) |

Neither is a real-bug shipping blocker. Both are test-side issues that don't reflect a regression in the live wire surface. Show-HN can ship; tests can be fixed in follow-up.

---

## Failure 1 — `tests/e2e/specs/server-card.spec.ts:31`

### What the test asserts (lines 28-31)

```ts
const hasIdentity =
  'name' in body || 'server_name' in body || 'id' in body;
expect(hasIdentity, 'server card has identity field (name/server_name/id)')
  .toBe(true);
```

The test checks for one of three TOP-LEVEL keys: `name` / `server_name` / `id`.

### What the handler actually returns

`app/http.go:325-358` registers `/.well-known/mcp/server-card.json`. The handler emits:

```json
{
  "$schema": "https://modelcontextprotocol.io/schemas/server-card/v1.0",
  "version": "1.0",
  "protocolVersion": "2025-06-18",
  "serverInfo": {
    "name": "Kite Trading MCP Server",
    "version": "v0.0.0",
    "description": "Indian stock market trading via Zerodha Kite Connect. 111 tools …",
    "homepage": "https://github.com/Sundeepg98/kite-mcp-server"
  },
  "transport": { "type": "streamable-http", "url": "/mcp" },
  "capabilities": { "tools": true, "resources": true, "prompts": true },
  "authentication": { "required": true, "schemes": ["oauth2"] }
}
```

Empirical capture confirmed via `curl -s http://127.0.0.1:8080/.well-known/mcp/server-card.json` against a freshly-built `017366f` binary running in WSL2 (DEV_MODE=true, no OAuth env). Top-level keys: `$schema`, `version`, `protocolVersion`, `serverInfo`, `transport`, `capabilities`, `authentication`.

NONE of `name`, `server_name`, `id` appear at top level. Identity is at `serverInfo.name`.

### MCP spec analysis

Two competing proposals govern this endpoint shape:

- **SEP-1649** (`/.well-known/mcp/server-card.json`, schema URL `https://modelcontextprotocol.io/schemas/server-card/v1.0`):
  Nests identity under `serverInfo.{name, version, description, homepage}`. The handler explicitly references this schema URL via `$schema` and matches it byte-for-byte.
  - Confirmed via SEP-1649 issue ([#1649](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/1649)) and the Ekamoira 2026 implementation guide.
- **SEP-2127** (PR-stage refinement, [#2127](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2127)):
  Promotes `name` to top level (e.g. `"name": "io.modelcontextprotocol.anonymous/brave-search"`) for reverse-DNS namespacing alignment with the MCP Registry's `server.json`. Still in flight, not finalised.

### Verdict

**MCP SPEC AMBIGUITY** masquerading as a stale test. The handler is SEP-1649-correct (which is what the schema URL it advertises says). The test was written against SEP-2127's draft shape (or against a generic registry-friendly assumption that any JSON manifest exposes a top-level `name`).

### Recommendation

**STALE TEST — relax the assertion.** Suggested change (NOT applied per the doc-only constraint):

```ts
const hasIdentity =
  'name' in body ||
  'server_name' in body ||
  'id' in body ||
  (typeof body.serverInfo === 'object' && body.serverInfo !== null && 'name' in body.serverInfo);
```

This accepts both the SEP-1649 nested shape (current handler) and a future SEP-2127 flat-name shape, without picking a winner before the spec converges.

**Estimated fix time**: ~5 minutes (single test file, single assertion).

**Pre/post launch**: **POST-LAUNCH**. Failing E2E here doesn't block Show HN — registries that crawl `/.well-known/mcp/server-card.json` (mcp-find, awesome-mcp-servers, official MCP Registry) all key off `serverInfo.name` per SEP-1649, which is what we already serve.

---

## Failure 2 — `tests/e2e/specs/tool-surface.spec.ts:83`

### What the test asserts (lines 53-83)

The test posts to `/mcp` with:

```http
POST /mcp HTTP/1.1
Content-Type: application/json
Accept: application/json, text/event-stream

{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}
```

It expects `status === 200` (lines 70-83), unless 401/403 (then it skips, treating it as auth-required).

### What the handler actually returns

Empirical capture (CI-style boot: `DEV_MODE=true`, no `OAUTH_JWT_SECRET`/`KITE_API_KEY`/`KITE_API_SECRET`, OAuth handler nil, `/mcp` registered without `RequireAuth` per `app/http.go:1240`):

```http
HTTP/1.1 404 Not Found
Content-Type: text/plain; charset=utf-8

Invalid session ID
```

### Why 404 (not 401, not 200)

`/mcp` is the streamable-HTTP MCP transport, served by `mcp-go`'s `server.StreamableHTTPServer` (`app/http.go:1063-1069`). The transport is **session-based** per the MCP streamable-HTTP protocol (rev `2025-06-18`):

1. Client POSTs `initialize` (no session header required).
2. Server allocates a session, returns `Mcp-Session-Id: <uuid>` response header alongside the JSON-RPC result.
3. ALL subsequent calls (including `tools/list`, `notifications/initialized`, `tools/call`, etc.) MUST include `Mcp-Session-Id: <uuid>`.
4. If the header is absent or unknown, the server returns `404 Not Found` with body `"Invalid session ID"`.

Confirmed at the library level. From `~/go/pkg/mod/github.com/mark3labs/mcp-go@v0.46.0/server/streamable_http.go:387-394`:

```go
isTerminated, err := sessionIdManager.Validate(sessionID)
if err != nil {
    http.Error(w, "Invalid session ID", http.StatusNotFound)
    return
}
if isTerminated {
    http.Error(w, "Session terminated", http.StatusNotFound)
    return
}
```

This is upstream mcp-go behavior. Our handler chain (`rateLimit → mcpHandler → streamable.ServeHTTP`) doesn't intercept; the 404 surfaces unchanged.

### Empirical confirmation of the full handshake

Same WSL2 server, scripted handshake:

```
POST /mcp { jsonrpc, id:1, method:"initialize", … }
→ 200 OK, Mcp-Session-Id: kitemcp-7504fb65-…

POST /mcp { jsonrpc, method:"notifications/initialized" }  + Mcp-Session-Id
→ 202 Accepted

POST /mcp { jsonrpc, id:2, method:"tools/list", params:{} }  + Mcp-Session-Id
→ 200 OK, full tools array
```

So the live server IS healthy. The test is just dispatching the wrong protocol shape.

### Cross-check: the Go-side E2E test does it correctly

`mcp/e2e_roundtrip_test.go:178-236` (`TestE2E_RoundtripInitializeAndToolsList`) explicitly performs `initialize` → `notifications/initialized` → `tools/list` over stdio. It carries the same surface lock contract (verifying `get_holdings` is present) but does so correctly. The Playwright spec's HTTP variant skipped that handshake.

### Verdict

**TRANSPORT SHAPE** mismatch. `tools/list` over plain HTTP without prior `initialize` cannot succeed against an MCP streamable-HTTP transport. The test's design is incompatible with the protocol. Not a server bug, not an auth gate, not an OAuth interaction — purely a test-side protocol mistake.

### Recommendation

**STALE TEST — rewrite the spec to perform a 3-step handshake** (NOT applied per the doc-only constraint):

```ts
// 1. POST initialize, capture Mcp-Session-Id from response headers.
const initRes = await request.post('/mcp', {
  data: { jsonrpc: '2.0', id: 1, method: 'initialize',
          params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'e2e', version: '1' } } },
  headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' },
});
const sid = initRes.headers()['mcp-session-id'];
expect(sid, 'session id allocated').toBeTruthy();

// 2. POST notifications/initialized (returns 202, no body).
await request.post('/mcp', {
  data: { jsonrpc: '2.0', method: 'notifications/initialized' },
  headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', 'Mcp-Session-Id': sid },
});

// 3. POST tools/list with the session id; assert hash as before.
const listRes = await request.post('/mcp', {
  data: { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} },
  headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', 'Mcp-Session-Id': sid },
});
expect(listRes.status()).toBe(200);
// … existing hash logic unchanged …
```

**Alternative**: `test.fixme` with TODO citing this doc, defer the rewrite. Keeps Go-side `tool_surface_lock_test.go` and `mcp/e2e_roundtrip_test.go` as the binding contracts (both run in CI today).

**Estimated fix time**: ~30-45 minutes (one test file; the latency-budget sub-test at line 125 needs the same handshake refactor).

**Pre/post launch**: **POST-LAUNCH**. The Go-side surface lock (`mcp/tool_surface_lock_test.go`) and the Go-side E2E roundtrip (`mcp/e2e_roundtrip_test.go`) ALREADY pin the same contract correctly. The Playwright spec is duplicate coverage that's currently broken by protocol mismatch — the actual wire is healthy and the contract is enforced.

---

## Out-of-band notes

- Build SHA used for empirical reproduction: `017366f` (clean, no local edits to source/tests).
- Build env: WSL2 Ubuntu, `go1.25.8 linux/amd64`, `go build -o /tmp/kite-mcp-server .`
- Server boot: `DEV_MODE=true BIND_ADDR=127.0.0.1:8080`, no OAuth/Kite/Telegram env. `/mcp` served by `streamable.ServeHTTP` directly via `app/http.go:1240` (no `RequireAuth` wrap, OAuth handler nil).
- Confirmed `/healthz` returned 200, `/.well-known/mcp/server-card.json` returned 200 with documented body, `/mcp` POST `initialize` returned 200 with `Mcp-Session-Id` header — the live server is healthy on every dimension the tests touch.
- `/mcp` GET (no session) returned `405 Method Not Allowed` (not shown in trace; consistent with mcp-go's POST-only POST-routes-by-method dispatch).

## Sources

- [SEP-1649: MCP Server Cards (issue)](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/1649) — defines the SEP-1649 server-card schema with `serverInfo.{name,version}` nesting.
- [SEP-2127: MCP Server Cards PR](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2127) — proposes top-level `name` for reverse-DNS namespacing.
- [Ekamoira: MCP Server Discovery 2026 Guide](https://www.ekamoira.com/blog/mcp-server-discovery-implement-well-known-mcp-json-2026-guide) — implementation guide showing both SEP-1649 nested and SEP-1960 manifest shapes.
- mcp-go upstream session-validation: `github.com/mark3labs/mcp-go@v0.46.0/server/streamable_http.go:387-394` (404 + "Invalid session ID" for missing/unknown session header).
- Go-side correct E2E reference: `mcp/e2e_roundtrip_test.go:178-236` (`TestE2E_RoundtripInitializeAndToolsList`).
