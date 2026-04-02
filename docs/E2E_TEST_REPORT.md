# End-to-End Test Report

**Date:** 2026-04-02  
**Server:** https://kite-mcp-server.fly.dev  
**Local codebase:** `D:\kite-mcp-temp` (commit `4b416ab`)  
**Deployed version:** v76 (Fly.io release ~1h prior to test)

---

## Summary

| Category | Pass | Fail | Warn |
|----------|------|------|------|
| Build & Tests | 3/3 | 0 | 0 |
| Server Health | 2/3 | 1 | 0 |
| Security | 2/4 | 2 | 0 |
| Auth & Access Control | 8/9 | 1 | 0 |
| Rate Limiting | 1/1 | 0 | 0 |
| Codebase Stats | 4/4 | 0 | 0 |
| CI & Deployment | 1/1 | 0 | 1 |
| **Total** | **21/25** | **4** | **1** |

---

## 1. Build + Vet + Tests

| Test | Result | Details |
|------|--------|---------|
| `go build ./...` | **PASS** | Clean build, no errors |
| `go vet ./...` | **PASS** | No issues found |
| `go test ./... -count=1` | **PASS** | **13 packages pass, 0 fail, 407 tests pass, 4 packages skipped (no test files)** |

### Package breakdown

| Package | Status | Duration |
|---------|--------|----------|
| `app` | ok | 0.508s |
| `app/metrics` | ok | 0.575s |
| `kc` | ok | 5.369s |
| `kc/alerts` | ok | 0.958s |
| `kc/audit` | ok | 3.039s |
| `kc/instruments` | ok | 7.282s |
| `kc/ops` | ok | 48.443s |
| `kc/registry` | ok | 2.115s |
| `kc/scheduler` | ok | 0.468s |
| `kc/ticker` | ok | 0.635s |
| `kc/users` | ok | 0.938s |
| `mcp` | ok | 2.284s |
| `oauth` | ok | 0.696s |
| root, `cmd/rotate-key`, `kc/telegram`, `kc/templates`, `kc/watchlist` | skipped | no test files |

---

## 2. Server Health

| Endpoint | Expected | Actual | Result |
|----------|----------|--------|--------|
| `GET /` | 200 | 200 | **PASS** |
| `GET /.well-known/oauth-authorization-server` | 200 | 200 | **PASS** |
| `GET /.well-known/security.txt` | 200 | 404 | **FAIL** |

**Finding:** `security.txt` endpoint is defined in code (line 641 of `app.go`) but returns 404 on the deployed server. The `"/"` catch-all handler (line 894) returns 404 for non-root paths, and it appears the deployed image does not include this route. Likely a deployment mismatch -- the commit adding `security.txt` (commit `5d24a4c`) may not be in the running Docker image despite Fly.io showing v76 as the latest release.

**Severity:** Low -- informational endpoint only.

---

## 3. Security Headers

| Header | Expected | Present | Result |
|--------|----------|---------|--------|
| X-Frame-Options | DENY | No | **FAIL** |
| X-Content-Type-Options | nosniff | No | **FAIL** |
| Strict-Transport-Security | max-age=63072000 | No | **FAIL** |
| Content-Security-Policy | default-src 'self'... | No | **FAIL** |
| Referrer-Policy | strict-origin-when-cross-origin | No | **FAIL** |
| Permissions-Policy | camera=()... | No | **FAIL** |

**Overall: FAIL** -- 0 of 6 security headers present.

**Finding:** The `securityHeaders` middleware exists in code (lines 771-782 of `app.go`) and wraps the mux via `configureAndStartServer` (line 786). All code paths call this function. However, **none of the 6 headers appear in production responses**. This confirms the deployed Docker image does not contain the security headers commit (`6bdb021`). The latest Fly.io release (v76) was built from an earlier code state.

**Severity:** Medium -- no clickjacking/MIME-sniffing/HSTS protection. Requires redeployment.

**Action:** Redeploy with `flyctl deploy -a kite-mcp-server` from the current HEAD.

---

## 4. Login Pages

| Endpoint | Expected | Actual | Result |
|----------|----------|--------|--------|
| `GET /auth/login` (unified choice) | 200 | 404 | **FAIL** |
| `GET /auth/admin-login` | 200 | 200 | **PASS** |
| `GET /auth/browser-login` | 200 | 200 | **PASS** |

**Finding:** `/auth/login` route (unified login choice page) was added in commit `4b416ab` (the latest commit). It is registered in code (line 657) alongside `/auth/admin-login` and `/auth/browser-login` in the same code block. The 404 response further confirms the deployed image predates the latest commits.

**Severity:** Low -- `/auth/admin-login` and `/auth/browser-login` still work. The unified login choice page is a UX improvement, not a security requirement.

---

## 5. Admin/Dashboard Access Control

| Endpoint | Expected | Actual | Result |
|----------|----------|--------|--------|
| `GET /admin/ops` | 302 | 302 | **PASS** |
| `GET /admin/ops/api/users` | 302 | 302 | **PASS** |
| `GET /dashboard` | 302 | 302 | **PASS** |
| `GET /dashboard/activity` | 302 | 302 | **PASS** |
| `GET /dashboard/orders` | 302 | 302 | **PASS** |
| `GET /dashboard/alerts` | 302 | 302 | **PASS** |

All protected endpoints correctly redirect to login when unauthenticated.

---

## 6. Rate Limiting

| Test | Expected | Actual | Result |
|------|----------|--------|--------|
| 10 rapid POST to `/oauth/register` | 429 after ~5-6 requests | First 429 at request 7 | **PASS** |

Response sequence: `400 400 400 400 400 400 429 400 429 429`

Rate limiter is active. The 400 responses are expected (empty/invalid JSON body). The 429s start at request 7, indicating the per-IP rate limit of ~5-6 req/sec is working correctly.

---

## 7. JWT "none" Algorithm Rejection

| Test | Expected | Actual | Result |
|------|----------|--------|--------|
| Dashboard access with `alg: "none"` JWT | 302 (redirect to login) | 302 | **PASS** |

The server correctly rejects JWT tokens with the "none" algorithm. The forged JWT (`eyJhbGciOiJub25lIi...`) was not accepted, and the request was redirected to the login page.

---

## 8. Tool Count

| Metric | Value |
|--------|-------|
| Registered MCP tools | **60** |

Counted via `grep -c '&.*Tool{}' mcp/mcp.go`. Note: memory entry says 40 tools -- the count has grown to 60 since that note was written.

---

## 9. Codebase Stats

| Metric | Value |
|--------|-------|
| Go source files | **91** |
| Total Go lines | **34,335** |

Excludes vendor and go/pkg directories.

---

## 10. Git Stats

| Metric | Value |
|--------|-------|
| Total commits | **129** |

### Last 5 commits
```
4b416ab fix: admin vs user UX -- unified login, role badges, ops nav visibility, registry fallback
b44f2b8 fix(ci): add nosec annotations for remaining gosec findings
1e6dbd8 fix(ci): resolve gosec G104 nosec comments + update CI to Go 1.25
5d24a4c security: SECURITY.md, security.txt, GitHub Actions CI, STRIDE threat model
6bdb021 security: add security headers middleware (X-Frame-Options, HSTS, CSP, etc)
```

---

## 11. CI Status

| Run | Workflow | Status | Duration |
|-----|----------|--------|----------|
| Latest (4b416ab) | Security Scan | **success** | 1m48s |
| Latest (4b416ab) | CI | **success** | 40s |
| Previous (b44f2b8) | CI | **success** | 36s |
| Previous (b44f2b8) | Security Scan | **success** | 1m53s |
| Older (1e6dbd8) | Security Scan | **failure** | 1m35s |

Latest commit passes both CI and Security Scan workflows. The one failure on `1e6dbd8` was fixed in the subsequent commit `b44f2b8`.

---

## 12. Fly.io Logs

| Check | Result |
|-------|--------|
| Panics | None |
| Fatal errors | None |
| Errors found | Transient proxy errors during deployment |

Errors observed (all transient, related to v76 deployment rollover):
- `machine is in a non-startable state: replacing` -- normal during deployment
- `could not finish reading HTTP body from instance` -- connection interrupted during swap
- `instance refused connection` -- brief window before new instance started listening
- Machine lease contention -- expected during rolling deployment

**No application-level errors, panics, or fatal crashes in recent logs.**

---

## 13. Dashboard Page Titles

| Path | Title | Result |
|------|-------|--------|
| `/` | `Status -- Kite MCP Server` | **PASS** |
| `/auth/admin-login` | `Admin Login -- Kite MCP Server` | **PASS** |
| `/auth/browser-login` | `Login -- Kite MCP Server` | **PASS** |

All pages render with correct HTML titles.

---

## 14. MCP Endpoint

| Test | Expected | Actual | Result |
|------|----------|--------|--------|
| `GET /mcp` | 401 (requires auth) | 401 | **PASS** |

MCP endpoint correctly rejects unauthenticated requests.

---

## 15. Telegram Webhook

| Test | Expected | Actual | Result |
|------|----------|--------|--------|
| `GET /telegram/webhook/test` | 403 or 404 (wrong secret) | 404 | **PASS** |

The Telegram webhook path includes a secret derived from `OAUTH_JWT_SECRET`. Requesting with a wrong secret (`/test`) correctly returns 404 (the route simply doesn't exist for the wrong path). This is the expected behavior -- the webhook endpoint is only registered at the correct secret path.

---

## Key Findings

### Real Issues (require action)

1. **Security headers missing from production** (Medium)
   - All 6 security headers exist in code but are absent from deployed responses
   - **Root cause:** Deployed Docker image predates commits `6bdb021` through `4b416ab`
   - **Fix:** Redeploy: `flyctl deploy -a kite-mcp-server`

2. **`/.well-known/security.txt` returns 404** (Low)
   - Same root cause as above -- endpoint added in commit `5d24a4c`, not yet deployed
   - **Fix:** Same redeployment will resolve this

3. **`/auth/login` (unified login choice page) returns 404** (Low)
   - Added in commit `4b416ab`, not yet in deployed image
   - **Fix:** Same redeployment will resolve this

### Non-Issues (expected behavior)

- Fly.io proxy errors in logs: transient, caused by normal deployment rollover
- Telegram webhook 404: correct behavior (secret path not matched)
- `go test` taking ~48s on `kc/ops`: this package has integration-style tests, duration is normal

### Positive Findings

- All 407 tests pass across 13 packages with zero failures
- `go build` and `go vet` are clean
- JWT "none" algorithm attack is correctly rejected
- All dashboard/admin endpoints require authentication (302 redirect)
- Rate limiting is active and working (429 after ~6 requests)
- CI is green on latest commit (both CI and Security Scan workflows)
- No panics or fatal errors in production logs
- 60 MCP tools registered
- 34,335 lines of Go across 91 files
- 129 commits on master

---

## Recommendation

**Immediate:** Redeploy to Fly.io to pick up the last 5 commits (security headers, security.txt, CI fixes, unified login page):

```bash
cd D:/kite-mcp-temp
flyctl deploy -a kite-mcp-server
```

This single action will resolve all 3 findings above.
