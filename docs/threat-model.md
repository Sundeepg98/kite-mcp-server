# Threat Model — kite-mcp-server

*Last reviewed: 2026-04-26*
*Methodology: STRIDE per asset / data flow*
*Scope: hosted Fly.io instance + self-host fork; excludes Kite Connect upstream and MCP client devices*

---

## 1. System view

```
┌──────────────────┐     OAuth bearer JWT (24h)    ┌─────────────────────┐
│  MCP Client      │ ───────────────────────────► │  kite-mcp-server    │
│  (Claude/ChatGPT)│                              │  (Fly.io / self)    │
└──────────────────┘                              └──────┬──────────────┘
                                                          │
                              Stripe webhook              │
                                  │                        ▼
                                  │              ┌──────────────────┐
                                  │              │  SQLite (alerts.db)
                                  │              │  encrypted-at-rest
                                  │              └──────┬───────────┘
                                  │                      │
                                  │             Litestream WAL ship
                                  │                      ▼
                                  │              ┌──────────────────┐
                                  ▼              │  Cloudflare R2   │
                          ┌──────────────┐       └──────────────────┘
                          │  Stripe API  │
                          └──────────────┘                      
                                  ▲
                                  │
                                  │       Kite Connect API
                                  └──────────────────────► kite.zerodha.com
```

## 2. Trust boundaries

| Boundary | Crossed by | Authentication |
|---|---|---|
| MCP client ↔ server | OAuth tool calls + dashboard SSO | OAuth bearer JWT (24h); cookie SSO (7d); per-IP rate-limited |
| Server ↔ Stripe | Stripe webhook events | Stripe-Signature HMAC verification |
| Server ↔ Kite Connect | Per-user OAuth flow | Per-user Kite developer credentials (AES-256-GCM encrypted at rest) |
| Server ↔ R2 | Litestream replication + DR drill restore | R2 access-key-id + secret-key; secrets never logged |
| Server internal: tool handler ↔ broker port | Composite Client interface | Compile-time type assertions; runtime call-stack via middleware |

## 3. Asset catalogue (T1 = highly sensitive per `docs/data-classification.md`)

| Asset | Tier | Storage | Lifecycle |
|---|---|---|---|
| Kite API key + secret | T1 | `kite_credentials` table, AES-256-GCM | Until consent withdraw or account delete |
| Kite access token | T1 | `kite_tokens` table, AES-256-GCM | Daily Kite expiry (~06:00 IST) |
| OAuth client credentials | T1 | `oauth_clients` table, AES-256-GCM | Until client revoke |
| Dashboard SSO bcrypt | T1 | `users.password_hash` | Until account delete |
| Domain audit events | T2 | `domain_events`, `tool_calls` | 90-day retention via cleanup job |
| Trading orders / positions | T2 | Kite-side; mirrored read-only in widgets | N/A (Kite source of truth) |
| Plugin manifests + SBOM | T3 | In-memory + `mcp/integrity.go` snapshot | Process lifetime |

## 4. STRIDE per asset

### S — Spoofing

| Vector | Mitigation | Residual |
|---|---|---|
| Forged MCP tool call (no JWT) | Bearer JWT verification middleware; 401 on missing/invalid | Low |
| Forged Stripe webhook | Stripe-Signature HMAC; replay-protection via `webhook_events` idempotency | Low |
| Forged OAuth callback (state token) | OAuth state stored in mcp-remote cache; HMAC-binding to client | Medium — depends on mcp-remote cache file perms |

### T — Tampering

| Vector | Mitigation | Residual |
|---|---|---|
| In-flight tool description manipulation (line-jumping) | `mcp/integrity.go` SHA-256 manifest at startup; mismatch → WARN | Low |
| Plugin code drift between deploys | `plugin_sbom.go` checksum + optional signature; SBOM exposed via admin endpoint | Low |
| Database row tampering (out-of-band write to alerts.db) | File-system perms; SEBI-side-of-house reconstruction via `domain_events` append-only log | Medium — operator with shell on Fly.io machine could tamper; mitigated by litestream history |
| Litestream replica tampering | R2 access-key separate from server creds; bucket versioning enabled | Low |

### R — Repudiation

| Vector | Mitigation | Residual |
|---|---|---|
| User denies placing an order | Tool-call audit trail (`algo2go/kite-mcp-audit/store.go`) with `CallID` + `RequestID` correlation; broker-side order book is authoritative | Low |
| Admin denies revoking credentials | `credential.revoked` domain event with `reason` field; append-only `domain_events` table | Low |
| User denies consent grant/revoke | `consent_log` append-only; DPDP-compliant per `docs/dpdp-reply-templates.md` | Low |

### I — Information disclosure

| Vector | Mitigation | Residual |
|---|---|---|
| Log line leaks PII / credentials | Redaction in audit summarizer (`algo2go/kite-mcp-audit/summarize.go`); email hashed in domain events; never log API key/secret/token | Low |
| Error response leaks internal state | Sanitised error messages; full stack-trace logged server-side only | Low |
| Side-channel via timing of crypto ops | Constant-time `crypto/subtle` for token comparisons; AES-GCM is constant-time per key | Low |
| Dashboard URL exposes session ID | UUIDs (random 122-bit), TLS-only, HTTP-only cookies, SameSite=Lax | Low |
| SBOM endpoint discloses internal plugin layout | SBOM is intentionally public for operator transparency; no sensitive paths exposed | Acceptable |

### D — Denial of service

| Vector | Mitigation | Residual |
|---|---|---|
| Tool-call flood from one user | Per-user, per-tool rate-limit middleware; circuit-breaker on error spike | Low |
| Webhook flood from forged Stripe | Stripe signature check rejects pre-processing; 65 KB body cap | Low |
| Anomaly detector self-DoS (cache thrash) | 10K-entry bound on `anomaly_cache`; 15-min TTL | Low |
| Goroutine leak in plugin watcher | `goleak.VerifyTestMain` in 8 test files; `Stop` lifecycle on `FillWatcher`, `OutboxPump` | Low |
| Disk fill from audit log | 90-day retention cleanup job; `tool_calls` table bounded | Low |

### E — Elevation of privilege

| Vector | Mitigation | Residual |
|---|---|---|
| Non-admin reaches admin tool | `adminCheck()` helper on every admin tool; `ADMIN_EMAILS` env-var allowlist | Low |
| Family member places order on admin's account | Per-user JWT scope; `riskguard` enforces email-tagged limits | Low |
| Plugin escalates to broker write | Plugins register via narrow Provider interfaces; broker write requires `OrderManager` port not in plugin SDK by default | Low |
| OAuth client privilege escalation (request elevated scope) | OAuth scope is fixed; client cannot request additional scopes via dynamic registration | Low |

## 5. Out-of-scope

- **MCP client-side compromise**: a malicious MCP client can call any tool the OAuth user is authorized for. Mitigation is user-side — pin trusted MCP clients only.
- **Kite Connect upstream compromise**: if Zerodha is breached, the per-user encrypted tokens become useless on the upstream side anyway; no action this server can take.
- **Operator-host compromise (self-host)**: a fork-and-host operator owning the machine has full access to encryption keys. Fork users assume operator-trust.
- **Regulatory shutdown**: out of threat-model scope (covered in `risk-register.md` R-06).

## 6. Review cadence

- **Quarterly**: walk every STRIDE row against new code paths shipped in the quarter.
- **Ad-hoc**: on every new external integration (new webhook source, new persistence sink, new MCP client target).
- **Update trigger**: any new asset added to §3 must have STRIDE rows added in §4.
