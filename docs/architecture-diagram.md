# Architecture Diagrams

Visual complement to [ARCHITECTURE.md](../ARCHITECTURE.md). Text-first for grep-ability; Mermaid for GitHub preview.

## High-level flow

```mermaid
flowchart LR
    User([User in Claude / ChatGPT])
    MCPClient[MCP Client / mcp-remote]
    MCPServer[Kite MCP Server<br/>Fly.io bom]
    Kite[Zerodha Kite Connect API]
    Telegram[Telegram Bot API]
    SQLite[(SQLite<br/>audit + sessions)]
    R2[(Cloudflare R2<br/>Litestream backup)]

    User <-->|stdio / streamable-http| MCPClient
    MCPClient <-->|MCP JSON-RPC| MCPServer
    MCPServer -->|OAuth per-user| Kite
    MCPServer -->|briefings / alerts| Telegram
    MCPServer <-->|reads + writes| SQLite
    SQLite -.->|continuous sync| R2
```

## Request lifecycle (tool call)

```mermaid
sequenceDiagram
    participant U as User
    participant C as MCP Client
    participant H as HTTP Middleware
    participant M as MCP Tool Handler
    participant R as RiskGuard
    participant A as Audit Store
    participant K as Kite API

    U->>C: "Sell 50 RELIANCE at market"
    C->>H: POST /mcp (tools/call place_order)
    H->>H: withRequestID (UUIDv7)
    H->>H: CorrelationMiddleware (CallID)
    H->>M: Route to PlaceOrderTool
    M->>R: Check (9 checks incl. anomaly + idempotency)
    R->>A: Read baseline (cached)
    R-->>M: OK / blocked
    alt Confirmed
        M->>K: POST /orders/regular
        K-->>M: order_id
        M->>A: Record (hash-chained)
        M-->>C: Order placed
    else Blocked
        M-->>C: Error message
    end
    C-->>U: Surface result
```

## Path 2 gate diagram

```mermaid
flowchart TB
    Env{ENABLE_TRADING}
    Gated[Order tools<br/>place/modify/cancel/GTT/MF<br/>18 total]
    Safe[Data/analytics tools<br/>~86 total<br/>get_*, analyze_concall, etc.]
    RegFilter[RegisterTools filter]

    Env -->|true<br/>local| RegFilter
    Env -->|false<br/>hosted| RegFilter
    Safe --> RegFilter
    Gated -->|only when true| RegFilter
    RegFilter -->|effective set| Server[(MCP Server<br/>tools/list)]
```

## Security layers

```mermaid
flowchart LR
    Req[Tool call] --> L1[X-Request-ID]
    L1 --> L2[Audit log]
    L2 --> L3[Hooks]
    L3 --> L4[CircuitBreaker]
    L4 --> L5[RiskGuard 9 checks]
    L5 --> L6[Rate limiter]
    L6 --> L7[Billing tier]
    L7 --> L8[Paper trade intercept]
    L8 --> L9[Dashboard URL]
    L9 --> Broker[Kite API]
```

## Data stores (AES-256-GCM encrypted via HKDF from OAUTH_JWT_SECRET)

```mermaid
erDiagram
    KITE_TOKEN_STORE ||--o{ USER : has
    KITE_CREDENTIAL_STORE ||--o{ USER : has
    SESSION_REGISTRY ||--o{ MCP_SESSION : tracks
    ALERT_STORE ||--o{ ALERT : contains
    CLIENT_STORE ||--o{ OAUTH_CLIENT : registers
    TOOL_CALLS }|--|| USER : logged-by
    ANOMALY_CACHE }|..|| USER : baselines
```

## Deployment topology (Fly.io)

```
┌──────────────────────────────────────────────────────┐
│ Fly.io bom region                                    │
│ ┌──────────────────────────────────────────────┐     │
│ │ kite-mcp-server machine (512 MB RAM)         │     │
│ │  ┌────────────┐    ┌─────────────┐           │     │
│ │  │ MCP server │ ←→ │ SQLite      │           │     │
│ │  │ (Go)       │    │ (data/)     │           │     │
│ │  └────────────┘    └──────┬──────┘           │     │
│ │                           │ Litestream       │     │
│ └──────────────────────────────┬───────────────┘     │
│                                │                     │
│  static egress IP              │                     │
│  209.71.68.157                 │                     │
└────────────────────────────────┼─────────────────────┘
                                 │
                                 ↓
                    ┌──────────────────────┐
                    │ Cloudflare R2        │
                    │ kite-mcp-backup      │
                    │ APAC                 │
                    └──────────────────────┘
                                 │
                                 ↓
     ┌──────────────────────────────────┐
     │ Zerodha Kite Connect API         │
     │ api.kite.trade                   │
     │ (IP 209.71.68.157 whitelisted)   │
     └──────────────────────────────────┘
```

## Related docs
- [ARCHITECTURE.md](../ARCHITECTURE.md) — high-level text
- [SECURITY.md](../SECURITY.md) — security posture
- [docs/monitoring.md](./monitoring.md) — observability
- [docs/incident-response.md](./incident-response.md) — when things go wrong
