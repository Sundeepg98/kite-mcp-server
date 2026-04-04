# htmx + SSE Admin Overview Refactor — Design Spec

## Goal
Replace client-side JS rendering of the Admin Overview tab with server-side Go templates + htmx SSE, as a proof of concept for migrating all dashboard pages.

## Architecture
Server-rendered HTML via Go `html/template` for instant first paint. SSE pushes updated HTML fragments every 10 seconds. Zero client-side JavaScript for the Overview tab. htmx 2.0.8 + SSE extension 2.2.4 vendored locally in embed.FS.

## Template Component System

```
kc/templates/
  components/
    stat_card.html       — reusable stat card partial
    tool_table.html      — reusable tool usage table partial
  fragments/
    overview_stats.html  — stat cards grid (uses stat_card N times)
    overview_tools.html  — tool usage section (uses tool_table)
  static/
    htmx.min.js          — htmx 2.0.8 core (16KB gzipped)
    htmx-sse.js          — SSE extension 2.2.4 (2KB)
```

## Data Flow

### Initial Load
1. Browser requests `GET /admin/ops`
2. `handler.go` parses ops.html as Go template
3. Executes `overview_stats.html` and `overview_tools.html` with live `OverviewData`
4. Returns full HTML with pre-rendered stats — user sees data on first paint

### Live Updates
1. htmx SSE extension connects to `GET /admin/ops/api/overview-stream`
2. Server sends two named events every 10 seconds:
   - `event: overview-stats` — rendered stat cards HTML
   - `event: overview-tools` — rendered tool table HTML
3. htmx swaps fragment content into matching `sse-swap` targets
4. On disconnect, htmx auto-reconnects with exponential backoff

## HTML Structure (ops.html Overview panel)

```html
<div id="panel-overview" class="panel active"
     hx-ext="sse" sse-connect="/admin/ops/api/overview-stream">

  <div id="statsGrid" class="stats-grid" sse-swap="overview-stats">
    {{template "overview_stats" .Overview}}
  </div>

  <div style="display:flex;align-items:center;justify-content:space-between">
    <div class="section-header" style="margin:0;border:none;padding:0">Tool Usage</div>
    <button id="verifyChainBtn" ...>Verify Audit Chain</button>
  </div>
  <div id="chainResult" ...></div>

  <div id="toolUsage" sse-swap="overview-tools">
    {{template "overview_tools" .Overview}}
  </div>
</div>
```

## SSE Endpoint

**Route:** `GET /admin/ops/api/overview-stream`
**Auth:** Same `adminAuth` middleware as all `/admin/ops/*` routes
**File:** `kc/ops/overview_sse.go` (new, ~80 lines)

### Server implementation:
- Verify `w.(http.Flusher)` support
- Set headers: `Content-Type: text/event-stream`, `Cache-Control: no-cache`, `Connection: keep-alive`
- 10-second ticker loop:
  - Call `buildOverview()` for latest data
  - Render `overview_stats.html` into `bytes.Buffer`
  - Render `overview_tools.html` into `bytes.Buffer`
  - Write SSE events (multiline data: prefix per line)
  - Flush
- Monitor `r.Context().Done()` for client disconnect
- Clean exit on context cancellation

### SSE wire format:
```
event: overview-stats
data: <div class="stat-card">...</div>
data: <div class="stat-card">...</div>

event: overview-tools
data: <div class="tbl-wrap">...</div>

```

## Template Partials

### stat_card.html
```html
{{define "stat_card"}}
<div class="stat-card">
  <div class="stat-label">{{.Label}}</div>
  <div class="stat-value{{if .Class}} {{.Class}}{{end}}">{{.Value}}</div>
</div>
{{end}}
```

### overview_stats.html
```html
{{define "overview_stats"}}
{{range .Cards}}{{template "stat_card" .}}{{end}}
{{end}}
```

Requires a Go struct to prepare card data:
```go
type StatCard struct {
    Label string
    Value string
    Class string // "green", "amber", "" etc.
}
```

### tool_table.html
```html
{{define "overview_tools"}}
<div class="tbl-wrap">
  <table><thead><tr><th>Counter</th><th>Value</th></tr></thead>
  <tbody>
  {{range .ToolUsage}}
    <tr><td>{{.Name}}</td><td>{{.Count}}</td></tr>
  {{else}}
    <tr><td colspan="2" style="text-align:center;color:var(--text-2)">No tool usage recorded</td></tr>
  {{end}}
  </tbody></table>
</div>
{{end}}
```

## Reconnection & Resilience

- htmx SSE extension has built-in exponential backoff reconnection
- Connection status via htmx events:
  - `htmx:sseOpen` → server status dot green, text "Online"
  - `htmx:sseError` → dot amber, text "Reconnecting..."
- ~10 lines of JS for the status indicator (the only JS for Overview)
- Graceful degradation: if htmx JS fails to load, server-rendered content is still visible — just won't auto-update

## Static Asset Serving

Add routes in `dashboard.go`:
- `GET /static/htmx.min.js` — htmx core, `Cache-Control: public, max-age=604800` (7 days)
- `GET /static/htmx-sse.js` — SSE extension, same caching

Both served from embed.FS. No CDN dependency. No external requests.

## handler.go Changes

Current pattern (raw file serve):
```go
func (h *Handler) serveOps(w http.ResponseWriter, r *http.Request) {
    data, _ := templates.FS.ReadFile("ops.html")
    bodyAttrs := fmt.Sprintf(`<body data-email="%s" ...>`, html.EscapeString(email))
    html := strings.Replace(string(data), "<body>", bodyAttrs, 1)
    w.Write([]byte(html))
}
```

New pattern (template execution):
```go
func (h *Handler) serveOps(w http.ResponseWriter, r *http.Request) {
    overview := h.buildOverview()
    cards := overviewToCards(overview)
    data := OpsPageData{
        Email:    email,
        IsAdmin:  admin,
        Overview: OverviewTemplateData{Cards: cards, ToolUsage: sortedUsage(overview)},
    }
    h.opsTmpl.ExecuteTemplate(w, "ops.html", data)
}
```

## ops.html Changes

### Removed (~80 lines):
- `refreshOverview()` function
- Stats grid DOM building (clearChildren + forEach loop)
- Tool table DOM building (clearChildren + forEach loop)
- `refreshOverview()` call from `refreshAll()`

### Added (~10 lines):
- `<script src="/static/htmx.min.js"></script>`
- `<script src="/static/htmx-sse.js"></script>`
- `hx-ext="sse"` + `sse-connect` + `sse-swap` attributes
- SSE connection status listener (~10 lines JS)

### Changed:
- `<body>` → `<body data-email="{{.Email}}" data-admin="{{.IsAdmin}}">`
- Overview panel: static HTML → Go template calls

## Files Changed

| File | Action | Estimate |
|------|--------|----------|
| `kc/templates/components/stat_card.html` | NEW | ~8 lines |
| `kc/templates/components/tool_table.html` | NEW | ~12 lines |
| `kc/templates/fragments/overview_stats.html` | NEW | ~5 lines |
| `kc/templates/fragments/overview_tools.html` | NEW | ~3 lines |
| `kc/templates/static/htmx.min.js` | NEW | vendored 16KB |
| `kc/templates/static/htmx-sse.js` | NEW | vendored 2KB |
| `kc/templates/ops.html` | MODIFY | -80 JS lines, +htmx attrs |
| `kc/templates/templates.go` | MODIFY | add new embeds |
| `kc/ops/handler.go` | MODIFY | template parsing + pre-render |
| `kc/ops/overview_sse.go` | NEW | SSE endpoint ~80 lines |
| `kc/ops/dashboard.go` | MODIFY | static routes for htmx JS |

## What Stays Unchanged
- All 7 other admin tabs (Sessions, Users, etc.) — still vanilla JS
- All 6 user dashboard pages — untouched
- `GET /admin/ops/api/overview` JSON endpoint — still works
- CSS — no changes
- Auth — SSE reuses adminAuth middleware
- MCP Apps widgets — untouched

## Success Criteria
1. Overview tab renders with data on first paint (no loading spinner)
2. Stats + tool table update every 10s via SSE without client-side JS
3. SSE auto-reconnects on disconnect with visual indicator
4. `go build ./...` produces single binary, all assets embedded
5. All 7 other tabs continue working identically
6. No external CDN or npm dependencies
