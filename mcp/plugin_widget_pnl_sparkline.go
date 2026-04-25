package mcp

import (
	"context"
	"time"

	"github.com/zerodha/kite-mcp-server/kc"
)

// pnlSparklineWidgetData reads the last 30 days of daily P&L snapshots
// from the alerts.DB `daily_pnl` table and formats them for a
// minimalist sparkline widget. This surfaces "how has my account
// trended?" in a single glance — the question that used to require a
// five-tool shell pipeline to answer.
//
// Data source: kc/alerts.DB.LoadDailyPnL — populated by the
// PnLSnapshotService scheduler task at 15:40 IST every trading day.
// Windows with no snapshots yet (fresh user, brand-new deployment)
// render an empty chart with a "no data yet" note, not an error.
//
// Handles nil manager (test path) by returning a zero-point payload.
// Handles missing DB (dev mode without ALERT_DB_PATH) the same way.
func pnlSparklineWidgetData(_ context.Context, manager *kc.Manager, email string) any {
	type pnlPoint struct {
		Date   string  `json:"date"`
		NetPnL float64 `json:"net_pnl"`
	}
	if manager == nil {
		return map[string]any{
			"error":  "unavailable",
			"points": []pnlPoint{},
		}
	}
	if email == "" {
		return map[string]any{
			"error":  "unauthenticated",
			"points": []pnlPoint{},
		}
	}
	db := manager.AlertDB()
	if db == nil {
		return map[string]any{
			"error":  "pnl snapshots require an alert DB (set ALERT_DB_PATH)",
			"points": []pnlPoint{},
		}
	}
	// 30-day trailing window.
	to := time.Now().UTC()
	from := to.AddDate(0, 0, -30)
	entries, err := db.LoadDailyPnL(email, from.Format("2006-01-02"), to.Format("2006-01-02"))
	if err != nil {
		return map[string]any{
			"error":  err.Error(),
			"points": []pnlPoint{},
		}
	}
	points := make([]pnlPoint, 0, len(entries))
	var latest float64
	var maxAbs float64
	for _, e := range entries {
		points = append(points, pnlPoint{Date: e.Date, NetPnL: e.NetPnL})
		latest = e.NetPnL
		if abs(e.NetPnL) > maxAbs {
			maxAbs = abs(e.NetPnL)
		}
	}
	trend := "flat"
	if len(points) >= 2 {
		first := points[0].NetPnL
		last := points[len(points)-1].NetPnL
		switch {
		case last > first+0.5: // >0.5 rupee tolerance for float noise
			trend = "up"
		case last < first-0.5:
			trend = "down"
		}
	}
	return map[string]any{
		"points":  points,
		"latest":  latest,
		"max_abs": maxAbs,
		"trend":   trend,
		"window":  "30d",
	}
}

func abs(f float64) float64 {
	if f < 0 {
		return -f
	}
	return f
}

// pnlSparklineTemplateHTML renders a 30-day net-P&L sparkline with a
// large summary number (today's latest). Uses namespaced SVG + safe
// DOM APIs (setAttribute + textContent) — no innerHTML on injected
// strings.
const pnlSparklineTemplateHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="color-scheme" content="dark light">
<title>P&L Sparkline</title>
<style>
:root { --bg:#0a0c10; --fg:#e2e8f0; --fg2:#94a3b8; --green:#34d399; --red:#f87171; --accent:#22d3ee; --mono:'SF Mono',Consolas,monospace; }
html.light { --bg:#fff; --fg:#0f172a; --fg2:#475569; }
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--fg);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;padding:16px;font-size:13px}
.card{display:grid;gap:12px}
.hdr{display:flex;justify-content:space-between;align-items:baseline}
.title{font-size:13px;color:var(--fg2);text-transform:uppercase;letter-spacing:0.06em}
.latest{font-family:var(--mono);font-size:28px;font-weight:600}
.up{color:var(--green)} .down{color:var(--red)}
svg{width:100%;height:80px}
.empty{color:var(--fg2);font-style:italic;padding:24px 0;text-align:center}
.meta{display:flex;justify-content:space-between;font-family:var(--mono);font-size:11px;color:var(--fg2)}
</style></head><body>
<div class="card">
  <div class="hdr"><span class="title">Net P&L — 30d</span><span class="meta-window" id="window">30d</span></div>
  <div class="latest" id="latest">--</div>
  <svg viewBox="0 0 200 60" id="spark" xmlns="http://www.w3.org/2000/svg"></svg>
  <div class="meta" id="meta"></div>
</div>
<script>
const DATA = "__INJECTED_DATA__";
(function(){
  const SVG_NS = 'http://www.w3.org/2000/svg';
  const svg = document.getElementById('spark');
  const latest = document.getElementById('latest');
  const meta = document.getElementById('meta');
  const win = document.getElementById('window');

  function fmtINR(v) {
    if (typeof v !== 'number') return '--';
    const sign = v < 0 ? '-' : (v > 0 ? '+' : '');
    return sign + '\u20B9' + Math.abs(v).toLocaleString('en-IN', {maximumFractionDigits: 0});
  }
  function mkSVG(tag, attrs) {
    const el = document.createElementNS(SVG_NS, tag);
    for (const k in attrs) el.setAttribute(k, attrs[k]);
    return el;
  }

  if (!DATA) { latest.textContent = 'no data'; return; }
  if (DATA.error) {
    latest.textContent = 'unavailable';
    const e = document.createElement('div');
    e.className = 'empty';
    e.textContent = DATA.error;
    svg.replaceWith(e);
    return;
  }
  const pts = DATA.points || [];
  latest.textContent = fmtINR(DATA.latest);
  latest.className = 'latest ' + (DATA.trend === 'up' ? 'up' : DATA.trend === 'down' ? 'down' : '');
  if (DATA.window) win.textContent = DATA.window;

  if (pts.length === 0) {
    const e = document.createElement('div');
    e.className = 'empty';
    e.textContent = 'no snapshots yet — first P&L captured after market close';
    svg.replaceWith(e);
    return;
  }

  // Sparkline path.
  const w = 200, h = 60, pad = 4;
  const values = pts.map(p => p.net_pnl);
  const min = Math.min(0, Math.min.apply(null, values));
  const max = Math.max(0, Math.max.apply(null, values));
  const span = (max - min) || 1;
  const n = values.length;
  const d = values.map((v, i) => {
    const x = pad + (i / Math.max(1, n-1)) * (w - 2*pad);
    const y = h - pad - ((v - min) / span) * (h - 2*pad);
    return (i === 0 ? 'M ' : 'L ') + x.toFixed(1) + ' ' + y.toFixed(1);
  }).join(' ');
  const color = DATA.trend === 'up' ? 'var(--green)' : DATA.trend === 'down' ? 'var(--red)' : 'var(--accent)';
  svg.appendChild(mkSVG('path', {d: d, stroke: color, 'stroke-width': 1.5, fill: 'none', 'stroke-linecap': 'round', 'stroke-linejoin': 'round'}));

  // Zero baseline.
  if (min < 0 && max > 0) {
    const yZero = h - pad - ((0 - min) / span) * (h - 2*pad);
    svg.appendChild(mkSVG('line', {x1: pad, y1: yZero, x2: w-pad, y2: yZero, stroke: 'var(--fg2)', 'stroke-width': 0.5, 'stroke-dasharray': '2 3'}));
  }

  const metaLeft = document.createElement('span');
  metaLeft.textContent = pts[0].date;
  const metaRight = document.createElement('span');
  metaRight.textContent = pts[pts.length-1].date;
  meta.appendChild(metaLeft);
  meta.appendChild(metaRight);
})();
</script>
</body></html>`
