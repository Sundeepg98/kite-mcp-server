package mcp

import (
	"context"

	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/usecases"
)

// sectorDonutWidgetData returns the portfolio sector-exposure
// allocation suitable for a donut-chart rendering. The widget answers
// the "am I over-concentrated in one sector?" question that sits on
// every trader's checklist — SEBI risk guidance flags single-sector
// exposure >30% as concentration risk.
//
// Data pipeline:
//   - portfolio holdings from the shared QueryBus
//     (cqrs.GetPortfolioQuery) — same source the portfolio widget uses;
//   - sector classification via lookupSector in sector_map.go — the
//     same ~150-stock map the sector_exposure MCP tool consumes;
//   - percentages computed against total holding value.
//
// Returns nil (rendering "not configured") when manager is nil; tests
// exercise this branch. Returns an error-shaped payload when the
// QueryBus dispatch fails — widget renders an inline error rather than
// leaving the user looking at an empty donut.
func sectorDonutWidgetData(ctx context.Context, manager *kc.Manager, email string) any {
	if manager == nil {
		return map[string]any{"error": "unavailable", "reason": "portfolio manager not configured"}
	}
	if email == "" {
		return map[string]any{"error": "unauthenticated"}
	}
	raw, err := manager.QueryBus().DispatchWithResult(ctx, cqrs.GetPortfolioQuery{Email: email})
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	portfolio, ok := raw.(*usecases.PortfolioResult)
	if !ok || portfolio == nil {
		return map[string]any{"error": "portfolio result missing"}
	}

	type sectorEntry struct {
		Sector      string  `json:"sector"`
		ValueINR    float64 `json:"value_inr"`
		Pct         float64 `json:"pct"`
		OverExposed bool    `json:"over_exposed,omitempty"`
	}

	// Accumulate sector -> value.
	type accum struct {
		value float64
		count int
	}
	buckets := make(map[string]*accum)
	var total float64
	for _, h := range portfolio.Holdings {
		value := h.LastPrice * float64(h.Quantity)
		if value <= 0 {
			continue
		}
		// Reuse the existing sector_tool.go classifier: normalise the
		// trading symbol and look up in the stockSectors map. Unmapped
		// symbols fall through to an explicit "Unmapped" bucket so
		// users can tell mapping-gap from data-gap.
		sector, mapped := stockSectors[normalizeSymbol(h.Tradingsymbol)]
		if !mapped {
			sector = "Unmapped"
		}
		b, ok := buckets[sector]
		if !ok {
			b = &accum{}
			buckets[sector] = b
		}
		b.value += value
		b.count++
		total += value
	}

	entries := make([]sectorEntry, 0, len(buckets))
	for sector, b := range buckets {
		pct := 0.0
		if total > 0 {
			pct = (b.value / total) * 100.0
		}
		entries = append(entries, sectorEntry{
			Sector:      sector,
			ValueINR:    b.value,
			Pct:         pct,
			OverExposed: pct > 30.0,
		})
	}
	// Sort by value desc for deterministic presentation.
	for i := 1; i < len(entries); i++ {
		for j := i; j > 0 && entries[j-1].ValueINR < entries[j].ValueINR; j-- {
			entries[j-1], entries[j] = entries[j], entries[j-1]
		}
	}

	return map[string]any{
		"total_value":   total,
		"sectors":       entries,
		"holding_count": len(portfolio.Holdings),
		"concentration_warning": func() string {
			for _, e := range entries {
				if e.OverExposed {
					return e.Sector + " exposure is " + formatPct(e.Pct) + " (> 30% threshold)"
				}
			}
			return ""
		}(),
	}
}

// Note: formatPct is defined in sector_tool.go and reused here for
// the concentration-warning string. Keeping a single formatter
// keeps the UI-readable thresholds aligned across the sector widget
// and the sector_exposure MCP tool.

// sectorDonutTemplateHTML renders an SVG donut using safe DOM APIs
// (SVG namespace element creation + setAttribute + textContent —
// no innerHTML on untrusted data). JSON data is injected server-side
// via __INJECTED_DATA__; the Go-side injectData helper escapes
// </script>, <!--, U+2028, U+2029 to prevent XSS breakout.
const sectorDonutTemplateHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="color-scheme" content="dark light">
<title>Sector Exposure</title>
<style>
:root { --bg:#0a0c10; --bg2:#161b24; --fg:#e2e8f0; --fg2:#94a3b8; --accent:#22d3ee; --amber:#fbbf24; --red:#f87171; --mono:'SF Mono',Consolas,monospace; }
html.light { --bg:#fff; --bg2:#f1f5f9; --fg:#0f172a; --fg2:#475569; }
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--fg);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;padding:16px;font-size:13px}
.hdr{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
.hdr h1{font-size:14px;font-weight:600}
.warn{background:rgba(248,113,113,0.1);border:1px solid var(--red);padding:8px 12px;border-radius:6px;margin-bottom:12px;color:var(--red);font-size:12px}
.chart{display:flex;gap:16px;align-items:flex-start}
svg{flex:0 0 180px}
.legend{flex:1;display:grid;gap:6px;font-family:var(--mono);font-size:11px}
.legend-row{display:grid;grid-template-columns:12px 1fr auto;gap:8px;align-items:center}
.swatch{width:12px;height:12px;border-radius:2px}
.pct{color:var(--fg2)}
.muted{color:var(--fg2)}
</style></head><body>
<div class="hdr"><h1>Sector Exposure</h1><span class="muted">donut</span></div>
<div id="warn-slot"></div>
<div class="chart">
  <svg viewBox="0 0 100 100" id="donut-svg" xmlns="http://www.w3.org/2000/svg"></svg>
  <div class="legend" id="legend"></div>
</div>
<script>
const DATA = "__INJECTED_DATA__";
(function(){
  const SVG_NS = 'http://www.w3.org/2000/svg';
  const svgRoot = document.getElementById('donut-svg');
  const legend = document.getElementById('legend');
  const warnSlot = document.getElementById('warn-slot');

  function mkSVG(tag, attrs) {
    const el = document.createElementNS(SVG_NS, tag);
    for (const k in attrs) el.setAttribute(k, attrs[k]);
    return el;
  }
  function mkDiv(cls, text) {
    const d = document.createElement('div');
    if (cls) d.className = cls;
    if (text !== undefined) d.textContent = text;
    return d;
  }
  function mkSpan(cls, text, styleBg) {
    const s = document.createElement('span');
    if (cls) s.className = cls;
    if (text !== undefined) s.textContent = text;
    if (styleBg) s.style.background = styleBg;
    return s;
  }

  if (!DATA || DATA.error) {
    const t = mkSVG('text', {x: 50, y: 55, 'text-anchor': 'middle', fill: 'currentColor', 'font-size': 10});
    t.textContent = (DATA && DATA.error) || 'no data';
    svgRoot.appendChild(t);
    return;
  }
  const sectors = DATA.sectors || [];
  if (DATA.concentration_warning) {
    warnSlot.appendChild(mkDiv('warn', DATA.concentration_warning));
  }
  const palette = ['#22d3ee','#34d399','#fbbf24','#f87171','#a78bfa','#fb7185','#60a5fa','#facc15','#4ade80','#c084fc'];
  const R = 40, C = 50;
  let offset = 0;
  sectors.forEach((s, i) => {
    const pct = s.pct || 0;
    const theta = (pct/100) * 2 * Math.PI;
    const x1 = C + R*Math.sin(offset);
    const y1 = C - R*Math.cos(offset);
    const x2 = C + R*Math.sin(offset+theta);
    const y2 = C - R*Math.cos(offset+theta);
    const large = theta > Math.PI ? 1 : 0;
    const color = palette[i % palette.length];
    const d = 'M '+C+' '+C+' L '+x1.toFixed(2)+' '+y1.toFixed(2)+
      ' A '+R+' '+R+' 0 '+large+' 1 '+x2.toFixed(2)+' '+y2.toFixed(2)+' Z';
    svgRoot.appendChild(mkSVG('path', {d: d, fill: color}));
    offset += theta;

    const row = mkDiv('legend-row');
    row.appendChild(mkSpan('swatch', '', color));
    row.appendChild(mkSpan('', String(s.sector)));
    row.appendChild(mkSpan('pct', pct.toFixed(1)+'%'));
    legend.appendChild(row);
  });
  // Donut hole
  svgRoot.appendChild(mkSVG('circle', {cx: 50, cy: 50, r: 22, fill: 'var(--bg)'}));
})();
</script>
</body></html>`
