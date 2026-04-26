package mcp

import (
	"context"

	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
)

// marginGaugeWidgetData returns the user's equity + commodity segment
// margin utilisation as {available, used, total} triples plus a
// precomputed utilisation percentage. Rendered as a radial gauge with
// one band per segment — the "am I about to trip margin?" question
// every intraday trader asks.
//
// Data pipeline: cqrs.GetMarginsQuery -> broker adapter -> Kite API.
// Same flow every margins-reading tool uses; nothing bespoke here.
//
// Nil-safety: nil manager renders "not configured". Failed dispatch
// renders an error banner. Zero total (fresh account) shows a
// deterministic "no margin info" message rather than a NaN bar.
func marginGaugeWidgetData(ctx context.Context, manager extAppManagerPort, email string) any {
	type segmentView struct {
		Segment   string  `json:"segment"`
		Available float64 `json:"available"`
		Used      float64 `json:"used"`
		Total     float64 `json:"total"`
		Pct       float64 `json:"pct"`
	}
	if manager == nil {
		return map[string]any{"error": "unavailable"}
	}
	if email == "" {
		return map[string]any{"error": "unauthenticated"}
	}
	raw, err := manager.QueryBus().DispatchWithResult(ctx, cqrs.GetMarginsQuery{Email: email})
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	m, ok := raw.(broker.Margins)
	if !ok {
		return map[string]any{"error": "unexpected margins shape"}
	}
	segments := []segmentView{
		viewForSegment("Equity", m.Equity),
		viewForSegment("Commodity", m.Commodity),
	}
	// Filter out empty segments (commodity often zero).
	nonEmpty := segments[:0]
	for _, s := range segments {
		if s.Total > 0 {
			nonEmpty = append(nonEmpty, s)
		}
	}
	return map[string]any{
		"segments": nonEmpty,
	}
}

func viewForSegment(name string, s broker.SegmentMargin) struct {
	Segment   string  `json:"segment"`
	Available float64 `json:"available"`
	Used      float64 `json:"used"`
	Total     float64 `json:"total"`
	Pct       float64 `json:"pct"`
} {
	pct := 0.0
	if s.Total > 0 {
		pct = (s.Used / s.Total) * 100.0
	}
	return struct {
		Segment   string  `json:"segment"`
		Available float64 `json:"available"`
		Used      float64 `json:"used"`
		Total     float64 `json:"total"`
		Pct       float64 `json:"pct"`
	}{
		Segment:   name,
		Available: s.Available,
		Used:      s.Used,
		Total:     s.Total,
		Pct:       pct,
	}
}

// marginGaugeTemplateHTML renders one horizontal gauge per segment
// with used / available / total readouts. Colour shifts from green
// (safe) through amber (>70%) to red (>90%) — intraday traders eye
// these bands before every new order.
const marginGaugeTemplateHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="color-scheme" content="dark light">
<title>Margin Utilisation</title>
<style>
:root { --bg:#0a0c10; --bg2:#161b24; --fg:#e2e8f0; --fg2:#94a3b8; --green:#34d399; --amber:#fbbf24; --red:#f87171; --border:#252d3a; --mono:'SF Mono',Consolas,monospace; }
html.light { --bg:#fff; --bg2:#f1f5f9; --fg:#0f172a; --fg2:#475569; --border:#e2e8f0; }
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--fg);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;padding:16px;font-size:13px}
.hdr{display:flex;justify-content:space-between;align-items:center;margin-bottom:14px}
.hdr h1{font-size:14px;font-weight:600}
.muted{color:var(--fg2)}
.seg{background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:12px;margin-bottom:10px}
.seg-hdr{display:flex;justify-content:space-between;margin-bottom:8px;font-family:var(--mono);font-size:12px}
.seg-name{font-weight:600}
.pct-safe{color:var(--green)} .pct-warn{color:var(--amber)} .pct-danger{color:var(--red)}
.bar-outer{background:var(--bg);border-radius:4px;height:8px;overflow:hidden;margin-bottom:8px}
.bar-inner{height:100%;transition:width 0.3s ease}
.kv{display:grid;grid-template-columns:repeat(3,1fr);gap:6px;font-family:var(--mono);font-size:11px}
.kv div:nth-child(odd){color:var(--fg2)}
.kv-block{display:flex;flex-direction:column;gap:2px}
.kv-label{color:var(--fg2);font-size:10px;text-transform:uppercase}
.empty{color:var(--fg2);text-align:center;padding:24px 0}
</style></head><body>
<div class="hdr"><h1>Margin Utilisation</h1><span class="muted">gauge</span></div>
<div id="slot"></div>
<script>
const DATA = "__INJECTED_DATA__";
(function(){
  const slot = document.getElementById('slot');
  function fmtINR(v){ return '\u20B9' + Math.round(v || 0).toLocaleString('en-IN'); }
  function mkDiv(cls, text){ const d = document.createElement('div'); if (cls) d.className = cls; if (text !== undefined) d.textContent = text; return d; }

  if (!DATA || DATA.error) {
    slot.appendChild(mkDiv('empty', (DATA && DATA.error) || 'no data'));
    return;
  }
  const segs = DATA.segments || [];
  if (segs.length === 0) {
    slot.appendChild(mkDiv('empty', 'no active segments — funds not yet transferred'));
    return;
  }
  segs.forEach(s => {
    const seg = mkDiv('seg');
    const hdr = mkDiv('seg-hdr');
    hdr.appendChild(mkDiv('seg-name', s.segment));

    const pctCls = s.pct >= 90 ? 'pct-danger' : s.pct >= 70 ? 'pct-warn' : 'pct-safe';
    hdr.appendChild(mkDiv('seg-pct ' + pctCls, s.pct.toFixed(1) + '%'));
    seg.appendChild(hdr);

    const outer = mkDiv('bar-outer');
    const inner = mkDiv('bar-inner');
    const color = s.pct >= 90 ? 'var(--red)' : s.pct >= 70 ? 'var(--amber)' : 'var(--green)';
    inner.style.width = Math.min(100, s.pct).toFixed(1) + '%';
    inner.style.background = color;
    outer.appendChild(inner);
    seg.appendChild(outer);

    const kv = mkDiv('kv');
    ['used', 'available', 'total'].forEach(k => {
      const block = mkDiv('kv-block');
      block.appendChild(mkDiv('kv-label', k));
      block.appendChild(mkDiv('', fmtINR(s[k])));
      kv.appendChild(block);
    });
    seg.appendChild(kv);
    slot.appendChild(seg);
  });
})();
</script>
</body></html>`
