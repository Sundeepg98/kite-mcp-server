package mcp

import (
	"context"

	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/usecases"
)

// returnsMatrixWidgetData builds a per-holding returns table. Rows are
// holdings; columns are time windows (1D change from Kite's
// day_change_percentage plus a lifetime % using avg price vs last
// price). The widget answers "what's actually working in my book?" —
// the question that motivates tax-loss harvesting, rebalancing, and
// "cut your losers" rules of thumb.
//
// Lifetime % is computed client-agnostically from current holdings:
// ((LastPrice - AveragePrice) / AveragePrice) * 100. 1D % comes
// straight from Kite's day_change_percentage field. Additional
// windows (1W, 1M, 3M, YTD) are NOT included in this first pass —
// those require historical candle fetches per symbol which is a
// broker-side rate-limit multiplier. Future work: pipe the
// historical_data tool's output through a rolling cache.
//
// Defensive on nil manager and missing broker.
func returnsMatrixWidgetData(ctx context.Context, manager extAppManagerPort, email string) any {
	type row struct {
		Symbol       string  `json:"symbol"`
		Qty          int     `json:"qty"`
		AvgPrice     float64 `json:"avg_price"`
		LastPrice    float64 `json:"last_price"`
		DayChangePct float64 `json:"day_change_pct"`
		LifetimePct  float64 `json:"lifetime_pct"`
		Value        float64 `json:"value"`
		PnL          float64 `json:"pnl"`
	}
	if manager == nil {
		return map[string]any{"error": "unavailable"}
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

	rows := make([]row, 0, len(portfolio.Holdings))
	var winnerCount, loserCount int
	var totalPnL float64
	for _, h := range portfolio.Holdings {
		lifetimePct := 0.0
		if h.AveragePrice > 0 {
			lifetimePct = ((h.LastPrice - h.AveragePrice) / h.AveragePrice) * 100.0
		}
		value := h.LastPrice * float64(h.Quantity)
		r := row{
			Symbol:       h.Tradingsymbol,
			Qty:          h.Quantity,
			AvgPrice:     h.AveragePrice,
			LastPrice:    h.LastPrice,
			DayChangePct: h.DayChangePct,
			LifetimePct:  lifetimePct,
			Value:        value,
			PnL:          h.PnL,
		}
		rows = append(rows, r)
		if h.PnL > 0 {
			winnerCount++
		} else if h.PnL < 0 {
			loserCount++
		}
		totalPnL += h.PnL
	}
	// Sort by lifetime_pct desc — most interesting at top (biggest
	// winners / biggest losers both surface immediately).
	for i := 1; i < len(rows); i++ {
		for j := i; j > 0 && rows[j-1].LifetimePct < rows[j].LifetimePct; j-- {
			rows[j-1], rows[j] = rows[j], rows[j-1]
		}
	}

	return map[string]any{
		"rows":           rows,
		"winner_count":   winnerCount,
		"loser_count":    loserCount,
		"total_pnl":      totalPnL,
		"holdings_count": len(rows),
	}
}

// returnsMatrixTemplateHTML is a dense table: symbol, qty, avg, last,
// 1D%, lifetime%, value, P&L. Winners are green; losers red. Sorted
// by lifetime-% descending so the biggest winner is row 1 and the
// biggest loser is the last row — the classic "winners and losers"
// split view.
const returnsMatrixTemplateHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="color-scheme" content="dark light">
<title>Returns Matrix</title>
<style>
:root { --bg:#0a0c10; --bg2:#161b24; --fg:#e2e8f0; --fg2:#94a3b8; --accent:#22d3ee; --green:#34d399; --red:#f87171; --border:#252d3a; --mono:'SF Mono',Consolas,monospace; }
html.light { --bg:#fff; --bg2:#f1f5f9; --fg:#0f172a; --fg2:#475569; --border:#e2e8f0; }
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--fg);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;padding:16px;font-size:13px}
.hdr{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px}
.hdr h1{font-size:14px;font-weight:600}
.muted{color:var(--fg2)}
.summary{display:flex;gap:20px;margin-bottom:14px;font-family:var(--mono);font-size:11px;color:var(--fg2)}
.summary strong{color:var(--fg)}
.win{color:var(--green)}
.loss{color:var(--red)}
table{width:100%;border-collapse:collapse;font-family:var(--mono);font-size:11px}
th,td{padding:6px 8px;text-align:right;border-bottom:1px solid var(--border)}
th{background:var(--bg2);color:var(--fg2);font-weight:600;text-transform:uppercase;letter-spacing:0.04em;font-size:10px}
th:first-child,td:first-child{text-align:left}
.empty{color:var(--fg2);text-align:center;padding:24px 0}
</style></head><body>
<div class="hdr"><h1>Returns Matrix</h1><span class="muted">sorted by lifetime %</span></div>
<div class="summary" id="summary"></div>
<table><thead><tr>
  <th>Symbol</th><th>Qty</th><th>Avg</th><th>Last</th><th>1D%</th><th>Life%</th><th>Value</th><th>P&amp;L</th>
</tr></thead><tbody id="tbody"></tbody></table>
<div id="empty-slot"></div>
<script>
const DATA = "__INJECTED_DATA__";
(function(){
  const tbody = document.getElementById('tbody');
  const summary = document.getElementById('summary');
  const emptySlot = document.getElementById('empty-slot');

  function mkTd(text, cls){ const td = document.createElement('td'); if (cls) td.className = cls; if (text !== undefined) td.textContent = text; return td; }
  function mkDiv(cls, text){ const d = document.createElement('div'); if (cls) d.className = cls; if (text !== undefined) d.textContent = text; return d; }
  function fmtINR(v){ if (v === 0 || v === undefined) return '0'; return (v < 0 ? '-' : '') + '\u20B9' + Math.abs(Math.round(v)).toLocaleString('en-IN'); }
  function fmtPct(v){ if (v === undefined) return '--'; return (v > 0 ? '+' : '') + v.toFixed(2) + '%'; }

  if (!DATA || DATA.error) {
    const e = mkDiv('empty', (DATA && DATA.error) || 'no data');
    emptySlot.appendChild(e);
    return;
  }
  const rows = DATA.rows || [];
  if (rows.length === 0) {
    emptySlot.appendChild(mkDiv('empty', 'no holdings'));
    return;
  }

  // Summary line.
  const parts = [
    {label: 'Holdings', value: String(DATA.holdings_count || 0)},
    {label: 'Winners', value: String(DATA.winner_count || 0), cls: 'win'},
    {label: 'Losers', value: String(DATA.loser_count || 0), cls: 'loss'},
    {label: 'Net P&L', value: fmtINR(DATA.total_pnl || 0), cls: (DATA.total_pnl || 0) >= 0 ? 'win' : 'loss'},
  ];
  parts.forEach(p => {
    const span = document.createElement('span');
    span.appendChild(document.createTextNode(p.label + ': '));
    const strong = document.createElement('strong');
    strong.textContent = p.value;
    if (p.cls) strong.className = p.cls;
    span.appendChild(strong);
    summary.appendChild(span);
  });

  rows.forEach(r => {
    const tr = document.createElement('tr');
    tr.appendChild(mkTd(r.symbol));
    tr.appendChild(mkTd(String(r.qty || 0)));
    tr.appendChild(mkTd(r.avg_price.toFixed(2)));
    tr.appendChild(mkTd(r.last_price.toFixed(2)));
    tr.appendChild(mkTd(fmtPct(r.day_change_pct), r.day_change_pct >= 0 ? 'win' : 'loss'));
    tr.appendChild(mkTd(fmtPct(r.lifetime_pct), r.lifetime_pct >= 0 ? 'win' : 'loss'));
    tr.appendChild(mkTd(fmtINR(r.value)));
    tr.appendChild(mkTd(fmtINR(r.pnl), r.pnl >= 0 ? 'win' : 'loss'));
    tbody.appendChild(tr);
  });
})();
</script>
</body></html>`
