package mcp

import (
	"context"
	"os"
)

// ipWhitelistWidgetData returns the deployment's static egress IP
// plus instructions for Kite developer console whitelisting. SEBI's
// April 2026 retail-algo framework requires IP whitelisting for
// order-placement API calls — without it, the first place_order
// returns a Kite 403. This widget surfaces:
//
//   - the canonical static egress IP for the Fly.io bom region
//     (209.71.68.157 — verified from kc-deployment memory);
//   - the override value if operator set FLY_EGRESS_IP env var
//     (for non-bom regions or ephemeral-tunnel dev setups);
//   - the Kite developer-console URL for the whitelisting flow;
//   - a one-line status line indicating "you must whitelist this IP
//     before order-placement will succeed".
//
// Zero live-state lookup — this widget is a pure documentation panel.
// Deliberate: probing the Kite API from here would be a wasted
// round-trip (a 403 from Kite is the only reliable signal of
// un-whitelisted IP, and we only learn that by placing a real order).
// The widget exists to tell the user WHAT to do; they verify the
// outcome by placing a test order.
func ipWhitelistWidgetData(_ context.Context, _ extAppManagerPort, email string) any {
	// Static egress IP baseline — the actual Fly.io bom-region IP
	// assigned to app kite-mcp-server. Operators running a different
	// region set FLY_EGRESS_IP.
	egressIP := os.Getenv("FLY_EGRESS_IP")
	if egressIP == "" {
		egressIP = "209.71.68.157"
	}

	// Kite developer-console URL. Kept as a constant because it's a
	// stable landing page — Zerodha hasn't changed the /apps path in
	// this codebase's lifetime.
	consoleURL := "https://kite.trade/connect/login"

	status := "action-required"
	if email == "" {
		status = "unauthenticated"
	}

	return map[string]any{
		"egress_ip":         egressIP,
		"kite_console_url":  consoleURL,
		"status":            status,
		"requirement":       "SEBI Apr 2026 — retail-algo framework requires IP whitelisting on every Kite developer app used for order placement.",
		"steps": []string{
			"Open your Kite developer console and locate your app.",
			"Add " + egressIP + " to the 'Whitelisted IPs' field.",
			"Save. First subsequent place_order call should succeed (instead of 403).",
		},
	}
}

// ipWhitelistTemplateHTML is a two-panel card: big IP readout with a
// copy button, and a three-step walkthrough. Safe DOM APIs only.
const ipWhitelistTemplateHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="color-scheme" content="dark light">
<title>IP Whitelist Status</title>
<style>
:root { --bg:#0a0c10; --bg2:#161b24; --fg:#e2e8f0; --fg2:#94a3b8; --accent:#22d3ee; --amber:#fbbf24; --red:#f87171; --border:#252d3a; --mono:'SF Mono',Consolas,monospace; }
html.light { --bg:#fff; --bg2:#f1f5f9; --fg:#0f172a; --fg2:#475569; --border:#e2e8f0; }
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--fg);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;padding:16px;font-size:13px}
.hdr{display:flex;justify-content:space-between;align-items:center;margin-bottom:14px}
.hdr h1{font-size:14px;font-weight:600}
.muted{color:var(--fg2)}
.ip-card{background:var(--bg2);border:1px solid var(--amber);border-radius:6px;padding:14px;display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
.ip-label{font-size:11px;color:var(--fg2);text-transform:uppercase;letter-spacing:0.06em;margin-bottom:4px}
.ip-value{font-family:var(--mono);font-size:22px;font-weight:600;color:var(--accent);letter-spacing:0.02em}
button{background:var(--accent);color:var(--bg);border:none;padding:6px 10px;border-radius:4px;font-family:var(--mono);font-size:11px;cursor:pointer}
button:hover{opacity:0.8}
.require{background:rgba(251,191,36,0.08);border:1px solid var(--amber);border-radius:6px;padding:10px 12px;font-size:12px;color:var(--amber);margin-bottom:12px}
.steps{background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:14px}
.steps h2{font-size:12px;color:var(--fg2);text-transform:uppercase;letter-spacing:0.06em;margin-bottom:8px}
.steps ol{padding-left:18px;font-size:12px}
.steps li{margin-bottom:6px}
.link{color:var(--accent);text-decoration:none}
.link:hover{text-decoration:underline}
</style></head><body>
<div class="hdr"><h1>IP Whitelist Status</h1><span class="muted">SEBI compliance</span></div>
<div id="require-slot"></div>
<div class="ip-card">
  <div>
    <div class="ip-label">Server egress IP</div>
    <div class="ip-value" id="ip">--</div>
  </div>
  <button id="copy">copy</button>
</div>
<div class="steps" id="steps"></div>
<script>
const DATA = "__INJECTED_DATA__";
(function(){
  const ipEl = document.getElementById('ip');
  const copy = document.getElementById('copy');
  const steps = document.getElementById('steps');
  const requireSlot = document.getElementById('require-slot');

  function mkDiv(cls, text){ const d = document.createElement('div'); if (cls) d.className = cls; if (text !== undefined) d.textContent = text; return d; }
  function mkEl(tag, cls, text){ const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; }

  if (!DATA) { ipEl.textContent = 'unavailable'; return; }
  ipEl.textContent = DATA.egress_ip || '--';

  if (DATA.requirement) {
    requireSlot.appendChild(mkDiv('require', DATA.requirement));
  }

  const h2 = mkEl('h2', '', 'Three-step setup');
  steps.appendChild(h2);
  const ol = document.createElement('ol');
  (DATA.steps || []).forEach(s => {
    ol.appendChild(mkEl('li', '', s));
  });
  steps.appendChild(ol);

  if (DATA.kite_console_url) {
    const a = document.createElement('a');
    a.className = 'link';
    a.href = DATA.kite_console_url;
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    a.textContent = 'Open Kite developer console \u2192';
    const p = mkEl('p', '', '');
    p.style.marginTop = '10px';
    p.appendChild(a);
    steps.appendChild(p);
  }

  copy.addEventListener('click', function(){
    navigator.clipboard && navigator.clipboard.writeText(DATA.egress_ip || '').then(function(){
      copy.textContent = 'copied!';
      setTimeout(function(){ copy.textContent = 'copy'; }, 1500);
    });
  });
})();
</script>
</body></html>`
