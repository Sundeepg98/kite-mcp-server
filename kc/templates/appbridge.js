// AppBridge v1.0 — MCP UI JSON-RPC bridge for Kite widgets
// Canonical source. Do not edit AppBridge inline in widget HTML files.
// To update: edit this file, then copy the AppBridge block into each *_app.html.
//
// Exports: init, callServerTool, openLink, notifySize,
//          sendMessage, updateModelContext, requestDisplayMode, downloadFile,
//          isIframe (getter)

const AppBridge = (() => {
  const isIframe = window.parent !== window;
  let nextId = 1;
  const pending = new Map();
  let hostContext = null;

  if (isIframe) {
    window.addEventListener('message', (event) => {
      if (event.source !== window.parent) return;
      let msg;
      try {
        msg = typeof event.data === 'string' ? JSON.parse(event.data) : event.data;
      } catch (e) { return; }
      if (!msg || msg.jsonrpc !== '2.0') return;

      if (msg.id != null && pending.has(msg.id)) {
        const {resolve, reject} = pending.get(msg.id);
        pending.delete(msg.id);
        if (msg.error) reject(new Error(msg.error.message || 'RPC error'));
        else resolve(msg.result);
        return;
      }

      if (msg.method === 'ping' && msg.id != null) {
        window.parent.postMessage({jsonrpc: '2.0', id: msg.id, result: {}}, '*');
        return;
      }

      if (msg.method === 'ui/resource-teardown' && msg.id != null) {
        window.parent.postMessage({jsonrpc: '2.0', id: msg.id, result: {}}, '*');
        return;
      }

      if (msg.method === 'ui/notifications/host-context-changed' && msg.params) {
        hostContext = Object.assign({}, hostContext, msg.params);
        applyHostTheme(hostContext);
      }
    });
  }

  function sendRequest(method, params) {
    if (!isIframe) return Promise.reject(new Error('Not in iframe'));
    return new Promise((resolve, reject) => {
      const id = nextId++;
      pending.set(id, {resolve, reject});
      window.parent.postMessage({jsonrpc: '2.0', id, method, params}, '*');
      setTimeout(() => {
        if (pending.has(id)) { pending.delete(id); reject(new Error('Timeout')); }
      }, 30000);
    });
  }

  async function init() {
    if (!isIframe) return null;
    const result = await sendRequest('ui/initialize', {
      protocolVersion: '2026-01-26',
      appInfo: { name: 'Kite Widget', version: '1.0.0' },
      appCapabilities: {},
    });
    hostContext = result.hostContext || null;
    if (hostContext) applyHostTheme(hostContext);
    window.parent.postMessage({jsonrpc: '2.0', method: 'ui/notifications/initialized'}, '*');
    return result;
  }

  async function callServerTool(name, args) {
    const result = await sendRequest('tools/call', { name, arguments: args || {} });
    if (result && result.content && result.content[0] && result.content[0].text) {
      try { return JSON.parse(result.content[0].text); } catch(e) {}
      return result.content[0].text;
    }
    return result;
  }

  function openLink(url) {
    if (!isIframe) { window.open(url, '_blank'); return; }
    sendRequest('ui/open-link', { url }).catch(() => window.open(url, '_blank'));
  }

  function applyHostTheme(ctx) {
    if (!ctx) return;
    if (ctx.theme === 'light') document.documentElement.classList.add('light');
    else document.documentElement.classList.remove('light');
  }

  function notifySize() {
    if (!isIframe) return;
    window.parent.postMessage({
      jsonrpc: '2.0',
      method: 'ui/notifications/size-changed',
      params: { width: document.documentElement.scrollWidth, height: document.documentElement.scrollHeight }
    }, '*');
  }

  if (typeof ResizeObserver !== 'undefined') {
    let resizeTimer;
    new ResizeObserver(() => {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(() => notifySize(), 100);
    }).observe(document.body);
  }

  async function sendMessage(text) {
    return sendRequest('ui/message', {
      role: 'user',
      content: [{ type: 'text', text }]
    });
  }

  async function updateModelContext(text) {
    return sendRequest('ui/update-model-context', {
      content: [{ type: 'text', text }]
    });
  }

  async function requestDisplayMode(mode) {
    return sendRequest('ui/request-display-mode', { mode });
  }

  async function downloadFile(filename, mimeType, data) {
    return sendRequest('ui/download-file', { filename, mimeType, data: btoa(data) });
  }

  return { init, callServerTool, openLink, notifySize,
    sendMessage, updateModelContext, requestDisplayMode, downloadFile,
    get isIframe() { return isIframe; } };
})();
