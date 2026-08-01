// Aegis - fleet control plane (local relay).
// Reads per-agent Cloudflare service tokens from aegis.config.json and:
//  - proxies read/control HTTP calls to each agent's webchat API (CF-Access-Client-* headers), and
//  - relays a WebSocket command channel to an agent's chat WS, streaming frames back to the browser.
// Every command send is appended to aegis-audit.jsonl (hash + length, never raw prompt).
// Binds loopback only; the operator reaches it locally (a fronting tunnel/Access is added at VM lift).

const http = require('http');
const https = require('https');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { WebSocketServer, WebSocket } = require('ws');

const PORT = parseInt(process.env.AEGIS_PORT || '7070', 10);
const HOST = process.env.AEGIS_BIND || '127.0.0.1';
const CFG = path.join(__dirname, 'aegis.config.json');
const AUDIT = path.join(__dirname, 'aegis-audit.jsonl');

if (!fs.existsSync(CFG)) {
  console.error('Missing aegis.config.json - copy aegis.config.example.json, fill in your service tokens.');
  process.exit(1);
}
const CONFIG = JSON.parse(fs.readFileSync(CFG, 'utf8'));
const AGENTS = CONFIG.agents || [];
const byName = {};
for (const a of AGENTS) byName[a.name] = a;

// --- audit: one JSONL line per command; hash + length only, never raw prompt ---
function audit(rec) {
  try {
    fs.appendFileSync(AUDIT, JSON.stringify({ ts: new Date().toISOString(), ...rec }) + '\n');
  } catch (e) { console.error('audit write failed:', e.message); }
}

// --- HTTP proxy to an agent's webchat API (unchanged behavior + service-token headers) ---
function callAgent(agent, method, apiPath, body) {
  return new Promise((resolve) => {
    const data = body != null ? JSON.stringify(body) : null;
    const headers = {
      'CF-Access-Client-Id': agent.clientId,
      'CF-Access-Client-Secret': agent.clientSecret,
      'Accept': 'application/json',
    };
    if (data) { headers['Content-Type'] = 'application/json'; headers['Content-Length'] = Buffer.byteLength(data); }
    const req = https.request({ method, hostname: agent.host, path: apiPath, headers }, (r) => {
      let buf = '';
      r.on('data', c => buf += c);
      r.on('end', () => resolve({ status: r.statusCode, body: buf }));
    });
    req.on('error', (e) => resolve({ status: 0, body: String(e.message) }));
    req.setTimeout(10000, () => { req.destroy(); resolve({ status: 0, body: 'timeout' }); });
    if (data) req.write(data);
    req.end();
  });
}

function readBody(req) {
  return new Promise((resolve) => {
    let b = ''; req.on('data', c => b += c);
    req.on('end', () => { try { resolve(b ? JSON.parse(b) : {}); } catch { resolve({}); } });
  });
}

const server = http.createServer(async (req, res) => {
  if (req.url === '/api/agents' && req.method === 'GET') {
    res.setHeader('Content-Type', 'application/json');
    return res.end(JSON.stringify(AGENTS.map(a => ({ name: a.name, host: a.host, profile: a.profile }))));
  }
  const m = req.url.match(/^\/api\/call\/([^/]+)$/);
  if (m && req.method === 'POST') {
    const agent = byName[decodeURIComponent(m[1])];
    if (!agent) { res.statusCode = 404; return res.end(JSON.stringify({ status: 404, body: 'unknown agent' })); }
    const { method = 'GET', path: apiPath = '/', body = null } = await readBody(req);
    const out = await callAgent(agent, method, apiPath, body);
    res.setHeader('Content-Type', 'application/json');
    return res.end(JSON.stringify(out));
  }
  if (req.url === '/' || req.url === '/index.html') {
    res.setHeader('Content-Type', 'text/html');
    return res.end(fs.readFileSync(path.join(__dirname, 'index.html')));
  }
  res.statusCode = 404; res.end('not found');
});

// --- WS command relay: browser <-> Aegis <-> agent chat WS ---
// Browser connects to  ws://<aegis>/ws/agent/<name> , sends {prompt[, tier]}.
// Aegis opens a client WS to the agent with service-token headers, forwards the prompt,
// and streams the agent's frames back to the browser, each tagged {agent, ...frame}.
const wss = new WebSocketServer({ noServer: true });

server.on('upgrade', (req, socket, head) => {
  const um = req.url.match(/^\/ws\/agent\/([^/?]+)/);
  if (!um) { socket.write('HTTP/1.1 404 Not Found\r\n\r\n'); socket.destroy(); return; }
  const agent = byName[decodeURIComponent(um[1])];
  if (!agent) { socket.write('HTTP/1.1 404 Not Found\r\n\r\n'); socket.destroy(); return; }
  wss.handleUpgrade(req, socket, head, (browserWs) => relay(browserWs, agent));
});

function relay(browserWs, agent) {
  let agentWs = null;
  let closed = false;
  const tell = (obj) => { if (browserWs.readyState === WebSocket.OPEN) browserWs.send(JSON.stringify({ agent: agent.name, ...obj })); };

  browserWs.on('message', (raw) => {
    let msg; try { msg = JSON.parse(raw); } catch { msg = { prompt: String(raw) }; }
    const prompt = (msg.prompt || '').toString();
    if (!prompt.trim()) { tell({ type: 'error', text: 'Empty prompt.' }); tell({ type: 'done' }); return; }

    audit({ agent: agent.name, event: 'command',
            promptSha256: crypto.createHash('sha256').update(prompt).digest('hex'),
            promptLen: prompt.length, status: 'sent' });

    // open a fresh agent WS per command (agents stream one response then we close)
    agentWs = new WebSocket('wss://' + agent.host + '/', {
      headers: { 'CF-Access-Client-Id': agent.clientId, 'CF-Access-Client-Secret': agent.clientSecret },
      handshakeTimeout: 10000,
    });
    agentWs.on('open', () => {
      const out = { prompt };
      if (msg.tier) out.tier = msg.tier;
      agentWs.send(JSON.stringify(out));
    });
    agentWs.on('message', (data) => {
      // pass agent frames straight through, tagged with the agent name
      let frame; try { frame = JSON.parse(data); } catch { frame = { type: 'token', text: String(data) }; }
      tell(frame);
      if (frame.type === 'done' && agentWs) { try { agentWs.close(); } catch {} }
    });
    agentWs.on('error', (e) => { tell({ type: 'error', text: 'agent connect: ' + e.message }); tell({ type: 'done' }); });
    agentWs.on('close', () => { /* command complete; browser stays open for next send */ });
  });

  browserWs.on('close', () => { closed = true; if (agentWs) { try { agentWs.close(); } catch {} } });
  browserWs.on('error', () => { if (agentWs) { try { agentWs.close(); } catch {} } });
}

server.listen(PORT, HOST, () =>
  console.log(`Aegis on http://${HOST}:${PORT}  agents: ${AGENTS.map(a => a.name).join(', ') || '(none - fill aegis.config.json)'}`));
