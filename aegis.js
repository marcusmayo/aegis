#!/usr/bin/env node
// Minimal Aegis - local fleet control panel. Zero dependencies (Node built-ins).
// Reads per-agent Cloudflare service tokens from aegis.config.json and proxies
// read/control calls to each agent's webchat API, adding CF-Access-Client-Id /
// CF-Access-Client-Secret so Access lets the machine call through to the agent's
// machine-auth. Secrets stay in this process; the browser only talks to the proxy.
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');

const PORT = process.env.AEGIS_PORT || 4600;
const CFG = path.join(__dirname, 'aegis.config.json');
if (!fs.existsSync(CFG)) {
  console.error('Missing aegis.config.json - copy aegis.config.example.json, fill in your service tokens.');
  process.exit(1);
}
const CONFIG = JSON.parse(fs.readFileSync(CFG, 'utf8'));
const AGENTS = CONFIG.agents || [];
const byName = Object.fromEntries(AGENTS.map(a => [a.name, a]));

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

http.createServer(async (req, res) => {
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
}).listen(PORT, () => console.log(`Aegis on http://localhost:${PORT}  agents: ${AGENTS.map(a => a.name).join(', ') || '(none - fill aegis.config.json)'}`));
