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
const cfcred = require('./cfcred.js');

const PORT = parseInt(process.env.AEGIS_PORT || '7070', 10);
const HOST = process.env.AEGIS_BIND || '127.0.0.1';
const CFG = path.join(__dirname, 'aegis.config.json');
const AUDIT = path.join(__dirname, 'aegis-audit.jsonl');

if (!fs.existsSync(CFG)) {
  console.error('Missing aegis.config.json - copy aegis.config.example.json, fill in your service tokens.');
  process.exit(1);
}

// Config is re-read from disk on demand so a freshly-registered agent shows up
// on "Refresh fleet" WITHOUT restarting Aegis. loadAgents() is the single source;
// callers never hold a stale array. A parse error keeps the last-good agents so a
// half-written file can't blank the fleet.
let lastGoodAgents = [];
function loadAgents() {
  try {
    const cfg = JSON.parse(fs.readFileSync(CFG, 'utf8'));
    lastGoodAgents = Array.isArray(cfg.agents) ? cfg.agents : [];
  } catch (e) {
    console.error('aegis.config.json re-read failed (' + e.message + ') - keeping last-good fleet');
  }
  return lastGoodAgents;
}
function agentByName(name) {
  return loadAgents().find(a => a && a.name === name) || null;
}
loadAgents(); // warm lastGoodAgents at startup (and validate the file is readable)

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

// --- Provisioning bridge: Aegis spawns fleetctl (agent-fleet-iac) --------------
// Aegis stays a thin console; fleetctl is the single source of truth for provision/
// decommission (caps + budget gates, fire-and-forget, teardown). The Aegis host holds
// CF_ACCOUNT_ID / CF_API_TOKEN / DEPLOYER_OBJECT_ID once (set when starting aegis.js);
// spawned fleetctl inherits them, so there's no per-shell env juggling. FLEET_IAC_ROOT
// points at the agent-fleet-iac checkout.
const os = require('os');
const { spawnSync, spawn } = require('child_process');
// Resolve the agent-fleet-iac checkout: env wins, then aegis.config.json "fleetIacRoot",
// then the sibling ../agent-fleet-iac (the standard workstation layout). Kills the
// per-window env-loss failure: a bare `node aegis.js` finds fleetctl on its own.
const FLEET_IAC_ROOT = (function () {
  if (process.env.FLEET_IAC_ROOT) return process.env.FLEET_IAC_ROOT;
  try { const cfg = JSON.parse(fs.readFileSync(CFG, 'utf8')); if (cfg.fleetIacRoot) return cfg.fleetIacRoot; } catch { /* no config yet */ }
  const sib = path.join(__dirname, '..', 'agent-fleet-iac');
  try { if (fs.existsSync(path.join(sib, 'provision', 'bin', 'fleetctl.js'))) return sib; } catch { /* ignore */ }
  return '';
})();
const NAME_RE = /^[a-z][a-z0-9-]{1,23}$/;

function fleetctlPath() { return path.join(FLEET_IAC_ROOT, 'provision', 'bin', 'fleetctl.js'); }

// Resolve a contract file for <name>. Prefer the persisted agents/<name>.agent.jsonc
// (so --go deletes the real local config); otherwise synthesize a temp contract from
// the request / the aegis.config entry (host -> domain). Temp files are caller-deleted.
function contractBody(name, opts = {}) {
  let { profile, domain } = opts;
  if (!profile || !domain) {
    const a = agentByName(name);
    if (a) { profile = profile || a.profile; if (!domain && a.host) domain = a.host.slice(a.host.indexOf('.') + 1); }
  }
  profile = (profile === 'castor') ? 'castor' : 'keel';
  domain = domain || 'keel-pm.com';
  const body = { contract: 1, name, profile, domain };
  if (opts.operatorEmail && !/[<>\s]/.test(opts.operatorEmail) && opts.operatorEmail.includes('@')) body.operatorEmail = opts.operatorEmail;
  return JSON.stringify(body, null, 2) + '\n';
}
function contractFor(name, opts = {}) {
  const persisted = FLEET_IAC_ROOT ? path.join(FLEET_IAC_ROOT, 'agents', `${name}.agent.jsonc`) : '';
  if (!opts.forceTemp && persisted && fs.existsSync(persisted)) return { file: persisted, temp: false };
  const tmp = path.join(os.tmpdir(), `aegis-${name}-${Date.now()}.agent.jsonc`);
  fs.writeFileSync(tmp, contractBody(name, opts));
  return { file: tmp, temp: true };
}

// Run fleetctl with the host env (CF_* etc.) inherited; AEGIS_CONFIG pinned to our config.
// fleetctl emits plain text when piped (util paint checks isTTY), so no ANSI to strip.
function runFleetctl(args) {
  if (!FLEET_IAC_ROOT) return { code: 2, out: 'FLEET_IAC_ROOT not set — start aegis.js with FLEET_IAC_ROOT=<path to agent-fleet-iac>.' };
  const fp = fleetctlPath();
  if (!fs.existsSync(fp)) return { code: 2, out: `fleetctl not found at ${fp} — check FLEET_IAC_ROOT.` };
  const r = spawnSync('node', [fp, ...args], {
    cwd: FLEET_IAC_ROOT,
    env: { ...process.env, CF_OPERATOR_EMAIL: operatorEmail(), AEGIS_CONFIG: CFG, NO_COLOR: '1' },
    encoding: 'utf8',
    maxBuffer: 8 * 1024 * 1024,
  });
  const out = (r.stdout || '') + (r.stderr ? (r.stdout ? '\n' : '') + r.stderr : '');
  return { code: r.status == null ? 1 : r.status, out };
}

function sendJson(res, obj, status = 200) { res.statusCode = status; res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(obj)); }

// Destructive lanes need real Cloudflare credentials -- a placeholder CF_ACCOUNT_ID silently
// orphaned heimdall's tunnel/DNS/Access/token during teardown. Fail closed with the exact fix.
function operatorEmail() {
  try { const c = JSON.parse(fs.readFileSync(CFG, 'utf8')); return (process.env.CF_OPERATOR_EMAIL || c.operatorEmail || '').trim(); }
  catch { return (process.env.CF_OPERATOR_EMAIL || '').trim(); }
}
function cfEnvProblem() {
  // Delegates to cfcred: 'ok' only after Cloudflare's live tokens/verify said
  // success + active at boot. Everything else carries the exact loud reason.
  return cfcred.state.ok ? '' : cfcred.state.reason;
}

// Stream a long-running fleetctl command over the HTTP response (chunked text). extraEnv is
// merged into the CHILD env only -- used for seed secrets, which are never persisted by Aegis
// and never appear in argv (so no shell history / process-listing exposure).
function streamFleetctl(res, args, extraEnv, onDone) {
  const fp = fleetctlPath();
  res.statusCode = 200;
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache');
  const child = spawn('node', [fp, ...args], {
    cwd: FLEET_IAC_ROOT,
    env: { ...process.env, CF_OPERATOR_EMAIL: operatorEmail(), ...(extraEnv || {}), AEGIS_CONFIG: CFG, NO_COLOR: '1' },
  });
  // Heartbeat: long Azure operations (RG create/delete) buffer for minutes with zero output;
  // a silent socket is where the heimdall-teardown stream died. Emit a liveness line whenever
  // the child has been quiet >20s -- keeps the connection warm and the operator informed.
  const t0 = Date.now(); let lastOut = Date.now();
  const beat = setInterval(() => {
    if (child.exitCode !== null) return;
    if (Date.now() - lastOut > 20000) {
      res.write('\n[still running — ' + Math.round((Date.now() - t0) / 1000) + 's elapsed; long Azure steps buffer their output]\n');
      lastOut = Date.now();
    }
  }, 5000);
  child.stdout.on('data', (d) => { lastOut = Date.now(); res.write(d); });
  child.stderr.on('data', (d) => { lastOut = Date.now(); res.write(d); });
  child.on('close', (code) => { clearInterval(beat); try { if (onDone) onDone(code); } catch { /* ignore */ } res.write('\n[fleetctl exit ' + code + ']\n'); res.end(); });
  child.on('error', (e) => { clearInterval(beat); res.write('\n[spawn error] ' + e.message + '\n'); res.end(); });
}

// Panel-facing cleanup for plan output: the panel has its own Execute UI, so strip the
// CLI "To EXECUTE … --go" hint, and relativize machine-absolute paths (FLEET_IAC_ROOT
// and the temp dir) so the panel never shows a non-portable local path.
function panelClean(out) {
  let s = String(out || '');
  for (const base of [FLEET_IAC_ROOT, os.tmpdir()]) {
    if (base) s = s.split(base + '\\').join('').split(base + '/').join('').split(base).join('');
  }
  const cut = s.indexOf('  To EXECUTE');
  if (cut >= 0) s = s.slice(0, cut).replace(/\s+$/, '') + '\n';
  return s;
}

const server = http.createServer(async (req, res) => {
  if (req.url === '/api/agents' && req.method === 'GET') {
    res.setHeader('Content-Type', 'application/json');
    // fresh read every call -> "Refresh fleet" reflects aegis.config.json now
    return res.end(JSON.stringify(loadAgents().map(a => ({ name: a.name, host: a.host, profile: a.profile }))));
  }
  if (req.url === '/api/reload' && req.method === 'POST') {
    const names = loadAgents().map(a => a.name);
    res.setHeader('Content-Type', 'application/json');
    return res.end(JSON.stringify({ ok: true, count: names.length, agents: names }));
  }
  const m = req.url.match(/^\/api\/call\/([^/]+)$/);
  if (m && req.method === 'POST') {
    const agent = agentByName(decodeURIComponent(m[1]));
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
  // --- Policy tab: attested governance gate (P2b). The fleetctl CLI is the ONLY
  // gate -- Aegis adds no second validator, it surfaces the CLI's verdict verbatim.
  if (req.url === '/api/policy/show' && req.method === 'GET') {
    const r = runFleetctl(['policy', 'show']);
    return sendJson(res, { ok: r.code === 0, out: panelClean(r.out) });
  }
  if (req.url === '/api/policy/set' && req.method === 'POST') {
    const b = await readBody(req);
    const key = String(b.key || '').trim();
    const value = String(b.value || '').trim();
    const attest = String(b.attest || '');
    const r = runFleetctl(['policy', 'set', key, value, '--attest', attest]);
    audit({ action: 'policy-set', key, value, outcome: r.code === 0 ? 'ok' : 'refused-or-error', via: 'panel' });
    return sendJson(res, { ok: r.code === 0, code: r.code, out: panelClean(r.out) });
  }
  // Merged attestation timeline: Aegis actions + the fleetctl policy ledger, newest first.
  if (req.url === '/api/attestations' && req.method === 'GET') {
    const rows = [];
    const pull = (file, sourceTag) => {
      try {
        for (const line of fs.readFileSync(file, 'utf8').trim().split('\n').slice(-40)) {
          try { rows.push({ source: sourceTag, ...JSON.parse(line) }); } catch { /* skip bad line */ }
        }
      } catch { /* file absent is fine */ }
    };
    pull(AUDIT, 'aegis');
    if (FLEET_IAC_ROOT) pull(path.join(FLEET_IAC_ROOT, 'provision', 'policy-audit.jsonl'), 'fleetctl');
    rows.sort((a, b2) => String(b2.ts || '').localeCompare(String(a.ts || '')));
    return sendJson(res, { ok: true, rows: rows.slice(0, 25) });
  }

  // Provisioning plan (READ-ONLY): preview `up` + the caps/budget gate for a proposed agent.
  if (req.url === '/api/provision/plan' && req.method === 'POST') {
    const b = await readBody(req);
    const name = String(b.name || '').trim();
    if (!NAME_RE.test(name)) return sendJson(res, { ok: false, out: 'invalid agent name — must match ^[a-z][a-z0-9-]{1,23}$' }, 400);
    const usePersisted = !!b.usePersisted;
    const { file, temp } = contractFor(name, { forceTemp: !usePersisted, profile: b.profile, domain: b.domain, operatorEmail: String(b.operatorEmail || '').trim() });
    const r = runFleetctl(['plan', file]);
    if (temp) { try { fs.unlinkSync(file); } catch { /* best effort */ } }
    audit({ action: 'provision-plan', name, code: r.code });
    return sendJson(res, { ok: r.code === 0, code: r.code, out: panelClean(r.out) });
  }
  // Provision WRITE-CONTRACT: persist agents/<name>.agent.jsonc (secret-free, contract:1).
  // Refuses to overwrite -- an existing contract means a live (or decommissionable) agent;
  // pick a new name or decommission first. This file is what `up --go` runs and what
  // decommission later deletes (the local-config surface).
  if (req.url === '/api/provision/write-contract' && req.method === 'POST') {
    const b = await readBody(req);
    const name = String(b.name || '').trim();
    if (!NAME_RE.test(name)) return sendJson(res, { ok: false, error: 'invalid agent name — must match ^[a-z][a-z0-9-]{1,23}$' }, 400);
    if (!FLEET_IAC_ROOT) return sendJson(res, { ok: false, error: 'FLEET_IAC_ROOT not set' }, 500);
    const file = path.join(FLEET_IAC_ROOT, 'agents', `${name}.agent.jsonc`);
    if (fs.existsSync(file)) return sendJson(res, { ok: false, error: `agents/${name}.agent.jsonc already exists — decommission first or pick a new name` }, 409);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, contractBody(name, { profile: b.profile, domain: b.domain, operatorEmail: String(b.operatorEmail || '').trim() }));
    audit({ action: 'provision-write-contract', name });
    return sendJson(res, { ok: true, file: `agents/${name}.agent.jsonc`, contract: JSON.parse(fs.readFileSync(file, 'utf8')) });
  }
  // Provision SEED: vault-seed the agent's API keys BEFORE `up --go` (bootstrap fetches them
  // at first boot -- a missed seed was part of example-03's failure). Keys are validated here,
  // passed to fleetctl set-secrets via the CHILD env only, never persisted or logged by Aegis.
  if (req.url === '/api/provision/seed' && req.method === 'POST') {
    const b = await readBody(req);
    const name = String(b.name || '').trim();
    if (!NAME_RE.test(name)) return sendJson(res, { ok: false, error: 'invalid agent name' }, 400);
    const anth = String(b.anthropicKey || '').trim();
    const ork = String(b.openrouterKey || '').trim();
    if (!anth || /[<>]/.test(anth) || !anth.startsWith('sk-ant-')) return sendJson(res, { ok: false, error: 'anthropicKey must be a real sk-ant-… key (no placeholders)' }, 400);
    if (!ork || /[<>]/.test(ork) || !ork.startsWith('sk-or-')) return sendJson(res, { ok: false, error: 'openrouterKey must be a real sk-or-… key (no placeholders)' }, 400);
    if (!FLEET_IAC_ROOT || !fs.existsSync(fleetctlPath())) return sendJson(res, { ok: false, error: 'FLEET_IAC_ROOT not set / fleetctl not found' }, 500);
    const persisted = path.join(FLEET_IAC_ROOT, 'agents', `${name}.agent.jsonc`);
    if (!fs.existsSync(persisted)) {
      audit({ action: 'provision-seed', name, outcome: 'refused: no contract' });
      return sendJson(res, { ok: false, error: `no agents/${name}.agent.jsonc — write the contract first` }, 400);
    }
    audit({ action: 'provision-seed', name, phase: 'start' });
    return streamFleetctl(res, ['set-secrets', name], { ANTHROPIC_API_KEY: anth, OPENROUTER_API_KEY: ork }, (code) => audit({ action: 'provision-seed', name, phase: 'done', code }));
  }
  // Provision EXECUTE (CREATES CLOUD RESOURCES): typed attestation `provision <name>`, then
  // streams `fleetctl up <contract> --go` LIVE via async spawn (the decommission-go pattern).
  // up's own preflight stays the fail-closed gate (caps/budget/placeholders): a failing check
  // aborts 'nothing created' before anything bills.
  if (req.url === '/api/provision/go' && req.method === 'POST') {
    const b = await readBody(req);
    const name = String(b.name || '').trim();
    const attest = String(b.attest || '').trim();
    if (!NAME_RE.test(name)) return sendJson(res, { ok: false, error: 'invalid agent name' }, 400);
    const required = 'I approve provisioning ' + name;
    const actor = (os.userInfo().username || 'unknown');
    if (attest !== required) {
      audit({ action: 'provision-go', name, actor, phrase: attest, outcome: 'refused: attestation mismatch' });
      return sendJson(res, { ok: false, error: 'REFUSED — attestation must read exactly:  ' + required }, 403);
    }
    const cfp = cfEnvProblem();
    if (cfp) return sendJson(res, { ok: false, error: cfp }, 400);
    const opEmail = operatorEmail();
    if (!opEmail || /[<>\s]/.test(opEmail) || !opEmail.includes('@')) return sendJson(res, { ok: false, error: 'operator email missing — add "operatorEmail": "you@example.com" to aegis.config.json (the email you log into the agents with), then retry (no restart needed)' }, 400);
    if (!FLEET_IAC_ROOT || !fs.existsSync(fleetctlPath())) return sendJson(res, { ok: false, error: 'FLEET_IAC_ROOT not set / fleetctl not found' }, 500);
    const persisted = path.join(FLEET_IAC_ROOT, 'agents', `${name}.agent.jsonc`);
    if (!fs.existsSync(persisted)) {
      audit({ action: 'provision-go', name, actor, phrase: attest, outcome: 'refused: no contract' });
      return sendJson(res, { ok: false, error: `no agents/${name}.agent.jsonc — write the contract first` }, 400);
    }
    audit({ action: 'provision-go', name, actor, phrase: attest, outcome: 'started' });
    return streamFleetctl(res, ['up', persisted, '--go'], null, (code) => audit({ action: 'provision-go', name, actor, phrase: attest, outcome: code === 0 ? 'done' : 'exit ' + code }));
  }
  // Binary passthrough for the agent EXPORT routes only (xlsx downloads the JSON
  // console proxy would corrupt). Tight allowlist: path must start with /export.
  {
    const fm = req.url.match(/^\/api\/fetch\/([^/?]+)\?path=([^&]+)$/);
    if (fm && req.method === 'GET') {
      const agent = agentByName(decodeURIComponent(fm[1]));
      const p = decodeURIComponent(fm[2]);
      if (!agent) return sendJson(res, { ok: false, error: 'unknown agent' }, 404);
      if (!/^\/export[A-Za-z0-9/_-]*$/.test(p)) return sendJson(res, { ok: false, error: 'only /export* paths are downloadable' }, 400);
      const r2 = https.request({ method: 'GET', hostname: agent.host, path: p, headers: {
        'CF-Access-Client-Id': agent.clientId, 'CF-Access-Client-Secret': agent.clientSecret } }, (ar) => {
        if (ar.statusCode !== 200) { let eb=''; ar.on('data',c=>eb+=c); ar.on('end',()=>sendJson(res,{ok:false,error:'agent returned HTTP '+ar.statusCode,body:String(eb).slice(0,200)},502)); return; }
        res.statusCode = 200;
        res.setHeader('Content-Type', ar.headers['content-type'] || 'application/octet-stream');
        res.setHeader('Content-Disposition', ar.headers['content-disposition'] || ('attachment; filename="' + agent.name + p.replace(/\//g,'-') + '.xlsx"'));
        ar.pipe(res);
      });
      r2.on('error', (e) => sendJson(res, { ok: false, error: 'agent unreachable: ' + e.message }, 502));
      r2.end();
      return;
    }
  }
  // Protection state (authoritative = the workstation policy via the fleetctl CLI).
  if (req.url === '/api/policy/protected' && req.method === 'GET') {
    const r = runFleetctl(['policy', 'show', '--json']);
    let list = []; try { list = JSON.parse(r.out || '{}').protectedAgents || []; } catch { /* unreadable */ }
    return sendJson(res, { ok: r.code === 0, protectedAgents: list });
  }
  // Protection toggle = the SAME attested ceremony, hosted on the card. The server
  // recomputes the new list from the live policy (never trusts the client); the
  // fleetctl CLI stays the sole gate (refusals ledger there); on success the
  // agent's mirror is pushed best-effort so the webchat badge follows.
  if (req.url === '/api/policy/protect-toggle' && req.method === 'POST') {
    const b = await readBody(req);
    const name = String(b.name || '').trim();
    const attest = String(b.attest || '').trim();
    if (!NAME_RE.test(name)) return sendJson(res, { ok: false, error: 'invalid agent name' }, 400);
    const cur = runFleetctl(['policy', 'show', '--json']);
    let list; try { list = JSON.parse(cur.out || '{}').protectedAgents || []; } catch { return sendJson(res, { ok: false, error: 'cannot read policy (fleetctl policy show --json failed)' }, 500); }
    const on = list.includes(name);
    const r = runFleetctl(['policy', on ? 'unprotect' : 'protect', name, '--attest', attest]);
    audit({ action: 'protect-toggle', name, verb: on ? 'unprotect' : 'protect', outcome: r.code === 0 ? 'ok' : 'exit ' + r.code });
    let next = list;
    if (r.code === 0) {
      const rr = runFleetctl(['policy', 'show', '--json']);
      try { next = JSON.parse(rr.out || '{}').protectedAgents || list; } catch { /* keep prior */ }
      const agent = agentByName(name); if (agent) { try { callAgent(agent, 'POST', '/protection', { protected: !on }); } catch { /* unreachable */ } }
    }
    return sendJson(res, { ok: r.code === 0, out: panelClean(r.out), protectedAgents: next });
  }
  // Decommission plan (READ-ONLY): discover which surfaces an agent still occupies.
  if (req.url === '/api/decommission/plan' && req.method === 'POST') {
    const b = await readBody(req);
    const name = String(b.name || '').trim();
    if (!NAME_RE.test(name)) return sendJson(res, { ok: false, out: 'invalid agent name — must match ^[a-z][a-z0-9-]{1,23}$' }, 400);
    const { file, temp } = contractFor(name, { profile: b.profile, domain: b.domain });
    const r = runFleetctl(['decommission', file]); // no --go => read-only discovery
    if (temp) { try { fs.unlinkSync(file); } catch { /* best effort */ } }
    audit({ action: 'decommission-plan', name, code: r.code });
    return sendJson(res, { ok: r.code === 0, code: r.code, out: panelClean(r.out) });
  }
  // Decommission EXECUTE: typed-phrase attested, streamed. The phrase is the gate
  // ("I approve decommissioning <name>", verbatim); a mismatch refuses, mutates
  // nothing, and the refusal is LEDGERED like every other attested attempt. On
  // match, fleetctl decommission --go streams here via async spawn + heartbeat so
  // the panel stays live through the minutes-long blocking RG delete.
  if (req.url === '/api/decommission/go' && req.method === 'POST') {
    const b = await readBody(req);
    const name = String(b.name || '').trim();
    const attest = String(b.attest || '');
    if (!NAME_RE.test(name)) return sendJson(res, { ok: false, out: 'invalid agent name — must match ^[a-z][a-z0-9-]{1,23}$' }, 400);
    const required = 'I approve decommissioning ' + name;
    const actor = (os.userInfo().username || 'unknown');
    if (attest.trim() !== required) {
      audit({ action: 'decommission-go', name, actor, phrase: attest, outcome: 'refused: attestation mismatch' });
      return sendJson(res, { ok: false, out: 'REFUSED — attestation must read exactly:\n  ' + required }, 400);
    }
    const { file } = contractFor(name, {});
    audit({ action: 'decommission-go', name, actor, phrase: attest, outcome: 'started' });
    return streamFleetctl(res, ['decommission', file, '--go'], null,
      (code) => audit({ action: 'decommission-go', name, actor, phrase: attest, outcome: code === 0 ? 'done' : 'exit ' + code }));
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
  const agent = agentByName(decodeURIComponent(um[1]));
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
    agentWs.on('error', (e) => {
      const m = String(e.message || '');
      let hint = '';
      if (/530/.test(m)) hint = ` — ${agent.name} unreachable: tunnel down (VM deallocated?). Start it: az vm start -g rg-${agent.name} -n ${agent.name}-vm`;
      else if (/502/.test(m)) hint = ` — ${agent.name} tunnel is up but nothing listens yet (agent starting or containers down)`;
      tell({ type: 'error', text: 'agent connect: ' + m + hint }); tell({ type: 'done' });
    });
    agentWs.on('close', () => { /* command complete; browser stays open for next send */ });
  });

  browserWs.on('close', () => { closed = true; if (agentWs) { try { agentWs.close(); } catch {} } });
  browserWs.on('error', () => { if (agentWs) { try { agentWs.close(); } catch {} } });
}

let bootCfg = {};
try { bootCfg = JSON.parse(fs.readFileSync(CFG, 'utf8')); } catch { /* loadAgents already warned */ }
cfcred.resolve(bootCfg, () =>
  server.listen(PORT, HOST, () =>
    console.log(`Aegis on http://${HOST}:${PORT}  agents: ${loadAgents().map(a => a.name).join(', ') || '(none - fill aegis.config.json)'}  \u00b7  fleetctl: ${FLEET_IAC_ROOT || 'MISSING (set FLEET_IAC_ROOT or aegis.config.json fleetIacRoot)'}  \u00b7  cf: ${cfEnvProblem() ? 'NOT READY (' + cfEnvProblem() + ')' : 'ok \u00b7 token: ' + cfcred.state.source}`)));
