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
const telegram = require('./telegram.js');

const PORT = parseInt(process.env.AEGIS_PORT || '7070', 10);
const HOST = process.env.AEGIS_BIND || '127.0.0.1';
const CFG = path.join(__dirname, 'aegis.config.json');
const AUDIT = path.join(__dirname, 'aegis-audit.jsonl');

// A missing registry is a WARNING, not an exit: under systemd an exit here is a restart loop
// (found on the hosted plane's first boot -- 150s of ExecStartPre per attempt, restart counter
// climbing, nothing wrong with the unit). The control plane can exist before its first agent;
// the panel shows an empty fleet and the enroll lane fills the registry, no restart needed.
if (!fs.existsSync(CFG)) {
  console.error('aegis.config.json not found at ' + CFG + ' - starting with an EMPTY fleet. Enroll agents with `fleetctl enroll <agent>` (or copy aegis.config.example.json for a workstation plane).');
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
    // absent registry: already warned at boot; anything else (bad JSON) is worth repeating
    if (e && e.code !== 'ENOENT') console.error('aegis.config.json re-read failed (' + e.message + ') - keeping last-good fleet');
  }
  return lastGoodAgents;
}
function agentByName(name) {
  return loadAgents().find(a => a && a.name === name) || null;
}
loadAgents(); // warm lastGoodAgents at startup (and validate the file is readable)

// --- actor: WHO did this, resolved per transport --------------------------------
// The prior derivation was os.userInfo().username -- the OS user of the AEGIS
// PROCESS, not the requester. On a workstation that happens to be the operator and
// reads correctly; on a hosted VM it collapses to the service account and is
// IDENTICAL for every action by every person while still LOOKING like an identity.
// A field that is confidently wrong is worse than an absent one, so this resolver
// NEVER falls back to the process owner for a request that did not arrive on
// loopback: an unattributable remote action is recorded as unattributed.
//
// Edge-trust model (matches fleet-core auth.js): Cloudflare Access terminates
// authentication and forwards only verified requests, so the assertion headers are
// taken at face value. That holds ONLY while the origin is unreachable except via
// the tunnel -- a hosted Aegis MUST stay bound to loopback with cloudflared dialing
// it locally. Binding 0.0.0.0 would make every header below attacker-supplied.
// (Verifying the JWT against Cloudflare's JWKS is the hardening step if that
// invariant ever has to relax.)
function isLoopback(req) {
  const a = String((req && req.socket && req.socket.remoteAddress) || '');
  return a === '127.0.0.1' || a === '::1' || a === '::ffff:127.0.0.1';
}
function jwtClaim(token) {
  try {
    const parts = String(token || '').split('.');
    if (parts.length !== 3) return null;
    const pad = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const claims = JSON.parse(Buffer.from(pad, 'base64').toString('utf8'));
    return claims.email || claims.common_name || null;  // human login, else service-token name
  } catch (e) { return null; }
}
// override lets a non-HTTP transport (the Telegram relay) supply its own identity,
// so actor stays meaningful across every way a command can reach the fleet.
function actorOf(req, override) {
  const cap = (v) => String(v).slice(0, 200);
  if (override && override.src && override.id) return { src: cap(override.src), id: cap(override.id) };
  const h = (req && req.headers) || {};
  const claim = jwtClaim(h['cf-access-jwt-assertion']);
  if (claim) return { src: 'cf-access', id: cap(claim) };
  if (h['cf-access-authenticated-user-email']) return { src: 'cf-access', id: cap(h['cf-access-authenticated-user-email']) };
  if (h['cf-access-client-id']) return { src: 'cf-access', id: cap(h['cf-access-client-id']) };
  if (isLoopback(req)) return { src: 'local', id: cap(os.userInfo().username || 'unknown') };
  return { src: 'unknown', id: 'unattributed' };
}

// --- audit: one JSONL line per command; hash + length only, never raw prompt -----
// Tamper-evident chain: every record carries seq + prev + hash, where hash covers
// the record with hash itself omitted and is written LAST. Verification is then
// exactly: parse, delete hash, re-stringify, compare. Editing or deleting any
// earlier line breaks every hash after it -- the ledger cannot be quietly rewritten.
// Records written before this change carry no hash; the chain starts at the first
// record that does and earlier lines are left byte-untouched, because rewriting
// history so it verifies is precisely the tamper this exists to detect.
let CHAIN = { seq: 0, hash: 'genesis' };
function initChain() {
  let lines = [];
  try { lines = fs.readFileSync(AUDIT, 'utf8').trim().split('\n').filter(Boolean); }
  catch (e) { return; }
  for (let i = lines.length - 1; i >= 0; i--) {
    try {
      const r = JSON.parse(lines[i]);
      if (r && r.hash && typeof r.seq === 'number') { CHAIN = { seq: r.seq, hash: r.hash }; return; }
    } catch (e) { /* skip unreadable line */ }
  }
  if (lines.length) CHAIN = { seq: 0, hash: 'genesis-after-' + lines.length + '-unchained' };
}
function audit(rec) {
  try {
    const body = { ts: new Date().toISOString(), seq: CHAIN.seq + 1, prev: CHAIN.hash, ...rec };
    const hash = crypto.createHash('sha256').update(JSON.stringify(body)).digest('hex');
    fs.appendFileSync(AUDIT, JSON.stringify({ ...body, hash }) + '\n');
    CHAIN = { seq: body.seq, hash };
  } catch (e) { console.error('audit write failed:', e.message); }
}
function verifyChain() {
  const out = { ok: true, checked: 0, unchained: 0, chainStart: null, chainEnd: null, broken: null };
  let lines = [];
  try { lines = fs.readFileSync(AUDIT, 'utf8').trim().split('\n').filter(Boolean); }
  catch (e) { return out; }
  let expectedPrev = null;
  for (let i = 0; i < lines.length; i++) {
    let r; try { r = JSON.parse(lines[i]); } catch (e) { out.unchained++; continue; }
    if (!r || !r.hash) { out.unchained++; continue; }
    if (expectedPrev !== null && r.prev !== expectedPrev) {
      out.ok = false; out.broken = { line: i + 1, seq: r.seq, reason: 'prev does not match preceding hash' };
      return out;
    }
    const body = { ...r }; delete body.hash;
    const calc = crypto.createHash('sha256').update(JSON.stringify(body)).digest('hex');
    if (calc !== r.hash) {
      out.ok = false; out.broken = { line: i + 1, seq: r.seq, reason: 'record hash mismatch (line edited)' };
      return out;
    }
    if (out.chainStart === null) out.chainStart = r.seq;
    out.chainEnd = r.seq;
    expectedPrev = r.hash;
    out.checked++;
  }
  return out;
}
initChain();

// --- HTTP proxy to an agent's webchat API (unchanged behavior + service-token headers) ---
// DELEGATION, stated honestly. Cloudflare validates our SERVICE TOKEN at the agent's
// edge, so the agent can verify that AEGIS called it -- the JWT it receives carries the
// token's common_name, never the operator's. Whoever asked Aegis to make the call is
// something only Aegis knows, and the agent cannot check it.
// So we forward it as an explicit ASSERTION on its own header rather than letting it
// masquerade as the authenticated caller. The agent records the two separately
// (actor = verified caller, onBehalfOf = our unverified claim). Collapsing them into
// one field would produce a confident, unfalsifiable identity -- the same failure as
// os.userInfo(), one layer down. The trust boundary stays visible in the ledger.
function callAgent(agent, method, apiPath, body, onBehalfOf) {
  return new Promise((resolve) => {
    const data = body != null ? JSON.stringify(body) : null;
    const headers = {
      'CF-Access-Client-Id': agent.clientId,
      'CF-Access-Client-Secret': agent.clientSecret,
      'Accept': 'application/json',
    };
    if (onBehalfOf && onBehalfOf.src && onBehalfOf.id) {
      // src:id -- neither field may contain a colon, CR, or LF (header-splitting guard).
      const clean = (v) => String(v).replace(/[^\x20-\x7e]/g, '').replace(/:/g, '_').slice(0, 200);
      headers['X-Aegis-On-Behalf-Of'] = clean(onBehalfOf.src) + ':' + clean(onBehalfOf.id);
    }
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

// Concurrent provisioning admission: policy maxBatch caps SIMULTANEOUS up --go runs
// (the per-run gate inside up.js only sees its own batch of 1). Registry is in-memory;
// entries clear on stream close/error, so a crashed aegis restart clears the ledger too.
const ACTIVE_GO = new Map();

// fleetctl's attested-acts ledger lives next to the policy file it belongs to (the live copy
// on a hosted plane, the checkout on a workstation). The checkout location is also read when
// it differs, so records written before a plane's policy moved are never lost to the view.
function fleetctlLedgerFiles() {
  const out = [];
  try {
    const pol = require(path.join(FLEET_IAC_ROOT, 'provision', 'lib', 'policy.js'));
    const p = pol.resolvePolicyPath();
    if (p) out.push(path.join(path.dirname(p), 'policy-audit.jsonl'));
  } catch (e) { /* no policy module */ }
  if (FLEET_IAC_ROOT) { const legacy = path.join(FLEET_IAC_ROOT, 'provision', 'policy-audit.jsonl'); if (!out.includes(legacy)) out.push(legacy); }
  return out.filter((f) => fs.existsSync(f));
}
function readJsonl(file) {
  try { return fs.readFileSync(file, 'utf8').trim().split('\n').filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean); }
  catch { return []; }
}
// Printable audit export: one self-contained HTML document the browser prints to PDF.
// Three ledgers, three sections, deliberately NOT merged -- the control plane records what was
// commanded, fleetctl records what was attested against policy, each agent records what it did;
// they are separate chains in separate trust domains and a merged stream would imply a single
// verifiable history that does not exist. Every section states its own verification result.
const escapeHtml = (v) => String(v == null ? '' : v).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
function who(a) { if (!a) return ''; if (typeof a === 'string') return a; return (a.label || a.id || '?') + (a.src ? ' [' + a.src + ']' : ''); }
async function buildAuditExport(actor) {
  const gen = new Date().toISOString();
  const plane = planeName();
  const chain = verifyChain();
  const cp = readJsonl(AUDIT);
  const fl = fleetctlLedgerFiles().flatMap((f) => readJsonl(f).map((r) => ({ ...r, _file: path.basename(path.dirname(f)) + '/' + path.basename(f) })));
  fl.sort((a, b) => String(a.ts || '').localeCompare(String(b.ts || '')));
  const agents = loadAgents();
  const agentBlocks = [];
  for (const a of agents) {
    let ver = null, rows = [], err = '';
    try { const v = await callAgent(a, 'GET', '/audit-verify', null, actor); ver = v && v.status === 200 ? (JSON.parse(v.body || '{}').chain || null) : null; if (!v || v.status !== 200) err = 'audit-verify HTTP ' + (v && v.status); } catch (e) { err = 'unreachable: ' + String(e.message || e).slice(0, 80); }
    try { const r = await callAgent(a, 'GET', '/audit-recent?limit=500', null, actor); rows = r && r.status === 200 ? (JSON.parse(r.body || '{}').rows || []) : []; } catch { /* keep err */ }
    agentBlocks.push({ name: a.name, profile: a.profile, host: a.host, ver, rows, err });
  }
  const css = 'body{font:12px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color:#111;margin:24px;max-width:1100px}h1{font-size:18px;margin:0 0 4px}h2{font-size:15px;margin:22px 0 6px;border-bottom:1px solid #999;padding-bottom:3px;page-break-before:always}h2.first{page-break-before:auto}.meta{color:#444;font-size:11px}table{border-collapse:collapse;width:100%;margin-top:6px}th,td{border:1px solid #bbb;padding:3px 5px;text-align:left;vertical-align:top;font-size:11px;word-break:break-word}th{background:#eee}.ok{color:#0a7f2e;font-weight:700}.bad{color:#b00020;font-weight:700}.note{background:#f4f4f4;border:1px solid #ddd;padding:6px 8px;font-size:11px;margin:6px 0}@media print{body{margin:10mm}h2{page-break-before:always}h2.first{page-break-before:auto}.noprint{display:none}}';
  const th = (cols) => '<tr>' + cols.map((c) => '<th>' + escapeHtml(c) + '</th>').join('') + '</tr>';
  const td = (cells) => '<tr>' + cells.map((c) => '<td>' + escapeHtml(c) + '</td>').join('') + '</tr>';
  let h = '<!doctype html><html><head><meta charset="utf-8"><title>Aegis audit export · ' + escapeHtml(plane) + ' · ' + escapeHtml(gen) + '</title><style>' + css + '</style></head><body>';
  h += '<h1>Aegis audit export — control plane <b>' + escapeHtml(plane) + '</b></h1><div class="meta">generated ' + escapeHtml(gen) + ' by ' + escapeHtml(who(actor)) + ' · agents: ' + escapeHtml(agents.map((a) => a.name).join(', ') || 'none') + '</div>';
  h += '<div class="note">Three ledgers, three sections, deliberately not merged. The control plane records what was <b>commanded</b>; fleetctl records what was <b>attested against policy</b>; each agent records what it <b>did</b>. They are separate chains in separate trust domains and neither can rewrite another, so no single merged history exists to print. Actor labels are readable names for verified identities; the recorded id is the fact.</div>';
  h += '<button class="noprint" onclick="window.print()" style="margin:8px 0;padding:6px 14px">Print / save as PDF</button>';
  // 1 control plane
  h += '<h2 class="first">1. Control plane ledger — aegis-audit.jsonl</h2><div class="meta">chain: ' + (chain.ok ? '<span class="ok">VERIFIED</span>' : '<span class="bad">BROKEN' + (chain.broken ? ' at seq ' + escapeHtml(chain.broken.seq) + ' — ' + escapeHtml(chain.broken.reason) : '') + '</span>') + ' · ' + escapeHtml(chain.checked || 0) + ' chained' + (chain.unchained ? ' · ' + escapeHtml(chain.unchained) + ' pre-chain' : '') + ' · ' + cp.length + ' records</div>';
  h += '<table>' + th(['seq', 'ts', 'action / event', 'agent', 'outcome / status', 'actor', 'detail']) + cp.map((x) => td([x.seq !== undefined ? '#' + x.seq : '', x.ts, x.action || x.event || '', x.name || x.agent || '', x.outcome || x.status || '', who(x.actor), [x.phrase ? '«' + x.phrase + '»' : '', x.key ? 'key ' + x.key : '', x.from && x.to && typeof x.from === 'string' ? x.from + '>' + x.to : '', x.mode ? 'mode ' + x.mode : '', x.via ? 'via ' + x.via : ''].filter(Boolean).join(' · ')])).join('') + '</table>';
  // 2 fleetctl
  h += '<h2>2. fleetctl attested acts — policy-audit.jsonl</h2><div class="meta">' + fl.length + ' records · files: ' + escapeHtml([...new Set(fl.map((r) => r._file))].join(', ') || 'none') + ' · append-only, not hash-chained (attested acts against policy; the control plane\'s chain above records who commanded them)</div>';
  h += '<table>' + th(['ts', 'action', 'key / name', 'from → to', 'outcome', 'actor', 'attestation']) + fl.map((x) => td([x.ts, x.action || '', [x.key, x.name].filter(Boolean).join(' / '), (x.from !== undefined || x.to !== undefined) ? (JSON.stringify(x.from) + ' → ' + JSON.stringify(x.to)) : (x.role ? x.role + (x.scope ? ' @ ' + x.scope : '') : ''), x.outcome || '', x.actor || '', x.phrase || ''])).join('') + '</table>';
  // 3 agents
  for (const b of agentBlocks) {
    h += '<h2>3. Agent chain — ' + escapeHtml(b.name) + ' (' + escapeHtml(b.profile || '?') + ') — logs/audit.jsonl</h2>';
    h += '<div class="meta">' + (b.err ? '<span class="bad">' + escapeHtml(b.err) + '</span>' : (b.ver ? (b.ver.ok ? '<span class="ok">chain VERIFIED</span> · ' + escapeHtml(b.ver.length || 0) + ' entries' : '<span class="bad">chain BROKEN at entry ' + escapeHtml(b.ver.brokenAt) + ' of ' + escapeHtml(b.ver.length || 0) + '</span>') : 'chain: unread')) + ' · showing ' + b.rows.length + ' most recent (agent-verified; this document is a copy, the chain stays with the agent)</div>';
    h += '<table>' + th(['ts', 'event', 'route', 'rc', 'duration', 'actor', 'on behalf of', 'detail']) + b.rows.map((x) => td([x.ts, x.event || '', x.route || '', x.exitCode !== undefined && x.exitCode !== null ? x.exitCode : '', x.durationMs !== undefined ? x.durationMs + 'ms' : '', who(x.actor), x.onBehalfOf ? who(x.onBehalfOf) : '', [x.name || '', x.job || '', x.jobId || '', x.protected !== undefined ? 'protected=' + x.protected : ''].filter(Boolean).join(' · ')])).join('') + '</table>';
  }
  h += '<div class="meta" style="margin-top:18px">end of export · ' + escapeHtml(gen) + '</div></body></html>';
  return h;
}
// The ONE way this process reads policy: fleetctl's own loader and resolver, so the plane
// and the CLI it spawns always read the same file -- $AEGIS_POLICY (the hosted plane's live,
// untracked copy) or the checkout default -- and an attested change is seen by both at once.
function loadPolicyCanonical() {
  const pol = require(path.join(FLEET_IAC_ROOT, 'provision', 'lib', 'policy.js'));
  return pol.loadPolicy(pol.resolvePolicyPath());
}
// Directed A2A allowlist, read through the canonical policy loader. Fails CLOSED: any
// read problem yields an empty list, so a broken policy file disables relaying rather
// than silently permitting it. Not cached -- an operator who has just attested a pair
// expects it to take effect, and this runs once per relay, not per request.
function readA2aPairs() {
  try { const pol = loadPolicyCanonical(); return Array.isArray(pol.a2aPairs) ? pol.a2aPairs.map(String) : []; }
  catch (e) { return []; }
}

// Telegram allowlist, same loader, same fail-closed shape: unreadable => nobody.
function readTelegramChatIds() {
  try { const pol = loadPolicyCanonical(); return Array.isArray(pol.telegramChatIds) ? pol.telegramChatIds.map(String) : []; }
  catch (e) { return []; }
}

let _mbCache = { v: 2, t: 0 };
function readMaxBatch() {
  if (Date.now() - _mbCache.t < 10000) return _mbCache.v;
  let v = 2;
  try {
    // Canonical loader (handles JSONC trailing comments + defaults) — never reparse policy here.
    const pol = loadPolicyCanonical();
    if (Number.isFinite(pol.maxBatch) && pol.maxBatch > 0) v = pol.maxBatch;
  } catch { /* default 2 */ }
  _mbCache = { v, t: Date.now() };
  return v;
}

// Run fleetctl with the host env (CF_* etc.) inherited; AEGIS_CONFIG pinned to our config.
// fleetctl emits plain text when piped (util paint checks isTTY), so no ANSI to strip.
async function runFleetctl(args) {
  if (!FLEET_IAC_ROOT) return { code: 2, out: 'FLEET_IAC_ROOT not set — start aegis.js with FLEET_IAC_ROOT=<path to agent-fleet-iac>.' };
  const fp = fleetctlPath();
  if (!fs.existsSync(fp)) return { code: 2, out: `fleetctl not found at ${fp} — check FLEET_IAC_ROOT.` };
  return await new Promise((resolve) => {
    const child = spawn('node', [fp, ...args], {
      cwd: FLEET_IAC_ROOT,
      env: { ...process.env, CF_OPERATOR_EMAIL: operatorEmail(), AEGIS_CONFIG: CFG, NO_COLOR: '1' },
    });
    let so = '', se = '';
    child.stdout.on('data', (d) => { so += d; });
    child.stderr.on('data', (d) => { se += d; });
    child.on('error', (e) => resolve({ code: 1, out: 'spawn error: ' + e.message }));
    child.on('close', (code) => resolve({ code: code == null ? 1 : code, out: so + (se ? (so ? '\n' : '') + se : '') }));
  });
}

// This plane's label: $AEGIS_PLANE, else the host name, slugged -- the same rule fleetctl enroll
// uses to name a plane's service tokens, so the panel and the lane never disagree about it.
function planeName() {
  const raw = (process.env.AEGIS_PLANE || os.hostname() || 'aegis').toLowerCase();
  return raw.replace(/[^a-z0-9-]/g, '-').replace(/^-+|-+$/g, '').slice(0, 40) || 'aegis';
}
function sendJson(res, obj, status = 200) { res.statusCode = status; res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(obj)); }

// Destructive lanes need real Cloudflare credentials -- a placeholder CF_ACCOUNT_ID silently
// orphaned an agent's tunnel/DNS/Access/token during teardown. Fail closed with the exact fix.
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
  // a silent socket is where a teardown stream once died. Emit a liveness line whenever
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
  child.on('error', (e) => { clearInterval(beat); try { if (onDone) onDone(-1); } catch { /* ignore */ } res.write('\n[spawn error] ' + e.message + '\n'); res.end(); });
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
    const out = await callAgent(agent, method, apiPath, body, actorOf(req));
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
    const r = await runFleetctl(['policy', 'show']);
    return sendJson(res, { ok: r.code === 0, out: panelClean(r.out) });
  }
  if (req.url === '/api/policy/set' && req.method === 'POST') {
    const b = await readBody(req);
    const key = String(b.key || '').trim();
    const value = String(b.value || '').trim();
    const attest = String(b.attest || '');
    const r = await runFleetctl(['policy', 'set', key, value, '--attest', attest]);
    audit({ action: 'policy-set', key, value, actor: actorOf(req), outcome: r.code === 0 ? 'ok' : 'refused-or-error', via: 'panel' });
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
    for (const f of fleetctlLedgerFiles()) pull(f, 'fleetctl');
    rows.sort((a, b2) => String(b2.ts || '').localeCompare(String(a.ts || '')));
    return sendJson(res, { ok: true, rows: rows.slice(0, 25) });
  }

  // ---- A2A relay: operator-initiated, attested, allowlisted, ledgered ---------------
  // Aegis is the ONLY thing that can see across agents; neither agent gains any reach.
  // Four gates, all fail-closed, checked before anything is sent:
  //   1. the pair must be explicitly allowlisted, and the grant is DIRECTED
  //   2. the operator must type the exact attestation sentence
  //   3. source and target must both be registered agents, and must differ
  //   4. the message must be non-empty and within the receiver's size limit
  // A refusal is ledgered as loudly as a success -- an attempt that was turned away is
  // exactly the thing an audit trail exists to show. The ledger records the message
  // DIGEST and length, never its text, matching the chat-command lane.
  if (req.url === '/api/a2a/send' && req.method === 'POST') {
    const b = await readBody(req);
    const from = String(b.from || '').trim();
    const to = String(b.to || '').trim();
    const text = typeof b.text === 'string' ? b.text : '';
    const attest = String(b.attest || '').trim();
    const actor = actorOf(req);
    const required = 'I approve relaying ' + from + ' to ' + to;
    const sha = text ? crypto.createHash('sha256').update(text, 'utf8').digest('hex') : null;
    const base = { action: 'a2a-relay', from, to, actor, textSha256: sha, textLen: Buffer.byteLength(text, 'utf8') };

    if (!NAME_RE.test(from) || !NAME_RE.test(to)) {
      audit({ ...base, outcome: 'refused: invalid agent name' });
      return sendJson(res, { ok: false, error: 'invalid agent name' }, 400);
    }
    if (from === to) {
      audit({ ...base, outcome: 'refused: same agent' });
      return sendJson(res, { ok: false, error: 'source and target must differ' }, 400);
    }
    const src = agentByName(from), dst = agentByName(to);
    if (!src || !dst) {
      audit({ ...base, outcome: 'refused: unknown agent' });
      return sendJson(res, { ok: false, error: 'unknown agent (both must be registered in aegis.config.json)' }, 404);
    }
    if (!text.trim()) {
      audit({ ...base, outcome: 'refused: empty message' });
      return sendJson(res, { ok: false, error: 'message is empty' }, 400);
    }
    const pairs = readA2aPairs();
    if (!pairs.includes(from + '>' + to)) {
      audit({ ...base, outcome: 'refused: pair not allowlisted' });
      return sendJson(res, { ok: false, error: 'REFUSED \u2014 "' + from + '>' + to + '" is not in policy a2aPairs. Grants are directional; add it with an attested policy set.' }, 403);
    }
    if (attest !== required) {
      audit({ ...base, phrase: attest, outcome: 'refused: attestation mismatch' });
      return sendJson(res, { ok: false, error: 'REFUSED \u2014 attestation must read exactly:  ' + required }, 403);
    }
    audit({ ...base, phrase: attest, outcome: 'started' });
    const out = await callAgent(dst, 'POST', '/a2a/deliver', { from, text }, actor);
    let body = null; try { body = JSON.parse(out.body || '{}'); } catch (e) { body = null; }
    const okDeliver = out.status === 200 && body && body.ok === true;
    audit({ ...base, phrase: attest, outcome: okDeliver ? 'delivered' : ('failed: HTTP ' + out.status), dest: body && body.dest, name: body && body.name });
    if (!okDeliver) return sendJson(res, { ok: false, error: (body && body.error) || ('delivery failed (HTTP ' + out.status + ')') }, 502);
    return sendJson(res, { ok: true, from, to, dest: body.dest, name: body.name, bytes: body.bytes, textSha256: body.textSha256 });
  }

  // Read-only: which directed pairs are currently permitted (drives the panel).
  if (req.url === '/api/a2a/pairs' && req.method === 'GET') {
    return sendJson(res, { ok: true, pairs: readA2aPairs() });
  }

  // Ledger integrity: walks the chain and reports the FIRST break with its line and
  // seq. Read-only and cheap; this is what the audit-chain compliance control will
  // call so the control verifies the chain instead of merely asserting one exists.
  if (req.url === '/api/audit/verify' && req.method === 'GET') {
    return sendJson(res, { ok: true, chain: verifyChain() });
  }
  // Printable export (HTML, print to PDF from the browser). Read-only; the act of exporting is
  // itself recorded on the control-plane chain, because a copy of the ledgers left the plane.
  if (req.url === '/api/audit/export' && req.method === 'GET') {
    const actor = actorOf(req);
    audit({ action: 'audit-export', actor, outcome: 'ok' });
    const html = await buildAuditExport(actor);
    res.statusCode = 200; res.setHeader('Content-Type', 'text/html; charset=utf-8'); res.setHeader('Cache-Control', 'no-store');
    return res.end(html);
  }

  // Control-plane ledger tail for the Audit view. Deliberately NOT merged with the
  // agents' logs: those are separate chains in separate trust domains, and neither can
  // rewrite the other. Presenting one stream would imply a single verifiable history
  // that does not exist -- so the panel shows two panes and says which is which.
  if (req.url.startsWith('/api/audit/recent') && req.method === 'GET') {
    const n = Math.min(Math.max(parseInt((req.url.split('limit=')[1] || '30'), 10) || 30, 1), 200);
    let rows = [];
    try {
      rows = fs.readFileSync(AUDIT, 'utf8').trim().split('\n').filter(Boolean).slice(-n)
        .map(l => { try { return JSON.parse(l); } catch (e) { return null; } })
        .filter(Boolean).reverse();
    } catch (e) { rows = []; }
    return sendJson(res, { ok: true, rows, chain: verifyChain() });
  }

  // Provisioning plan (READ-ONLY): preview `up` + the caps/budget gate for a proposed agent.
  if (req.url === '/api/provision/active' && req.method === 'GET') {
    return sendJson(res, { ok: true, active: [...ACTIVE_GO.keys()], maxBatch: readMaxBatch() });
  }
  if (req.url === '/api/provision/plan' && req.method === 'POST') {
    const b = await readBody(req);
    const name = String(b.name || '').trim();
    if (!NAME_RE.test(name)) return sendJson(res, { ok: false, out: 'invalid agent name — must match ^[a-z][a-z0-9-]{1,23}$' }, 400);
    const usePersisted = !!b.usePersisted;
    const { file, temp } = contractFor(name, { forceTemp: !usePersisted, profile: b.profile, domain: b.domain, operatorEmail: String(b.operatorEmail || '').trim() });
    const r = await runFleetctl(['plan', file]);
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
    const actor = actorOf(req);
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
    if (ACTIVE_GO.has(name)) {
      audit({ action: 'provision-go', name, actor, phrase: attest, outcome: 'refused: duplicate active run' });
      return sendJson(res, { ok: false, error: 'a provisioning run for "' + name + '" is already active' }, 409);
    }
    const mb = readMaxBatch();
    if (ACTIVE_GO.size >= mb) {
      audit({ action: 'provision-go', name, actor, phrase: attest, outcome: 'refused: maxBatch (' + ACTIVE_GO.size + ' active, cap ' + mb + ')' });
      return sendJson(res, { ok: false, error: 'REFUSED — ' + ACTIVE_GO.size + ' provisioning run(s) already active; policy maxBatch=' + mb }, 429);
    }
    ACTIVE_GO.set(name, Date.now());
    audit({ action: 'provision-go', name, actor, phrase: attest, outcome: 'started (' + ACTIVE_GO.size + '/' + mb + ' concurrent)' });
    return streamFleetctl(res, ['up', persisted, '--go'], null, (code) => { ACTIVE_GO.delete(name); audit({ action: 'provision-go', name, actor, phrase: attest, outcome: code === 0 ? 'done' : 'exit ' + code }); });
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
    const r = await runFleetctl(['policy', 'show', '--json']);
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
    const cur = await runFleetctl(['policy', 'show', '--json']);
    let list; try { list = JSON.parse(cur.out || '{}').protectedAgents || []; } catch { return sendJson(res, { ok: false, error: 'cannot read policy (fleetctl policy show --json failed)' }, 500); }
    const on = list.includes(name);
    const r = await runFleetctl(['policy', on ? 'unprotect' : 'protect', name, '--attest', attest]);
    audit({ action: 'protect-toggle', name, verb: on ? 'unprotect' : 'protect', actor: actorOf(req), outcome: r.code === 0 ? 'ok' : 'exit ' + r.code });
    let next = list;
    if (r.code === 0) {
      const rr = await runFleetctl(['policy', 'show', '--json']);
      try { next = JSON.parse(rr.out || '{}').protectedAgents || list; } catch { /* keep prior */ }
      const agent = agentByName(name); if (agent) { try { callAgent(agent, 'POST', '/protection', { protected: !on }, actorOf(req)); } catch { /* unreachable */ } }
    }
    return sendJson(res, { ok: r.code === 0, out: panelClean(r.out), protectedAgents: next });
  }
  // Which control plane is this? Two planes exist (hosted primary, workstation break-glass)
  // and an operator must be able to read which one they are commanding: same panel, same
  // agents, different ledgers. $AEGIS_PLANE wins, else the host name -- the same rule
  // fleetctl enroll uses to name a plane's service tokens.
  // ---- Discovery: what Azure holds against THIS plane's registry (fleetctl discover --json).
  // Read-only. Two planes, two registries, one Azure: an agent provisioned elsewhere shows up
  // here as unenrolled (an Enroll away), a registry entry whose RG is gone shows up as gone (a
  // registry-only Decommission away). The panel offers the door; the attested lanes stay the door.
  if (req.url === '/api/fleet/discover' && req.method === 'GET') {
    const r = await runFleetctl(['discover', '--json', '--plane=' + planeName()]);
    let j = null;
    try { const lines = String(r.out || '').trim().split('\n'); j = JSON.parse(lines[lines.length - 1]); } catch { j = null; }
    if (!j) return sendJson(res, { ok: false, out: panelClean(r.out || 'discover produced no JSON') }, 502);
    return sendJson(res, { ok: r.code === 0, ...j });
  }
  if (req.url === '/api/plane' && req.method === 'GET') {
    const ts = telegram.state;
    return sendJson(res, { plane: planeName(), bind: HOST + ':' + PORT, fleetctl: !!FLEET_IAC_ROOT, cf: cfEnvProblem() ? 'not ready' : 'ok',
      telegram: ts.on ? 'on' : ('off' + (ts.reason ? ' (' + ts.reason + ')' : '')),
      // live counters: is it polling, where is the cursor, what failed last, and which chats
      // knocked without being allowlisted (the onboarding read-out -- your own id appears here)
      telegramDetail: { on: ts.on, bot: ts.bot || null, source: ts.source, polls: ts.polls, offset: ts.offset, lastError: ts.lastError || null, lastPollAt: ts.lastPollAt || null, unknownChats: Object.keys(ts.chatsSeen || {}) } });
  }
  // ---- Enroll: adopt an already-provisioned agent into THIS plane with its own token
  // (fleetctl enroll). The plane label is pinned on the argv so the token name and the
  // attestation sentence are exactly what this plane calls itself, never a guess.
  if (req.url === '/api/enroll/plan' && req.method === 'POST') {
    const b = await readBody(req);
    const name = String(b.name || '').trim();
    if (!NAME_RE.test(name)) return sendJson(res, { ok: false, out: 'invalid agent name — must match ^[a-z][a-z0-9-]{1,23}$' }, 400);
    const r = await runFleetctl(['enroll', name, '--plane=' + planeName()]);
    audit({ action: 'enroll-plan', name, plane: planeName(), code: r.code });
    return sendJson(res, { ok: r.code === 0, code: r.code, out: panelClean(r.out) });
  }
  if (req.url === '/api/enroll/go' && req.method === 'POST') {
    const b = await readBody(req);
    const name = String(b.name || '').trim();
    const attest = String(b.attest || '');
    if (!NAME_RE.test(name)) return sendJson(res, { ok: false, out: 'invalid agent name — must match ^[a-z][a-z0-9-]{1,23}$' }, 400);
    const plane = planeName();
    const required = 'I approve enrolling ' + name + ' in the control plane ' + plane;
    const actor = actorOf(req);
    const base = { action: 'enroll-go', name, plane, actor };
    if (attest.trim() !== required) {
      audit({ ...base, phrase: attest, outcome: 'refused: attestation mismatch' });
      return sendJson(res, { ok: false, out: 'REFUSED — attestation must read exactly:\n  ' + required }, 400);
    }
    audit({ ...base, phrase: attest, outcome: 'started' });
    return streamFleetctl(res, ['enroll', name, '--plane=' + plane, '--go', '--attest', attest.trim()], null, (code) => audit({ ...base, phrase: attest, outcome: code === 0 ? 'done' : 'exit ' + code }));
  }
  // ---- Migrate: agent -> agent, mediated by THIS plane (fleetctl migrate) ------------
  // Plan is read-only (fleetctl reads both agents' volumes over run-command; ~1 min).
  // Execute is typed-phrase attested, streamed, and ledgered twice by design: here (who
  // commanded it, edge-verified) and in fleetctl's policy-audit ledger (what moved:
  // blobs, sha256, member counts, the source chain head as cross-anchor).
  if (req.url === '/api/migrate/plan' && req.method === 'POST') {
    const b = await readBody(req);
    const from = String(b.from || '').trim(), to = String(b.to || '').trim();
    const scope = String(b.scope || '').trim(), blob = String(b.blob || '').trim();
    if (!NAME_RE.test(from) || !NAME_RE.test(to)) return sendJson(res, { ok: false, out: 'invalid agent name — must match ^[a-z][a-z0-9-]{1,23}$' }, 400);
    if (from === to) return sendJson(res, { ok: false, out: 'from and to are the same agent' }, 400);
    if (scope && !/^[a-z0-9,-]{1,120}$/.test(scope)) return sendJson(res, { ok: false, out: 'scope must be a comma list of volume names (a-z, 0-9, -)' }, 400);
    if (blob && !/^[A-Za-z0-9._-]{1,200}$/.test(blob)) return sendJson(res, { ok: false, out: 'snapshot name fails safe charset' }, 400);
    const overwrite = b.overwrite === true;
    const args = ['migrate', from, to]; if (scope) args.push('--scope=' + scope); if (blob) args.push('--blob=' + blob); if (overwrite) args.push('--overwrite');
    const r = await runFleetctl(args);
    audit({ action: 'migrate-plan', from, to, scope: scope || null, blob: blob || null, mode: overwrite ? 'overwrite' : 'add-only', code: r.code });
    return sendJson(res, { ok: r.code === 0, code: r.code, out: panelClean(r.out) });
  }
  if (req.url === '/api/migrate/go' && req.method === 'POST') {
    const b = await readBody(req);
    const from = String(b.from || '').trim(), to = String(b.to || '').trim();
    const scope = String(b.scope || '').trim(), blob = String(b.blob || '').trim();
    const attest = String(b.attest || '');
    if (!NAME_RE.test(from) || !NAME_RE.test(to)) return sendJson(res, { ok: false, out: 'invalid agent name — must match ^[a-z][a-z0-9-]{1,23}$' }, 400);
    if (from === to) return sendJson(res, { ok: false, out: 'from and to are the same agent' }, 400);
    if (scope && !/^[a-z0-9,-]{1,120}$/.test(scope)) return sendJson(res, { ok: false, out: 'scope must be a comma list of volume names (a-z, 0-9, -)' }, 400);
    if (blob && !/^[A-Za-z0-9._-]{1,200}$/.test(blob)) return sendJson(res, { ok: false, out: 'snapshot name fails safe charset' }, 400);
    // Add-only and overwrite are different acts with different sentences (see fleetctl migrate).
    const overwrite = b.overwrite === true;
    const required = 'I approve migrating ' + from + ' to ' + to + (overwrite ? ' overwriting existing files' : '');
    const actor = actorOf(req);
    const base = { action: 'migrate-go', from, to, scope: scope || null, blob: blob || null, mode: overwrite ? 'overwrite' : 'add-only', actor };
    if (attest.trim() !== required) {
      audit({ ...base, phrase: attest, outcome: 'refused: attestation mismatch' });
      return sendJson(res, { ok: false, out: 'REFUSED — attestation must read exactly:\n  ' + required }, 400);
    }
    const args = ['migrate', from, to]; if (scope) args.push('--scope=' + scope); if (blob) args.push('--blob=' + blob); if (overwrite) args.push('--overwrite');
    args.push('--go', '--attest', attest.trim());
    audit({ ...base, phrase: attest, outcome: 'started' });
    return streamFleetctl(res, args, null, (code) => audit({ ...base, phrase: attest, outcome: code === 0 ? 'done' : 'exit ' + code }));
  }
  // Decommission plan (READ-ONLY): discover which surfaces an agent still occupies.
  if (req.url === '/api/decommission/plan' && req.method === 'POST') {
    const b = await readBody(req);
    const name = String(b.name || '').trim();
    if (!NAME_RE.test(name)) return sendJson(res, { ok: false, out: 'invalid agent name — must match ^[a-z][a-z0-9-]{1,23}$' }, 400);
    const { file, temp } = contractFor(name, { profile: b.profile, domain: b.domain });
    const r = await runFleetctl(['decommission', file]); // no --go => read-only discovery
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
    const actor = actorOf(req);
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
  // Resolve WHO at upgrade time -- the only point the HTTP request (and its Access
  // assertion) is still in hand; every command on this socket is attributed to it.
  const actor = actorOf(req);
  wss.handleUpgrade(req, socket, head, (browserWs) => relay(browserWs, agent, actor));
});

// ONE path to an agent for every door into the plane. Opens a fresh WS to the agent with
// the plane's service token, sends the prompt, streams frames to onFrame, calls onDone once
// (on 'done', close, or error). opts.onBehalfOf rides as X-Aegis-On-Behalf-Of -- the plane's
// ASSERTION of who asked (never merged with the verified caller, which is the plane's token).
// Returns the socket so a caller that owns a browser connection can close it early.
function sendToAgent(agent, prompt, onFrame, onDone, opts) {
  const o = opts || {};
  let done = false; const finish = () => { if (!done) { done = true; try { onDone && onDone(); } catch { /* ignore */ } } };
  const headers = { 'CF-Access-Client-Id': agent.clientId, 'CF-Access-Client-Secret': agent.clientSecret };
  if (o.onBehalfOf && o.onBehalfOf.src && o.onBehalfOf.id) {
    const clean = (v) => String(v).replace(/[^\x21-\x7e]/g, '').slice(0, 200);
    headers['X-Aegis-On-Behalf-Of'] = clean(o.onBehalfOf.src) + ':' + clean(o.onBehalfOf.id);
  }
  const agentWs = new WebSocket('wss://' + agent.host + '/', { headers, handshakeTimeout: 10000 });
  agentWs.on('open', () => {
    const out = { prompt };
    if (o.tier) out.tier = o.tier;
    agentWs.send(JSON.stringify(out));
  });
  agentWs.on('message', (data) => {
    let frame; try { frame = JSON.parse(data); } catch { frame = { type: 'token', text: String(data) }; }
    try { onFrame(frame); } catch { /* ignore */ }
    if (frame.type === 'done') { try { agentWs.close(); } catch {} finish(); }
  });
  agentWs.on('error', (e) => {
    const m = String(e.message || '');
    let hint = '';
    if (/530/.test(m)) hint = ` — ${agent.name} unreachable: tunnel down (VM deallocated?). Start it: az vm start -g rg-${agent.name} -n ${agent.name}-vm`;
    else if (/502/.test(m)) hint = ` — ${agent.name} tunnel is up but nothing listens yet (agent starting or containers down)`;
    try { onFrame({ type: 'error', text: 'agent connect: ' + m + hint }); onFrame({ type: 'done' }); } catch { /* ignore */ }
    finish();
  });
  agentWs.on('close', () => finish());
  return agentWs;
}

function relay(browserWs, agent, actor) {
  let agentWs = null;
  const tell = (obj) => { if (browserWs.readyState === WebSocket.OPEN) browserWs.send(JSON.stringify({ agent: agent.name, ...obj })); };

  browserWs.on('message', (raw) => {
    let msg; try { msg = JSON.parse(raw); } catch { msg = { prompt: String(raw) }; }
    const prompt = (msg.prompt || '').toString();
    if (!prompt.trim()) { tell({ type: 'error', text: 'Empty prompt.' }); tell({ type: 'done' }); return; }

    audit({ agent: agent.name, event: 'command', actor,
            promptSha256: crypto.createHash('sha256').update(prompt).digest('hex'),
            promptLen: prompt.length, status: 'sent' });

    // one agent WS per command (agents stream one response then we close); the browser's
    // edge-verified identity rides as the plane's assertion, exactly as Telegram's chat id does
    agentWs = sendToAgent(agent, prompt, tell, () => { /* command complete; browser stays open for next send */ }, { tier: msg.tier, onBehalfOf: actor && actor.src !== 'unknown' ? actor : null });
  });

  browserWs.on('close', () => { if (agentWs) { try { agentWs.close(); } catch {} } });
  browserWs.on('error', () => { if (agentWs) { try { agentWs.close(); } catch {} } });
}

let bootCfg = {};
try { bootCfg = JSON.parse(fs.readFileSync(CFG, 'utf8')); } catch { /* loadAgents already warned */ }
cfcred.resolve(bootCfg, () =>
  server.listen(PORT, HOST, () => {
    console.log(`Aegis on http://${HOST}:${PORT}  agents: ${loadAgents().map(a => a.name).join(', ') || '(none - fill aegis.config.json)'}  \u00b7  fleetctl: ${FLEET_IAC_ROOT || 'MISSING (set FLEET_IAC_ROOT or aegis.config.json fleetIacRoot)'}  \u00b7  cf: ${cfEnvProblem() ? 'NOT READY (' + cfEnvProblem() + ')' : 'ok \u00b7 token: ' + cfcred.state.source}`);
    // Telegram door: read + chat only, allowlist from policy, off unless a bot token resolves.
    // Started AFTER the plane listens, and only when FLEET_IAC_ROOT is known (the allowlist
    // is policy); a plane without policy has no allowlist, so it has no Telegram either.
    if (FLEET_IAC_ROOT) {
      telegram.start({
        cfg: bootCfg, loadAgents, agentByName, readChatIds: readTelegramChatIds, sendToAgent, callAgent, audit, planeName,
        stateFile: path.join(__dirname, 'telegram-state.json'),
        log: (...a) => console.log('telegram:', ...a),
      });
    } else console.log('telegram: off (FLEET_IAC_ROOT unset — no policy, no allowlist)');
  }));
