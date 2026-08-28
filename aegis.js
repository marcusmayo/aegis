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
const zlib = require('zlib');
const { spawnSync, spawn } = require('child_process');
// Resolve the agent-fleet-iac checkout: env wins, then aegis.config.json "fleetIacRoot",
// then the sibling ../agent-fleet-iac (the standard workstation layout). Kills the
// per-window env-loss failure: a bare `node aegis.js` finds fleetctl on its own.
const FLEET_IAC_ROOT = (function () {
  if (process.env.FLEET_IAC_ROOT) return process.env.FLEET_IAC_ROOT;
  try { const cfg = JSON.parse(fs.readFileSync(CFG, 'utf8')); if (cfg.fleetIacRoot) return cfg.fleetIacRoot; } catch { /* no config yet */ }
  // The fleet repo was renamed to `fleet`; a fresh workstation clones it under that name, while
  // machines keep their historical checkout dirs. Try the new sibling first, the old one second.
  const sibNew = path.join(__dirname, '..', 'fleet');
  if (fs.existsSync(path.join(sibNew, 'provision', 'bin', 'fleetctl.js'))) return sibNew;
  const sib = path.join(__dirname, '..', 'agent-fleet-iac');
  try { if (fs.existsSync(path.join(sib, 'provision', 'bin', 'fleetctl.js'))) return sib; } catch { /* ignore */ }
  return '';
})();
const NAME_RE = /^[a-z][a-z0-9-]{1,23}$/;

// The plane's own two checkouts, read-only: local head, remote head after a fetch, branch, and
// tracked dirt (the ledger and backups are untracked by design and never block a pull).
function repoState(dir) {
  if (!dir) return { present: false };
  const g = (args) => { const r = spawnSync('git', ['-C', dir, ...args], { encoding: 'utf8', timeout: 30000 }); return r.status === 0 ? (r.stdout || '').trim() : null; };
  const fetched = spawnSync('git', ['-C', dir, 'fetch', '-q', 'origin'], { encoding: 'utf8', timeout: 60000 }).status === 0;
  const branch = g(['rev-parse', '--abbrev-ref', 'HEAD']) || '?';
  const local = g(['rev-parse', '--short', 'HEAD']) || '?';
  const remote = g(['rev-parse', '--short', 'origin/' + branch]) || '?';
  const dirty = (g(['status', '--porcelain', '--untracked-files=no']) || '').split('\n').filter(Boolean).length;
  return { present: true, dir, fetched, branch, local, remote, dirty, pending: fetched && local !== '?' && remote !== '?' && local !== remote };
}
// The commits this PROCESS is running, captured once at start. index.html is read from disk on
// every request while aegis.js runs from memory, so a plane that pulled but never restarted
// serves the NEW panel from the NEW checkout while executing the OLD server code -- and it looks
// healthy from every angle: unit active, panel served, git clean, "up to date". Live: the update
// button posted the one-click body the new UI sends while the old process still demanded an
// attestation, so the panel refused with nowhere to type the phrase, and every attested action
// taken through that plane had been running pre-fix lanes for hours. A checkout is not a
// deployment until the unit restarts, so the plane states both and says when they differ.
const BOOT = (() => {
  const at = (dir) => {
    if (!dir) return null;
    const r = spawnSync('git', ['-C', dir, 'rev-parse', '--short', 'HEAD'], { encoding: 'utf8' });
    return r.status === 0 ? (r.stdout || '').trim() : null;
  };
  return { aegis: at(__dirname), fleet: at(FLEET_IAC_ROOT), at: new Date().toISOString() };
})();

// null when either side is unknown -- an unreadable checkout is not evidence of a skew.
function planeSkew(pre) {
  const s = pre || planeRepoState();
  const out = [];
  for (const [k, label] of [['aegis', 'aegis'], ['fleet', 'agent-fleet-iac']]) {
    const disk = s[k] && s[k].local;
    const running = BOOT[k];
    if (disk && running && disk !== running) out.push(`${label}: running ${running}, checkout ${disk}`);
  }
  return { skewed: out.length > 0, detail: out, boot: BOOT, checkout: repoHeads(s) };
}

// The plane restarts by ending, not by asking. It spent three updates spawning
// `sudo systemctl restart aegis` into silence: the unit sets NoNewPrivileges=yes, which makes the
// kernel ignore sudo's setuid bit at exec, so sudo died as uid 1000 BEFORE pam -- no restart, no
// auth.log line, no crash, and a panel that said "restarting" every time. The answer is not to
// hand the plane privilege back. systemd already owns the restart policy and needs no permission
// from us: exit with a status the unit restarts on, and let it. Nothing setuid is involved, so
// there is no bit to inherit and nothing that can fail quietly. The exit is ledgered first --
// audit is a synchronous append -- so the intent is on disk before the process is gone, and the
// panel proves the outcome by watching bootedAt change rather than by being told.
const RESTART_EXIT = 75;
function restartUnit(base) {
  audit({ ...base, outcome: 'restarting: exiting ' + RESTART_EXIT + ' for systemd to bring the unit back' });
  setTimeout(() => process.exit(RESTART_EXIT), 250);
}

function planeRepoState() {
  const unit = spawnSync('systemctl', ['is-active', 'aegis'], { encoding: 'utf8' });
  return { aegis: repoState(__dirname), fleet: repoState(FLEET_IAC_ROOT), unit: (unit.stdout || '').trim() || 'unknown' };
}
function repoHeads(s) { return { aegis: s.aegis && s.aegis.local, fleet: s.fleet && s.fleet.local }; }

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
// ---------------------------------------------------------------------------
// Ledger archive. The chains live on the machines that wrote them, and those machines are
// disposable -- an agent's chain is inside a nightly tarball the store deletes at fourteen
// days, so beyond a fortnight the only copy was on the VM. This lane writes a verified copy
// into the ledgers class, which no lifecycle rule can delete.
//
// The PLANE writes it, not the agents. One writer keeps every agent's MSI scoped to its own
// container, and the plane is the only party that already re-verifies what it received: each
// hash recomputed, each record's prev_hash matched to the next-older one, so a page boundary
// that dropped a record shows up as a break rather than as a gap nobody notices.
//
// Each run covers a WINDOW, not all of history: from two days before the last successful
// capture, to now. The overlap means a day the plane was down, or an agent unreachable, is
// picked up by the next run -- and pageAgentAudit walks backwards, so a first run with no
// state captures everything the agents still hold.
const LEDGER_STATE = path.join(__dirname, 'ledger-archive.json');
const LEDGER_OVERLAP_MS = 48 * 3600 * 1000;
const LEDGER_TICK_MS = 3600 * 1000;

function ledgerState() {
  try { return JSON.parse(fs.readFileSync(LEDGER_STATE, 'utf8')) || {}; } catch { return {}; }
}
function ledgerStateWrite(st) {
  try { fs.writeFileSync(LEDGER_STATE, JSON.stringify(st, null, 1)); } catch (e) { /* state is a convenience, never a gate */ }
}

async function gatherLedgers(range, actor) {
  const inRange = (r) => (!range.from || String(r.ts || '') >= range.from) && (!range.to || String(r.ts || '') < range.to);
  const cp = readJsonl(AUDIT).filter(inRange);
  const fl = fleetctlLedgerFiles()
    .flatMap((f) => readJsonl(f).map((r) => ({ ...r, _file: path.basename(f) })))
    .filter(inRange)
    .sort((a, b) => String(a.ts || '').localeCompare(String(b.ts || '')));
  const blocks = [];
  for (const a of loadAgents()) {
    const pg = await pageAgentAudit(a, actor, range);
    blocks.push({
      name: a.name, profile: a.profile || null, host: a.host || null,
      rows: pg.rows, pages: pg.pages, heldTotal: pg.total, oldestTs: pg.oldestTs,
      reverified: reverifyRows(pg.rows), err: pg.err || null,
    });
  }
  return {
    schema: 'aegis.ledger-archive/1',
    capturedAt: new Date().toISOString(),
    plane: planeName(),
    window: { from: range.from || null, to: range.to || null },
    note: 'Metadata and hashes only -- no prompt, reply or note content is held in any chain. '
      + 'A chain proves a record existed unaltered at capture time; it does not say what it said.',
    controlPlane: { chain: verifyChain(), records: cp },
    fleetctl: { records: fl },
    agents: blocks,
  };
}

// One capture: gather, gzip, hand the bytes to the fleet lane to store. fleetctl owns the store
// (it resolves the account and speaks az); the plane owns the verification. `backup put` is
// append-only, so a second run on the same day reports the blob already exists and changes
// nothing -- that is a success, not a failure.
async function ledgerArchiveRun(actor, reason) {
  const st = ledgerState();
  const to = new Date().toISOString();
  const from = st.lastCapturedAt ? new Date(Date.parse(st.lastCapturedAt) - LEDGER_OVERLAP_MS).toISOString() : null;
  const day = to.slice(0, 10);
  const blob = planeName() + '/' + day + '.json.gz';
  let doc;
  try { doc = await gatherLedgers({ from, to }, actor); }
  catch (e) { audit({ action: 'ledger-archive', actor, reason, outcome: 'failed: gather: ' + String(e.message || e).slice(0, 160) }); return { ok: false, error: String(e.message || e) }; }
  const counts = {
    controlPlane: doc.controlPlane.records.length,
    fleetctl: doc.fleetctl.records.length,
    agents: doc.agents.map((a) => ({ name: a.name, rows: a.rows.length, reverified: a.reverified.ok, err: a.err })),
  };
  const tmp = path.join(os.tmpdir(), 'aegis-ledger-' + day + '-' + process.pid + '.json.gz');
  try {
    fs.writeFileSync(tmp, zlib.gzipSync(Buffer.from(JSON.stringify(doc)), { level: 9 }));
    const bytes = fs.statSync(tmp).size;
    const r = await runFleetctl(['backup', 'put', 'ledgers', tmp, '--as', blob]);
    // Append-only: a blob already there for today means the invariant holds (an object exists,
    // unchanged), whatever exit code the lane chose for saying so. Only a real failure fails.
    const already = /already exists/i.test(r.out || '');
    if (r.code !== 0 && !already) {
      audit({ action: 'ledger-archive', actor, reason, blob, bytes, counts, outcome: 'failed: put exit ' + r.code + ': ' + panelClean(r.out).split('\n')[0] });
      return { ok: false, error: panelClean(r.out) };
    }
    ledgerStateWrite({ lastCapturedAt: to, lastBlob: blob, lastBytes: bytes, lastCounts: counts, lastReason: reason });
    audit({ action: 'ledger-archive', actor, reason, blob, bytes, counts, window: doc.window, outcome: already ? 'ok (already present for today)' : 'ok' });
    return { ok: true, blob, bytes, counts, already, window: doc.window };
  } catch (e) {
    audit({ action: 'ledger-archive', actor, reason, blob, outcome: 'failed: ' + String(e.message || e).slice(0, 160) });
    return { ok: false, error: String(e.message || e) };
  } finally { try { fs.unlinkSync(tmp); } catch { /* gone */ } }
}

// Hourly tick, one capture per UTC day. Hourly rather than daily so a plane that was restarted
// (or was down at the hour) still catches the day, and so the first capture happens minutes
// after this lane ships rather than tomorrow.
let LEDGER_TIMER = null;
function ledgerArchiveStart() {
  if (LEDGER_TIMER) return;
  const tick = async () => {
    const st = ledgerState();
    const today = new Date().toISOString().slice(0, 10);
    if (st.lastCapturedAt && String(st.lastCapturedAt).slice(0, 10) === today) return;
    await ledgerArchiveRun({ id: 'aegis-timer', label: 'ledger archive timer', src: 'timer' }, 'timer');
  };
  setTimeout(() => { tick().catch(() => {}); }, 30000);
  LEDGER_TIMER = setInterval(() => { tick().catch(() => {}); }, LEDGER_TICK_MS);
  if (LEDGER_TIMER.unref) LEDGER_TIMER.unref();
}

// Printable audit export: one self-contained HTML document the browser prints to PDF.
// Three ledgers, three sections, deliberately NOT merged -- the control plane records what was
// commanded, fleetctl records what was attested against policy, each agent records what it did;
// they are separate chains in separate trust domains and a merged stream would imply a single
// verifiable history that does not exist. Every section states its own verification result.
const escapeHtml = (v) => String(v == null ? '' : v).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
function who(a) { if (!a) return ''; if (typeof a === 'string') return a; return (a.label || a.id || '?') + (a.src ? ' [' + a.src + ']' : ''); }
// Agent chains changed vocabulary over time: older keel records name the thing that happened in
// `action`, newer ones in `event`, and a few carry `op`. The export's agent table read only
// `event`, so every pre-change record printed with an empty first column -- the rows were there,
// hash-verified and continuous, saying nothing about what they were. An audit document whose
// oldest entries are blank is worse than one that admits a gap, because it looks complete.
// Same for the outcome column, which older records call `status` or `result`.
const evOf = (x) => x.event || x.action || x.op || '';
const outOf = (x) => x.outcome || x.status || x.result || '';

// Re-verify agent rows the plane received (newest-first raw chain entries): each hash is
// recomputed exactly as the agent computed it (sha256 of prev_hash + the entry without its hash,
// in the entry's own key order, which JSON preserves), and each entry's prev_hash must equal the
// next-older entry's hash. So the export states what the plane itself checked, not only what the
// agent said about itself -- and a page boundary that skipped a record shows as a break.
function reverifyRows(rows) {
  const crypto = require('crypto');
  let checked = 0;
  for (let i = 0; i < rows.length; i++) {
    const e = rows[i];
    if (!e || typeof e.hash !== 'string' || typeof e.prev_hash !== 'string') return { ok: false, checked, brokenAt: e && e.ts, why: 'entry without hash fields' };
    const copy = { ...e }; delete copy.hash;
    const want = crypto.createHash('sha256').update(e.prev_hash + JSON.stringify(copy)).digest('hex');
    if (want !== e.hash) return { ok: false, checked, brokenAt: e.ts, why: 'hash mismatch' };
    if (i + 1 < rows.length && rows[i + 1] && e.prev_hash !== rows[i + 1].hash) return { ok: false, checked: checked + 1, brokenAt: e.ts, why: 'continuity break (a record between two pages is missing, or the chain is broken here)' };
    checked++;
  }
  return { ok: true, checked, brokenAt: null };
}
// Page an agent's chain backwards through the requested window: newest 500 with ts < until,
// then again with until = the oldest ts received, until a page comes back short or the window's
// start is passed. Coverage is stated from what the agent reports it holds.
async function pageAgentAudit(a, actor, range) {
  const rows = []; let until = range.to || null, pages = 0, total = null, oldestTs = null, err = '';
  while (pages < 400) {
    const q = '/audit-recent?limit=500' + (range.from ? '&since=' + encodeURIComponent(range.from) : '') + (until ? '&until=' + encodeURIComponent(until) : '');
    let j = null;
    try { const r = await callAgent(a, 'GET', q, null, actor); if (r && r.status === 200) j = JSON.parse(r.body || '{}'); else err = 'audit-recent HTTP ' + (r && r.status); } catch (e) { err = 'unreachable: ' + String(e.message || e).slice(0, 80); }
    if (!j) break;
    if (total === null) { total = typeof j.total === 'number' ? j.total : null; oldestTs = j.oldestTs || null; }
    const w = j.rows || [];
    rows.push(...w); pages++;
    if (w.length < 500) break;
    const oldest = w[w.length - 1] && w[w.length - 1].ts; if (!oldest) break;
    until = oldest;
    if (range.from && oldest <= range.from) break;
  }
  return { rows, pages, total, oldestTs, err };
}
async function buildAuditExport(actor, range) {
  range = range || {};
  const inRange = (r) => (!range.from || String(r.ts || '') >= range.from) && (!range.to || String(r.ts || '') < range.to);
  const gen = new Date().toISOString();
  const plane = planeName();
  const chain = verifyChain();
  const cpAll = readJsonl(AUDIT); const cp = cpAll.filter(inRange);
  const flAll = fleetctlLedgerFiles().flatMap((f) => readJsonl(f).map((r) => ({ ...r, _file: path.basename(path.dirname(f)) + '/' + path.basename(f) })));
  const fl = flAll.filter(inRange);
  fl.sort((a, b) => String(a.ts || '').localeCompare(String(b.ts || '')));
  const agents = loadAgents();
  const agentBlocks = [];
  for (const a of agents) {
    let ver = null, err = '';
    try { const v = await callAgent(a, 'GET', '/audit-verify', null, actor); ver = v && v.status === 200 ? (JSON.parse(v.body || '{}').chain || null) : null; if (!v || v.status !== 200) err = 'audit-verify HTTP ' + (v && v.status); } catch (e) { err = 'unreachable: ' + String(e.message || e).slice(0, 80); }
    const pg = await pageAgentAudit(a, actor, range);
    if (pg.err && !err) err = pg.err;
    const re = reverifyRows(pg.rows);
    agentBlocks.push({ name: a.name, profile: a.profile, host: a.host, ver, rows: pg.rows, pages: pg.pages, total: pg.total, oldestTs: pg.oldestTs, re, err });
  }
  const rangeText = (range.from || range.to) ? ('range ' + (range.from || 'beginning') + ' \u2192 ' + (range.to || 'now')) : 'full history';
  const css = 'body{font:12px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color:#111;margin:24px;max-width:1100px}h1{font-size:18px;margin:0 0 4px}h2{font-size:15px;margin:22px 0 6px;border-bottom:1px solid #999;padding-bottom:3px;page-break-before:always}h2.first{page-break-before:auto}.meta{color:#444;font-size:11px}table{border-collapse:collapse;width:100%;margin-top:6px}th,td{border:1px solid #bbb;padding:3px 5px;text-align:left;vertical-align:top;font-size:11px;word-break:break-word}th{background:#eee}.ok{color:#0a7f2e;font-weight:700}.bad{color:#b00020;font-weight:700}.note{background:#f4f4f4;border:1px solid #ddd;padding:6px 8px;font-size:11px;margin:6px 0}@media print{body{margin:10mm}h2{page-break-before:always}h2.first{page-break-before:auto}.noprint{display:none}}';
  const th = (cols) => '<tr>' + cols.map((c) => '<th>' + escapeHtml(c) + '</th>').join('') + '</tr>';
  const td = (cells) => '<tr>' + cells.map((c) => '<td>' + escapeHtml(c) + '</td>').join('') + '</tr>';
  let h = '<!doctype html><html><head><meta charset="utf-8"><title>Aegis audit export · ' + escapeHtml(plane) + ' · ' + escapeHtml(gen) + '</title><style>' + css + '</style></head><body>';
  h += '<h1>Aegis audit export — control plane <b>' + escapeHtml(plane) + '</b></h1><div class="meta">generated ' + escapeHtml(gen) + ' by ' + escapeHtml(who(actor)) + ' · ' + escapeHtml(rangeText) + ' · agents: ' + escapeHtml(agents.map((a) => a.name).join(', ') || 'none') + '</div>';
  h += '<div class="note">Three ledgers, three sections, deliberately not merged. The control plane records what was <b>commanded</b>; fleetctl records what was <b>attested against policy</b>; each agent records what it <b>did</b>. They are separate chains in separate trust domains and neither can rewrite another, so no single merged history exists to print. Actor labels are readable names for verified identities; the recorded id is the fact.</div>';
  h += '<button class="noprint" onclick="window.print()" style="margin:8px 0;padding:6px 14px">Print / save as PDF</button>';
  // 1 control plane
  h += '<h2 class="first">1. Control plane ledger — aegis-audit.jsonl</h2><div class="meta">chain: ' + (chain.ok ? '<span class="ok">VERIFIED</span>' : '<span class="bad">BROKEN' + (chain.broken ? ' at seq ' + escapeHtml(chain.broken.seq) + ' — ' + escapeHtml(chain.broken.reason) : '') + '</span>') + ' · ' + escapeHtml(chain.checked || 0) + ' chained' + (chain.unchained ? ' · ' + escapeHtml(chain.unchained) + ' pre-chain' : '') + ' · ' + cp.length + ' in ' + escapeHtml(rangeText) + ' (' + cpAll.length + ' held)</div>';
  h += '<table>' + th(['seq', 'ts', 'action / event', 'agent', 'outcome / status', 'actor', 'detail']) + cp.map((x) => td([x.seq !== undefined ? '#' + x.seq : '', x.ts, evOf(x), x.name || x.agent || '', outOf(x), who(x.actor), [x.phrase ? '«' + x.phrase + '»' : '', x.key ? 'key ' + x.key : '', x.from && x.to && typeof x.from === 'string' ? x.from + '>' + x.to : '', x.mode ? 'mode ' + x.mode : '', x.via ? 'via ' + x.via : ''].filter(Boolean).join(' · ')])).join('') + '</table>';
  // 2 fleetctl
  h += '<h2>2. fleetctl attested acts — policy-audit.jsonl</h2><div class="meta">' + fl.length + ' records · files: ' + escapeHtml([...new Set(fl.map((r) => r._file))].join(', ') || 'none') + ' · append-only, not hash-chained (attested acts against policy; the control plane\'s chain above records who commanded them)</div>';
  h += '<table>' + th(['ts', 'action', 'key / name', 'from → to', 'outcome', 'actor', 'attestation']) + fl.map((x) => td([x.ts, x.action || '', [x.key, x.name].filter(Boolean).join(' / '), (x.from !== undefined || x.to !== undefined) ? (JSON.stringify(x.from) + ' → ' + JSON.stringify(x.to)) : (x.role ? x.role + (x.scope ? ' @ ' + x.scope : '') : ''), x.outcome || '', x.actor || '', x.phrase || ''])).join('') + '</table>';
  // 3 agents
  for (const b of agentBlocks) {
    h += '<h2>3. Agent chain — ' + escapeHtml(b.name) + ' (' + escapeHtml(b.profile || '?') + ') — logs/audit.jsonl</h2>';
    h += '<div class="meta">' + (b.err ? '<span class="bad">' + escapeHtml(b.err) + '</span>' : (b.ver ? (b.ver.ok ? '<span class="ok">chain VERIFIED by the agent</span> · ' + escapeHtml(b.ver.length || 0) + ' entries' : '<span class="bad">chain BROKEN at entry ' + escapeHtml(b.ver.brokenAt) + '</span>') : 'chain state unknown'))
      + ' · ' + b.rows.length + ' records in ' + escapeHtml(rangeText) + (b.total !== null && b.total !== undefined ? ' of ' + b.total + ' held' + (b.oldestTs ? ' since ' + escapeHtml(b.oldestTs) : '') : '') + ' · ' + b.pages + ' page' + (b.pages === 1 ? '' : 's') + ' of 500'
      + ' · plane re-verification of what it received: ' + (b.rows.length ? (b.re.ok ? '<span class="ok">OK (' + b.re.checked + ' hashes + continuity)</span>' : '<span class="bad">BROKEN at ' + escapeHtml(b.re.brokenAt) + ' — ' + escapeHtml(b.re.why) + '</span>') : 'nothing to check')
      + ' (this document is a copy; the chain stays with the agent)</div>';
    h += '<table>' + th(['ts', 'event', 'outcome', 'route', 'rc', 'duration', 'actor', 'on behalf of', 'detail']) + b.rows.map((x) => td([x.ts, evOf(x), outOf(x), x.route || '', x.exitCode !== undefined && x.exitCode !== null ? x.exitCode : '', x.durationMs !== undefined ? x.durationMs + 'ms' : '', who(x.actor), x.onBehalfOf ? who(x.onBehalfOf) : '', [x.name || '', x.job || '', x.jobId || '', x.protected !== undefined ? 'protected=' + x.protected : ''].filter(Boolean).join(' · ')])).join('') + '</table>';
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

// Telegram allowlist -- read from aegis.config.json, NOT from policy. The policy file is
// committed and reviewable; a chat id is a per-installation identifier that must not be
// published to git, so it lives beside the other per-install values here. Same fail-closed
// shape as before: unreadable, missing or malformed => nobody, because a Telegram lane that
// permits everyone on a bad read is worse than one that answers no one.
function readTelegramChatIds() {
  try {
    const cfg = JSON.parse(fs.readFileSync(CFG, 'utf8'));
    if (!Array.isArray(cfg.telegramChatIds)) return [];
    // Same shape the policy validator enforced, kept here now that the validator is gone.
    return cfg.telegramChatIds.map(String).filter((x) => /^-?[0-9]{5,20}$/.test(x));
  } catch (e) { return []; }
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
    child.on('error', (e) => resolve({ code: 4, out: 'spawn error: ' + e.message }));
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

// ---- background / inlay ---------------------------------------------------------------------
// SIBLING, NOT SHARED: the agents run this same two-slot lane from fleet-core/webchat-ops.js
// (search "background / inlay" there). Kept separate on purpose -- aegis is not a core consumer:
// no vendored core, no manifest, and a different execution environment (a systemd unit under
// NoNewPrivileges, not a container), so binding it to core would be a larger change than the
// duplication it removes. Change one, read the other: what must stay in step is the wire shape
// (/ui/background, slots page|inlay, magic-byte typing, 12 MB cap), not the code.
// Aegis's own look, and only its own: the agents each own theirs. Two OPTIONAL slots -- `page`
// fills the window, `inlay` is what the panels ghost; with only `page` uploaded the panels ghost
// that. Files live beside the audit ledger in the checkout, gitignored, so a deallocate/start
// keeps them and `git pull` never touches them. This is a sibling of the agents' implementation
// in fleet-core webchat-ops.js rather than a shared module, because Aegis is not a core consumer
// and binding it to the manifest is a bigger change than the feature; keep the two in step.
const UI_DIR = path.join(__dirname, 'ui-state');
const UI_JSON = path.join(UI_DIR, 'ui.json');
const BG_SLOTS = { page: 1, inlay: 1 };
// Magic bytes, never the extension and never the client's Content-Type -- both are caller-chosen.
// SVG is refused outright: it is a script carrier, and this is the one route that accepts a file.
const BG_MAGIC = [
  { ext: 'png',  mime: 'image/png',  test: (b) => b.length > 8 && b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47 },
  { ext: 'jpg',  mime: 'image/jpeg', test: (b) => b.length > 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff },
  { ext: 'webp', mime: 'image/webp', test: (b) => b.length > 12 && b.slice(0, 4).toString('ascii') === 'RIFF' && b.slice(8, 12).toString('ascii') === 'WEBP' },
];
// 12 MB, not 8: the operator's real scenes run to 7.8 MB and a cap that rejects the files in
// actual use is a cap set by guesswork.
const BG_MAX = 12 * 1024 * 1024;

function bgReadUi() {
  try { const j = JSON.parse(fs.readFileSync(UI_JSON, 'utf8')); return (j && typeof j === 'object') ? j : {}; }
  catch { return {}; }
}
function bgWriteUi(next) {
  try {
    fs.mkdirSync(UI_DIR, { recursive: true });
    fs.writeFileSync(UI_JSON, JSON.stringify(next) + '\n');
  } catch (e) { console.error('ui.json write failed: ' + e.message); }
}
function bgSlotFile(slot) {
  for (const m of BG_MAGIC) {
    const f = path.join(UI_DIR, slot + '.' + m.ext);
    if (fs.existsSync(f)) return { file: f, ext: m.ext, mime: m.mime };
  }
  return null;
}
function bgClamp(v, lo, hi, dflt) {
  const n = Number(v);
  return Number.isFinite(n) ? Math.min(hi, Math.max(lo, n)) : dflt;
}
function bgState() {
  const ui = bgReadUi();
  const out = { ok: true, accept: BG_MAGIC.map((m) => m.mime), maxBytes: BG_MAX, slots: {} };
  for (const slot of Object.keys(BG_SLOTS)) {
    const f = bgSlotFile(slot);
    const s = (ui.background && ui.background[slot]) || {};
    out.slots[slot] = {
      present: !!f,
      ext: f ? f.ext : null,
      fit: s.fit || 'cover',
      posX: bgClamp(s.posX, 0, 100, 50),
      posY: bgClamp(s.posY, 0, 100, 50),
      opacity: bgClamp(s.opacity, 0, 1, slot === 'inlay' ? 0.14 : 1),
      rotate: bgClamp(s.rotate, -180, 180, slot === 'inlay' ? -6 : 0),
      scale: bgClamp(s.scale, 0.2, 3, slot === 'inlay' ? 1.4 : 1),
      // Mean luminance measured in the BROWSER on a canvas and labelled as such. It drives the
      // panel-text contrast flip only; decoding images here would add a dependency for no gain.
      lum: (typeof s.lum === 'number') ? s.lum : null,
      lumSource: (typeof s.lum === 'number') ? 'client-measured' : null,
      aspect: (typeof s.aspect === 'number') ? s.aspect : null,
      w: (typeof s.w === 'number') ? s.w : null,
      h: (typeof s.h === 'number') ? s.h : null,
    };
  }
  return out;
}
function bgReadRaw(req, cap) {
  return new Promise((resolve, reject) => {
    const chunks = []; let n = 0; let done = false;
    req.on('data', (c) => {
      if (done) return;
      n += c.length;
      // Do NOT destroy here: killing the socket races the 413 and the client sees a connection
      // reset instead of the reason. The route answers first, then closes.
      if (n > cap) { done = true; reject(new Error('too large')); return; }
      chunks.push(c);
    });
    req.on('end', () => { if (!done) { done = true; resolve(Buffer.concat(chunks)); } });
    req.on('error', (e) => { if (!done) { done = true; reject(e); } });
  });
}


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
// fleetctl's exit contract on the policy lane: 0 the control is fully applied; 1 the policy gate
// applied and is enforcing but its Azure mirror (lock, budget object) did not -- a half-applied
// control, whose honest word is incomplete, not refused, because something did change; anything
// else refused or errored and changed nothing. The plane records the same verdict the fleetctl
// ledger holds, so the two chains cannot disagree about what happened.
function policyVerdict(code) {
  if (code === 0) return 'ok';
  if (code === 1) return 'incomplete: policy applied, azure mirror not applied -- see the fleetctl policy ledger';
  return 'refused-or-error: exit ' + code;
}

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
  // --- background: Aegis's own page + panel-inlay images (its look only; agents own theirs) ---
  {
    const bgm = req.url.match(/^\/api\/background(?:\/([a-z]+))?(?:\/(file|settings))?(?:\?.*)?$/);
    if (bgm) {
      const slot = bgm[1] || null;
      const verb = bgm[2] || null;
      if (req.method === 'GET' && !slot) return sendJson(res, bgState());
      if (slot && !BG_SLOTS[slot]) return sendJson(res, { ok: false, error: 'unknown slot' }, 400);

      if (req.method === 'GET' && verb === 'file') {
        const f = bgSlotFile(slot);
        if (!f) { res.statusCode = 404; return res.end(); }
        res.setHeader('Content-Type', f.mime);
        res.setHeader('Cache-Control', 'no-store');
        return res.end(fs.readFileSync(f.file));
      }

      if (req.method === 'POST' && verb === 'settings') {
        const b = await readBody(req);
        const ui = bgReadUi();
        const cur = ui.background || {};
        const st = Object.assign({}, cur[slot]);
        if (b.fit !== undefined) st.fit = (['cover', 'contain', 'fill'].indexOf(String(b.fit)) >= 0) ? String(b.fit) : 'cover';
        if (b.posX !== undefined) st.posX = bgClamp(b.posX, 0, 100, 50);
        if (b.posY !== undefined) st.posY = bgClamp(b.posY, 0, 100, 50);
        if (b.opacity !== undefined) st.opacity = bgClamp(b.opacity, 0, 1, 0.14);
        if (b.rotate !== undefined) st.rotate = bgClamp(b.rotate, -180, 180, 0);
        if (b.scale !== undefined) st.scale = bgClamp(b.scale, 0.2, 3, 1);
        cur[slot] = st; ui.background = cur; bgWriteUi(ui);
        return sendJson(res, bgState());
      }

      if (req.method === 'POST' && slot) {
        let buf;
        try { buf = await bgReadRaw(req, BG_MAX); }
        catch (e) {
          const tooBig = /too large/.test(e.message);
          res.statusCode = tooBig ? 413 : 400;
          res.setHeader('Content-Type', 'application/json');
          res.setHeader('Connection', 'close');
          return res.end(JSON.stringify({ ok: false, error: tooBig ? 'too large (max ' + BG_MAX + ' bytes)' : 'read failed' }), () => { try { req.destroy(); } catch { /* already gone */ } });
        }
        if (!buf || !buf.length) return sendJson(res, { ok: false, error: 'empty body - POST the raw image bytes' }, 400);
        const kind = BG_MAGIC.find((m) => m.test(buf));
        if (!kind) return sendJson(res, { ok: false, error: 'not a PNG, JPEG or WebP (checked by content, not by name)' }, 415);
        try {
          fs.mkdirSync(UI_DIR, { recursive: true });
          // one fixed name per slot: no traversal surface and no unbounded growth
          for (const m of BG_MAGIC) { try { fs.unlinkSync(path.join(UI_DIR, slot + '.' + m.ext)); } catch { /* absent */ } }
          fs.writeFileSync(path.join(UI_DIR, slot + '.' + kind.ext), buf, { mode: 0o644 });
        } catch (e) { return sendJson(res, { ok: false, error: 'write failed: ' + e.message }, 500); }
        const q = {};
        const qs = req.url.indexOf('?');
        if (qs >= 0) for (const [k, v] of new URLSearchParams(req.url.slice(qs + 1))) q[k] = v;
        const ui = bgReadUi();
        const cur = ui.background || {};
        cur[slot] = Object.assign({}, cur[slot], {
          lum: q.lum !== undefined ? bgClamp(q.lum, 0, 1, null) : (cur[slot] || {}).lum,
          aspect: q.aspect !== undefined ? bgClamp(q.aspect, 0.05, 20, null) : (cur[slot] || {}).aspect,
          w: q.w !== undefined ? bgClamp(q.w, 1, 20000, null) : (cur[slot] || {}).w,
          h: q.h !== undefined ? bgClamp(q.h, 1, 20000, null) : (cur[slot] || {}).h,
        });
        ui.background = cur; bgWriteUi(ui);
        audit({ action: 'ui-background-set', slot, bytes: buf.length, ext: kind.ext, actor: actorOf(req), via: 'panel' });
        return sendJson(res, bgState());
      }

      // Reset. Deliberately NOT attested: it destroys a preference, and gating cosmetics
      // cheapens the gate. Clearing `page` clears `inlay` too -- an inlay with nothing behind
      // it is not a state worth having.
      if (req.method === 'DELETE' && slot) {
        const kill = (slot === 'page') ? ['page', 'inlay'] : ['inlay'];
        const ui = bgReadUi();
        const cur = ui.background || {};
        for (const s2 of kill) {
          for (const m of BG_MAGIC) { try { fs.unlinkSync(path.join(UI_DIR, s2 + '.' + m.ext)); } catch { /* absent */ } }
          delete cur[s2];
        }
        if (Object.keys(cur).length) ui.background = cur; else delete ui.background;
        bgWriteUi(ui);
        audit({ action: 'ui-background-reset', slots: kill.join(','), actor: actorOf(req), via: 'panel' });
        return sendJson(res, bgState());
      }
    }
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
    audit({ action: 'policy-set', key, value, actor: actorOf(req), outcome: policyVerdict(r.code), via: 'panel' });
    return sendJson(res, { ok: r.code === 0, incomplete: r.code === 1, code: r.code, out: panelClean(r.out) });
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
  // Ledger archive: state (what was last captured) and a manual capture. Read-only GET; the
  // POST is the same act the timer performs, ledgered with the operator as its reason.
  if (req.url === '/api/ledgers/state' && req.method === 'GET') {
    return sendJson(res, { ok: true, enabled: !!FLEET_IAC_ROOT, plane: planeName(), ...ledgerState() });
  }
  if (req.url === '/api/ledgers/archive' && req.method === 'POST') {
    if (!FLEET_IAC_ROOT) return sendJson(res, { ok: false, error: 'FLEET_IAC_ROOT unset — the fleet lane owns the store' }, 500);
    const r = await ledgerArchiveRun(actorOf(req), 'operator');
    return sendJson(res, r, r.ok ? 200 : 500);
  }
  if (req.url === '/api/audit/verify' && req.method === 'GET') {
    return sendJson(res, { ok: true, chain: verifyChain() });
  }
  // Printable export (HTML, print to PDF from the browser). Read-only; the act of exporting is
  // itself recorded on the control-plane chain, because a copy of the ledgers left the plane.
  if (req.url.startsWith('/api/audit/export') && req.method === 'GET') {
    const actor = actorOf(req);
    const u = new URL(req.url, 'http://x');
    const iso = (v) => { if (!v) return null; const d = new Date(v); return isNaN(d.getTime()) ? null : d.toISOString(); };
    const range = { from: iso(u.searchParams.get('from')), to: iso(u.searchParams.get('to')) };
    audit({ action: 'audit-export', actor, outcome: 'ok', range: (range.from || range.to) ? range : 'full' });
    const html = await buildAuditExport(actor, range);
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
    const verb = on ? 'unprotect' : 'protect';
    // A REQUEST, not a decision. This plane used to run `policy <verb>` itself, which worked
    // only because it wrote its own untracked policy copy. With one committed policy file that
    // same write would dirty a tracked file on a host with no push credentials: the change
    // would never reach git, and the next Update plane would collide with it. So the panel now
    // does what an agent already does -- ask -- and the CLI plus a commit decides. The attest
    // phrase is kept as provenance for the request: who asked, in what words.
    audit({ action: 'protect-request', name, verb, phrase: attest, actor: actorOf(req), outcome: 'requested' });
    const agent = agentByName(name);
    if (agent) { try { callAgent(agent, 'POST', '/protection', { request: verb }, actorOf(req)); } catch { /* unreachable */ } }
    const required = 'I approve ' + (on ? 'unprotecting ' : 'protecting ') + name;
    return sendJson(res, {
      ok: true, requested: verb, protectedAgents: list,
      out: 'REQUESTED: ' + verb + ' ' + name + ' -- nothing has changed yet.\n\n'
         + 'This plane can request a protection change but not decide one. The policy file is\n'
         + 'committed and reviewable, and this host cannot push, so a change made here would\n'
         + 'never reach git and would collide with the next Update plane.\n\n'
         + 'Complete it on the workstation:\n'
         + '  node provision/bin/fleetctl.js policy ' + verb + ' ' + name + ' --attest "' + required + '"\n'
         + '  git commit -am "policy: ' + verb + ' ' + name + '" && git push\n\n'
         + 'then Update plane here, and this card will follow.',
    });
  }
  // Which control plane is this? Two planes exist (hosted primary, workstation break-glass)
  // and an operator must be able to read which one they are commanding: same panel, same
  // agents, different ledgers. $AEGIS_PLANE wins, else the host name -- the same rule
  // fleetctl enroll uses to name a plane's service tokens.
  // ---- Update plane: the plane's own two checkouts (this repo, the fleet repo) moved to their
  // pushed HEADs and the unit restarted -- from the panel, as an attested act. This is what
  // `fleetctl aegis update` does from a workstation over run-command; here the plane does it to
  // itself: fetch and read heads for the plan (nothing moved), fast-forward-only pulls as the
  // service user for the go (a diverged checkout refuses rather than merges; a failed pull leaves
  // the unit alone), the act ledgered with before/after commits, then the restart through the one
  // sudoers rule the plane holds (systemctl restart aegis) after the response has gone out.
  if (req.url === '/api/plane/update/plan' && req.method === 'GET') {
    // One read of both checkouts, two facts from it: disk vs origin (is there a pull to make)
    // and process vs disk (is there a restart to make). The second is invisible to git and is
    // the state that looked healthiest -- clean, current, unit active, and running old code.
    const st = planeRepoState();
    return sendJson(res, { ok: true, plane: planeName(), ...st, skew: planeSkew(st) });
  }
  // The confirmation is the move itself, not a typed sentence: the panel sends the exact commits
  // the operator saw in the plan (from -> to per repo) and the plane accepts only if that is still
  // the move it would make. A push that lands between plan and go makes the plan stale and the go
  // is refused with the new heads. The record is unchanged -- actor, plane, before/after -- and it
  // is what an auditor needs; the sentence had been the same friction as a destructive act for a
  // reversible fast-forward, and today it was typed six times.
  if (req.url === '/api/plane/update/go' && req.method === 'POST') {
    const b = await readBody(req);
    const plane = planeName();
    const actor = actorOf(req);
    const base = { action: 'plane-update', plane, actor };
    const before = planeRepoState();
    const expect = (b && typeof b.expect === 'object' && b.expect) || {};
    const stale = [];
    for (const r of ['aegis', 'fleet']) {
      const e = expect[r] || {}, s = before[r] || {};
      if (!s.present) continue;
      if (!s.pending) continue;                                    // nothing to move for this repo
      if (e.from !== s.local || e.to !== s.remote) stale.push(r + ': plan said ' + (e.from || '?') + ' \u2192 ' + (e.to || '?') + ', plane sees ' + s.local + ' \u2192 ' + s.remote);
    }
    // A checkout is not a deployment, so "nothing to pull" is not "nothing to do": if this
    // process is older than the code on disk, restarting IS the update. Refusing it for want of
    // a pull is what left a stale plane with no way to recover itself from its own panel.
    const skew = planeSkew(before);
    if (!(before.aegis && before.aegis.pending) && !(before.fleet && before.fleet.pending)) {
      if (!skew.skewed) {
        audit({ ...base, outcome: 'refused: nothing pending', before: repoHeads(before) });
        return sendJson(res, { ok: false, out: 'nothing to update — both checkouts are at their pushed HEADs, and this process is running them' }, 400);
      }
      // Same grammar as a pull: the panel names what it saw and the plane refuses if that is no
      // longer the move. Here the move is "boot what is on disk", so the disk heads are the move.
      const er = (expect && typeof expect.restart === 'object' && expect.restart) || {};
      const rs = [];
      for (const r of ['aegis', 'fleet']) { const s = before[r] || {}; if (s.present && er[r] !== s.local) rs.push(r + ': plan said ' + (er[r] || '?') + ', plane sees ' + s.local); }
      if (rs.length) {
        audit({ ...base, outcome: 'refused: restart plan stale', expect, before: repoHeads(before) });
        return sendJson(res, { ok: false, out: 'REFUSED — the plan is stale, check for updates again:\n  ' + rs.join('\n  ') }, 409);
      }
      audit({ ...base, outcome: 'done: restart only', running: skew.boot, skew: skew.detail, before: repoHeads(before) });
      sendJson(res, { ok: true, pulls: {}, restartOnly: true, restarting: true, skew: skew.detail, out: 'nothing to pull — this process is older than the checkouts; restarting the unit in ~1 s — the panel will reconnect' });
      setTimeout(() => restartUnit(base), 800);
      return;
    }
    if (stale.length) {
      audit({ ...base, outcome: 'refused: plan stale', expect, before: repoHeads(before) });
      return sendJson(res, { ok: false, out: 'REFUSED — the plan is stale, check for updates again:\n  ' + stale.join('\n  ') }, 409);
    }
    audit({ ...base, expect, outcome: 'started', before: repoHeads(before) });
    const pulls = {};
    let failed = false;
    for (const r of ['aegis', 'fleet']) {
      const dir = r === 'aegis' ? __dirname : FLEET_IAC_ROOT;
      const p = spawnSync('git', ['-C', dir, 'pull', '--ff-only', '-q'], { encoding: 'utf8', timeout: 120000 });
      const head = spawnSync('git', ['-C', dir, 'rev-parse', '--short', 'HEAD'], { encoding: 'utf8' });
      pulls[r] = { ok: p.status === 0, before: before[r] && before[r].local, after: (head.stdout || '').trim(), note: (p.stderr || p.stdout || '').trim().split('\n').filter(Boolean).slice(-1)[0] || '' };
      if (p.status !== 0) failed = true;
    }
    if (failed) {
      audit({ ...base, outcome: 'failed: a pull failed; unit not restarted', pulls });
      return sendJson(res, { ok: false, pulls, out: 'a pull failed (diverged checkout?) — the unit was NOT restarted' }, 500);
    }
    audit({ ...base, outcome: 'done', pulls });
    sendJson(res, { ok: true, pulls, restarting: true, out: 'pulled both checkouts; restarting the unit in ~1 s — the panel will reconnect' });
    setTimeout(() => restartUnit(base), 800);
    return;
  }
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
    const skew = planeSkew();
    return sendJson(res, { plane: planeName(), bind: HOST + ':' + PORT, fleetctl: !!FLEET_IAC_ROOT, cf: cfEnvProblem() ? 'not ready' : 'ok',
      running: skew.boot, checkout: skew.checkout, skewed: skew.skewed, skewDetail: skew.detail, bootedAt: BOOT.at,
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
    // Telegram door: read + chat only, allowlist from aegis.config.json, off unless a bot token resolves.
    // Started AFTER the plane listens, and only when FLEET_IAC_ROOT is known (the allowlist
    // is policy); a plane without policy has no allowlist, so it has no Telegram either.
    if (FLEET_IAC_ROOT) {
      telegram.start({
        cfg: bootCfg, loadAgents, agentByName, readChatIds: readTelegramChatIds, sendToAgent, callAgent, audit, planeName,
        stateFile: path.join(__dirname, 'telegram-state.json'),
        log: (...a) => console.log('telegram:', ...a),
      });
    } else console.log('telegram: off (FLEET_IAC_ROOT unset — no policy, no allowlist)');
    // Ledger archive: one verified capture per UTC day into the ledgers class. Needs the fleet
    // lane (it owns the store), so a plane without FLEET_IAC_ROOT simply says so and archives
    // nothing rather than failing quietly on a timer nobody watches.
    if (FLEET_IAC_ROOT) { ledgerArchiveStart(); console.log('ledger archive: on (one capture per UTC day into ledgers/' + planeName() + '/)'); }
    else console.log('ledger archive: off (FLEET_IAC_ROOT unset — the fleet lane owns the store)');
  }));
