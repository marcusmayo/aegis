'use strict';
// telegram.js — the control plane's Telegram door. Read + chat only, by construction.
//
// WHAT IT IS. A long-poll relay: this process asks api.telegram.org for updates (outbound
// HTTPS, 25 s long-poll, one poller) and forwards allowlisted operators' text to a fleet
// agent through the SAME path the browser console uses (sendToAgent). No inbound port, no
// webhook, no new surface on the plane. What comes back is the agent's streamed answer,
// aggregated, sent as plain text in 4096-char chunks.
//
// WHO. The numeric chat ids in policy `telegramChatIds` (attested, empty = nobody). Any
// other chat is ignored SILENTLY -- a public bot must not confirm it exists -- and logged
// once per id, which is how an operator learns their own id before attesting it. The
// policy is re-read on every message: an attested change takes effect at once, and a
// broken policy file reads as empty (fails closed).
//
// WHAT IT CAN DO. Chat, and the per-agent OPERATOR CONTROLS the panel's cards expose --
// the same agent endpoints, nothing the cards cannot do:
//   /agents /use <agent> /status /new /help        chat + lock
//   /web on|off                                    the agent's web-access toggle
//   /model  |  /model <n|slug>                     list models (web-capable marked) | switch
//   /staged  |  /process <name|all>                staged uploads awaiting Process | process them
//   /queue                                         the agent's intake queue (read)
//   plain text -> the locked target; "<agent>: <text>" goes to that agent once.
// Nothing else exists here: no provisioning, policy, migrate, decommission, relay or grant --
// there is no code path for them, so no phrase typed into a phone can reach them. Every state
// change (/use /new /web /model /process) is ledgered with actor telegram:<chat id>. Heavy
// lifting stays in the panel or the agent's own webchat.
//
// PROVENANCE. Every command is ledgered on the plane's chain with actor {src:'telegram',
// id:<chat id>} through the same actorOf override the HTTP lanes use, and the agent is told
// X-Aegis-On-Behalf-Of: telegram:<chat id> (the plane's assertion; the agent still records
// the plane's token as the verified caller).
//
// TOKEN. $TELEGRAM_BOT_TOKEN, else vault secret `telegram-bot-token` (same vault, same az
// session as the Cloudflare token). Absent -> the lane is off, one log line, nothing else.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const API = 'https://api.telegram.org/bot';
const MAX_MSG = 4096;
const MAX_PROMPT = 4000;
const NAME_RE = /^[a-z][a-z0-9-]{1,23}$/;

const state = { on: false, source: '', reason: 'not started', chatsSeen: {}, lastError: '', polls: 0, offset: 0, lastPollAt: null, bot: '' };

function az(args) {
  const r = process.platform === 'win32'
    ? spawnSync('az ' + args.join(' '), { shell: true, encoding: 'utf8', timeout: 30000 })
    : spawnSync('az', args, { encoding: 'utf8', timeout: 30000 });
  return { out: (r.stdout || '').trim(), err: (r.stderr || '').trim().split('\n')[0] || String(r.error || '').split('\n')[0] };
}
function resolveToken(cfg) {
  const env = (process.env.TELEGRAM_BOT_TOKEN || '').trim();
  if (env) return { token: env, source: 'env' };
  const vault = ((cfg && cfg.cfVaultName) || '').trim();
  if (!vault || !/^[a-zA-Z0-9-]{3,24}$/.test(vault)) return { token: '', source: '', reason: 'no $TELEGRAM_BOT_TOKEN and no cfVaultName to read telegram-bot-token from' };
  const r = az(['keyvault', 'secret', 'show', '--vault-name', vault, '--name', 'telegram-bot-token', '--query', 'value', '-o', 'tsv']);
  if (!r.out) return { token: '', source: '', reason: 'no $TELEGRAM_BOT_TOKEN and vault ' + vault + ' has no telegram-bot-token (' + (r.err || 'empty') + ') — lane off' };
  return { token: r.out.trim(), source: 'vault(' + vault + ')' };
}
// Pure: does this token look like a bot token (digits:secret)? Exported for tests.
function looksLikeBotToken(t) { return /^\d{6,12}:[A-Za-z0-9_-]{30,}$/.test(String(t || '')); }

// Pure: split text into <=MAX_MSG chunks on line boundaries where possible. Exported for tests.
function chunk(text, max = MAX_MSG) {
  const out = []; let s = String(text || '');
  while (s.length > max) {
    let cut = s.lastIndexOf('\n', max); if (cut < max * 0.5) cut = max;
    out.push(s.slice(0, cut)); s = s.slice(cut).replace(/^\n/, '');
  }
  if (s.length || !out.length) out.push(s);
  return out;
}
// Pure: parse an inbound text into a command. Exported for tests.
function parseCommand(text) {
  const t = String(text || '').trim();
  const m = t.match(/^\/([a-z]+)(?:@\w+)?(?:\s+([\s\S]*))?$/i);
  if (m) return { cmd: m[1].toLowerCase(), arg: (m[2] || '').trim() };
  const to = t.match(/^([a-z][a-z0-9-]{1,23}):\s+([\s\S]+)$/);
  if (to) return { cmd: 'to', arg: to[1], text: to[2].trim() };
  return { cmd: 'text', text: t };
}

function start(deps) {
  // deps: { cfg, loadAgents, agentByName, readChatIds, sendToAgent, callAgent, audit, log, stateFile, fetch }
  const log = deps.log || ((...a) => console.log('telegram:', ...a));
  const f = deps.fetch || globalThis.fetch;
  const tok = resolveToken(deps.cfg);
  if (!tok.token) { state.on = false; state.reason = tok.reason; log(tok.reason); return state; }
  if (!looksLikeBotToken(tok.token)) { state.on = false; state.reason = 'telegram-bot-token does not look like a bot token — lane off'; log(state.reason); return state; }
  state.on = true; state.source = tok.source; state.reason = '';
  const base = API + tok.token + '/';
  const stateFile = deps.stateFile;
  let sticky = {}; try { sticky = JSON.parse(fs.readFileSync(stateFile, 'utf8')); } catch { sticky = {}; }
  const saveSticky = () => { try { fs.writeFileSync(stateFile, JSON.stringify(sticky, null, 2)); } catch { /* best effort */ } };

  const api = async (method, body) => {
    // hard deadline: (long-poll timeout + 15s) or 20s -- a hung socket must surface as an error
    // in the journal and a retry, never as a silent stall of the whole lane
    const deadline = ((body && body.timeout) || 0) * 1000 + 15000;
    const ac = (typeof AbortController !== 'undefined') ? new AbortController() : null;
    const timer = ac ? setTimeout(() => ac.abort(), deadline) : null;
    let r;
    try { r = await f(base + method, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}), signal: ac ? ac.signal : undefined }); }
    finally { if (timer) clearTimeout(timer); }
    let j = null; try { j = await r.json(); } catch { /* ignore */ }
    if (!j || !j.ok) throw new Error(method + ' failed: ' + (j && j.description ? j.description : ('HTTP ' + r.status)));
    return j.result;
  };
  const say = async (chatId, text) => { for (const part of chunk(text)) await api('sendMessage', { chat_id: chatId, text: part, disable_web_page_preview: true }); };
  const typing = (chatId) => api('sendChatAction', { chat_id: chatId, action: 'typing' }).catch(() => {});

  const help = () => 'Aegis — fleet control plane (chat + agent controls; nothing destructive)\n' +
    '/agents — list agents; ▸ marks the one this chat is locked to\n' +
    '/use <agent> — lock this chat to an agent\n' +
    '/status — plane, target, web and model\n' +
    '/new — start a fresh conversation on the target\n' +
    '/web on|off — the target\'s web access\n' +
    '/model — list models (★ web-capable); /model <n|slug> — switch\n' +
    '/staged — uploads awaiting Process; /process <name|all> — process them\n' +
    '/queue — the target\'s intake queue\n' +
    'anything else — sent to the target agent\n' +
    '<agent>: <text> — one message to that agent without changing the lock';

  // agent calls: JSON in, JSON out; a non-200 is reported as text, never thrown into the loop
  const agentJson = async (agent, method, p, body, chatId) => {
    const r = await deps.callAgent(agent, method, p, body, { src: 'telegram', id: chatId });
    let j = null; try { j = JSON.parse(r && r.body || '{}'); } catch { j = null; }
    return { status: r ? r.status : 0, json: j, raw: r ? String(r.body || '').slice(0, 200) : '' };
  };
  const modelInfo = async (agent, chatId) => {
    const r = await agentJson(agent, 'GET', '/model', null, chatId);
    if (r.status !== 200 || !r.json) return null;
    return { options: r.json.options || [], active: r.json.active || null, webActive: !!r.json.webActive };
  };
  const modelLine = (mi) => {
    if (!mi) return 'model: n/a';
    return mi.options.map((o, i) => (i + 1) + '. ' + (o.slug === mi.active ? '▸ ' : '  ') + (o.label || o.slug) + (o.web ? ' ★' : '') + (o.label && o.label !== o.slug ? '  (' + o.slug + ')' : '')).join('\n') + '\nactive: ' + (mi.active || '?') + (mi.webActive ? '  · web ON' : '');
  };
  const webState = async (agent, chatId) => { const r = await agentJson(agent, 'GET', '/web-access', null, chatId); return r.status === 200 && r.json ? !!r.json.enabled : null; };

  async function handle(msg) {
    const chatId = String(msg.chat && msg.chat.id);
    const text = String(msg.text || '');
    const allowed = deps.readChatIds();
    if (!allowed.includes(chatId)) {
      if (!state.chatsSeen[chatId]) { state.chatsSeen[chatId] = Date.now(); log('ignored message from unknown chat ' + chatId + ' (not in policy telegramChatIds)'); }
      return; // silent
    }
    const c = parseCommand(text);
    const actor = { src: 'telegram', id: chatId };
    const agents = deps.loadAgents();
    // A lock is a pointer to a registry entry, so it dies with the entry: after a decommission
    // /agents still said "locked to <gone agent>" and every plain message went nowhere with a
    // confusing error. Clear it here, once, and say so -- with three agents in the lane a stale
    // lock stops being cosmetic and starts sending work at a name that no longer exists.
    let cur = sticky[chatId] || '';
    if (cur && !deps.agentByName(cur)) {
      delete sticky[chatId]; saveSticky();
      deps.audit({ event: 'telegram-lock-cleared', agent: cur, actor, outcome: 'ok (agent left the registry)' });
      say(chatId, cur + ' is no longer in the fleet — this chat is unlocked. /agents to see what is left.');
      cur = '';
    }
    if (c.cmd === 'start' || c.cmd === 'help') return say(chatId, help());
    if (c.cmd === 'agents') return say(chatId, (agents.length ? agents.map((a) => (a.name === cur ? '▸ ' : '  ') + a.name + '  (' + (a.profile || '?') + ')').join('\n') : 'no agents registered') + (cur ? '\n\nlocked to: ' + cur : '\n\nno target locked — /use <agent>'));
    if (c.cmd === 'use') {
      if (!NAME_RE.test(c.arg) || !deps.agentByName(c.arg)) return say(chatId, 'unknown agent — /agents to list');
      sticky[chatId] = c.arg; saveSticky();
      deps.audit({ event: 'telegram-use', agent: c.arg, actor });
      return say(chatId, 'locked to ' + c.arg);
    }
    if (c.cmd === 'status') {
      const t = cur ? deps.agentByName(cur) : null;
      let reach = 'n/a', extra = '';
      if (t) {
        // the same probe the panel's cards use for "reachable": GET /color (every agent serves it)
        try { const r = await deps.callAgent(t, 'GET', '/color', null, { src: 'telegram', id: chatId }); reach = r && r.status === 200 ? 'reachable' : ('HTTP ' + (r && r.status)); } catch (e) { reach = 'unreachable (' + String(e.message || e).slice(0, 80) + ')'; }
        try { const w = await webState(t, chatId); const mi = await modelInfo(t, chatId); extra = '\nweb: ' + (w === null ? 'n/a' : (w ? 'ON' : 'OFF')) + '\nmodel: ' + (mi ? ((mi.options.find((o) => o.slug === mi.active) || {}).label || mi.active || '?') : 'n/a'); } catch { /* keep the basics */ }
      }
      return say(chatId, 'plane: ' + (deps.planeName ? deps.planeName() : 'aegis') + '\ntarget: ' + (cur || 'none') + (t ? '  ' + reach : '') + extra + '\nagents: ' + agents.map((a) => a.name).join(', '));
    }
    // ---- operator controls: the same agent endpoints as the panel's cards ----
    const needTarget = () => { const t = cur ? deps.agentByName(cur) : null; if (!t) say(chatId, 'no target locked — /use <agent> first'); return t; };
    if (c.cmd === 'web') {
      const t = needTarget(); if (!t) return;
      const arg = c.arg.toLowerCase();
      if (arg !== 'on' && arg !== 'off') { const w = await webState(t, chatId); return say(chatId, t.name + ' web: ' + (w === null ? 'n/a' : (w ? 'ON' : 'OFF')) + '\n/web on | /web off'); }
      const enable = arg === 'on';
      deps.audit({ event: 'telegram-web', agent: t.name, actor, enabled: enable });
      const r = await agentJson(t, 'POST', '/web-access', { enabled: enable }, chatId);
      if (r.status !== 200) return say(chatId, 'web toggle failed: HTTP ' + r.status + (r.raw ? ' ' + r.raw : ''));
      // The toggle endpoint is AUTHORITATIVE now: it captures the model on a forced switch and
      // restores it on disable, server-side. This lane used to duplicate the switch client-side
      // and said nothing on restore -- the same tab-local pattern the webchat shed. The agent's
      // own message carries what actually happened ("switched to X; your model comes back" /
      // "restored Y"), so relay it instead of narrating a second, possibly disagreeing, version.
      const msg = r.json && r.json.message ? r.json.message : ('web ' + (enable ? 'ON' : 'OFF'));
      return say(chatId, t.name + ' — ' + msg);
    }
    if (c.cmd === 'model' || c.cmd === 'models') {
      const t = needTarget(); if (!t) return;
      const mi = await modelInfo(t, chatId);
      if (!mi) return say(chatId, 'model list unavailable on ' + t.name);
      if (!c.arg) return say(chatId, t.name + ' models:\n' + modelLine(mi) + '\n/model <n|slug> to switch');
      let pick = null;
      if (/^\d+$/.test(c.arg)) pick = mi.options[Number(c.arg) - 1] || null;
      else pick = mi.options.find((o) => o.slug === c.arg || (o.label && o.label.toLowerCase() === c.arg.toLowerCase())) || null;
      if (!pick) return say(chatId, 'unknown model — /model to list, then /model <n|slug>');
      if (mi.webActive && !pick.web) return say(chatId, (pick.label || pick.slug) + ' cannot search and web is ON for ' + t.name + ' — /web off first, or pick a ★ model');
      deps.audit({ event: 'telegram-model', agent: t.name, actor, slug: pick.slug });
      const r = await agentJson(t, 'POST', '/model/select', { slug: pick.slug }, chatId);
      return say(chatId, r.status === 200 ? t.name + ' model → ' + (pick.label || pick.slug) : 'model switch failed: HTTP ' + r.status + (r.raw ? ' ' + r.raw : ''));
    }
    if (c.cmd === 'staged') {
      const t = needTarget(); if (!t) return;
      const r = await agentJson(t, 'GET', '/files/staged', null, chatId);
      if (r.status !== 200 || !r.json) return say(chatId, 'staged list unavailable on ' + t.name + (r.status === 404 ? ' (import lane not on this agent yet)' : ' (HTTP ' + r.status + ')'));
      const files = r.json.files || [];
      return say(chatId, files.length ? t.name + ' staged (→ ' + (r.json.dest || '?') + '):\n' + files.map((f, i) => (i + 1) + '. ' + f.name + '  ' + (f.bytes || 0) + ' b').join('\n') + '\n/process <name|n|all>' : t.name + ': nothing staged');
    }
    if (c.cmd === 'process') {
      const t = needTarget(); if (!t) return;
      const r = await agentJson(t, 'GET', '/files/staged', null, chatId);
      if (r.status !== 200 || !r.json) return say(chatId, 'staged list unavailable on ' + t.name + ' (HTTP ' + r.status + ')');
      const files = r.json.files || [];
      if (!files.length) return say(chatId, t.name + ': nothing staged to process');
      let targets = [];
      if (!c.arg || c.arg === 'all') targets = files;
      else if (/^\d+$/.test(c.arg)) targets = files[Number(c.arg) - 1] ? [files[Number(c.arg) - 1]] : [];
      else targets = files.filter((f) => f.name === c.arg);
      if (!targets.length) return say(chatId, 'no such staged file — /staged to list, then /process <name|n|all>');
      const lines = [];
      for (const f of targets) {
        deps.audit({ event: 'telegram-process', agent: t.name, actor, file: f.name });
        const pr = await agentJson(t, 'POST', '/files/process', { name: f.name }, chatId);
        lines.push((pr.status === 200 ? '✓ ' : '✗ ') + f.name + (pr.status === 200 ? ' → ' + (r.json.dest || 'processed') : '  HTTP ' + pr.status + (pr.raw ? ' ' + pr.raw : '')));
      }
      return say(chatId, t.name + ' process:\n' + lines.join('\n'));
    }
    if (c.cmd === 'queue' || c.cmd === 'pending') {
      const t = needTarget(); if (!t) return;
      const r = await agentJson(t, 'GET', '/pending', null, chatId);
      if (r.status !== 200 || !r.json) return say(chatId, 'queue unavailable on ' + t.name + ' (HTTP ' + r.status + ')');
      const p = r.json; const items = Array.isArray(p.items) ? p.items : (Array.isArray(p) ? p : (p.groups && typeof p.groups === 'object' ? [].concat(...Object.values(p.groups).filter(Array.isArray)) : []));
      const n = items.length || (typeof p.count === 'number' ? p.count : 0);
      const names = items.slice(0, 15).map((it, i) => (i + 1) + '. ' + (typeof it === 'string' ? it : (it.name || it.file || it.id || JSON.stringify(it).slice(0, 60))));
      return say(chatId, t.name + ' queue: ' + n + (names.length ? '\n' + names.join('\n') + (items.length > 15 ? '\n…' : '') : '') + '\n(ask the agent to process an item; the review lane lives in its webchat)');
    }
    if (c.cmd === 'new') {
      const t = cur ? deps.agentByName(cur) : null;
      if (!t) return say(chatId, 'no target locked — /use <agent> first');
      deps.audit({ event: 'telegram-new', agent: t.name, actor });
      try { const r = await deps.callAgent(t, 'POST', '/session/reset', {}, { src: 'telegram', id: chatId }); return say(chatId, r && r.status === 200 ? 'new conversation on ' + t.name : 'reset failed: HTTP ' + (r && r.status)); }
      catch (e) { return say(chatId, 'reset failed: ' + String(e.message || e).slice(0, 120)); }
    }
    let target = null, prompt = '';
    if (c.cmd === 'to') { target = deps.agentByName(c.arg); prompt = c.text; if (!target) return say(chatId, 'unknown agent "' + c.arg + '" — /agents to list'); }
    else if (c.cmd === 'text') { target = cur ? deps.agentByName(cur) : null; prompt = c.text; if (!target) return say(chatId, 'no target locked — /use <agent> first, or "<agent>: <text>"'); }
    else return say(chatId, 'unknown command — /help');
    if (!prompt.trim()) return say(chatId, 'empty message');
    if (prompt.length > MAX_PROMPT) return say(chatId, 'message too long (' + prompt.length + ' > ' + MAX_PROMPT + ')');

    deps.audit({ agent: target.name, event: 'command', actor, promptSha256: crypto.createHash('sha256').update(prompt).digest('hex'), promptLen: prompt.length, status: 'sent', via: 'telegram' });
    let acc = ''; let err = '';
    const beat = setInterval(() => typing(chatId), 4000); typing(chatId);
    await new Promise((resolve) => {
      deps.sendToAgent(target, prompt, (frame) => {
        if (!frame) return;
        if (frame.type === 'token') acc += (frame.text || '');
        else if (frame.type === 'error') err += (err ? '\n' : '') + (frame.text || 'error');
      }, () => resolve(), { onBehalfOf: { src: 'telegram', id: chatId } });
    });
    clearInterval(beat);
    const body = (acc.trim() || (err ? '' : '(no text in the answer)')) + (err ? '\n[error] ' + err : '');
    return say(chatId, target.name + ' ▸\n' + body);
  }

  async function loop() {
    let backoff = 5000;
    // On start, skip the backlog: commands typed while the plane was down are not executed late.
    try { const u = await api('getUpdates', { offset: -1, timeout: 0 }); if (u && u.length) state.offset = u[u.length - 1].update_id + 1; log('start: skipped ' + (u ? u.length : 0) + ' backlog update(s), polling from offset ' + state.offset); }
    catch (e) { log('start: backlog read failed (' + String(e.message || e) + ') — polling from offset 0'); }
    for (;;) {
      if (!state.on) return;
      try {
        state.polls++;
        const updates = await api('getUpdates', { offset: state.offset, timeout: 25, allowed_updates: ['message'] });
        state.lastPollAt = new Date().toISOString();
        backoff = 5000;
        if (updates && updates.length) log('poll: ' + updates.length + ' update(s), offset ' + state.offset);
        for (const u of updates || []) {
          state.offset = Math.max(state.offset, u.update_id + 1);
          if (u.message && u.message.text) { try { await handle(u.message); } catch (e) { state.lastError = String(e.message || e); log('handle error: ' + state.lastError); } }
        }
      } catch (e) {
        state.lastError = String(e.message || e); log('poll error: ' + state.lastError + ' — retry in ' + (backoff / 1000) + 's');
        await new Promise((r) => setTimeout(r, backoff)); backoff = Math.min(backoff * 2, 60000);
      }
    }
  }
  // Whose token is this? Ask Telegram before claiming 'on': a token that resolves to the wrong
  // bot (or none) must be legible in the journal and /api/plane, not discovered by silence.
  api('getMe').then((me) => {
    state.bot = (me && me.username) ? '@' + me.username : '(no username)';
    // The allowlist moved out of the policy file when telegramChatIds was retired from it: a
    // tracked, committed file must not carry a chat id. It now lives in the plane's own
    // aegis.config.json. The behaviour was correct from that moment; this line was not, and a
    // boot line that names the wrong source is how a wrong belief survives three weeks.
    log('on — bot ' + state.bot + ', token from ' + state.source + ', long-poll, allowlist from aegis.config.json telegramChatIds');
    loop().catch((e) => { state.on = false; state.reason = 'loop died: ' + String(e.message || e); log(state.reason); });
  }).catch((e) => {
    state.on = false; state.reason = 'getMe failed (' + String(e.message || e) + ') — token invalid or Telegram unreachable; lane off';
    log(state.reason);
  });
  return state;
}

function stop() { state.on = false; }
module.exports = { start, stop, state, chunk, parseCommand, looksLikeBotToken, resolveToken };
