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
// WHAT IT CAN DO. /agents /use <agent> /status /new /help, and plain text -> the sticky
// target (per chat, persisted). A message beginning "<agent>: " goes to that agent once
// without moving the sticky target. Nothing else exists here: no provisioning, policy,
// migrate, decommission, relay or grant -- there is no code path for them, so no phrase
// typed into a phone can reach them. /new resets the target's conversation (the one state
// change), same as the panel's New.
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

  const help = () => 'Aegis — fleet control plane (read + chat only)\n' +
    '/agents — list agents and which one this chat is locked to\n' +
    '/use <agent> — lock this chat to an agent\n' +
    '/status — plane and target status\n' +
    '/new — start a fresh conversation on the target\n' +
    'anything else — sent to the target agent\n' +
    '<agent>: <text> — one message to that agent without changing the lock';

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
    const cur = sticky[chatId] || '';
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
      let reach = 'n/a';
      if (t) { try { const r = await deps.callAgent(t, 'GET', '/health/liveness', null, { src: 'telegram', id: chatId }); reach = r && r.status === 200 ? 'reachable' : ('HTTP ' + (r && r.status)); } catch (e) { reach = 'unreachable (' + String(e.message || e).slice(0, 80) + ')'; } }
      return say(chatId, 'plane: ' + (deps.planeName ? deps.planeName() : 'aegis') + '\ntarget: ' + (cur || 'none') + (t ? '  ' + reach : '') + '\nagents: ' + agents.map((a) => a.name).join(', '));
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
    log('on — bot ' + state.bot + ', token from ' + state.source + ', long-poll, allowlist from policy telegramChatIds');
    loop().catch((e) => { state.on = false; state.reason = 'loop died: ' + String(e.message || e); log(state.reason); });
  }).catch((e) => {
    state.on = false; state.reason = 'getMe failed (' + String(e.message || e) + ') — token invalid or Telegram unreachable; lane off';
    log(state.reason);
  });
  return state;
}

function stop() { state.on = false; }
module.exports = { start, stop, state, chunk, parseCommand, looksLikeBotToken, resolveToken };
