// cfcred.js -- fail-loud Cloudflare credential resolution for Aegis.
//
// Order of truth at boot (resolve(config, cb)):
//   CF_ACCOUNT_ID:      env  -> config.cfAccountId            (not a secret; lives in config)
//   CF_API_TOKEN:       env  -> Azure Key Vault secret        (az keyvault secret show, uses
//                              config.cfVaultName / cf-api-token; retrieval rides the operator's
//                              az login session, so every fetch is Azure-AD-audited)
//   DEPLOYER_OBJECT_ID: env  -> az ad signed-in-user show
//
// THE GATE IS LIVE: a resolved token is only 'ok' after Cloudflare's own
// GET /client/v4/user/tokens/verify returns success:true + status:active.
// Anything else -- vault fetch failure, malformed id, revoked/expired token --
// surfaces verbatim in state.reason, the banner, and both destructive lanes.
// No shape-guessing: Cloudflare is the authority on its own credentials.
//
// Resolved values are written back into process.env so fleetctl spawns inherit
// them unchanged. state.source records where the token came from (env | vault).
'use strict';
const https = require('https');
const { spawnSync } = require('child_process');

const state = { ok: false, source: '', reason: 'credentials not resolved yet (boot in progress)' };

function az(args) {
  const r = spawnSync('az', args, { encoding: 'utf8', timeout: 30000, shell: process.platform === 'win32' });
  return { out: (r.stdout || '').trim(), err: (r.stderr || '').trim().split('\n')[0] || String(r.error || '').split('\n')[0] };
}

function verifyLive(token, cb) {
  const req = https.get({
    host: 'api.cloudflare.com', path: '/client/v4/user/tokens/verify',
    headers: { Authorization: 'Bearer ' + token }, timeout: 6000,
  }, (res) => {
    let body = '';
    res.on('data', (d) => { body += d; });
    res.on('end', () => {
      try {
        const j = JSON.parse(body);
        if (j.success && j.result && j.result.status === 'active') return cb(null);
        const e = (j.errors && j.errors[0]) || {};
        cb('Cloudflare rejects the token (' + (e.code || res.statusCode) + ': ' + (e.message || (j.result && j.result.status) || 'not active') + ')');
      } catch { cb('Cloudflare verify returned unparseable response (HTTP ' + res.statusCode + ')'); }
    });
  });
  req.on('timeout', () => { req.destroy(); cb('Cloudflare verify timed out'); });
  req.on('error', (e) => cb('Cloudflare verify unreachable: ' + e.message));
}

function resolve(config, cb) {
  const cfg = config || {};
  // 1) account id -- env wins, else config; must be 32 hex.
  const id = (process.env.CF_ACCOUNT_ID || cfg.cfAccountId || '').trim();
  if (!/^[0-9a-f]{32}$/.test(id)) {
    state.ok = false; state.reason = 'CF_ACCOUNT_ID invalid — set "cfAccountId" (32-hex) in aegis.config.json';
    return cb(state);
  }
  process.env.CF_ACCOUNT_ID = id;

  // 2) token -- env wins (still live-verified), else Key Vault.
  let token = (process.env.CF_API_TOKEN || '').trim();
  let source = 'env';
  if (!token) {
    const vault = (cfg.cfVaultName || '').trim();
    if (!vault) {
      state.ok = false; state.reason = 'CF_API_TOKEN not in env and no "cfVaultName" in aegis.config.json';
      return cb(state);
    }
    const r = az(['keyvault', 'secret', 'show', '--vault-name', vault, '--name', 'cf-api-token', '--query', 'value', '-o', 'tsv']);
    if (!r.out) {
      state.ok = false; state.reason = 'Key Vault fetch failed (' + vault + '/cf-api-token): ' + (r.err || 'empty value') + ' — az login?';
      return cb(state);
    }
    token = r.out.trim(); source = 'vault(' + vault + ')';
  }

  // 3) deployer object id -- env wins, else derive from the az session.
  if (!/^[0-9a-f-]{36}$/.test((process.env.DEPLOYER_OBJECT_ID || '').trim())) {
    const d = az(['ad', 'signed-in-user', 'show', '--query', 'id', '-o', 'tsv']);
    if (/^[0-9a-f-]{36}$/.test(d.out)) process.env.DEPLOYER_OBJECT_ID = d.out;
    // non-fatal here: only `up --go` needs it, and fleetctl preflight fails closed on absence
  }

  // 4) THE GATE: Cloudflare's own verdict on the token.
  verifyLive(token, (err) => {
    if (err) { state.ok = false; state.source = source; state.reason = err; return cb(state); }
    process.env.CF_API_TOKEN = token;
    state.ok = true; state.source = source; state.reason = '';
    cb(state);
  });
}

module.exports = { resolve, state };
