'use strict';
// The relay's own timeout, pinned against the endpoints it relays to.
//
// A flat 10s reported FAILED in the panel for work the agent went on to finish: /files/process
// bounds its classifier at 60s and deliberately answers verdict:pending on timeout, and a
// 928 KB photo measured 9.97s agent-side before image reading grew an orientation search and a
// second grid pass. A relay tighter than its endpoint turns a slow answer into a false failure.
//
// aegis.js is a single long module that binds an express app at require time, so the function is
// sliced out and evaluated rather than imported -- the same approach the fleet suite uses for
// core/webchat-ops.js. Slicing keeps the test honest about which bytes it is pinning: if the
// function is renamed or moved, this fails rather than silently testing nothing.
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const SRC = fs.readFileSync(path.join(__dirname, '..', 'aegis.js'), 'utf8');
const START = SRC.indexOf('const RELAY_TIMEOUT_MS');
const END = SRC.indexOf('function callAgent(');
assert.ok(START >= 0 && END > START,
  'the relay timeout block was not found in aegis.js -- this test is pinning nothing');
const relayTimeoutMs = new Function(SRC.slice(START, END) + '\nreturn relayTimeoutMs;')();

test('a slow route gets more than the endpoint it calls bounds itself at', () => {
  // /files/process answers pending at 60s. Anything at or below that gives up before the
  // endpoint can deliver the answer it was always going to give.
  assert.ok(relayTimeoutMs('/files/process') > 60000,
    'the relay would give up before /files/process reaches its own 60s bound');
  assert.ok(relayTimeoutMs('/pending/interpret') > 60000,
    'a vision call can outlast the default and would report a false failure');
});

test('every other route keeps the short default', () => {
  for (const p of ['/health/liveliness', '/build', '/queue', '/skill-status', '/files/stage']) {
    assert.strictEqual(relayTimeoutMs(p), 10000, p + ' should not have been widened');
  }
});

test('the slow bound is matched on the route, not on a substring anywhere in the path', () => {
  assert.strictEqual(relayTimeoutMs('/x/files/process'), 10000,
    'a route is matched from the start of the path, or any path containing it inherits its bound');
  assert.strictEqual(relayTimeoutMs('/files/processing-stats'), 10000,
    'a longer route sharing a prefix must not inherit the slow bound');
});

test('a missing or odd path falls back to the default rather than throwing', () => {
  for (const p of [undefined, null, '', 0]) {
    assert.strictEqual(relayTimeoutMs(p), 10000, 'the relay must not throw on ' + String(p));
  }
});

test('the timeout body says which bound was hit, so a false failure is diagnosable', () => {
  assert.match(SRC, /body: 'timeout after ' \+ tmo \+ 'ms'/,
    "a bare 'timeout' cannot be told apart from the endpoint's own pending answer");
});
