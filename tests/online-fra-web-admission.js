'use strict';

// The web admission dance: a leaked lease without the browser's key admits
// nothing; the browser with its key admits exactly once per challenge.

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { createOnlineFraWebAdmission, NONCE_STORE_MAX } = require('../src/lib/online-fra-web-admission');

let assertions = 0;
function equal(actual, expected, message) { assertions += 1; assert.equal(actual, expected, message); }
function ok(value, message) { assertions += 1; assert.ok(value, message); }
function code(fn, expected) {
  assertions += 1;
  try { fn(); } catch (error) { assert.equal(error.code, expected); return; }
  assert.fail(`expected ${expected}`);
}

const browser = crypto.generateKeyPairSync('ed25519');
const browserSpki = browser.publicKey.export({ type: 'spki', format: 'der' });
const browserWire = browserSpki.toString('base64url');
const fingerprint = crypto.createHash('sha256').update(browserSpki).digest('hex');
const webLease = { endpointRole: 'web-client', deviceId: `web-${'a'.repeat(24)}`, mtlsFingerprint: fingerprint };

function harness() {
  const connects = [];
  let nowMs = 1_800_000_000_000;
  const admission = createOnlineFraWebAdmission({
    relay: { connect: request => { connects.push(request); return Object.freeze({ connectionId: 'conn_1', ...request.lease }); } },
    clock: () => nowMs
  });
  return { admission, connects, advance: ms => { nowMs += ms; } };
}

function signed(nonce, key = browser.privateKey) {
  return crypto.sign(null, Buffer.from(nonce, 'base64url'), key).toString('base64url');
}

// The happy dance: challenge -> sign -> admit, and the relay sees key-lease.
{
  const { admission, connects } = harness();
  const { nonce } = admission.challenge();
  const receipt = admission.admit({ lease: webLease, browserPublicKeySpki: browserWire, nonce, signature: signed(nonce) });
  equal(receipt.connectionId, 'conn_1');
  equal(connects[0].identity.authType, 'key-lease');
  equal(connects[0].identity.mtlsFingerprint, fingerprint);
}

// Single use: the same nonce cannot admit twice -- even after a SUCCESS.
{
  const { admission } = harness();
  const { nonce } = admission.challenge();
  admission.admit({ lease: webLease, browserPublicKeySpki: browserWire, nonce, signature: signed(nonce) });
  code(() => admission.admit({ lease: webLease, browserPublicKeySpki: browserWire, nonce, signature: signed(nonce) }),
    'ONLINE_FRA_WEB_ADMISSION_NONCE_UNKNOWN');
}

// A leaked lease without the key is NOTHING: wrong key, junk signature, and a
// signature by a different key all refuse -- and a failed attempt burns the
// nonce, so it cannot be brute-forced against.
{
  const { admission, connects } = harness();
  const other = crypto.generateKeyPairSync('ed25519');
  const first = admission.challenge();
  code(() => admission.admit({ lease: webLease, browserPublicKeySpki: browserWire, nonce: first.nonce, signature: signed(first.nonce, other.privateKey) }),
    'ONLINE_FRA_WEB_ADMISSION_PROOF_INVALID');
  code(() => admission.admit({ lease: webLease, browserPublicKeySpki: browserWire, nonce: first.nonce, signature: signed(first.nonce) }),
    'ONLINE_FRA_WEB_ADMISSION_NONCE_UNKNOWN');
  // A key that does not match the lease's committed fingerprint refuses even
  // with a valid possession proof for THAT key.
  const second = admission.challenge();
  const otherWire = other.publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');
  code(() => admission.admit({ lease: webLease, browserPublicKeySpki: otherWire, nonce: second.nonce, signature: signed(second.nonce, other.privateKey) }),
    'ONLINE_FRA_WEB_ADMISSION_KEY_MISMATCH');
  equal(connects.length, 0, 'nothing reached the relay');
}

// Expiry: a stale challenge refuses by name.
{
  const { admission, advance } = harness();
  const { nonce } = admission.challenge();
  advance(61_000);
  code(() => admission.admit({ lease: webLease, browserPublicKeySpki: browserWire, nonce, signature: signed(nonce) }),
    'ONLINE_FRA_WEB_ADMISSION_NONCE_EXPIRED');
}

// The store is bounded: hammering challenge() cannot grow memory past the cap.
//
// BOUND TO THE EXPORTED CONSTANT, NOT A LITERAL, and the loop has to exceed it.
// This read `3000` against a hardcoded `1024` and asserted <= 1024. When the cap
// was raised to 8192 the assertion failed -- correctly, it was pinning the old
// number -- but the deeper problem is that 3000 challenges never reached a cap of
// 8192 at all, so the version of this test that merely swapped the literal would
// have exercised no eviction and passed for the wrong reason.
{
  const { admission } = harness();
  for (let index = 0; index < NONCE_STORE_MAX + 200; index += 1) admission.challenge();
  ok(admission.pendingChallenges() <= NONCE_STORE_MAX,
    `bounded (${admission.pendingChallenges()} > ${NONCE_STORE_MAX})`);
}

// ONE LIVE CHALLENGE PER CONNECTION, which is the actual fix and not merely a
// larger number.
//
// WHY IT MATTERS, stated as the attack it closes: eviction is oldest-first, so
// while a connection could add an unbounded number of live challenges, an attacker
// opening sockets could push the store to its bound and then evict honest
// challengers deterministically -- specifically a browser that had just been handed
// its nonce and was still computing its WebCrypto signature over it. Replacing a
// connection's OWN nonce makes the store size track live connections rather than
// total attempts, so the global eviction below is a memory guard rather than an
// attacker-steerable queue.
{
  const { admission } = harness();
  const first = admission.challenge({ connectionId: 'conn_a' }).nonce;
  const second = admission.challenge({ connectionId: 'conn_a' }).nonce;
  equal(admission.pendingChallenges(), 1, 'asking twice on one connection leaves one live challenge');
  ok(first !== second, 'the replacement is a fresh nonce, not the same one handed out again');

  // And it replaces only its own: a second connection is untouched.
  admission.challenge({ connectionId: 'conn_b' });
  equal(admission.pendingChallenges(), 2, 'a different connection keeps its own challenge');
  admission.challenge({ connectionId: 'conn_a' });
  equal(admission.pendingChallenges(), 2, "conn_a's re-ask did not evict conn_b");
}

// MACHINES MAY COME THROUGH THIS DOOR TOO (2026-08-20). A machine signing with
// the Ed25519 identity key it generated itself is the stronger shape -- the
// mTLS path's private key is generated server-side and travels -- so the door
// is no longer the browser's alone. Same dance, same checks, both machine roles.
for (const role of ['machine-a', 'machine-b']) {
  const { admission, connects } = harness();
  const { nonce } = admission.challenge();
  const receipt = admission.admit({ lease: { ...webLease, endpointRole: role }, browserPublicKeySpki: browserWire, nonce, signature: signed(nonce) });
  equal(typeof receipt.connectionId, 'string');
  equal(connects[0].identity.authType, 'key-lease');
  equal(connects[0].lease.endpointRole, role);
}

// A role the lease schema does not name is still refused.
{
  const { admission } = harness();
  const { nonce } = admission.challenge();
  code(() => admission.admit({ lease: { ...webLease, endpointRole: 'operator' }, browserPublicKeySpki: browserWire, nonce, signature: signed(nonce) }),
    'ONLINE_FRA_WEB_ADMISSION_ROLE_INVALID');
}

console.log(`online-fra-web-admission: ${assertions} assertions passed`);
