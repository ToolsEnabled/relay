'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const {
  LEASE_SCHEMA_VERSION,
  MAX_LEASE_TTL_MS,
  createOnlineFraRendezvousRelay,
  leaseSigningBytes
} = require('../src/lib/online-fra-rendezvous-relay');

let assertions = 0;
function equal(actual, expected, message) { assertions += 1; assert.equal(actual, expected, message); }
function ok(value, message) { assertions += 1; assert.ok(value, message); }
function deepEqual(actual, expected, message) { assertions += 1; assert.deepEqual(actual, expected, message); }
function code(fn, expected) {
  assertions += 1;
  assert.throws(fn, error => error && error.code === expected, expected);
}

const authority = crypto.generateKeyPairSync('ed25519');
const fingerprintA = 'a'.repeat(64);
const fingerprintB = 'b'.repeat(64);
const fingerprintC = 'c'.repeat(64);
const fingerprintD = 'd'.repeat(64);
const digestOne = '1'.repeat(64);
const digestTwo = '2'.repeat(64);
let nowMs = 1_800_000_000_000;
let randomCounter = 0;

function x25519PublicKey() {
  return crypto.generateKeyPairSync('x25519').publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
}

const pairOne = Object.freeze({ pairId: 'pair-ab', machineAId: 'machine-a', machineBId: 'machine-b', capabilityDigest: digestOne });
const pairTwo = Object.freeze({ pairId: 'pair-cd', machineAId: 'machine-c', machineBId: 'machine-d', capabilityDigest: digestTwo });

function identity(deviceId, mtlsFingerprint, overrides = {}) {
  return { verified: true, authType: 'mtls', deviceId, mtlsFingerprint, ...overrides };
}

function lease({ pair = pairOne, role = 'machine-a', generation = 7, overrides = {} } = {}) {
  const deviceId = role === 'machine-a' ? pair.machineAId : pair.machineBId;
  const peerDeviceId = role === 'machine-a' ? pair.machineBId : pair.machineAId;
  const mtlsFingerprint = deviceId === 'machine-a' ? fingerprintA
    : deviceId === 'machine-b' ? fingerprintB
      : deviceId === 'machine-c' ? fingerprintC : fingerprintD;
  const base = {
    schemaVersion: LEASE_SCHEMA_VERSION,
    leaseId: `lease_${deviceId}_${randomCounter++}`,
    pairId: pair.pairId,
    deviceId,
    peerDeviceId,
    endpointRole: role,
    mtlsFingerprint,
    generation,
    issuedAtMs: nowMs - 10,
    expiresAtMs: nowMs + 60_000,
    nonce: crypto.randomBytes(24).toString('base64url'),
    ephemeralX25519PublicKey: x25519PublicKey(),
    capabilityDigest: pair.capabilityDigest,
    signature: Buffer.alloc(64).toString('base64url'),
    ...overrides
  };
  base.signature = crypto.sign(null, leaseSigningBytes(base), authority.privateKey).toString('base64url');
  return base;
}

function stateKey(pairId, generation) {
  return `${pairId}:${generation}`;
}

// Test-only stand-in for the required durable authority.  Passing one instance
// to fresh relay cores models the persistence boundary that prevents replay or
// revoked-pair resurrection after a process restart.
function authoritativeState() {
  const consumedNonces = new Map();
  const revokedPairs = new Set();
  let failure = null;
  return {
    setFailure(value) { failure = value; },
    admitLease({ nonce, expiresAtMs, pairId, generation }) {
      if (failure === 'admit') throw new Error('authoritative admission unavailable');
      for (const [storedNonce, storedExpiry] of consumedNonces) {
        if (storedExpiry <= nowMs) consumedNonces.delete(storedNonce);
      }
      if (revokedPairs.has(stateKey(pairId, generation))) return { ok: true, outcome: 'revoked' };
      if (consumedNonces.has(nonce)) return { ok: true, outcome: 'replayed' };
      consumedNonces.set(nonce, expiresAtMs);
      return { ok: true, outcome: 'accepted' };
    },
    pairState({ pairId, generation }) {
      if (failure === 'read') throw new Error('authoritative read unavailable');
      if (failure === 'read-malformed') return { ok: false, revoked: false };
      return { ok: true, revoked: revokedPairs.has(stateKey(pairId, generation)) };
    },
    revokePair({ pairId, generation }) {
      if (failure === 'write') throw new Error('authoritative write unavailable');
      if (failure === 'write-malformed') return { ok: false, revoked: false };
      revokedPairs.add(stateKey(pairId, generation));
      return { ok: true, revoked: true };
    }
  };
}

function relay({ events = [], sink, enabled = true, pairs = [pairOne], leaseState = authoritativeState(), ...overrides } = {}) {
  return createOnlineFraRendezvousRelay({
    enabled,
    authorityPublicKey: authority.publicKey,
    generation: 7,
    pairs,
    clock: () => nowMs,
    randomBytes: size => {
      const value = Buffer.alloc(size);
      value.writeUInt32BE(++randomCounter, Math.max(0, size - 4));
      return value;
    },
    eventSink: sink || (event => { events.push(event); }),
    leaseState,
    ...overrides
  });
}

function connectPair(instance, pair = pairOne) {
  const aLease = lease({ pair, role: 'machine-a' });
  const bLease = lease({ pair, role: 'machine-b' });
  const a = instance.connect({ identity: identity(aLease.deviceId, aLease.mtlsFingerprint), lease: aLease });
  const b = instance.connect({ identity: identity(bLease.deviceId, bLease.mtlsFingerprint), lease: bLease });
  return { a, b, aLease, bLease };
}

function run() {
  const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'lib', 'online-fra-rendezvous-relay.js'), 'utf8');
  ok(!/require\('node:(?:net|http|https|tls)'\)/.test(source), 'relay core must not create a network listener');
  ok(!/JSON\.parse\(frame/.test(source), 'relay core must not parse opaque frames');

  {
    const instance = relay({ enabled: false });
    const a = lease();
    code(() => instance.connect({ identity: identity(a.deviceId, a.mtlsFingerprint), lease: a }), 'ONLINE_FRA_RELAY_DISABLED');
  }

  {
    code(() => createOnlineFraRendezvousRelay({
      enabled: true,
      authorityPublicKey: authority.publicKey,
      pairs: [pairOne],
      eventSink: () => {}
    }), 'ONLINE_FRA_LEASE_STATE_REQUIRED');
    code(() => relay({ leaseState: {} }), 'ONLINE_FRA_LEASE_STATE_INVALID');
  }

  {
    const events = [];
    const instance = relay({ events });
    const { a, b } = connectPair(instance);
    equal(a.paired, false);
    equal(b.paired, true);
    const aState = instance.connectionMetadata(a.connectionId);
    const bState = instance.connectionMetadata(b.connectionId);
    equal(aState.peerConnectionId, b.connectionId);
    equal(bState.peerConnectionId, a.connectionId);
    const marker = Buffer.from('private-control-marker');
    deepEqual(instance.route({ connectionId: a.connectionId, peerConnectionId: b.connectionId, frame: marker }), { delivered: true, bytes: marker.length });
    deepEqual(instance.take(b.connectionId), marker);
    equal(instance.take(b.connectionId), null);
    ok(!JSON.stringify(events).includes('private-control-marker'), 'metadata events must not contain opaque payload bytes');
    equal(instance.snapshot().activeConnections, 2);
    equal(instance.snapshot().queuedBytes, 0);
  }

  {
    const instance = relay();
    const a = lease();
    code(() => instance.connect({ lease: a }), 'ONLINE_FRA_MTLS_IDENTITY_INVALID');
    code(() => instance.connect({ identity: identity(a.deviceId, fingerprintB), lease: a }), 'ONLINE_FRA_MTLS_IDENTITY_MISMATCH');
    code(() => instance.connect({ identity: identity(a.deviceId, a.mtlsFingerprint, { verified: false }), lease: a }), 'ONLINE_FRA_MTLS_IDENTITY_INVALID');
  }

  // KEY-LEASE FOR MACHINES (2026-08-20). A machine that proved possession of
  // its own identity key at the edge is attested as key-lease, and the relay
  // admits it for either machine role. web-lease stays the web role's alias
  // and is NOT accepted for a machine; mtls is NOT accepted for the web role.
  {
    const instance = relay();
    const a = lease({ role: 'machine-a' });
    const b = lease({ role: 'machine-b' });
    const ra = instance.connect({ identity: identity(a.deviceId, a.mtlsFingerprint, { authType: 'key-lease' }), lease: a });
    const rb = instance.connect({ identity: identity(b.deviceId, b.mtlsFingerprint, { authType: 'key-lease' }), lease: b });
    ok(ra.connectionId && rb.connectionId, 'both machines admitted on key-lease');
    equal(instance.connectionMetadata(ra.connectionId).peerConnectionId, rb.connectionId, 'and they are paired');
    const fresh = relay();
    const c = lease({ role: 'machine-a' });
    code(() => fresh.connect({ identity: identity(c.deviceId, c.mtlsFingerprint, { authType: 'web-lease' }), lease: c }), 'ONLINE_FRA_MTLS_IDENTITY_INVALID');
    code(() => fresh.connect({ identity: identity(c.deviceId, c.mtlsFingerprint, { authType: 'bearer' }), lease: c }), 'ONLINE_FRA_MTLS_IDENTITY_INVALID');
  }

  {
    const instance = relay();
    const malformedIdentity = identity('machine-a', fingerprintA);
    code(() => instance.connect({ identity: malformedIdentity, lease: {} }), 'ONLINE_FRA_LEASE_INVALID');
    const good = lease();
    const forged = { ...good, nonce: crypto.randomBytes(24).toString('base64url') };
    code(() => instance.connect({ identity: identity(forged.deviceId, forged.mtlsFingerprint), lease: forged }), 'ONLINE_FRA_LEASE_SIGNATURE_INVALID');
    const alteredEphemeral = { ...good, ephemeralX25519PublicKey: x25519PublicKey() };
    code(() => instance.connect({ identity: identity(alteredEphemeral.deviceId, alteredEphemeral.mtlsFingerprint), lease: alteredEphemeral }), 'ONLINE_FRA_LEASE_SIGNATURE_INVALID');
    const invalidEphemeral = lease({ overrides: { ephemeralX25519PublicKey: Buffer.alloc(32, 9).toString('base64url') } });
    code(() => instance.connect({ identity: identity(invalidEphemeral.deviceId, invalidEphemeral.mtlsFingerprint), lease: invalidEphemeral }), 'ONLINE_FRA_LEASE_INVALID');
    const expired = lease({ overrides: { issuedAtMs: nowMs - 70_000, expiresAtMs: nowMs - 1 } });
    code(() => instance.connect({ identity: identity(expired.deviceId, expired.mtlsFingerprint), lease: expired }), 'ONLINE_FRA_LEASE_TIME_INVALID');
    const future = lease({ overrides: { issuedAtMs: nowMs + 1, expiresAtMs: nowMs + 60_000 } });
    code(() => instance.connect({ identity: identity(future.deviceId, future.mtlsFingerprint), lease: future }), 'ONLINE_FRA_LEASE_TIME_INVALID');
    const overlong = lease({ overrides: { issuedAtMs: nowMs, expiresAtMs: nowMs + MAX_LEASE_TTL_MS + 1 } });
    code(() => instance.connect({ identity: identity(overlong.deviceId, overlong.mtlsFingerprint), lease: overlong }), 'ONLINE_FRA_LEASE_TIME_INVALID');
  }

  {
    const instance = relay();
    const wrongPeer = lease({ overrides: { peerDeviceId: 'machine-c' } });
    code(() => instance.connect({ identity: identity(wrongPeer.deviceId, wrongPeer.mtlsFingerprint), lease: wrongPeer }), 'ONLINE_FRA_LEASE_BINDING_INVALID');
    const wrongRole = lease({ overrides: { endpointRole: 'machine-b' } });
    code(() => instance.connect({ identity: identity(wrongRole.deviceId, wrongRole.mtlsFingerprint), lease: wrongRole }), 'ONLINE_FRA_LEASE_BINDING_INVALID');
    const wrongGeneration = lease({ generation: 8 });
    code(() => instance.connect({ identity: identity(wrongGeneration.deviceId, wrongGeneration.mtlsFingerprint), lease: wrongGeneration }), 'ONLINE_FRA_LEASE_BINDING_INVALID');
    const wrongDigest = lease({ overrides: { capabilityDigest: 'f'.repeat(64) } });
    code(() => instance.connect({ identity: identity(wrongDigest.deviceId, wrongDigest.mtlsFingerprint), lease: wrongDigest }), 'ONLINE_FRA_LEASE_BINDING_INVALID');
  }

  {
    const instance = relay({ maxConnectionsPerDevice: 2 });
    const a = lease();
    const accepted = instance.connect({ identity: identity(a.deviceId, a.mtlsFingerprint), lease: a });
    equal(accepted.endpointRole, 'machine-a');
    instance.close(accepted.connectionId);
    code(() => instance.connect({ identity: identity(a.deviceId, a.mtlsFingerprint), lease: a }), 'ONLINE_FRA_LEASE_REPLAYED');
    const differentLease = lease();
    instance.connect({ identity: identity(differentLease.deviceId, differentLease.mtlsFingerprint), lease: differentLease });
    const duplicateRole = lease();
    code(() => instance.connect({ identity: identity(duplicateRole.deviceId, duplicateRole.mtlsFingerprint), lease: duplicateRole }), 'ONLINE_FRA_DUPLICATE_ENDPOINT_ROLE');
  }

  {
    const leaseState = authoritativeState();
    const firstRelay = relay({ leaseState });
    const a = lease();
    firstRelay.connect({ identity: identity(a.deviceId, a.mtlsFingerprint), lease: a });
    const restartedRelay = relay({ leaseState });
    code(() => restartedRelay.connect({ identity: identity(a.deviceId, a.mtlsFingerprint), lease: a }), 'ONLINE_FRA_LEASE_REPLAYED');
  }

  {
    const instance = relay();
    const first = lease();
    instance.connect({ identity: identity(first.deviceId, first.mtlsFingerprint), lease: first });
    const second = lease();
    code(() => instance.connect({ identity: identity(second.deviceId, second.mtlsFingerprint), lease: second }), 'ONLINE_FRA_CONNECTION_CAPACITY_EXCEEDED');
  }

  {
    const leaseState = authoritativeState();
    const firstRelay = relay({ leaseState });
    connectPair(firstRelay);
    equal(firstRelay.revokePair({ pairId: pairOne.pairId, generation: 7, reason: 'operator-kill' }), true);
    const restartedRelay = relay({ leaseState });
    const fresh = lease();
    code(() => restartedRelay.connect({ identity: identity(fresh.deviceId, fresh.mtlsFingerprint), lease: fresh }), 'ONLINE_FRA_PAIR_REVOKED');
  }

  {
    const leaseState = authoritativeState();
    leaseState.setFailure('admit');
    const instance = relay({ leaseState });
    const a = lease();
    code(() => instance.connect({ identity: identity(a.deviceId, a.mtlsFingerprint), lease: a }), 'ONLINE_FRA_LEASE_STATE_UNAVAILABLE');
    equal(instance.snapshot().activeConnections, 0);
  }

  {
    const leaseState = authoritativeState();
    const instance = relay({ leaseState });
    const pair = connectPair(instance);
    leaseState.setFailure('read');
    code(() => instance.route({ connectionId: pair.a.connectionId, peerConnectionId: pair.b.connectionId, frame: Buffer.from([1]) }), 'ONLINE_FRA_LEASE_STATE_UNAVAILABLE');
    equal(instance.snapshot().activeConnections, 0);
  }

  {
    const leaseState = authoritativeState();
    const instance = relay({ leaseState });
    connectPair(instance);
    leaseState.setFailure('write');
    code(() => instance.revokePair({ pairId: pairOne.pairId, generation: 7, reason: 'operator-kill' }), 'ONLINE_FRA_LEASE_STATE_UNAVAILABLE');
    equal(instance.snapshot().activeConnections, 0);
  }

  {
    const leaseState = authoritativeState();
    const instance = relay({ leaseState });
    const pair = connectPair(instance);
    leaseState.setFailure('read-malformed');
    code(() => instance.take(pair.a.connectionId), 'ONLINE_FRA_LEASE_STATE_UNAVAILABLE');
    equal(instance.snapshot().activeConnections, 0);
  }

  {
    const instance = relay({ maxFrameBytes: 4, maxQueuedBytesPerConnection: 4, maxQueuedBytesPerDevice: 4, maxQueuedBytesPerPair: 4 });
    const { a, b } = connectPair(instance);
    code(() => instance.route({ connectionId: a.connectionId, peerConnectionId: b.connectionId, frame: Buffer.alloc(5) }), 'ONLINE_FRA_OPAQUE_FRAME_INVALID');
    instance.route({ connectionId: a.connectionId, peerConnectionId: b.connectionId, frame: Buffer.alloc(4, 1) });
    code(() => instance.route({ connectionId: a.connectionId, peerConnectionId: b.connectionId, frame: Buffer.alloc(1, 2) }), 'ONLINE_FRA_BACKPRESSURE');
    equal(instance.take(b.connectionId).length, 4);
  }

  {
    const instance = relay({ maxFrameBytes: 4, maxQueuedBytesPerConnection: 4, maxQueuedBytesPerDevice: 4, maxQueuedBytesPerPair: 6 });
    const { a, b } = connectPair(instance);
    instance.route({ connectionId: a.connectionId, peerConnectionId: b.connectionId, frame: Buffer.alloc(4, 1) });
    code(() => instance.route({ connectionId: b.connectionId, peerConnectionId: a.connectionId, frame: Buffer.alloc(3, 2) }), 'ONLINE_FRA_BACKPRESSURE');
  }

  {
    const instance = relay({ pairs: [pairOne, pairTwo], maxConnectionsPerDevice: 1, maxConnectionsPerPair: 2 });
    const first = connectPair(instance, pairOne);
    const second = connectPair(instance, pairTwo);
    code(() => instance.route({ connectionId: first.a.connectionId, peerConnectionId: second.b.connectionId, frame: Buffer.from([1]) }), 'ONLINE_FRA_ROUTE_PEER_MISMATCH');
    equal(instance.take(second.b.connectionId), null);
    instance.route({ connectionId: first.a.connectionId, peerConnectionId: first.b.connectionId, frame: Buffer.from([7]) });
    deepEqual(instance.take(first.b.connectionId), Buffer.from([7]));
  }

  {
    const instance = relay();
    const first = connectPair(instance);
    equal(instance.revokePair({ pairId: pairOne.pairId, generation: 7, reason: 'operator-kill' }), true);
    equal(instance.snapshot().activeConnections, 0);
    code(() => instance.connectionMetadata(first.a.connectionId), 'ONLINE_FRA_CONNECTION_UNKNOWN');
    const fresh = lease();
    code(() => instance.connect({ identity: identity(fresh.deviceId, fresh.mtlsFingerprint), lease: fresh }), 'ONLINE_FRA_PAIR_REVOKED');
  }

  {
    // REGRESSION for agent-coord finding/fable-review/mission-bridge-three-
    // defects thread 3 (online-fra minor findings): revokePair's final
    // sink() call was wrapped in `catch (error) { throw error; }` -- inert,
    // since it only ever rethrows the exact same error already about to
    // propagate. Removing it must not change behavior: a sink failure here
    // still surfaces as ONLINE_FRA_EVENT_SINK_FAILED, and -- unlike the
    // OTHER sink() failures in this file, which DO need to closePair as a
    // recovery step because they fail before revocation state is durable --
    // revocation itself already completed here (persistRevocation and
    // closePair both ran before this specific sink call), so a fresh
    // connect for the same pair/generation must still see it as revoked.
    const leaseState = authoritativeState();
    const events = [];
    const failingSink = event => {
      if (event.type === 'online_fra.pair.revoked') throw new Error('sink-failure-marker');
      events.push(event);
    };
    const instance = relay({ leaseState, sink: failingSink });
    connectPair(instance);
    code(() => instance.revokePair({ pairId: pairOne.pairId, generation: 7, reason: 'operator-kill' }), 'ONLINE_FRA_EVENT_SINK_FAILED');
    equal(instance.snapshot().activeConnections, 0, 'revocation already closed the pair before the failing sink call');
    const fresh = lease();
    code(() => instance.connect({ identity: identity(fresh.deviceId, fresh.mtlsFingerprint), lease: fresh }), 'ONLINE_FRA_PAIR_REVOKED');
  }

  {
    const instance = relay();
    const pair = connectPair(instance);
    nowMs += 60_001;
    /* THE REASON SURVIVES THE CLOSE, briefly, for whoever asks next.
       This asserted 'ONLINE_FRA_CONNECTION_UNKNOWN' -- true but useless, and the
       edge could only pass it on to a browser as an internal error. A person
       whose tab had been displaced by their own second tab was told their
       computer had not answered. It had. So a connection the relay closed for a
       known reason now names that reason to the next caller; a connection id it
       has genuinely never heard of is still 'unknown'. */
    code(() => instance.connectionMetadata(pair.a.connectionId), 'ONLINE_FRA_LEASE_EXPIRED');
    code(() => instance.connectionMetadata('never-issued-by-this-relay'), 'ONLINE_FRA_CONNECTION_UNKNOWN');
    equal(instance.snapshot().activeConnections, 0);
  }

  {
    const failingAdmission = relay({ sink: () => { throw new Error('audit unavailable'); } });
    const a = lease();
    code(() => failingAdmission.connect({ identity: identity(a.deviceId, a.mtlsFingerprint), lease: a }), 'ONLINE_FRA_EVENT_SINK_FAILED');
    equal(failingAdmission.snapshot().activeConnections, 0);

    let failRoute = false;
    const failingRoute = relay({ sink: event => {
      if (event.type === 'online_fra.frame.routed') failRoute = true;
      if (failRoute) throw new Error('audit unavailable');
    } });
    const pair = connectPair(failingRoute);
    code(() => failingRoute.route({ connectionId: pair.a.connectionId, peerConnectionId: pair.b.connectionId, frame: Buffer.from([1]) }), 'ONLINE_FRA_EVENT_SINK_FAILED');
    equal(failingRoute.snapshot().activeConnections, 0);
  }

  {
    const verificationFailure = relay({ verifyLease: () => false });
    const a = lease();
    code(() => verificationFailure.connect({ identity: identity(a.deviceId, a.mtlsFingerprint), lease: a }), 'ONLINE_FRA_LEASE_SIGNATURE_INVALID');
  }

  // NO FRAME CONTENT REACHES THE LOGS. THIS TEST IS A PUBLISHED PROMISE.
  //
  // The Privacy Policy (§6) tells users, in these words, that the relay moving
  // their end-to-end encrypted frames is "held in place by a test that reads
  // the relay's own source and fails if it ever tries to parse a frame, and by
  // a second test asserting no frame content reaches its logs."
  //
  // The first of those is the source read at the top of run(). This is the
  // second. Until it existed the sentence was true in substance but described
  // a test that did not exist under that description -- the guarantee was
  // carried by an assertion about the metadata EVENT stream and, separately,
  // by the nginx config refusing to enable an access log. Both are real, and
  // neither is what a reader of that sentence would go looking for.
  //
  // Checked two ways, because either alone is weak:
  //
  //   STATICALLY -- the relay core contains no logging call of any kind. It
  //   cannot leak a frame to a log because it never writes one. That is a
  //   stronger property than the sentence claims and it is the one worth
  //   defending: an added console.log in this file is a privacy regression,
  //   and this fails on it before anyone has to notice it in review.
  //
  //   DYNAMICALLY -- route a frame carrying a distinctive marker with every
  //   process-level output stream captured, and require the marker to appear
  //   in none of them. This catches a leak arriving through a dependency or a
  //   helper, which the static half would miss.
  //
  // If this test is ever renamed, moved, or deleted, Privacy §6 stops being
  // true as written and must change BEFORE publication, never after.
  {
    ok(!/console\s*\.\s*(?:log|info|warn|error|debug|trace|dir)\s*\(/.test(source),
      'relay core must not call console -- no frame content can reach a log it never writes');
    ok(!/process\s*\.\s*(?:stdout|stderr)\s*\.\s*write\s*\(/.test(source),
      'relay core must not write to stdout or stderr');

    const marker = 'frame-content-must-never-be-logged-4a7f2c91';
    const captured = [];
    const consoleMethods = ['log', 'info', 'warn', 'error', 'debug', 'trace', 'dir'];
    const originalConsole = new Map();
    for (const method of consoleMethods) {
      originalConsole.set(method, console[method]);
      console[method] = (...args) => { captured.push(args.map(String).join(' ')); };
    }
    const originalStdout = process.stdout.write;
    const originalStderr = process.stderr.write;
    process.stdout.write = chunk => { captured.push(String(chunk)); return true; };
    process.stderr.write = chunk => { captured.push(String(chunk)); return true; };

    let routed = null;
    let snapshot = null;
    try {
      const events = [];
      const instance = relay({ events });
      const { a, b } = connectPair(instance);
      const frame = Buffer.from(marker);
      routed = instance.route({ connectionId: a.connectionId, peerConnectionId: b.connectionId, frame });
      // Take it back out, and take a snapshot, so anything that logs on the
      // delivery or reporting path is exercised too rather than only on send.
      instance.take(b.connectionId);
      snapshot = instance.snapshot();
      captured.push(JSON.stringify(events));
      instance.close(a.connectionId);
      instance.close(b.connectionId);
    } finally {
      for (const method of consoleMethods) console[method] = originalConsole.get(method);
      process.stdout.write = originalStdout;
      process.stderr.write = originalStderr;
    }

    // The frame really did move -- otherwise this asserts nothing.
    deepEqual(routed, { delivered: true, bytes: marker.length },
      'precondition: the marked frame must actually have been routed');
    ok(snapshot && typeof snapshot.activeConnections === 'number',
      'precondition: the reporting path must actually have run');
    ok(!captured.join('\n').includes(marker),
      'no frame content may reach console, stdout, stderr, or the metadata event stream');
  }

  // --- runtime pair registration and the account-routing seam -------------
  //
  // A hosted relay onboards customers while it runs; the construction-time
  // pair list cannot. Registration grants nothing by itself -- admission still
  // requires an authority-signed lease -- and the admissionAuthority hook is
  // the deliberately architecture-neutral seam: under the ASK model it holds
  // an accountForPair lookup, under the TOLD model it is absent, and this
  // section proves both postures against the same relay.
  {
    const pairNew = Object.freeze({ pairId: 'pair-ef', machineAId: 'machine-e', machineBId: 'machine-f', capabilityDigest: digestOne });

    // A runtime-registered pair becomes fully admissible: both roles connect,
    // pair, and route -- the whole point of the API.
    {
      const events = [];
      const instance = relay({ events });
      code(() => instance.connect({ identity: identity(pairNew.machineAId, fingerprintD), lease: lease({ pair: pairNew, role: 'machine-a', overrides: { mtlsFingerprint: fingerprintD } }) }), 'ONLINE_FRA_LEASE_BINDING_INVALID');
      const receipt = instance.registerPair(pairNew);
      equal(receipt.pairId, 'pair-ef', 'registration answers with the pair id');
      equal(receipt.pairCount, 2, 'the instance now carries both pairs');
      ok(events.some(event => event.type === 'online_fra.pair.registered' && event.pairId === 'pair-ef'),
        'registration is an audited event');
      const aLease = lease({ pair: pairNew, role: 'machine-a', overrides: { mtlsFingerprint: fingerprintC } });
      const bLease = lease({ pair: pairNew, role: 'machine-b', overrides: { mtlsFingerprint: fingerprintD } });
      const a = instance.connect({ identity: identity(aLease.deviceId, fingerprintC), lease: aLease });
      const b = instance.connect({ identity: identity(bLease.deviceId, fingerprintD), lease: bLease });
      equal(b.paired, true, 'a runtime-registered pair pairs exactly like a constructed one');
      const routed = instance.route({ connectionId: a.connectionId, peerConnectionId: b.connectionId, frame: Buffer.from('x') });
      equal(routed.delivered, true, 'and routes frames');
      equal(instance.snapshot().pairCount, 2, 'the snapshot reports the live pair count');
    }

    // Validation is construction-grade: duplicate pair ids, device ids already
    // taken by ANY pair, and the cap all refuse -- and a refused registration
    // leaves no trace, so the same devices can register correctly afterwards.
    {
      const instance = relay({});
      code(() => instance.registerPair({ ...pairNew, pairId: 'pair-ab' }), 'ONLINE_FRA_RELAY_PAIR_INVALID');
      code(() => instance.registerPair({ ...pairNew, machineAId: 'machine-a' }), 'ONLINE_FRA_RELAY_PAIR_INVALID');
      instance.registerPair(pairNew);
      code(() => instance.registerPair({ pairId: 'pair-gh', machineAId: 'machine-g', machineBId: 'machine-e', capabilityDigest: digestOne }), 'ONLINE_FRA_RELAY_PAIR_INVALID');
      const capped = relay({ maxPairs: 2 });
      capped.registerPair(pairNew);
      code(() => capped.registerPair({ pairId: 'pair-gh', machineAId: 'machine-g', machineBId: 'machine-h', capabilityDigest: digestOne }), 'ONLINE_FRA_RELAY_PAIR_CAPACITY_EXCEEDED');
      // The default cap is unchanged: 16 at construction, as every existing
      // deployment expects, and maxPairs cannot exceed its ceiling.
      code(() => relay({ pairs: Array.from({ length: 17 }, (_, i) => ({ pairId: `pair-x${i}`, machineAId: `machine-xa${i}`, machineBId: `machine-xb${i}`, capabilityDigest: digestOne })) }), 'ONLINE_FRA_RELAY_PAIR_INVALID');
      code(() => relay({ maxPairs: 4097 }), 'ONLINE_FRA_RELAY_CAPACITY_INVALID');
    }

    // Retirement closes the pair's connections, frees its device ids for
    // later registration, and is audited -- and it is not revocation: the
    // durable lease store is never touched by it.
    {
      const events = [];
      const instance = relay({ events });
      instance.registerPair(pairNew);
      const aLease = lease({ pair: pairNew, role: 'machine-a', overrides: { mtlsFingerprint: fingerprintC } });
      const a = instance.connect({ identity: identity(aLease.deviceId, fingerprintC), lease: aLease });
      equal(instance.retirePair({ pairId: 'pair-ef' }), true, 'retirement answers plainly');
      /* Names the retirement rather than 'unknown', for the same reason as the
         expiry case above: the edge is asking why its socket stopped working. */
      code(() => instance.connectionMetadata(a.connectionId), 'ONLINE_FRA_PAIR_RETIRED');
      code(() => instance.connect({ identity: identity(pairNew.machineAId, fingerprintC), lease: lease({ pair: pairNew, role: 'machine-a', overrides: { mtlsFingerprint: fingerprintC } }) }), 'ONLINE_FRA_LEASE_BINDING_INVALID');
      ok(events.some(event => event.type === 'online_fra.pair.retired' && event.pairId === 'pair-ef'),
        'retirement is an audited event');
      instance.registerPair({ pairId: 'pair-ef2', machineAId: 'machine-e', machineBId: 'machine-f', capabilityDigest: digestOne });
      code(() => instance.retirePair({ pairId: 'pair-zz' }), 'ONLINE_FRA_RETIREMENT_INVALID');
    }

    // The admissionAuthority seam: a yes admits, anything else refuses with
    // its own code, a refusal never consumes the nonce (the same lease is
    // admissible the moment the authority recovers), and an async authority
    // is a refusal because the relay is deliberately synchronous.
    {
      const decisions = [];
      let allow = false;
      const instance = relay({
        admissionAuthority: request => { decisions.push(request); return allow; }
      });
      const aLease = lease({ pair: pairOne, role: 'machine-a' });
      code(() => instance.connect({ identity: identity(aLease.deviceId, aLease.mtlsFingerprint), lease: aLease }), 'ONLINE_FRA_PAIR_UNAUTHORIZED');
      equal(decisions.length, 1, 'the authority was consulted');
      equal(decisions[0].pairId, 'pair-ab', 'and saw only signature-proven claims');
      allow = true;
      const admitted = instance.connect({ identity: identity(aLease.deviceId, aLease.mtlsFingerprint), lease: aLease });
      equal(admitted.deviceId, 'machine-a', 'the SAME lease admits after the authority recovers: the refusal did not burn the nonce');

      const throwing = relay({ admissionAuthority: () => { throw new Error('account server down'); } });
      const tLease = lease({ pair: pairOne, role: 'machine-a' });
      code(() => throwing.connect({ identity: identity(tLease.deviceId, tLease.mtlsFingerprint), lease: tLease }), 'ONLINE_FRA_PAIR_UNAUTHORIZED');

      const asyncAuthority = relay({ admissionAuthority: async () => true });
      const pLease = lease({ pair: pairOne, role: 'machine-a' });
      code(() => asyncAuthority.connect({ identity: identity(pLease.deviceId, pLease.mtlsFingerprint), lease: pLease }), 'ONLINE_FRA_PAIR_UNAUTHORIZED');

      code(() => relay({ admissionAuthority: 'yes' }), 'ONLINE_FRA_RELAY_OPTIONS_INVALID');
    }
  }

  // --- fair use, layer 1: the per-pair token bucket -----------------------
  //
  // Absent by default (self-host unmetered); over budget is THROTTLED, never
  // thrown -- the connection lives, the frame waits. Published figures are 20
  // MB burst / 1 MB-minute refill; the test uses small numbers, same shape.
  {
    let clockMs = nowMs; // the fixture's leases are stamped from nowMs; a diverged clock is a time-invalid lease, not a bucket test
    const instance = relay({
      clock: () => clockMs,
      maxFrameBytes: 1024,
      maxQueuedBytesPerConnection: 8 * 1024,
      maxQueuedBytesPerDevice: 8 * 1024,
      maxQueuedBytesPerPair: 16 * 1024,
      pairRateLimit: { burstBytes: 3 * 1024, refillBytesPerMinute: 2048 }
    });
    const { a, b } = connectPair(instance);
    const frame = Buffer.alloc(1024, 7);

    // The burst passes instantly -- this is what keeps real work invisible.
    for (let index = 0; index < 3; index += 1) {
      equal(instance.route({ connectionId: a.connectionId, peerConnectionId: b.connectionId, frame }).delivered, true);
      instance.take(b.connectionId);
    }
    // The fourth is throttled: not delivered, not thrown, nothing consumed.
    const verdict = instance.route({ connectionId: a.connectionId, peerConnectionId: b.connectionId, frame });
    equal(verdict.delivered, false);
    equal(verdict.throttled, true);
    ok(verdict.retryAfterMs > 0 && verdict.retryAfterMs <= 60_000, 'retryAfterMs names when the refill suffices');
    equal(instance.take(b.connectionId), null, 'a throttled frame was never queued');
    equal(instance.connectionMetadata(a.connectionId).connectionId, a.connectionId, 'and the connection LIVES');

    // Refill: half a minute later (leases live 60s from mint -- advancing a
    // full minute expires the CONNECTIONS, which is a different test) the
    // 2048/min refill has restored one frame's worth.
    clockMs += 30_000;
    equal(instance.route({ connectionId: a.connectionId, peerConnectionId: b.connectionId, frame }).delivered, true);

    // Config refusals: a burst below one frame could never pass anything, and
    // the shape is exact-keys like everything else here.
    code(() => relay({ maxFrameBytes: 4096, pairRateLimit: { burstBytes: 1024, refillBytesPerMinute: 1024 } }), 'ONLINE_FRA_RELAY_OPTIONS_INVALID');
    code(() => relay({ pairRateLimit: { burstBytes: 65536 } }), 'ONLINE_FRA_RELAY_OPTIONS_INVALID');

    // And absent by default: without the option, no frame is ever throttled.
    const unmetered = relay({});
    const pairTwo = connectPair(unmetered);
    for (let index = 0; index < 50; index += 1) {
      equal(unmetered.route({ connectionId: pairTwo.a.connectionId, peerConnectionId: pairTwo.b.connectionId, frame: Buffer.alloc(512, 1) }).delivered, true);
      unmetered.take(pairTwo.b.connectionId);
    }
  }

  // --- the web-client role: the browser beside the pair ---------------------
  //
  // Owner ruling 2026-08-19: a signed-in browser drives the customer's own
  // machine. A third role, one slot per pair, displacement not refusal, no
  // mTLS (the edge proves possession of the key whose SPKI SHA-256 sits in
  // the fingerprint slot and attests authType 'web-lease') -- and the
  // machine<->machine contract untouched, which the UNCHANGED tests above
  // already prove.
  {
    const webKey = crypto.generateKeyPairSync('ed25519');
    const webFingerprint = crypto.createHash('sha256')
      .update(webKey.publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
    const webLease = (overrides = {}) => lease({ pair: pairOne, role: 'machine-a', overrides: {
      endpointRole: 'web-client',
      deviceId: `web-${'e'.repeat(24)}`,
      peerDeviceId: pairOne.machineAId,
      mtlsFingerprint: webFingerprint,
      ...overrides
    } });
    const webIdentity = (leaseValue, overrides = {}) => ({
      verified: true, authType: 'web-lease', deviceId: leaseValue.deviceId, mtlsFingerprint: leaseValue.mtlsFingerprint, ...overrides
    });

    const instance = relay({});
    const { a, b } = connectPair(instance);

    // Admission: web-lease authType required; mtls on a web lease refused.
    const wl = webLease();
    code(() => instance.connect({ identity: { ...webIdentity(wl), authType: 'mtls' }, lease: wl }), 'ONLINE_FRA_MTLS_IDENTITY_INVALID');
    const web = instance.connect({ identity: webIdentity(wl), lease: wl });
    equal(web.endpointRole, 'web-client');
    equal(web.paired, false, 'the web endpoint does not pair; it addresses machines per frame');

    // Routing: web -> machine-a, machine-b -> web, both real deliveries.
    equal(instance.route({ connectionId: web.connectionId, peerConnectionId: a.connectionId, frame: Buffer.from('to-a') }).delivered, true);
    deepEqual(instance.take(a.connectionId), Buffer.from('to-a'));
    equal(instance.route({ connectionId: b.connectionId, peerConnectionId: web.connectionId, frame: Buffer.from('to-web') }).delivered, true);
    deepEqual(instance.take(web.connectionId), Buffer.from('to-web'));

    // The machine link is still the machine link.
    equal(instance.route({ connectionId: a.connectionId, peerConnectionId: b.connectionId, frame: Buffer.from('m2m') }).delivered, true);
    deepEqual(instance.take(b.connectionId), Buffer.from('m2m'));

    // A web lease bound to a machine's device id, or to a peer outside the
    // pair, is refused at binding.
    code(() => instance.connect({ identity: webIdentity(webLease({ deviceId: pairOne.machineAId })), lease: webLease({ deviceId: pairOne.machineAId }) }), 'ONLINE_FRA_LEASE_BINDING_INVALID');

    // DISPLACEMENT: a second web lease closes the first, never a refusal.
    const events = [];
    const displacing = relay({ events });
    const pairTwoConns = connectPair(displacing);
    const firstLease = webLease();
    const first = displacing.connect({ identity: webIdentity(firstLease), lease: firstLease });
    const secondLease = webLease({ deviceId: `web-${'f'.repeat(24)}` });
    const second = displacing.connect({ identity: webIdentity(secondLease), lease: secondLease });
    /* THE COMMENT BELOW SAID "the old browser tab is told it was displaced", and
       it was not true of the tab -- only of the event sink, which no browser can
       read. The tab's own edge asked this very question and was told 'unknown',
       closed the socket as an internal error, and the page reported that the
       person's computer had not answered. It had; their own second tab had taken
       the slot, exactly as designed. Measured on production 2026-08-22: tab one
       answered before tab two opened and timed out after it, saying "The machine
       did not answer. It may be switched off."
       So the reason is now answerable by the party that needs it. */
    code(() => displacing.connectionMetadata(first.connectionId), 'ONLINE_FRA_WEB_DISPLACED');
    ok(events.some(event => event.type === 'online_fra.connection.closed' && event.reason === 'ONLINE_FRA_WEB_DISPLACED'),
      'the displacement is audited as well as answerable');
    equal(displacing.connectionMetadata(second.connectionId).endpointRole, 'web-client');
    // And the machines never noticed.
    equal(displacing.route({ connectionId: pairTwoConns.a.connectionId, peerConnectionId: pairTwoConns.b.connectionId, frame: Buffer.from('still') }).delivered, true);

    // Web-to-web has no meaning: enforced even hypothetically (route refuses
    // a web source naming a web peer of another instance's shape).
    code(() => instance.route({ connectionId: web.connectionId, peerConnectionId: web.connectionId, frame: Buffer.from('x') }), 'ONLINE_FRA_ROUTE_PEER_MISMATCH');

    // The machine capacity budget is untouched by the web slot: both machine
    // slots were already full when the web endpoint joined, and it joined.
    equal(instance.snapshot().activeConnections >= 3, true);
  }

  // --- the solo pair: one computer, served ----------------------------------
  //
  // Owner ruling: "If theres only one computer connected we need to serve that
  // one computer in the interface. If there's two we need to serve both in the
  // interface and both need to be controllable." The relay's half is
  // PERMISSIVE only: a pair whose B side is null -- present and exactly null
  // -- registers, its one machine admits with a null peer, its web slot
  // addresses that one machine, and nothing about a two-machine pair moves
  // (every section above is the proof of that, and none of them changed).
  {
    const pairSolo = Object.freeze({ pairId: 'pair-solo', machineAId: 'machine-solo', machineBId: null, capabilityDigest: digestOne });
    const soloIdentity = (leaseValue, overrides = {}) => identity(leaseValue.deviceId, leaseValue.mtlsFingerprint, overrides);

    // Registration: at construction and at runtime, with the usual receipt.
    {
      const events = [];
      const constructed = relay({ events, pairs: [pairOne, pairSolo] });
      equal(constructed.snapshot().pairCount, 2, 'a solo pair constructs beside a two-machine one');
      const instance = relay({ events });
      const receipt = instance.registerPair(pairSolo);
      equal(receipt.pairId, 'pair-solo');
      equal(receipt.pairCount, 2, 'a solo pair registers at runtime like any other');
      ok(events.some(event => event.type === 'online_fra.pair.registered' && event.pairId === 'pair-solo'), 'and is audited the same way');
    }

    // The key must be PRESENT and null. An absent key is still the old
    // refusal, so a caller that forgot machineBId is never taken as solo; an
    // undefined value is not null either. Device ids stay globally unique
    // across solo and two-machine pairs alike.
    {
      const instance = relay({});
      code(() => instance.registerPair({ pairId: 'pair-solo', machineAId: 'machine-solo', capabilityDigest: digestOne }), 'ONLINE_FRA_RELAY_PAIR_INVALID');
      code(() => instance.registerPair({ pairId: 'pair-solo', machineAId: 'machine-solo', machineBId: undefined, capabilityDigest: digestOne }), 'ONLINE_FRA_RELAY_PAIR_INVALID');
      code(() => relay({ pairs: [{ pairId: 'pair-solo', machineAId: 'machine-solo', capabilityDigest: digestOne }] }), 'ONLINE_FRA_RELAY_PAIR_INVALID');
      code(() => instance.registerPair({ ...pairSolo, machineAId: pairOne.machineBId }), 'ONLINE_FRA_RELAY_PAIR_INVALID');
      instance.registerPair(pairSolo);
      code(() => instance.registerPair({ pairId: 'pair-gh', machineAId: 'machine-g', machineBId: pairSolo.machineAId, capabilityDigest: digestOne }), 'ONLINE_FRA_RELAY_PAIR_INVALID');
      code(() => instance.registerPair({ pairId: 'pair-solo-2', machineAId: pairSolo.machineAId, machineBId: null, capabilityDigest: digestOne }), 'ONLINE_FRA_RELAY_PAIR_INVALID');
      equal(instance.snapshot().pairCount, 2, 'every refusal above left no trace');
    }

    // Machine admission: machine-a with peerDeviceId null admits, unpaired,
    // with no machine-b leg. A lease NAMING a peer the pair does not have is
    // refused at binding; so is a machine-b lease, because there is no B; so
    // is a null peer on a TWO-machine pair (the lease says "no peer" about a
    // pair that has one); and a WEB lease never gets to say null at all --
    // its shape still names the machine it drives.
    {
      const events = [];
      const instance = relay({ events, pairs: [pairSolo] });
      const soloLease = lease({ pair: pairSolo, role: 'machine-a' });
      equal(soloLease.peerDeviceId, null, 'precondition: the fixture mints a null peer for a solo machine');
      const a = instance.connect({ identity: soloIdentity(soloLease), lease: soloLease });
      equal(a.endpointRole, 'machine-a');
      equal(a.paired, false, 'a solo machine is admitted and is not paired -- there is nobody to pair with');
      const meta = instance.connectionMetadata(a.connectionId);
      equal(meta.peerConnectionId, null);
      equal(meta.peerDeviceId, null);
      equal(meta.legs['machine-a'], a.connectionId);
      equal(meta.legs['machine-b'], null, 'the B leg is absent, not an error');
      const namedPeer = lease({ pair: pairSolo, role: 'machine-a', overrides: { peerDeviceId: 'machine-b' } });
      code(() => instance.connect({ identity: soloIdentity(namedPeer), lease: namedPeer }), 'ONLINE_FRA_LEASE_BINDING_INVALID');
      const asB = lease({ pair: pairSolo, role: 'machine-b', overrides: { deviceId: 'machine-ghost', peerDeviceId: pairSolo.machineAId } });
      code(() => instance.connect({ identity: soloIdentity(asB), lease: asB }), 'ONLINE_FRA_LEASE_BINDING_INVALID');
      const twoMachine = relay({});
      const nullOnPair = lease({ pair: pairOne, role: 'machine-a', overrides: { peerDeviceId: null } });
      code(() => twoMachine.connect({ identity: soloIdentity(nullOnPair), lease: nullOnPair }), 'ONLINE_FRA_LEASE_BINDING_INVALID');
      const webNull = lease({ pair: pairOne, role: 'machine-a', overrides: { endpointRole: 'web-client', deviceId: `web-${'a'.repeat(24)}`, peerDeviceId: null } });
      code(() => twoMachine.connect({ identity: soloIdentity(webNull, { authType: 'web-lease' }), lease: webNull }), 'ONLINE_FRA_LEASE_INVALID');
      equal(instance.snapshot().activeConnections, 1, 'only the solo machine is connected');
      ok(!/\bnull\b|undefined/.test(JSON.stringify(events)), 'no event summarising the solo pair prints a null or undefined side');
    }

    // The web slot on a solo pair addresses the ONE machine, and the relay
    // waits for nothing: the browser is admitted before the machine, its
    // first frame reaches the machine before the machine has sent a byte,
    // and the machine's answer reaches the browser the same way. A web lease
    // naming a peer the pair does not have is refused; displacement still
    // works; and the per-pair floor was NOT lowered to make room for any of
    // this -- one machine plus one web slot is all a solo pair ever holds.
    {
      const webKey = crypto.generateKeyPairSync('ed25519');
      const webFingerprint = crypto.createHash('sha256').update(webKey.publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
      const webLease = (overrides = {}) => lease({ pair: pairSolo, role: 'machine-a', overrides: {
        endpointRole: 'web-client', deviceId: `web-${'5'.repeat(24)}`, peerDeviceId: pairSolo.machineAId, mtlsFingerprint: webFingerprint, ...overrides
      } });
      const webIdentity = leaseValue => ({ verified: true, authType: 'web-lease', deviceId: leaseValue.deviceId, mtlsFingerprint: leaseValue.mtlsFingerprint });
      const events = [];
      const instance = relay({ events, pairs: [pairSolo] });
      const wl = webLease();
      const web = instance.connect({ identity: webIdentity(wl), lease: wl });
      equal(web.paired, false, 'admitted first, with no machine present yet');
      const soloLease = lease({ pair: pairSolo, role: 'machine-a' });
      const a = instance.connect({ identity: soloIdentity(soloLease), lease: soloLease });
      equal(instance.connectionMetadata(web.connectionId).legs['machine-a'], a.connectionId, 'the browser can see the one machine leg');
      equal(instance.connectionMetadata(web.connectionId).legs['machine-b'], null);
      equal(instance.take(a.connectionId), null, 'precondition: the machine has neither sent nor received anything');
      equal(instance.route({ connectionId: web.connectionId, peerConnectionId: a.connectionId, frame: Buffer.from('hello-from-browser') }).delivered, true);
      deepEqual(instance.take(a.connectionId), Buffer.from('hello-from-browser'), 'delivered without any hello from the machine leg first');
      equal(instance.route({ connectionId: a.connectionId, peerConnectionId: web.connectionId, frame: Buffer.from('hello-from-machine') }).delivered, true);
      deepEqual(instance.take(web.connectionId), Buffer.from('hello-from-machine'));
      const elsewhere = webLease({ peerDeviceId: 'machine-b' });
      code(() => instance.connect({ identity: webIdentity(elsewhere), lease: elsewhere }), 'ONLINE_FRA_LEASE_BINDING_INVALID');
      const second = webLease({ deviceId: `web-${'6'.repeat(24)}` });
      const replaced = instance.connect({ identity: webIdentity(second), lease: second });
      code(() => instance.connectionMetadata(web.connectionId), 'ONLINE_FRA_WEB_DISPLACED');
      equal(instance.connectionMetadata(replaced.connectionId).endpointRole, 'web-client');
      equal(instance.snapshot().activeConnections, 2);
      code(() => relay({ maxConnectionsPerPair: 1 }), 'ONLINE_FRA_RELAY_CAPACITY_INVALID');
      ok(!/\bnull\b|undefined/.test(JSON.stringify(events)), 'the accepted/routed/dequeued/closed events of a solo pair name no null side');
    }

    // Retirement frees the solo machine's id for a later registration -- as
    // the B of a two-machine pair, or as a solo again -- and an open solo
    // connection is closed with the retirement named, exactly as for a pair.
    {
      const instance = relay({});
      instance.registerPair(pairSolo);
      const soloLease = lease({ pair: pairSolo, role: 'machine-a' });
      const a = instance.connect({ identity: soloIdentity(soloLease), lease: soloLease });
      code(() => instance.registerPair({ pairId: 'pair-reuse', machineAId: 'machine-r', machineBId: pairSolo.machineAId, capabilityDigest: digestOne }), 'ONLINE_FRA_RELAY_PAIR_INVALID');
      equal(instance.retirePair({ pairId: 'pair-solo' }), true);
      code(() => instance.connectionMetadata(a.connectionId), 'ONLINE_FRA_PAIR_RETIRED');
      instance.registerPair({ pairId: 'pair-reuse', machineAId: 'machine-r', machineBId: pairSolo.machineAId, capabilityDigest: digestOne });
      equal(instance.retirePair({ pairId: 'pair-reuse' }), true);
      instance.registerPair(pairSolo);
      equal(instance.snapshot().pairCount, 2, 'the freed id registered again: as the B of a pair, then as a solo');
    }
  }

  console.log(`online FRA rendezvous relay tests passed (${assertions} assertions).`);
}

run();
