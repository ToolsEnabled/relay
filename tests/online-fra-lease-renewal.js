'use strict';

// Production core + production SQLite + production proof verifier + real
// loopback WebSockets. Time advances locally, not by increasing lease TTLs.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { WebSocket, WebSocketServer } = require('ws');
const { createOnlineFraRendezvousRelay, leaseSigningBytes, LEASE_SCHEMA_VERSION } = require('../src/lib/online-fra-rendezvous-relay');
const { createOnlineFraSqliteLeaseState } = require('../src/lib/online-fra-sqlite-lease-state');
const { createOnlineFraWebAdmission } = require('../src/lib/online-fra-web-admission');
const { createOnlineFraWebSocketAdapter } = require('../src/lib/online-fra-websocket-adapter');

process.exitCode = 1;
let checks = 0;
function equal(a, b, why) { checks++; assert.deepEqual(a, b, why); }
function code(fn, expected) { checks++; assert.throws(fn, error => error?.code === expected, expected); }
function key() {
  const pair = crypto.generateKeyPairSync('ed25519');
  const spki = pair.publicKey.export({ type: 'spki', format: 'der' });
  return { publicKeySpki: spki.toString('base64url'), fingerprint: crypto.createHash('sha256').update(spki).digest('hex'),
    sign: bytes => crypto.sign(null, bytes, pair.privateKey) };
}
function fixture({ solo = false } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'fra-renewal-'));
  fs.chmodSync(root, 0o700);
  const authority = crypto.generateKeyPairSync('ed25519');
  const identities = { 'machine-a': key(), 'machine-b': key(), 'web-client': key() };
  const pair = { pairId: 'pair-renewal', machineAId: 'machine-alpha', machineBId: solo ? null : 'machine-bravo', capabilityDigest: 'c'.repeat(64) };
  let at = Date.now(), seq = 0, authorized = true, current = true, sinkFails = false, renewalEffect = () => {};
  const events = [];
  const db = createOnlineFraSqliteLeaseState({ enabled: true, dbPath: path.join(root, 'leases.sqlite'), clock: () => at });
  db.open();
  db.initializePair({ pairId: pair.pairId, generation: 1, capabilityDigest: pair.capabilityDigest });
  const build = () => createOnlineFraRendezvousRelay({ enabled: true, pairs: [pair], generation: 1,
    authorityPublicKey: authority.publicKey, leaseState: db, clock: () => at,
    admissionAuthority: () => authorized, connectionAuthority: () => current,
    eventSink: event => {
      if (event.type === 'online_fra.connection.renewed') {
        if (sinkFails) throw new Error('fixture sink outage');
        renewalEffect();
      }
      events.push(event);
    } });
  const relay = build();
  const admission = createOnlineFraWebAdmission({ relay, clock: () => at });
  function lease(role = 'machine-a', overrides = {}) {
    const value = { schemaVersion: LEASE_SCHEMA_VERSION, leaseId: `lease_renewal_${++seq}`, pairId: pair.pairId,
      deviceId: role === 'web-client' ? 'web-owner-session' : role === 'machine-a' ? pair.machineAId : pair.machineBId,
      peerDeviceId: role === 'machine-a' ? pair.machineBId : pair.machineAId, endpointRole: role,
      mtlsFingerprint: identities[role].fingerprint, generation: 1, issuedAtMs: at, expiresAtMs: at + 6000,
      nonce: crypto.randomBytes(32).toString('base64url'),
      ephemeralX25519PublicKey: crypto.generateKeyPairSync('x25519').publicKey.export({ format: 'der', type: 'spki' }).toString('base64url'),
      capabilityDigest: pair.capabilityDigest, signature: '', ...overrides };
    value.signature = crypto.sign(null, leaseSigningBytes(value), authority.privateKey).toString('base64url');
    return value;
  }
  const identity = value => ({ verified: true, authType: 'key-lease', deviceId: value.deviceId, mtlsFingerprint: value.mtlsFingerprint });
  const connect = value => relay.connect({ lease: value, identity: identity(value) });
  const renew = (id, value) => relay.renew({ connectionId: id, lease: value, identity: identity(value) });
  return { relay, db, build, admission, pair, identities, events, lease, identity, connect, renew,
    now: () => at, advance: ms => { at += ms; }, authorize: value => { authorized = value; },
    current: value => { current = value; }, sinkFails: () => { sinkFails = true; },
    duringRenewal: effect => { renewalEffect = effect; },
    cleanup: () => { db.close(); fs.rmSync(root, { recursive: true, force: true }); } };
}

function coreTests() {
  for (const solo of [false, true]) {
    const f = fixture({ solo });
    try {
      const a0 = f.lease(), w0 = f.lease('web-client');
      const a = f.connect(a0), w = f.connect(w0);
      const b = solo ? null : f.connect(f.lease('machine-b'));
      const ids = f.relay.connectionMetadata(a.connectionId).legs;
      for (let cycle = 0; cycle < 8; cycle++) {
        f.advance(2000);
        // Queue a web command before renewing either endpoint. It must remain
        // queued for exactly the same machine and retain its source identity.
        const frame = crypto.randomBytes(31);
        f.relay.route({ connectionId: w.connectionId, peerConnectionId: a.connectionId, frame });
        for (const c of [a, b, w].filter(Boolean)) {
          const fresh = f.lease(c.endpointRole);
          equal(f.renew(c.connectionId, fresh), { leaseId: fresh.leaseId, expiresAtMs: fresh.expiresAtMs });
        }
        equal(f.relay.connectionMetadata(a.connectionId).legs, ids, 'every slot keeps the same connection');
        equal(f.relay.take(a.connectionId), frame, 'queued bytes survive renewal unchanged');
        equal(f.relay.take(a.connectionId), null, 'no duplicate');
      }
      equal(f.now() > a0.expiresAtMs, true, 'traffic survived the initial lease');
      equal(f.relay.snapshot().activeConnections, solo ? 2 : 3);
      equal(f.events.filter(e => e.type === 'online_fra.connection.accepted').length, solo ? 2 : 3, 'no reconnect or displacement');
      f.advance(6000);
      code(() => f.renew(a.connectionId, f.lease()), 'ONLINE_FRA_LEASE_EXPIRED');
      equal(f.relay.snapshot().activeConnections, 0, 'nonrenewed leases still expire');
    } finally { f.cleanup(); }
  }

  const f = fixture();
  try {
    const original = f.lease(), a = f.connect(original), oldExpiry = original.expiresAtMs;
    f.advance(1000);
    code(() => f.renew(a.connectionId, original), 'ONLINE_FRA_RENEWAL_LEASE_STALE');
    for (const overrides of [
      { expiresAtMs: oldExpiry }, { issuedAtMs: original.issuedAtMs - 1 },
      { leaseId: original.leaseId }, { nonce: original.nonce }
    ]) code(() => f.renew(a.connectionId, f.lease('machine-a', overrides)), 'ONLINE_FRA_RENEWAL_LEASE_STALE');
    for (const overrides of [
      { issuedAtMs: f.now() + 1 }, { expiresAtMs: f.now() }, { expiresAtMs: f.now() + 15 * 60_000 + 1 }
    ]) code(() => f.renew(a.connectionId, f.lease('machine-a', overrides)), 'ONLINE_FRA_LEASE_TIME_INVALID');
    for (const overrides of [ { pairId: 'pair-other' }, { generation: 2 }, { capabilityDigest: 'd'.repeat(64) }, { peerDeviceId: 'machine-other' } ]) {
      code(() => f.renew(a.connectionId, f.lease('machine-a', overrides)), 'ONLINE_FRA_LEASE_BINDING_INVALID');
    }
    for (const role of ['machine-b', 'web-client']) code(() => f.renew(a.connectionId, f.lease(role)), 'ONLINE_FRA_RENEWAL_IDENTITY_MISMATCH');
    code(() => f.renew(a.connectionId, f.lease('machine-a', { mtlsFingerprint: key().fingerprint })), 'ONLINE_FRA_RENEWAL_IDENTITY_MISMATCH');
    const forged = f.lease(); forged.expiresAtMs++;
    code(() => f.renew(a.connectionId, forged), 'ONLINE_FRA_LEASE_SIGNATURE_INVALID');
    equal(f.relay.connectionMetadata(a.connectionId).expiresAtMs, oldExpiry, 'refusals do not extend old authorization');
    f.authorize(false);
    const fresh = f.lease();
    code(() => f.renew(a.connectionId, fresh), 'ONLINE_FRA_PAIR_UNAUTHORIZED');
    f.authorize(true);
    f.renew(a.connectionId, fresh); // Authority refusal did not burn the lease.
    const restarted = f.build();
    code(() => restarted.connect({ lease: fresh, identity: f.identity(fresh) }), 'ONLINE_FRA_LEASE_REPLAYED');
    f.advance(1000);
    const nonceReuse = f.lease('machine-a', { nonce: original.nonce });
    code(() => f.renew(a.connectionId, nonceReuse), 'ONLINE_FRA_LEASE_REPLAYED');
    f.relay.revokePair({ pairId: f.pair.pairId, generation: 1 });
    code(() => f.renew(a.connectionId, f.lease()), 'ONLINE_FRA_PAIR_REVOKED');
    const nextProcess = f.build(), nextLease = f.lease();
    code(() => nextProcess.connect({ lease: nextLease, identity: f.identity(nextLease) }), 'ONLINE_FRA_PAIR_REVOKED');
  } finally { f.cleanup(); }

  for (const role of ['machine-a', 'web-client']) {
    const f = fixture();
    try {
      const endpoint = f.connect(f.lease(role)); f.advance(1000); f.current(false);
      code(() => f.renew(endpoint.connectionId, f.lease(role)), role === 'web-client' ? 'ONLINE_FRA_WEB_SESSION_REVOKED' : 'ONLINE_FRA_CONNECTION_UNAUTHORIZED');
      equal(f.relay.snapshot().activeConnections, 0);
    } finally { f.cleanup(); }
  }
  for (const outage of ['sqlite', 'sink']) {
    const f = fixture();
    try {
      const a = f.connect(f.lease()); f.advance(1000);
      if (outage === 'sqlite') f.db.close(); else f.sinkFails();
      code(() => f.renew(a.connectionId, f.lease()), outage === 'sqlite' ? 'ONLINE_FRA_LEASE_STATE_UNAVAILABLE' : 'ONLINE_FRA_EVENT_SINK_FAILED');
      equal(f.relay.snapshot().activeConnections, 0, 'failed authority/audit fails closed');
    } finally { f.cleanup(); }
  }
  for (const change of ['expiry', 'pair-revocation', 'account-revocation']) {
    const f = fixture();
    try {
      const a = f.connect(f.lease()); f.advance(1000);
      f.duringRenewal(() => {
        if (change === 'expiry') f.advance(5000);
        else if (change === 'pair-revocation') f.relay.revokePair({ pairId: f.pair.pairId, generation: 1 });
        else f.current(false);
      });
      const expected = change === 'expiry' ? 'ONLINE_FRA_LEASE_EXPIRED'
        : change === 'pair-revocation' ? 'ONLINE_FRA_PAIR_REVOKED' : 'ONLINE_FRA_CONNECTION_UNAUTHORIZED';
      code(() => f.renew(a.connectionId, f.lease()), expected);
      equal(f.relay.snapshot().activeConnections, 0, 'authority withdrawn during synchronous renewal cannot be resurrected');
    } finally { f.cleanup(); }
  }
}

function proofTests() {
  const f = fixture();
  try {
    const a = f.connect(f.lease()); f.advance(1000);
    const fresh = f.lease(), who = f.identities['machine-a'];
    const packet = (challenge, signingKey = who) => ({ lease: fresh, browserPublicKeySpki: who.publicKeySpki,
      nonce: challenge.nonce, signature: signingKey.sign(Buffer.from(challenge.nonce, 'base64url')).toString('base64url') });
    const admitChallenge = f.admission.challenge();
    code(() => f.admission.renew({ connectionId: a.connectionId, ...packet(admitChallenge) }), 'ONLINE_FRA_WEB_ADMISSION_CONNECTION_MISMATCH');
    const renewChallenge = f.admission.challenge({ connectionId: a.connectionId });
    code(() => f.admission.admit(packet(renewChallenge)), 'ONLINE_FRA_WEB_ADMISSION_CONNECTION_MISMATCH');
    const wrongConnection = f.admission.challenge({ connectionId: 'conn_other' });
    code(() => f.admission.renew({ connectionId: a.connectionId, ...packet(wrongConnection) }), 'ONLINE_FRA_WEB_ADMISSION_CONNECTION_MISMATCH');
    const badSignature = f.admission.challenge({ connectionId: a.connectionId });
    code(() => f.admission.renew({ connectionId: a.connectionId, ...packet(badSignature, key()) }), 'ONLINE_FRA_WEB_ADMISSION_PROOF_INVALID');
    code(() => f.admission.renew({ connectionId: a.connectionId, ...packet(badSignature) }), 'ONLINE_FRA_WEB_ADMISSION_NONCE_UNKNOWN');
    const success = f.admission.challenge({ connectionId: a.connectionId });
    equal(f.admission.renew({ connectionId: a.connectionId, ...packet(success) }), { leaseId: fresh.leaseId, expiresAtMs: fresh.expiresAtMs });
    code(() => f.admission.renew({ connectionId: a.connectionId, ...packet(success) }), 'ONLINE_FRA_WEB_ADMISSION_NONCE_UNKNOWN');
    const expired = f.admission.challenge({ connectionId: a.connectionId });
    f.advance(60_000);
    code(() => f.admission.renew({ connectionId: a.connectionId, ...packet(expired) }), 'ONLINE_FRA_WEB_ADMISSION_NONCE_EXPIRED');
    equal(f.admission.pendingChallenges(), 0);
  } finally { f.cleanup(); }
}

function inbox(ws) {
  const queue = [], waiting = [];
  ws.on('message', (data, binary) => {
    const message = binary ? Buffer.from(data) : JSON.parse(data.toString());
    const index = waiting.findIndex(w => w.match(message));
    if (index < 0) queue.push(message); else { const w = waiting.splice(index, 1)[0]; clearTimeout(w.timer); w.resolve(message); }
  });
  return match => {
    const index = queue.findIndex(match);
    if (index >= 0) return Promise.resolve(queue.splice(index, 1)[0]);
    return new Promise((resolve, reject) => {
      const item = { match, resolve, timer: setTimeout(() => { waiting.splice(waiting.indexOf(item), 1); reject(new Error('loopback response timed out')); }, 2000) };
      waiting.push(item);
    });
  };
}
async function until(predicate) {
  const stop = Date.now() + 2000;
  while (!predicate()) { if (Date.now() >= stop) throw new Error('loopback state timed out'); await new Promise(r => setTimeout(r, 5)); }
}

async function socketTests() {
  const f = fixture();
  const server = http.createServer((req, res) => { res.writeHead(426); res.end(); });
  const adapter = createOnlineFraWebSocketAdapter({ enabled: true, WebSocketServer, httpServer: server,
    relay: f.relay, keyAdmission: f.admission, hostname: 'relay.example.net', verifyProxyRequest: () => ({ ok: false }),
    eventSink: () => {}, clock: f.now, setTimer: setTimeout, clearTimer: clearTimeout });
  const sockets = [];
  adapter.start();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const url = `ws://127.0.0.1:${server.address().port}/v1/rendezvous`;
  async function dial(role) {
    const ws = new WebSocket(url), next = inbox(ws); sockets.push(ws);
    const challenge = await next(m => !!m.challenge), value = f.lease(role), who = f.identities[role];
    ws.send(JSON.stringify({ lease: value, publicKeySpki: who.publicKeySpki, nonce: challenge.challenge,
      signature: who.sign(Buffer.from(challenge.challenge, 'base64url')).toString('base64url') }));
    await until(() => f.events.some(e => e.type === 'online_fra.connection.accepted' && e.leaseId === value.leaseId));
    return { ws, next, role, original: value };
  }
  async function request(ep) {
    ep.ws.send(JSON.stringify({ renew: 'request' }));
    return ep.next(m => !!m.challenge && m.renewal === true);
  }
  function answer(ep, challenge, value, who = f.identities[ep.role]) {
    ep.ws.send(JSON.stringify({ renew: value, publicKeySpki: who.publicKeySpki, nonce: challenge.challenge,
      signature: who.sign(Buffer.from(challenge.challenge, 'base64url')).toString('base64url') }));
  }
  try {
    const a = await dial('machine-a'), b = await dial('machine-b'), w = await dial('web-client');
    const ids = f.events.filter(e => e.type === 'online_fra.connection.accepted').map(e => e.connectionId);
    for (let round = 0; round < 8; round++) {
      f.advance(2000);
      for (const ep of [a, b, w]) {
        const challenge = await request(ep), value = f.lease(ep.role);
        equal(challenge.challenge !== ep.previousChallenge, true, 'each challenge is fresh'); ep.previousChallenge = challenge.challenge;
        // Binary data continues while the proof is outstanding.
        const payload = crypto.randomBytes(35);
        w.ws.send(Buffer.concat([Buffer.from([1]), payload]));
        equal(await a.next(Buffer.isBuffer), Buffer.concat([Buffer.from([3]), payload]));
        answer(ep, challenge, value);
        equal((await ep.next(m => !!m.renewed)).renewed, { leaseId: value.leaseId, expiresAtMs: value.expiresAtMs });
      }
      const payload = crypto.randomBytes(29);
      a.ws.send(Buffer.concat([Buffer.from([2]), payload]));
      equal(await b.next(Buffer.isBuffer), Buffer.concat([Buffer.from([1]), payload]));
      a.ws.send(Buffer.concat([Buffer.from([3]), payload]));
      equal(await w.next(Buffer.isBuffer), Buffer.concat([Buffer.from([1]), payload]));
      equal(adapter.snapshot().sockets, 3);
    }
    equal(f.events.filter(e => e.type === 'online_fra.connection.accepted').map(e => e.connectionId), ids);
    equal(f.now() > a.original.expiresAtMs, true);

    // A signature for another socket's challenge, even by the right role's
    // key, cannot renew this connection. Its correct challenge still works.
    f.advance(1000);
    const ac = await request(a), bc = await request(b);
    answer(a, bc, f.lease());
    equal((await a.next(m => !!m.renewalRefused)).renewalRefused.code, 'ONLINE_FRA_WS_RENEWAL_NONCE_MISMATCH');
    const af = f.lease(); answer(a, ac, af);
    equal((await a.next(m => !!m.renewed)).renewed.leaseId, af.leaseId);
    answer(a, ac, af);
    equal((await a.next(m => !!m.renewalRefused)).renewalRefused.code, 'ONLINE_FRA_WS_RENEWAL_NONCE_MISMATCH');
    const bf = f.lease('machine-b'); answer(b, bc, bf);
    equal((await b.next(m => !!m.renewed)).renewed.leaseId, bf.leaseId);

    // Both challenge spam and a bad new proof leave old authorization bounded.
    a.ws.send(JSON.stringify({ renew: 'request' }));
    equal((await a.next(m => !!m.renewalRefused)).renewalRefused.code, 'ONLINE_FRA_WS_RENEWAL_THROTTLED');
    f.advance(1000);
    const bad = await request(a), wrong = key();
    answer(a, bad, f.lease(), wrong);
    equal((await a.next(m => !!m.renewalRefused)).renewalRefused.code, 'ONLINE_FRA_WEB_ADMISSION_KEY_MISMATCH');
    equal(f.admission.pendingChallenges(), 0);

    if (process.env.ENGINE_RELAY_CLIENT) {
      // Optional cross-repo gate uses the shipped client, not an engine test
      // relay helper. It replaces A only after the old socket is closed.
      const { connectOnlineFraRelay } = require(path.resolve(process.env.ENGINE_RELAY_CLIENT));
      a.ws.terminate(); await until(() => adapter.snapshot().sockets === 2);
      const received = [], initial = f.lease();
      const client = await connectOnlineFraRelay({ url, lease: initial, proof: f.identities['machine-a'], onFrame: bytes => received.push(Buffer.from(bytes)) });
      try {
        await until(() => adapter.snapshot().sockets === 3);
        f.advance(1000); const fresh = f.lease();
        equal(await client.renew({ lease: fresh, proof: f.identities['machine-a'] }), { leaseId: fresh.leaseId, expiresAtMs: fresh.expiresAtMs });
        w.ws.send(Buffer.from([1, 9, 8, 7])); await until(() => received.length === 1);
        equal(received[0], Buffer.from([9, 8, 7]));
      } finally { client.close(); }
      await until(() => adapter.snapshot().sockets === 2);
    }

    // An unanswered challenge is bounded by the edge's admission deadline,
    // even if the old lease remains good. A duplicate request cannot replace
    // that challenge or grow the nonce store.
    f.advance(1000);
    const longer = await request(b), longerLease = f.lease('machine-b', { expiresAtMs: f.now() + 30_000 });
    answer(b, longer, longerLease); await b.next(m => !!m.renewed);
    f.advance(1000); const abandoned = await request(b);
    b.ws.send(JSON.stringify({ renew: 'request' }));
    equal((await b.next(m => !!m.renewalRefused)).renewalRefused.code, 'ONLINE_FRA_WS_RENEWAL_BUSY');
    equal(f.admission.pendingChallenges(), 1);
    f.advance(10_000); answer(b, abandoned, f.lease('machine-b', { expiresAtMs: f.now() + 30_000 }));
    equal((await b.next(m => !!m.renewalRefused)).renewalRefused.code, 'ONLINE_FRA_WS_RENEWAL_EXPIRED');
    equal(f.admission.pendingChallenges(), 0);
    equal(b.ws.readyState, WebSocket.OPEN, 'the unextended old lease remains valid');

    // Revocation between challenge and answer closes the underlying endpoint,
    // regardless of the new lease's signature or future expiry.
    f.advance(1000); const revokedChallenge = await request(b);
    const revokedLease = f.lease('machine-b'); f.current(false);
    answer(b, revokedChallenge, revokedLease);
    equal((await b.next(m => !!m.renewalRefused)).renewalRefused.code, 'ONLINE_FRA_CONNECTION_UNAUTHORIZED');
    await until(() => b.ws.readyState === WebSocket.CLOSED);
    adapter.drain(); await until(() => adapter.snapshot().sockets === 0);
    equal(f.admission.pendingChallenges(), 0);
  } finally {
    for (const ws of sockets) ws.terminate();
    adapter.stop(); await new Promise(resolve => server.close(resolve)); f.cleanup();
  }
}

(async () => {
  coreTests(); proofTests(); await socketTests();
  console.log(`online-fra-lease-renewal: ${checks} assertions passed (production SQLite and loopback sockets${process.env.ENGINE_RELAY_CLIENT ? ', shipped engine client' : ''})`);
  process.exitCode = 0;
})().catch(error => { console.error(error); process.exitCode = 1; });
