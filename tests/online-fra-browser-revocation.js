'use strict';

// Real service, SQLite read-only authority, signed leases and relay core. Only
// the WebSocket transport and clock are controlled for bounded timer checks.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { EventEmitter } = require('node:events');
const { DatabaseSync } = require('node:sqlite');
const { createOnlineFraRelayService } = require('../src/lib/online-fra-relay-service');
const { createOnlineFraRendezvousRelay, leaseSigningBytes } = require('../src/lib/online-fra-rendezvous-relay');
const { createOnlineFraWebSocketAdapter, DEFAULTS } = require('../src/lib/online-fra-websocket-adapter');
const { createOnlineFraWebAdmission } = require('../src/lib/online-fra-web-admission');

const digest = 'd'.repeat(64);
const pairs = ['one', 'two'].map(name => ({ pairId: `relay-${name}`, accountId: 'fixture-account',
  machineAId: `machine-${name}-a`, machineBId: `machine-${name}-b`, capabilityDigest: digest }));
const identity = lease => ({ verified: true, authType: 'key-lease', deviceId: lease.deviceId, mtlsFingerprint: lease.mtlsFingerprint });
function mint(authority, pair, role, options = {}) {
  const at = options.at ?? Date.now();
  const lease = { schemaVersion: 'online-fra-lease.v1', leaseId: `lease-${crypto.randomBytes(8).toString('hex')}`,
    pairId: pair.pairId, deviceId: role === 'web-client' ? `web-${pair.pairId}` : role === 'machine-a' ? pair.machineAId : pair.machineBId,
    peerDeviceId: role === 'machine-a' ? pair.machineBId : pair.machineAId, endpointRole: role,
    mtlsFingerprint: 'a'.repeat(64), generation: 1, issuedAtMs: at, expiresAtMs: at + 600_000,
    nonce: crypto.randomBytes(24).toString('base64url'),
    ephemeralX25519PublicKey: crypto.generateKeyPairSync('x25519').publicKey.export({ type: 'spki', format: 'der' }).toString('base64url'),
    capabilityDigest: digest, signature: '', ...options };
  delete lease.at;
  lease.signature = crypto.sign(null, leaseSigningBytes(lease), authority.privateKey).toString('base64url');
  return lease;
}
async function world(run) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'relay-browser-revocation-'));
  const db = new DatabaseSync(path.join(dir, 'devices.sqlite3'));
  // Existing device-registry contract; the relay never imports the account
  // implementation or opens its separate account/session database.
  db.exec(`CREATE TABLE devices (pair_id TEXT PRIMARY KEY, account_id TEXT NOT NULL, device_id TEXT, revoked_at_ms INTEGER);
    CREATE TABLE relay_pairs (relay_pair_id TEXT PRIMARY KEY, account_id TEXT NOT NULL, a_pair_id TEXT NOT NULL,
      b_pair_id TEXT, capability_digest TEXT NOT NULL, created_at_ms INTEGER NOT NULL);
    CREATE TABLE relay_web_sessions (relay_pair_id TEXT PRIMARY KEY, account_id TEXT NOT NULL,
      web_device_id TEXT NOT NULL, expires_at_ms INTEGER NOT NULL, session_sha256 TEXT);`);
  for (const pair of pairs) {
    for (const id of [pair.machineAId, pair.machineBId]) db.prepare('INSERT INTO devices VALUES (?, ?, ?, NULL)').run(id, pair.accountId, id);
    db.prepare('INSERT INTO relay_pairs VALUES (?, ?, ?, ?, ?, 1)').run(pair.pairId, pair.accountId, pair.machineAId, pair.machineBId, digest);
  }
  const authority = crypto.generateKeyPairSync('ed25519');
  const service = createOnlineFraRelayService({ accountDbPath: path.join(dir, 'devices.sqlite3'),
    leaseStatePath: path.join(dir, 'leases.sqlite3'), authorityPublicKeyPem: authority.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    control: { port: 0, token: 'synthetic-test-control-token-0000000000000000' },
    pathTrustAttestor: c => ({ ok: true, parentPath: c.parentPath, filePath: c.filePath, generation: c.generation, stage: c.stage }) });
  const intro = (pair, deviceId = `web-${pair.pairId}`, session = pair.pairId) => {
    db.prepare('INSERT OR REPLACE INTO relay_web_sessions VALUES (?, ?, ?, ?, ?)')
      .run(pair.pairId, pair.accountId, deviceId, Date.now() + 600_000, crypto.createHash('sha256').update(session).digest('hex'));
  };
  const connect = (pair, role, options) => {
    const lease = mint(authority, pair, role, options);
    return { ...service.relay.connect({ lease, identity: identity(lease) }), lease };
  };
  const withdraw = session => db.prepare('DELETE FROM relay_web_sessions WHERE session_sha256 = ?')
    .run(crypto.createHash('sha256').update(session).digest('hex'));
  try { await service.start(); await run({ db, service, relay: service.relay, authority, intro, connect, withdraw }); }
  finally { await service.stop(); db.close(); fs.rmSync(dir, { recursive: true, force: true }); }
}
const revoked = error => error.code === 'ONLINE_FRA_WEB_SESSION_REVOKED';
const refused = error => error.code === 'ONLINE_FRA_PAIR_UNAUTHORIZED';
const route = (relay, from, to, text) => relay.route({ connectionId: from.connectionId, peerConnectionId: to.connectionId, frame: Buffer.from(text) });

test('web admission requires a current matching introduction and cannot displace another browser on refusal', () => world(w => {
  const pair = pairs[0];
  w.connect(pair, 'machine-a');
  assert.throws(() => w.connect(pair, 'web-client'), refused);
  w.intro(pair, 'web-current', 'current-session');
  const current = w.connect(pair, 'web-client', { deviceId: 'web-current' });
  assert.throws(() => w.connect(pair, 'web-client', { deviceId: 'web-retained-old-capability' }), refused);
  assert.equal(w.relay.connectionMetadata(current.connectionId).deviceId, 'web-current');
  w.withdraw('current-session');
  assert.throws(() => w.relay.connectionMetadata(current.connectionId), revoked);
  assert.throws(() => w.connect(pair, 'web-client', { deviceId: 'web-current' }), refused);
}));

test('withdrawing one session rejects its already-admitted browser while preserving the other session and machines', () => world(w => {
  const [first, second] = pairs;
  w.intro(first, undefined, 'first-session'); w.intro(second, undefined, 'second-session');
  const a = w.connect(first, 'machine-a'); const b = w.connect(first, 'machine-b');
  const web = w.connect(first, 'web-client');
  const otherMachine = w.connect(second, 'machine-a'); const otherWeb = w.connect(second, 'web-client');
  assert.equal(route(w.relay, web, a, 'before withdrawal').delivered, true);
  assert.equal(w.relay.take(a.connectionId).toString(), 'before withdrawal');
  w.withdraw('first-session');
  assert.throws(() => route(w.relay, web, a, 'retained capability'), revoked);
  assert.throws(() => w.relay.take(web.connectionId), revoked);
  assert.equal(route(w.relay, a, b, 'machine-only').delivered, true);
  assert.equal(w.relay.take(b.connectionId).toString(), 'machine-only');
  assert.equal(route(w.relay, otherWeb, otherMachine, 'other browser').delivered, true);
  assert.equal(w.relay.take(otherMachine.connectionId).toString(), 'other browser');
  assert.equal(w.relay.snapshot().activeConnections, 4);
}));

test('a response to a revoked web target is dropped without disconnecting its machine', () => world(w => {
  const pair = pairs[0]; w.intro(pair);
  const a = w.connect(pair, 'machine-a'); const web = w.connect(pair, 'web-client');
  w.withdraw(pair.pairId);
  assert.deepEqual(route(w.relay, a, web, 'late response'), { delivered: false, bytes: 0 });
  assert.equal(w.relay.connectionMetadata(a.connectionId).legs['web-client'], null);
  assert.throws(() => w.relay.take(web.connectionId), revoked);
  assert.equal(w.relay.snapshot().activeConnections, 1);
}));

test('withdrawal purges queued web commands and responses but retains machine-to-machine frames and correct byte totals', () => world(w => {
  const pair = pairs[0]; w.intro(pair);
  const a = w.connect(pair, 'machine-a'); const b = w.connect(pair, 'machine-b'); const web = w.connect(pair, 'web-client');
  route(w.relay, web, a, 'queued command'); route(w.relay, b, a, 'keep this'); route(w.relay, a, web, 'queued response');
  assert.ok(w.relay.snapshot().queuedBytes > 0);
  w.withdraw(pair.pairId);
  assert.equal(w.relay.take(a.connectionId).toString(), 'keep this');
  assert.equal(w.relay.take(a.connectionId), null);
  assert.throws(() => w.relay.take(web.connectionId), revoked);
  assert.equal(w.relay.snapshot().queuedBytes, 0);
}));

test('expired introduction refuses both a fresh admission and an admitted lease still inside its own expiry', () => world(w => {
  const pair = pairs[0]; w.intro(pair);
  const web = w.connect(pair, 'web-client');
  w.db.prepare('UPDATE relay_web_sessions SET expires_at_ms = ?').run(Date.now() - 1);
  assert.throws(() => w.relay.connectionMetadata(web.connectionId), revoked);
  assert.throws(() => w.connect(pair, 'web-client', { deviceId: web.lease.deviceId }), refused);
}));

test('a missing or unreadable introduction lookup fails closed only for web connections', () => world(w => {
  const pair = pairs[0]; w.intro(pair);
  const a = w.connect(pair, 'machine-a'); const b = w.connect(pair, 'machine-b'); const web = w.connect(pair, 'web-client');
  w.db.exec('DROP TABLE relay_web_sessions');
  assert.throws(() => w.connect(pair, 'web-client', { deviceId: 'web-new' }), refused);
  assert.throws(() => w.relay.connectionMetadata(web.connectionId), revoked);
  assert.equal(route(w.relay, a, b, 'unaffected machine traffic').delivered, true);
  assert.equal(w.relay.take(b.connectionId).toString(), 'unaffected machine traffic');
  assert.equal(w.service.admissionAuthority({ pairId: pair.pairId, endpointRole: 'machine-a' }), true);
}));

test('an introduction with a different account binding cannot authorize its browser', () => world(w => {
  const pair = pairs[0]; w.intro(pair);
  w.db.exec("UPDATE relay_web_sessions SET account_id = 'another-account'");
  assert.throws(() => w.connect(pair, 'web-client'), refused);
}));

class Timers {
  constructor() { this.now = 1_000_000; this.items = new Map(); this.serial = 0; }
  set = (fn, ms) => { const id = ++this.serial; this.items.set(id, { fn, at: this.now + ms }); return id; };
  clear = id => this.items.delete(id);
  advance(ms) { this.now += ms; for (const [id, item] of [...this.items]) if (item.at <= this.now) { this.items.delete(id); item.fn(); } }
}
class Socket extends EventEmitter {
  readyState = 1; bufferedAmount = 0; sent = []; closes = [];
  send(data) { this.sent.push(Buffer.from(data)); }
  ping() {}
  close(code) { this.closes.push(code); this.readyState = 3; this.emit('close'); }
}
class WebSocketServer {
  handleUpgrade(request, socket, head, callback) { callback(socket.ws); }
  close() {}
}
function edgeWorld() {
  const timers = new Timers(); const httpServer = new EventEmitter();
  const authority = crypto.generateKeyPairSync('ed25519'); const browser = crypto.generateKeyPairSync('ed25519');
  const pair = pairs[0]; let authorized = true; let unavailable = false;
  const relay = createOnlineFraRendezvousRelay({ enabled: true, authorityPublicKey: authority.publicKey,
    pairs: [{ pairId: pair.pairId, machineAId: pair.machineAId, machineBId: pair.machineBId, capabilityDigest: digest }],
    clock: () => timers.now, eventSink() {},
    admissionAuthority: request => { if (request.endpointRole !== 'web-client') return true; if (unavailable) throw new Error('synthetic lookup failure'); return authorized; },
    leaseState: { admitLease: () => ({ ok: true, outcome: 'accepted' }), pairState: () => ({ ok: true, revoked: false }), revokePair: () => ({ ok: true, revoked: true }) } });
  const adapter = createOnlineFraWebSocketAdapter({ enabled: true, WebSocketServer, httpServer, relay,
    hostname: 'relay.example.net', eventSink() {}, clock: () => timers.now, setTimer: timers.set, clearTimer: timers.clear,
    verifyProxyRequest: request => request.machine ? { ok: true, tlsSni: 'relay.example.net', clientVerify: 'SUCCESS',
      deviceId: pair.machineAId, fingerprint: 'a'.repeat(64), ip: '127.0.0.2' } : { ok: false },
    keyAdmission: createOnlineFraWebAdmission({ relay, clock: () => timers.now }), clientIpFor: () => '127.0.0.3' });
  function upgrade(machine = false) {
    const ws = new Socket(); const socket = { ws, destroy() { throw new Error('unexpected refusal before admission'); } };
    httpServer.emit('upgrade', { method: 'GET', url: '/v1/rendezvous', machine }, socket, Buffer.alloc(0));
    return ws;
  }
  adapter.start();
  const machine = upgrade(true);
  const machineLease = mint(authority, pair, 'machine-a', { at: timers.now });
  machine.emit('message', Buffer.from(JSON.stringify({ lease: machineLease })), false);
  const web = upgrade(); const nonce = JSON.parse(web.sent[0].toString()).challenge;
  const publicKeySpki = browser.publicKey.export({ type: 'spki', format: 'der' });
  const webLease = mint(authority, pair, 'web-client', { at: timers.now,
    mtlsFingerprint: crypto.createHash('sha256').update(publicKeySpki).digest('hex') });
  web.emit('message', Buffer.from(JSON.stringify({ lease: webLease, nonce, publicKeySpki: publicKeySpki.toString('base64url'),
    signature: crypto.sign(null, Buffer.from(nonce, 'base64url'), browser.privateKey).toString('base64url') })), false);
  assert.equal(relay.snapshot().activeConnections, 2);
  return { timers, relay, adapter, web, machine, revoke() { authorized = false; }, failLookup() { unavailable = true; } };
}
for (const condition of ['withdrawn', 'lookup failure']) test(`the default edge closes a ${condition} browser within one second even while backpressured`, () => {
  const w = edgeWorld();
  try {
    w.web.bufferedAmount = DEFAULTS.maxBufferedBytes + 1;
    w.machine.bufferedAmount = DEFAULTS.maxBufferedBytes + 1;
    if (condition === 'withdrawn') w.revoke(); else w.failLookup();
    w.timers.advance(999); assert.equal(w.web.readyState, 1);
    w.timers.advance(1); assert.equal(w.web.readyState, 3); assert.equal(w.web.closes.at(-1), 1008);
    assert.equal(w.machine.readyState, 1); assert.equal(w.relay.snapshot().activeConnections, 1);
  } finally { w.adapter.kill(); }
});

test('retained browser socket cannot submit a frame after withdrawal before its timer fires', () => {
  const w = edgeWorld();
  try {
    const before = w.machine.sent.length; w.revoke();
    w.web.emit('message', Buffer.concat([Buffer.from([1]), Buffer.from('retained capability command')]), true);
    assert.equal(w.machine.sent.length, before); assert.equal(w.web.readyState, 3); assert.equal(w.machine.readyState, 1);
  } finally { w.adapter.kill(); }
});

test('a machine response after withdrawal drops the web leg while retaining the machine socket', () => {
  const w = edgeWorld();
  try {
    const before = w.web.sent.length; w.revoke();
    w.machine.emit('message', Buffer.concat([Buffer.from([3]), Buffer.from('late response')]), true);
    assert.equal(w.web.sent.length, before); assert.equal(w.machine.readyState, 1);
    w.timers.advance(1_000); assert.equal(w.web.readyState, 3);
  } finally { w.adapter.kill(); }
});


test('lease expiry is still enforced by the periodic edge check when a receiver remains backpressured', () => {
  const w = edgeWorld();
  try {
    w.web.bufferedAmount = DEFAULTS.maxBufferedBytes + 1;
    w.machine.bufferedAmount = DEFAULTS.maxBufferedBytes + 1;
    for (let tick = 0; tick < 599; tick += 1) {
      w.web.emit('pong'); w.machine.emit('pong'); w.timers.advance(1_000);
    }
    assert.equal(w.web.readyState, 1);
    w.web.emit('pong'); w.machine.emit('pong'); w.timers.advance(1_000);
    assert.equal(w.web.readyState, 3); assert.equal(w.web.closes.at(-1), 1000);
    assert.equal(w.machine.readyState, 3); assert.equal(w.relay.snapshot().activeConnections, 0);
  } finally { w.adapter.kill(); }
});
