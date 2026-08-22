'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { createOnlineFraWebSocketAdapter, DEFAULTS } = require('../src/lib/online-fra-websocket-adapter');
const {
  LEASE_SCHEMA_VERSION, createOnlineFraRendezvousRelay, leaseSigningBytes
} = require('../src/lib/online-fra-rendezvous-relay');
let assertions = 0;
const equal = (...a) => { assertions += 1; return assert.equal(...a); };
const ok = (...a) => { assertions += 1; return assert.ok(...a); };
function throws(run, predicate) { assertions += 1; return assert.throws(run, predicate); }

class FakeTimers {
  constructor() { this.now = 1_000_000; this.next = 1; this.items = new Map(); }
  set = (fn, ms) => { const id = this.next++; this.items.set(id, { fn, at: this.now + ms }); return id; };
  clear = id => this.items.delete(id);
  advance(ms) { this.now += ms; for (const [id, item] of [...this.items]) if (item.at <= this.now) { this.items.delete(id); item.fn(); } }
}
class FakeSocket { constructor() { this.destroyed = false; } destroy() { this.destroyed = true; } }
class FakeWs {
  constructor() { this.handlers = new Map(); this.readyState = 1; this.bufferedAmount = 0; this.sent = []; this.closed = []; this.pings = 0; }
  on(name, fn) { const list = this.handlers.get(name) || []; list.push(fn); this.handlers.set(name, list); }
  once(name, fn) { this.on(name, fn); }
  emit(name, ...args) { for (const fn of [...(this.handlers.get(name) || [])]) fn(...args); }
  send(data, options) { this.sent.push({ data: Buffer.from(data), options }); }
  ping() { this.pings += 1; }
  close(code) { this.closed.push(code); this.readyState = 3; this.emit('close'); }
}
class FakeWss {
  constructor(options) { this.options = options; this.closed = false; FakeWss.instances.push(this); }
  handleUpgrade(req, socket, head, callback) { this.last = { req, socket, head }; callback(socket.ws); }
  close() { this.closed = true; }
}
FakeWss.instances = [];

function fixture(overrides = {}) {
  const timers = new FakeTimers(); const events = []; const routes = []; const outbound = [];
  const httpServer = { handlers: new Map(), on(name, fn) { this.handlers.set(name, fn); }, off(name) { this.handlers.delete(name); } };
  const relay = {
    connect(input) { relay.connects.push(input); return { connectionId: 'connection-1' }; },
    connectionMetadata(id) { relay.metadata.push(id); return { peerConnectionId: 'peer-1', endpointRole: 'machine-a', legs: { 'machine-a': id, 'machine-b': 'peer-1', 'web-client': null } }; },
    route(input) { routes.push(input); },
    take(id) { relay.takes.push(id); return outbound.shift() ?? null; },
    close(id, reason) { relay.closes.push({ id, reason }); },
    connects: [], metadata: [], takes: [], closes: []
  };
  const base = {
    WebSocketServer: FakeWss, enabled: true, httpServer, relay, hostname: 'fra-relay.devices.example.net',
    eventSink: event => events.push(event), verifyProxyRequest: () => ({ ok: true, tlsSni: 'fra-relay.devices.example.net', clientVerify: 'SUCCESS', deviceId: 'device-a', fingerprint: 'a'.repeat(64), ip: '10.0.0.2' }),
    clock: () => timers.now, setTimer: timers.set, clearTimer: timers.clear,
    maxFrameBytes: 1024, maxAdmissionBytes: 128, maxSockets: 2, maxSocketsPerIp: 1, maxAdmissionsPerIp: 2,
    admissionWindowMs: 100, admissionTimeoutMs: 20, pingIntervalMs: 10, idleTimeoutMs: 30, maxBufferedBytes: 1024, maxDrainPerTick: 3,
    ...overrides
  };
  return { timers, events, routes, outbound, httpServer, relay, base, adapter: createOnlineFraWebSocketAdapter(base) };
}
function upgrade(test, request = { method: 'GET', url: '/v1/rendezvous' }, ws = new FakeWs(), head = Buffer.alloc(0)) {
  const socket = new FakeSocket(); socket.ws = ws; test.httpServer.handlers.get('upgrade')(request, socket, head); return { socket, ws };
}

(() => {
  throws(() => createOnlineFraWebSocketAdapter({}), error => error && error.code === 'ONLINE_FRA_WS_OPTIONS_INVALID');
  const inert = fixture({ enabled: false });
  equal(inert.adapter.snapshot().started, false); equal(inert.adapter.start(), false); equal(FakeWss.instances.length, 0);
  const test = fixture(); equal(test.adapter.start(), true); equal(test.adapter.start(), false);
  const settings = FakeWss.instances.at(-1).options; equal(settings.noServer, true); equal(settings.maxPayload, 1024); equal(settings.perMessageDeflate, false);
  for (const request of [{ method: 'POST', url: '/v1/rendezvous' }, { method: 'GET', url: '/v1/rendezvous?x=1' }]) { const result = upgrade(test, request); equal(result.socket.destroyed, true); }
  equal(upgrade(test, { method: 'GET', url: '/v1/rendezvous' }, new FakeWs(), Buffer.from('x')).socket.destroyed, true);
  for (const bad of [
    { tlsSni: 'other.example' }, { clientVerify: 'NONE' }, { clientVerify: 'FAILED:bad' }, { deviceId: 'X' }, { fingerprint: 'nothex' }, { ip: 'not-ip' }
  ]) { const badTest = fixture({ verifyProxyRequest: () => ({ ok: true, tlsSni: 'fra-relay.devices.example.net', clientVerify: 'SUCCESS', deviceId: 'device-a', fingerprint: 'a'.repeat(64), ip: '10.0.0.2', ...bad }) }); badTest.adapter.start(); equal(upgrade(badTest).socket.destroyed, true); }
  { const ipv6 = fixture({ verifyProxyRequest: () => ({ ok: true, tlsSni: 'fra-relay.devices.example.net', clientVerify: 'SUCCESS', deviceId: 'device-a', fingerprint: 'a'.repeat(64), ip: '2001:db8::2' }) }); ipv6.adapter.start(); equal(upgrade(ipv6).socket.destroyed, false); }
  { const asyncTest = fixture({ verifyProxyRequest: () => Promise.resolve({}) }); asyncTest.adapter.start(); equal(upgrade(asyncTest).socket.destroyed, true); }
  throws(() => fixture({ eventSink: async () => {} }), error => error && error.code === 'ONLINE_FRA_WS_EVENT_SINK');
  { const thenable = { then(resolve, reject) { reject(new Error('later')); } }; const sink = fixture({ eventSink: () => thenable }); sink.adapter.start(); const result = upgrade(sink); equal(result.ws.closed.length, 1); }
  const first = upgrade(test); equal(first.socket.destroyed, false); equal(test.adapter.snapshot().sockets, 1); equal(test.events.at(-1).type, 'online_fra.ws.connected');
  first.ws.emit('message', Buffer.from('{"lease":{"id":"PRIVATE-MARKER"}}'), false);
  equal(test.relay.connects.length, 1); equal(test.relay.metadata.length, 2); equal(test.events.at(-1).type, 'online_fra.ws.admitted'); ok(!JSON.stringify(test.events).includes('PRIVATE-MARKER'));
  equal(test.relay.connects[0].identity.authType, 'mtls');
  first.ws.emit('message', Buffer.concat([Buffer.from([0x02]), Buffer.from('abc')]), true); equal(test.routes.length, 1); equal(test.routes[0].peerConnectionId, 'peer-1'); ok(Buffer.isBuffer(test.routes[0].frame)); equal(test.routes[0].frame[0], 0x01, 'the edge stamps the SOURCE leg in place of the target byte'); equal(test.routes[0].frame.subarray(1).toString(), 'abc', 'and leaves the payload alone');
  test.outbound.push(Buffer.from('out-1'), Buffer.from('out-2')); test.adapter.drain(); equal(first.ws.sent.length, 2); ok(first.ws.sent.every(item => item.options.binary === true));
  first.ws.bufferedAmount = 2000; test.outbound.push(Buffer.from('blocked')); test.adapter.drain(); equal(first.ws.sent.length, 2);
  first.ws.bufferedAmount = 0; test.timers.advance(10); equal(first.ws.pings, 1); first.ws.emit('pong'); test.timers.advance(10); equal(first.ws.pings, 2);
  const sameIp = upgrade(test); equal(sameIp.socket.destroyed, true, 'per-IP active cap rejects while first is live');
  first.ws.emit('close'); equal(test.adapter.snapshot().sockets, 0); equal(test.relay.closes.length, 1); first.ws.emit('error', new Error('late')); equal(test.adapter.snapshot().sockets, 0, 'late events are ignored');
  const rateLimited = upgrade(test); rateLimited.ws.emit('close'); const rateAgain = upgrade(test); equal(rateAgain.socket.destroyed, true, 'admission rate persists after close'); test.timers.advance(101); const recovered = upgrade(test); equal(recovered.socket.destroyed, false, 'admission window recovers'); recovered.ws.emit('close');
  { const admission = fixture(); admission.adapter.start(); const { ws } = upgrade(admission); ws.emit('message', Buffer.from('{"bad":1}'), false); equal(ws.closed.length, 1); equal(admission.adapter.snapshot().sockets, 0); }
  { const timeout = fixture(); timeout.adapter.start(); const { ws } = upgrade(timeout); timeout.timers.advance(21); equal(ws.closed.length, 1); equal(timeout.adapter.snapshot().sockets, 0); }
  { const idle = fixture(); idle.adapter.start(); const { ws } = upgrade(idle); ws.emit('message', Buffer.from('{"lease":1}'), false); idle.timers.advance(31); equal(ws.closed.at(-1), 1001); }
  { const frame = fixture(); frame.adapter.start(); const { ws } = upgrade(frame); ws.emit('message', Buffer.from('{"lease":1}'), false); ws.emit('message', Buffer.concat([Buffer.from([0x02]), Buffer.alloc(1024)]), true); equal(ws.closed.length, 1); }
  {
    let paired = false; const routes = [];
    const relay = {
      connect: () => ({ connectionId: 'connection-1' }),
      connectionMetadata: () => ({ peerConnectionId: paired ? 'peer-1' : null, endpointRole: 'machine-a', legs: { 'machine-a': 'connection-1', 'machine-b': paired ? 'peer-1' : null, 'web-client': null } }),
      route: input => routes.push(input), take: () => null, close() {}
    };
    const awaiting = fixture({ relay }); awaiting.adapter.start(); const { ws } = upgrade(awaiting);
    ws.emit('message', Buffer.from('{"lease":1}'), false); equal(ws.closed.length, 0, 'first endpoint remains admitted while its peer connects');
    paired = true; ws.emit('message', Buffer.concat([Buffer.from([0x02]), Buffer.from('opaque')]), true); equal(routes.length, 1);
  }
  { const badRelay = fixture({ relay: { connect: () => Promise.resolve({}), route() {}, take() { return null; }, close() {}, connectionMetadata() { return { peerConnectionId: 'peer-1' }; } } }); badRelay.adapter.start(); const { ws } = upgrade(badRelay); ws.emit('message', Buffer.from('{"lease":1}'), false); equal(ws.closed.length, 1); }
  { const sink = fixture({ eventSink: () => { throw new Error('sink'); } }); sink.adapter.start(); const result = upgrade(sink); equal(result.ws.closed.length, 1); equal(sink.adapter.snapshot().sockets, 0); }
  { const stopped = fixture(); stopped.adapter.start(); const server = FakeWss.instances.at(-1); const { ws } = upgrade(stopped); stopped.adapter.stop(); equal(ws.closed.at(-1), 1001); equal(server.closed, true); equal(stopped.adapter.snapshot().rateEntries, 0); equal(stopped.adapter.stop(), true); equal(stopped.httpServer.handlers.has('upgrade'), false); }
  { const revoked = fixture(); revoked.adapter.start(); const { ws } = upgrade(revoked); equal(revoked.adapter.kill(), true); equal(ws.closed.at(-1), 1008); }
  {
    const authority = crypto.generateKeyPairSync('ed25519');
    const pair = { pairId: 'pair-ab', machineAId: 'device-a', machineBId: 'device-b', capabilityDigest: '1'.repeat(64) };
    const state = {
      admitLease: () => ({ ok: true, outcome: 'accepted' }),
      pairState: () => ({ ok: true, revoked: false }),
      revokePair: () => ({ ok: true, revoked: true })
    };
    const realRelay = createOnlineFraRendezvousRelay({
      enabled: true, authorityPublicKey: authority.publicKey, generation: 1, pairs: [pair],
      clock: () => 1_000_000, randomBytes: size => Buffer.alloc(size, 7), eventSink: () => {}, leaseState: state
    });
    const endpoint = {
      schemaVersion: LEASE_SCHEMA_VERSION, leaseId: 'lease_device_a_0001', pairId: pair.pairId,
      deviceId: 'device-a', peerDeviceId: 'device-b', endpointRole: 'machine-a', mtlsFingerprint: 'a'.repeat(64),
      generation: 1, issuedAtMs: 999_990, expiresAtMs: 1_060_000,
      nonce: crypto.randomBytes(24).toString('base64url'),
      ephemeralX25519PublicKey: crypto.generateKeyPairSync('x25519').publicKey.export({ format: 'der', type: 'spki' }).toString('base64url'),
      capabilityDigest: pair.capabilityDigest, signature: Buffer.alloc(64).toString('base64url')
    };
    endpoint.signature = crypto.sign(null, leaseSigningBytes(endpoint), authority.privateKey).toString('base64url');
    const direct = realRelay.connect({
      identity: { verified: true, authType: 'mtls', deviceId: 'device-a', mtlsFingerprint: 'a'.repeat(64) },
      lease: endpoint
    });
    realRelay.close(direct.connectionId);
    const integrated = fixture({ relay: realRelay, maxAdmissionBytes: 8192 }); integrated.adapter.start(); const { ws } = upgrade(integrated);
    ws.emit('message', Buffer.from(JSON.stringify({ lease: endpoint })), false);
    equal(ws.closed.length, 0, 'the adapter identity is accepted by the real relay while awaiting the peer');
    equal(realRelay.snapshot().activeConnections, 1); ws.emit('close'); equal(realRelay.snapshot().activeConnections, 0);
  }

  // A SOLO PAIR THROUGH THE REAL EDGE AND THE REAL RELAY. One machine (the
  // certificate door) and its browser (the key door) on a pair whose B side
  // is null. The browser's first frame lands on the machine's socket before
  // the machine has sent a single byte -- the relay waits for no hello and no
  // peer -- and a frame addressed to the machine-b leg, which a solo pair will
  // never have, is dropped and counted exactly as an absent peer is, with the
  // browser's socket kept. No log line names a null or undefined side.
  {
    const { createOnlineFraWebAdmission } = require('../src/lib/online-fra-web-admission');
    const authority = crypto.generateKeyPairSync('ed25519');
    const pair = { pairId: 'pair-solo', machineAId: 'device-solo', machineBId: null, capabilityDigest: '2'.repeat(64) };
    const state = {
      admitLease: () => ({ ok: true, outcome: 'accepted' }),
      pairState: () => ({ ok: true, revoked: false }),
      revokePair: () => ({ ok: true, revoked: true })
    };
    const soloRelay = createOnlineFraRendezvousRelay({
      enabled: true, authorityPublicKey: authority.publicKey, generation: 1, pairs: [pair],
      clock: () => 1_000_000, eventSink: () => {}, leaseState: state
    });
    const signedLease = fields => {
      const value = {
        schemaVersion: LEASE_SCHEMA_VERSION, leaseId: `lease_${crypto.randomBytes(4).toString('hex')}`, pairId: pair.pairId,
        generation: 1, issuedAtMs: 999_990, expiresAtMs: 1_060_000,
        nonce: crypto.randomBytes(24).toString('base64url'),
        ephemeralX25519PublicKey: crypto.generateKeyPairSync('x25519').publicKey.export({ format: 'der', type: 'spki' }).toString('base64url'),
        capabilityDigest: pair.capabilityDigest, signature: Buffer.alloc(64).toString('base64url'), ...fields
      };
      value.signature = crypto.sign(null, leaseSigningBytes(value), authority.privateKey).toString('base64url');
      return value;
    };
    const browser = crypto.generateKeyPairSync('ed25519');
    const browserSpki = browser.publicKey.export({ type: 'spki', format: 'der' });
    const machineLease = signedLease({ deviceId: 'device-solo', peerDeviceId: null, endpointRole: 'machine-a', mtlsFingerprint: 'a'.repeat(64) });
    const webLease = signedLease({ deviceId: `web-${'7'.repeat(24)}`, peerDeviceId: 'device-solo', endpointRole: 'web-client', mtlsFingerprint: crypto.createHash('sha256').update(browserSpki).digest('hex') });
    const logs = [];
    const solo = fixture({
      relay: soloRelay, keyAdmission: createOnlineFraWebAdmission({ relay: soloRelay, clock: () => 1 }),
      maxAdmissionBytes: 8192, maxSockets: 4, maxSocketsPerIp: 2, maxAdmissionsPerIp: 4,
      // The machine presents a certificate; the browser cannot and takes the key door.
      verifyProxyRequest: req => (req.certificate
        ? { ok: true, tlsSni: 'fra-relay.devices.example.net', clientVerify: 'SUCCESS', deviceId: 'device-solo', fingerprint: 'a'.repeat(64), ip: '10.0.0.40' }
        : { ok: false }),
      clientIpFor: () => '10.0.0.41',
      log: line => logs.push(line)
    });
    solo.adapter.start();
    const machine = upgrade(solo, { method: 'GET', url: '/v1/rendezvous', certificate: true });
    machine.ws.emit('message', Buffer.from(JSON.stringify({ lease: machineLease })), false);
    equal(machine.ws.closed.length, 0, 'the solo machine is admitted with a null peer');
    equal(soloRelay.snapshot().activeConnections, 1);
    const web = upgrade(solo);
    const challenge = JSON.parse(web.ws.sent[0].data.toString('utf8')).challenge;
    web.ws.emit('message', Buffer.from(JSON.stringify({
      lease: webLease, publicKeySpki: browserSpki.toString('base64url'), nonce: challenge,
      signature: crypto.sign(null, Buffer.from(challenge, 'base64url'), browser.privateKey).toString('base64url')
    })), false);
    equal(web.ws.readyState, 1, 'the browser is admitted beside the one machine');
    equal(soloRelay.snapshot().activeConnections, 2);
    equal(machine.ws.sent.length, 0, 'precondition: the machine has not sent a byte');
    web.ws.emit('message', Buffer.concat([Buffer.from([0x01]), Buffer.from('hello-solo')]), true);
    equal(machine.ws.sent.length, 1, 'delivered to the one machine without waiting for a hello from it');
    equal(machine.ws.sent[0].data[0], 0x03, 'stamped with the web source leg');
    equal(machine.ws.sent[0].data.subarray(1).toString(), 'hello-solo');
    machine.ws.emit('message', Buffer.concat([Buffer.from([0x03]), Buffer.from('answer')]), true);
    equal(web.ws.sent.length, 2, 'the answer reached the browser (its first send was the challenge)');
    equal(web.ws.sent[1].data[0], 0x01);
    equal(web.ws.sent[1].data.subarray(1).toString(), 'answer');
    web.ws.emit('message', Buffer.concat([Buffer.from([0x02]), Buffer.from('nobody')]), true);
    equal(web.ws.readyState, 1, 'addressing the B leg a solo pair never has does not cost the browser its socket');
    equal(solo.events.filter(e => e.type === 'online_fra.ws.frame_dropped' && e.reason === 'leg_absent').length, 1, 'it is counted');
    ok(logs.some(line => line.startsWith('frame dropped: no machine-b leg')), 'and said out loud once');
    machine.ws.emit('close'); web.ws.emit('close');
    equal(soloRelay.snapshot().activeConnections, 0);
    ok(!logs.some(line => /\bnull\b|undefined/.test(line)), 'no log line of a solo pair prints a null or undefined side');
  }

  // KEY-POSSESSION MODE. No certificate: the request carries no attestation, so
  // with `keyAdmission` configured the socket is admitted provisionally, the
  // edge's FIRST frame is the challenge, and the endpoint's first frame is the
  // proof -- which must quote THIS socket's nonce, not just any valid one.
  {
    const crypto = require('node:crypto');
    const { createOnlineFraWebAdmission } = require('../src/lib/online-fra-web-admission');
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const spki = publicKey.export({ type: 'spki', format: 'der' });
    const fingerprint = crypto.createHash('sha256').update(spki).digest('hex');
    const lease = { endpointRole: 'machine-a', deviceId: 'device-k', mtlsFingerprint: fingerprint };
    const sign = nonce => crypto.sign(null, Buffer.from(nonce, 'base64url'), privateKey).toString('base64url');
    const noCert = () => ({ ok: false });
    // The relay double is built first so the admission and the adapter share it.
    const relayDouble = () => { const connects = []; return { connects, metadata: [], takes: [], closes: [],
      connect(input) { connects.push(input); return { connectionId: 'connection-1' }; },
      connectionMetadata(id) { return { peerConnectionId: 'peer-1', endpointRole: 'machine-a', legs: { 'machine-a': id, 'machine-b': 'peer-1', 'web-client': null } }; }, route() {}, take() { return null; }, close() {} }; };

    // 1. A proof quoting some OTHER socket's nonce closes this socket and never reaches the relay.
    {
      const relay = relayDouble();
      const keyAdmission = createOnlineFraWebAdmission({ relay, clock: () => 1 });
      const k = fixture({ relay, verifyProxyRequest: noCert, keyAdmission, maxAdmissionBytes: 2048, clientIpFor: () => '10.0.0.9' });
      k.adapter.start();
      const { socket, ws } = upgrade(k);
      equal(socket.destroyed, false, 'no certificate + key admission configured -> accepted provisionally');
      equal(ws.sent.length, 1, 'the edge speaks first');
      equal(typeof JSON.parse(ws.sent[0].data.toString('utf8')).challenge, 'string');
      const other = keyAdmission.challenge().nonce;
      ws.emit('message', Buffer.from(JSON.stringify({ lease, publicKeySpki: spki.toString('base64url'), nonce: other, signature: sign(other) })), false);
      equal(ws.readyState, 3, 'another socket\'s nonce closes this one');
      equal(relay.connects.length, 0, 'and never reaches the relay');
    }

    // 2. Right nonce, right key, right signature: admitted, and the relay sees key-lease with the lease's fingerprint.
    {
      const relay = relayDouble();
      const keyAdmission = createOnlineFraWebAdmission({ relay, clock: () => 1 });
      const g = fixture({ relay, verifyProxyRequest: noCert, keyAdmission, maxAdmissionBytes: 2048, clientIpFor: () => '10.0.0.10' });
      g.adapter.start();
      const { ws } = upgrade(g);
      const nonce = JSON.parse(ws.sent[0].data.toString('utf8')).challenge;
      ws.emit('message', Buffer.from(JSON.stringify({ lease, publicKeySpki: spki.toString('base64url'), nonce, signature: sign(nonce) })), false);
      equal(ws.readyState, 1, 'admitted');
      equal(relay.connects.length, 1);
      equal(relay.connects[0].identity.authType, 'key-lease');
      equal(relay.connects[0].identity.mtlsFingerprint, fingerprint);
      equal(relay.connects[0].identity.deviceId, 'device-k');
    }

    // 3. A wrong signature with the right nonce: closed, not admitted.
    {
      const relay = relayDouble();
      const keyAdmission = createOnlineFraWebAdmission({ relay, clock: () => 1 });
      const b = fixture({ relay, verifyProxyRequest: noCert, keyAdmission, maxAdmissionBytes: 2048, clientIpFor: () => '10.0.0.11' });
      b.adapter.start();
      const { ws } = upgrade(b);
      const nonce = JSON.parse(ws.sent[0].data.toString('utf8')).challenge;
      ws.emit('message', Buffer.from(JSON.stringify({ lease, publicKeySpki: spki.toString('base64url'), nonce, signature: sign('AAAA') })), false);
      equal(ws.readyState, 3, 'bad signature closes the socket');
      equal(relay.connects.length, 0);
    }

    // 4. Without keyAdmission, no certificate still means rejection at upgrade -- unchanged behaviour.
    {
      const none = fixture({ verifyProxyRequest: noCert });
      none.adapter.start();
      equal(upgrade(none).socket.destroyed, true, 'mTLS-only deployments reject exactly as before');
    }

    // 4b. A frame to a leg that is not connected yet is DROPPED and counted -- the
    //     sender keeps its socket, because "peer not here yet" is the normal state
    //     while two machines race to connect, not a protocol violation.
    {
      const relay = relayDouble();
      relay.connectionMetadata = (id) => ({ peerConnectionId: null, endpointRole: 'machine-a', legs: { 'machine-a': id, 'machine-b': null, 'web-client': null } });
      const keyAdmission = createOnlineFraWebAdmission({ relay, clock: () => 1 });
      const early = fixture({ relay, verifyProxyRequest: noCert, keyAdmission, maxAdmissionBytes: 2048, clientIpFor: () => '10.0.0.12' });
      early.adapter.start();
      const { ws } = upgrade(early);
      const nonce = JSON.parse(ws.sent[0].data.toString('utf8')).challenge;
      ws.emit('message', Buffer.from(JSON.stringify({ lease, publicKeySpki: spki.toString('base64url'), nonce, signature: sign(nonce) })), false);
      equal(ws.readyState, 1, 'admitted alone');
      ws.emit('message', Buffer.concat([Buffer.from([0x02]), Buffer.from('hello-too-early')]), true);
      equal(ws.readyState, 1, 'a frame to the absent peer does NOT close the socket');
      equal(early.routes.length, 0, 'and is not routed');
      equal(early.events.filter(e => e.type === 'online_fra.ws.frame_dropped' && e.reason === 'leg_absent').length, 1, 'it is counted');
    }

    // 5. An unusable client IP is refused before any challenge is issued.
    {
      const relay = relayDouble();
      const keyAdmission = createOnlineFraWebAdmission({ relay, clock: () => 1 });
      const bad = fixture({ relay, verifyProxyRequest: noCert, keyAdmission, maxAdmissionBytes: 2048, clientIpFor: () => 'not-an-ip' });
      bad.adapter.start();
      equal(upgrade(bad).socket.destroyed, true, 'no usable client address -> rejected at upgrade');
    }
  }

  ok(DEFAULTS.maxFrameBytes > 0);
  console.log(`Online FRA websocket adapter tests passed (${assertions} assertions).`);
})();
