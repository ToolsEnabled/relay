'use strict';
// THE EDGE OVER A REAL SOCKET. Everything else in this suite drives the
// websocket adapter through a fake socket, which is the right way to test its
// state machine and the wrong way to find out whether it works with the actual
// `ws` server and an actual client. This boots a real loopback HTTP server,
// mounts the adapter on it with the real WebSocketServer, and connects with
// Node's own global WebSocket -- the client a machine will use -- to run the
// key-possession dance end to end: challenge, signed proof, admission, and one
// binary frame routed to a peer. The relay underneath is a small in-memory
// double; what is under test is the wire.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const http = require('node:http');
const net = require('node:net');
const { WebSocketServer } = require('ws');
const { createOnlineFraWebAdmission } = require('../src/lib/online-fra-web-admission');
const { createOnlineFraWebSocketAdapter } = require('../src/lib/online-fra-websocket-adapter');

let assertions = 0;
const equal = (a, b, m) => { assertions += 1; assert.equal(a, b, m); };
const ok = (v, m) => { assertions += 1; assert.ok(v, m); };

// An in-memory relay double: two connections form one pair; route() queues a
// frame for the peer; take() drains it. Enough to prove the edge carries bytes.
function relayDouble() {
  const connections = new Map();
  const queues = new Map();
  let seq = 0;
  return {
    connect({ identity, lease }) {
      const id = `conn_${++seq}`;
      connections.set(id, { identity, lease });
      queues.set(id, []);
      return { connectionId: id, deviceId: lease.deviceId };
    },
    connectionMetadata(id) {
      const me = connections.get(id);
      const legs = { 'machine-a': null, 'machine-b': null, 'web-client': null };
      for (const [other, c] of connections) if (c.lease.pairId === me.lease.pairId) legs[c.lease.endpointRole] = other;
      const peerRole = me.lease.endpointRole === 'machine-a' ? 'machine-b' : 'machine-a';
      return { peerConnectionId: me.lease.endpointRole === 'web-client' ? null : legs[peerRole], endpointRole: me.lease.endpointRole, legs };
    },
    route({ peerConnectionId, frame }) { queues.get(peerConnectionId).push(Buffer.from(frame)); },
    take(id) { const q = queues.get(id); return q && q.length ? q.shift() : null; },
    close(id) { connections.delete(id); queues.delete(id); },
    snapshot() { return { connections: connections.size }; },
  };
}

function endpoint(role, pairId) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  return {
    lease: { endpointRole: role, deviceId: `dev-${role}`, pairId, mtlsFingerprint: crypto.createHash('sha256').update(spki).digest('hex') },
    publicKeySpki: spki.toString('base64url'),
    sign: (nonce) => crypto.sign(null, Buffer.from(nonce, 'base64url'), privateKey).toString('base64url'),
  };
}

// Connect, answer the challenge, resolve once admitted (the first binary frame
// or a 'ready' marker would both do; here the admission is implied by the
// socket staying open past the proof, so we resolve on the next tick after
// sending it and let the frame exchange prove the rest).
function connectAndAdmit(url, ep) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url);
    ws.binaryType = 'arraybuffer';
    const frames = [];
    ws.addEventListener('error', (e) => reject(new Error('socket error: ' + (e.message || e.type))));
    ws.addEventListener('close', (e) => { ws._closed = e.code; });
    ws.addEventListener('message', (event) => {
      if (typeof event.data === 'string') {
        const challenge = JSON.parse(event.data);
        ws.send(JSON.stringify({ lease: ep.lease, publicKeySpki: ep.publicKeySpki, nonce: challenge.challenge, signature: ep.sign(challenge.challenge) }));
        setTimeout(() => resolve({ ws, frames }), 50);
        return;
      }
      frames.push(Buffer.from(event.data));
    });
  });
}

(async () => {
  const relay = relayDouble();
  const keyAdmission = createOnlineFraWebAdmission({ relay, clock: () => Date.now() });
  const events = [];
  const httpServer = http.createServer((req, res) => { res.statusCode = 426; res.end(); });
  const adapter = createOnlineFraWebSocketAdapter({
    enabled: true, WebSocketServer, httpServer, relay, hostname: 'relay.example.net',
    verifyProxyRequest: () => ({ ok: false }), keyAdmission,
    eventSink: (e) => events.push(e), clock: () => Date.now(),
    setTimer: (fn, ms) => setTimeout(fn, ms), clearTimer: (id) => clearTimeout(id),
    maxAdmissionBytes: 4096, pingIntervalMs: 1000, idleTimeoutMs: 5000,
  });
  adapter.start();
  await new Promise((r) => httpServer.listen(0, '127.0.0.1', r));
  const url = `ws://127.0.0.1:${httpServer.address().port}/v1/rendezvous`;

  const a = endpoint('machine-a', 'pair-1');
  const b = endpoint('machine-b', 'pair-1');
  const A = await connectAndAdmit(url, a);
  const B = await connectAndAdmit(url, b);
  equal(A.ws.readyState, 1, 'A admitted and open');
  equal(B.ws.readyState, 1, 'B admitted and open');
  equal(relay.snapshot().connections, 2, 'the relay saw both connections');
  equal(events.filter((e) => e.type === 'online_fra.ws.admitted').length, 2, 'two admissions recorded');

  // A sends one sealed-looking binary frame; B receives the same bytes.
  const payload = crypto.randomBytes(1024);
  // A addresses machine-b (0x02); B receives it stamped from machine-a (0x01).
  A.ws.send(Buffer.concat([Buffer.from([0x02]), payload]));
  // the adapter drains on its ping tick or on the next inbound frame; nudge it
  await new Promise((r) => setTimeout(r, 200));
  adapter.drain();
  await new Promise((r) => setTimeout(r, 100));
  equal(B.frames.length, 1, 'B received exactly one frame');
  equal(B.frames[0][0], 0x01, 'stamped with the SOURCE leg: machine-a');
  ok(B.frames[0].subarray(1).equals(payload), 'and the payload is byte-identical');

  // A proof signed with the WRONG key is refused at the socket, not the relay.
  const impostor = endpoint('machine-a', 'pair-2');
  const wrongKey = { ...impostor, sign: endpoint('machine-a', 'pair-2').sign }; // different key than the fingerprint
  const refused = await new Promise((resolve) => {
    const ws = new WebSocket(url);
    ws.addEventListener('message', (event) => {
      const challenge = JSON.parse(event.data);
      ws.send(JSON.stringify({ lease: wrongKey.lease, publicKeySpki: wrongKey.publicKeySpki, nonce: challenge.challenge, signature: wrongKey.sign(challenge.challenge) }));
    });
    ws.addEventListener('close', (e) => resolve(e.code));
    ws.addEventListener('error', () => {});
  });
  equal(refused, 1008, 'a signature from a key other than the fingerprinted one closes the socket with policy violation');
  equal(relay.snapshot().connections, 2, 'and the relay never saw it');

  /* THE ADMISSION SLOT MUST COME BACK WHEN THE HANDSHAKE NEVER COMPLETES.
   *
   * This is the one finding from the edge pentest that a reader would not get
   * from the state machine, because it lives in the contract of somebody else's
   * library. upgrade() takes a per-address admission slot and returns it from its
   * synchronous catch or from closeContext() -- and closeContext only runs once
   * the handleUpgrade callback has fired. ws@8 does neither for a malformed
   * handshake: given a missing or invalid Sec-WebSocket-Key or an unsupported
   * Sec-WebSocket-Version it destroys the socket and returns WITHOUT calling back
   * and WITHOUT throwing. So one routed-but-malformed GET leaked one slot, for
   * good: no race, no timing, just repetition.
   *
   * MEASURED on the pre-fix tree with maxSockets 8 / maxSocketsPerIp 4: twelve
   * malformed upgrades and a legitimate client was then refused outright. From a
   * single IPv6 /64 the same trick filled the whole rate table, after which every
   * address the relay had not already seen was refused -- an unauthenticated,
   * silent, permanent denial of service on a remote-access product, cleared only
   * by restarting the process.
   *
   * Asserted with a REAL malformed handshake rather than a stubbed one, because a
   * fake socket would be asserting my model of ws, which is the thing that was
   * wrong in the first place. */
  {
    /* ITS OWN EDGE, WITH A SMALL BUDGET, AND THAT DETAIL IS THE TEST.
       The adapter above runs on the defaults -- maxSocketsPerIp 64 -- so twelve
       leaked slots prove nothing: the first version of this test passed against
       the PRE-FIX adapter and was therefore worthless. The leak is only visible
       once the per-address budget is small enough to exhaust, which is exactly
       how the pentest found it (maxSockets 8, maxSocketsPerIp 4). A regression
       test that cannot fail on the unfixed code is not a regression test. */
    const leakRelay = relayDouble();
    const leakServer = http.createServer((q, r) => { r.statusCode = 426; r.end(); });
    const leakAdapter = createOnlineFraWebSocketAdapter({
      enabled: true, WebSocketServer, httpServer: leakServer, relay: leakRelay,
      hostname: 'relay.example.net', verifyProxyRequest: () => ({ ok: false }),
      keyAdmission: createOnlineFraWebAdmission({ relay: leakRelay, clock: () => Date.now() }),
      eventSink: () => {}, clock: () => Date.now(),
      setTimer: (fn, ms) => setTimeout(fn, ms), clearTimer: (id) => clearTimeout(id),
      maxAdmissionBytes: 4096, pingIntervalMs: 1000, idleTimeoutMs: 5000,
      maxSockets: 8, maxSocketsPerIp: 4,
    });
    leakAdapter.start();
    await new Promise((r) => leakServer.listen(0, '127.0.0.1', r));
    const leakPort = leakServer.address().port;

    await Promise.all(Array.from({ length: 12 }, () => new Promise((resolve) => {
      const socket = net.connect(leakPort, '127.0.0.1', () => {
        socket.write('GET /v1/rendezvous HTTP/1.1\r\nHost: relay.example.net\r\n'
          + 'Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 99\r\n\r\n');
      });
      socket.on('data', () => {});
      socket.on('error', () => resolve());
      socket.on('close', () => resolve());
      setTimeout(() => { socket.destroy(); resolve(); }, 250);
    })));
    await new Promise((r) => setTimeout(r, 150));

    const after = await connectAndAdmit(`ws://127.0.0.1:${leakPort}/v1/rendezvous`,
      endpoint('machine-a', 'pair-slot'));
    equal(after.ws.readyState, 1,
      'a legitimate client is still admitted after twelve malformed handshakes');
    after.ws.close();
    leakAdapter.stop();
    await new Promise((r) => leakServer.close(r));
  }

  A.ws.close(); B.ws.close();
  adapter.stop();
  await new Promise((r) => httpServer.close(r));
  console.log(`online-fra-edge-socket: ${assertions} assertions passed (real ws server, real WebSocket client)`);
})().catch((error) => { console.error(error); process.exit(1); });
