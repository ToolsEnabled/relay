'use strict';

// THE ONE PROOF THAT NEEDS BOTH HALVES OF THE SPLIT.
//
// Before the relay was moved out of the engine, tests/providers.billing/
// hosted-relay-entitlement.js in the engine repo proved all of this in one
// file, because all of it lived in one repo. Two of its sections need the real
// relay, which is now here; the module they wrap (providers/hosted-relay-
// entitlement.js) is deliberately still in the OPEN engine repo, because its
// public value is a negative claim -- "a self-hosted operator never loads a
// licence check" -- and a negative claim about code nobody can read is not a
// claim, it is a promise.
//
// So this proof cannot live in either repo alone, and it is placed HERE rather
// than in the engine on purpose. The dependency points one way only:
//
//     private relay repo  --reads-->  open engine repo
//
// and never back. The open repo must never require anything from this one, or
// the published half stops being able to build, test, or even load by itself,
// which is precisely the failure the split exists to avoid. We always have both
// checkouts; a customer or contributor only ever needs the open one.
//
// SECTIONS CARRIED HERE, keeping their original numbering so the two files can
// still be read against each other:
//   A3 -- a self-hosted operator's own path: the real relay admits a real pair
//         with zero licence involvement. Needs the relay only.
//   C  -- the entitlement gate is a genuine drop-in for the real websocket
//         adapter, in both deployment shapes, using the SAME adapter code.
//         Needs the relay AND the engine's entitlement gate.
//
// Run: npm run test:crossrepo
//      ENGINE_REPO=/path/to/toolsenabled-current npm run test:crossrepo

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const {
  LEASE_SCHEMA_VERSION, createOnlineFraRendezvousRelay, leaseSigningBytes
} = require('../src/lib/online-fra-rendezvous-relay');
const { createOnlineFraWebSocketAdapter } = require('../src/lib/online-fra-websocket-adapter');

// LOCATING THE ENGINE, AND REFUSING RATHER THAN SKIPPING.
//
// A missing engine checkout makes this file unable to answer its question. It
// exits 2 (cannot run) and never 0 (ran, all good). A cross-repo test that
// quietly passes when the other repo is absent is worse than no test: it
// reports a proof it did not perform, on the exact boundary the split created.
// THE DEFAULT SEARCHES RATHER THAN COUNTS DIRECTORIES, BECAUSE COUNTING BROKE.
//
// This previously resolved `__dirname/../../toolsenabled-current`, which was
// correct only while this repo sat directly beside the engine on the Desktop.
// The 2026-08-14 reorg moved it two levels deeper (under
// toolsenabled/toolsenabled-paid/), so the default pointed at
// `toolsenabled-paid/toolsenabled-current` -- a path that has never existed.
// The file did exactly what it promises below and exited 2 rather than
// pretending to pass, so nothing was silently proven; but the effect was that
// the one test proving the hosted gate is a drop-in for the real relay went
// unrunnable, and stayed that way unnoticed.
//
// A fixed depth would just wait to break on the next move. Walking up from here
// and looking for a directory that actually CONTAINS the file we need is
// self-correcting, and it fails the same honest way when the engine is truly
// absent. ENGINE_REPO still wins outright when set.
const ENTITLEMENT_RELATIVE = path.join('src', 'lib', 'providers', 'hosted-relay-entitlement.js');

function locateEngineRepo() {
  if (process.env.ENGINE_REPO) return path.resolve(process.env.ENGINE_REPO);
  let directory = __dirname;
  for (;;) {
    const candidate = path.join(directory, 'toolsenabled-current');
    if (fs.existsSync(path.join(candidate, ENTITLEMENT_RELATIVE))) return candidate;
    const parent = path.dirname(directory);
    if (parent === directory) break;
    directory = parent;
  }
  // Nothing found: return the historical shape so the refusal message below
  // still names a concrete path rather than "undefined".
  return path.resolve(path.join(__dirname, '..', '..', 'toolsenabled-current'));
}

const ENGINE_REPO = locateEngineRepo();
const ENGINE_ENTITLEMENT = path.join(ENGINE_REPO, ENTITLEMENT_RELATIVE);

if (!fs.existsSync(ENGINE_ENTITLEMENT)) {
  console.error(
    `Cannot run: the open engine repository was not found at ${ENGINE_REPO}.\n` +
    `Expected ${ENGINE_ENTITLEMENT}.\n` +
    'Set ENGINE_REPO to the engine checkout. This test is REFUSING, not skipping: it proves the\n' +
    'hosted gate is a drop-in for the real relay, and it cannot prove that with only one half present.'
  );
  process.exit(2);
}

const {
  createHostedRelayAdmission,
  HOSTED_RELAY_DEPLOYMENT_MARKER
} = require(ENGINE_ENTITLEMENT);
const license = require(path.join(ENGINE_REPO, 'src', 'lib', 'providers', 'license.js'));
// Minting moved out of the open verification module (license-issuance.js is
// the owner-side half and is withheld from the engine's public cut). This test
// runs beside a FULL engine checkout, so prefer the issuance module and fall
// back for older trees; refuse -- like every other absence here -- if neither
// side of the split can mint.
const issueKey = (() => {
  try { return require(path.join(ENGINE_REPO, 'src', 'lib', 'providers', 'license-issuance.js')).issueKey; }
  catch { /* older engine tree: minting still lives in license.js */ }
  return license.issueKey;
})();
if (typeof issueKey !== 'function') {
  console.error('REFUSED: the engine checkout beside this repo cannot mint a license (license-issuance.js absent and license.js does not issue).');
  process.exit(2);
}
const { sha256 } = require(path.join(ENGINE_REPO, 'src', 'lib', 'audit-store.js'));
const { LicenseStore } = require(path.join(ENGINE_REPO, 'src', 'lib', 'license-store.js'));

let assertions = 0;
function equal(actual, expected, message) { assertions += 1; assert.equal(actual, expected, message); }
function ok(value, message) { assertions += 1; assert.ok(value, message); }

function makeSigner() {
  const pair = crypto.generateKeyPairSync('ed25519');
  const publicKeyPem = pair.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const keyId = `license-ed25519-${sha256(pair.publicKey.export({ type: 'spki', format: 'der' }))}`;
  return { keyId, publicKeyPem, sign: value => crypto.sign(null, value, pair.privateKey) };
}

function withTempLicenseStore(fn) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'toolsenabled-hosted-relay-'));
  const store = new LicenseStore({ file: path.join(root, 'licenses.sqlite3') });
  try { return fn(store); }
  finally { store.close(); fs.rmSync(root, { recursive: true, force: true }); }
}

// ---------------------------------------------------------------------------
// A3. A self-hosted operator's own code path: construct the real relay engine
// directly (as the engine's PACKAGE.md documents self-hosting must) and
// connect a real pair -- with zero reference to license.js anywhere in this
// block.
// ---------------------------------------------------------------------------
{
  const authority = crypto.generateKeyPairSync('ed25519');
  const pair = Object.freeze({ pairId: 'self-hosted-pair', machineAId: 'sh-a', machineBId: 'sh-b', capabilityDigest: '3'.repeat(64) });
  const leaseState = {
    admitLease: () => ({ ok: true, outcome: 'accepted' }),
    pairState: () => ({ ok: true, revoked: false }),
    revokePair: () => ({ ok: true, revoked: true })
  };
  const selfHostedRelay = createOnlineFraRendezvousRelay({
    enabled: true, authorityPublicKey: authority.publicKey, generation: 1, pairs: [pair],
    clock: () => 5_000_000, randomBytes: size => Buffer.alloc(size, 4), eventSink: () => {}, leaseState
  });
  const endpoint = {
    schemaVersion: LEASE_SCHEMA_VERSION, leaseId: 'lease_self_hosted_1', pairId: pair.pairId,
    deviceId: 'sh-a', peerDeviceId: 'sh-b', endpointRole: 'machine-a', mtlsFingerprint: 'a'.repeat(64),
    generation: 1, issuedAtMs: 4_999_990, expiresAtMs: 5_060_000,
    nonce: crypto.randomBytes(24).toString('base64url'),
    ephemeralX25519PublicKey: crypto.generateKeyPairSync('x25519').publicKey.export({ format: 'der', type: 'spki' }).toString('base64url'),
    capabilityDigest: pair.capabilityDigest, signature: Buffer.alloc(64).toString('base64url')
  };
  endpoint.signature = crypto.sign(null, leaseSigningBytes(endpoint), authority.privateKey).toString('base64url');
  const connected = selfHostedRelay.connect({
    identity: { verified: true, authType: 'mtls', deviceId: 'sh-a', mtlsFingerprint: 'a'.repeat(64) },
    lease: endpoint
  });
  ok(connected.connectionId, 'self-hosted relay admits a valid pair with no licence involved at all');
  equal(selfHostedRelay.snapshot().activeConnections, 1);
}

// ---------------------------------------------------------------------------
// SECTION C -- real relay + real websocket adapter, both deployment shapes,
// same adapter code.
// ---------------------------------------------------------------------------

withTempLicenseStore(store => {
  class FakeTimers {
    constructor() { this.now = 1_000_000; this.next = 1; this.items = new Map(); }
    set = (fn, ms) => { const id = this.next++; this.items.set(id, { fn, at: this.now + ms }); return id; };
    clear = id => this.items.delete(id);
  }
  class FakeSocket { constructor() { this.destroyed = false; } destroy() { this.destroyed = true; } }
  class FakeWs {
    constructor() { this.handlers = new Map(); this.readyState = 1; this.bufferedAmount = 0; this.closed = []; }
    on(name, fn) { const list = this.handlers.get(name) || []; list.push(fn); this.handlers.set(name, list); }
    once(name, fn) { this.on(name, fn); }
    emit(name, ...args) { for (const fn of [...(this.handlers.get(name) || [])]) fn(...args); }
    send() {}
    ping() {}
    close(code) { this.closed.push(code); this.readyState = 3; this.emit('close'); }
  }
  class FakeWss {
    constructor(options) { this.options = options; }
    handleUpgrade(req, socket, head, callback) { callback(socket.ws); }
    close() {}
  }

  const authority = crypto.generateKeyPairSync('ed25519');
  const pair = Object.freeze({ pairId: 'hosted-pair', machineAId: 'hosted-a', machineBId: 'hosted-b', capabilityDigest: '9'.repeat(64) });
  const leaseState = {
    admitLease: () => ({ ok: true, outcome: 'accepted' }),
    pairState: () => ({ ok: true, revoked: false }),
    revokePair: () => ({ ok: true, revoked: true })
  };
  function realRelay() {
    return createOnlineFraRendezvousRelay({
      enabled: true, authorityPublicKey: authority.publicKey, generation: 1, pairs: [pair],
      clock: () => 2_000_000, randomBytes: size => Buffer.alloc(size, 6), eventSink: () => {}, leaseState
    });
  }
  function endpointLease() {
    const endpoint = {
      schemaVersion: LEASE_SCHEMA_VERSION, leaseId: `lease_${crypto.randomBytes(4).toString('hex')}`, pairId: pair.pairId,
      deviceId: 'hosted-a', peerDeviceId: 'hosted-b', endpointRole: 'machine-a', mtlsFingerprint: 'a'.repeat(64),
      generation: 1, issuedAtMs: 1_999_990, expiresAtMs: 2_060_000,
      nonce: crypto.randomBytes(24).toString('base64url'),
      ephemeralX25519PublicKey: crypto.generateKeyPairSync('x25519').publicKey.export({ format: 'der', type: 'spki' }).toString('base64url'),
      capabilityDigest: pair.capabilityDigest, signature: Buffer.alloc(64).toString('base64url')
    };
    endpoint.signature = crypto.sign(null, leaseSigningBytes(endpoint), authority.privateKey).toString('base64url');
    return endpoint;
  }

  const signer = makeSigner();
  const licenseNow = Date.parse('2026-08-01T00:00:00.000Z');
  const licenseDeps = { signer, store, now: () => licenseNow, assertActive: () => {}, record: () => {} };
  const validLicense = issueKey({
    product: 'toolsenabled-operator-cloud', licensee: 'hosted-pair-customer', expiresAt: '2027-08-01T00:00:00.000Z', licenseId: 'lic_hostedpair01'
  }, licenseDeps);

  function adapterFixture(relay) {
    const timers = new FakeTimers();
    const httpServer = { handlers: new Map(), on(name, fn) { this.handlers.set(name, fn); }, off(name) { this.handlers.delete(name); } };
    const adapter = createOnlineFraWebSocketAdapter({
      WebSocketServer: FakeWss, enabled: true, httpServer, relay, hostname: 'hosted.relay.example.net',
      eventSink: () => {}, verifyProxyRequest: () => ({
        ok: true, tlsSni: 'hosted.relay.example.net', clientVerify: 'SUCCESS', deviceId: 'hosted-a', fingerprint: 'a'.repeat(64), ip: '10.0.0.9'
      }),
      clock: () => timers.now, setTimer: timers.set, clearTimer: timers.clear,
      maxFrameBytes: 1024, maxAdmissionBytes: 8192, maxSockets: 8, maxSocketsPerIp: 4, maxAdmissionsPerIp: 8,
      // maxSocketsPerIp must stay BELOW maxSockets: a per-address share equal to the
      // whole pool is not a share, and the adapter now refuses that configuration at
      // construction. This read 4 and 4, which the guard rejects.
      admissionWindowMs: 1000, admissionTimeoutMs: 500, pingIntervalMs: 10000, idleTimeoutMs: 20000, maxBufferedBytes: 1024, maxDrainPerTick: 3
    });
    adapter.start();
    const ws = new FakeWs();
    const socket = new FakeSocket();
    socket.ws = ws;
    httpServer.handlers.get('upgrade')({ method: 'GET', url: '/v1/rendezvous' }, socket, Buffer.alloc(0));
    return { adapter, ws, socket };
  }

  // C1. Hosted deployment, valid entitlement: the adapter admits exactly as
  // it would for a self-hosted relay -- the wrapper is a real drop-in.
  {
    const underlying = realRelay();
    const hosted = createHostedRelayAdmission({
      deployment: HOSTED_RELAY_DEPLOYMENT_MARKER, relay: underlying,
      trustedPublicKeyPem: signer.publicKeyPem,
      resolveLicenseKey: pairId => (pairId === pair.pairId ? validLicense.licenseKey : null),
      licenseDependencies: { store, now: () => licenseNow, record: () => {} },
      record: () => {}
    });
    const { ws, socket } = adapterFixture(hosted);
    ws.emit('message', Buffer.from(JSON.stringify({ lease: endpointLease() })), false);
    equal(socket.destroyed, false);
    equal(ws.closed.length, 0, 'a fully entitled hosted connection is admitted');
    equal(underlying.snapshot().activeConnections, 1);
  }

  // C2. Hosted deployment, NO entitlement on file for the pair: the same
  // adapter code refuses admission, and critically, the real relay never
  // reaches an active connection for it.
  {
    const underlying = realRelay();
    const hosted = createHostedRelayAdmission({
      deployment: HOSTED_RELAY_DEPLOYMENT_MARKER, relay: underlying,
      trustedPublicKeyPem: signer.publicKeyPem,
      resolveLicenseKey: () => null,
      licenseDependencies: { store, now: () => licenseNow, record: () => {} },
      record: () => {}
    });
    const { ws } = adapterFixture(hosted);
    ws.emit('message', Buffer.from(JSON.stringify({ lease: endpointLease() })), false);
    equal(ws.closed.length, 1, 'the websocket adapter closes the socket when admission is refused');
    equal(underlying.snapshot().activeConnections, 0, 'the real relay never admits an unentitled pair');
  }

  // C3. Self-hosted deployment, same adapter code, the RAW relay passed
  // straight through -- no entitlement wrapper anywhere in the call graph.
  {
    const underlying = realRelay();
    const { ws, socket } = adapterFixture(underlying);
    ws.emit('message', Buffer.from(JSON.stringify({ lease: endpointLease() })), false);
    equal(socket.destroyed, false);
    equal(ws.closed.length, 0, 'self-hosted admits the same lease with zero licence involvement');
    equal(underlying.snapshot().activeConnections, 1);
  }
});

console.log(`Hosted relay drop-in (cross-repo) tests passed (${assertions} assertions).`);
