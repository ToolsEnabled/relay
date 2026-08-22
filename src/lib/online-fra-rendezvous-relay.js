'use strict';

// Pure, disabled-by-default rendezvous state machine for the future online
// FRA transport.  It owns no listener, socket, credential, command parser, or
// cryptographic payload decryption.  A trusted adapter supplies the result of
// an already-completed mTLS device check; this core verifies signed short
// leases, pairs exact endpoints, and moves only opaque binary frames.

const crypto = require('node:crypto');

const LEASE_SCHEMA_VERSION = 'online-fra-lease.v1';
// machine-a / machine-b are the pair; web-client is the owner's signed-in
// browser, admitted BESIDE the pair (owner ruling 2026-08-19: the browser
// control surface ships at launch). One web slot per pair; a new web
// connection DISPLACES the old, mirroring the account service's web-session
// displacement; machine-to-machine routing is untouched by its presence.
// A pair may be SOLO -- machineBId null, one machine, still one web slot --
// so a person with one computer connected is served too (see normalizedPair).
const ENDPOINT_ROLES = Object.freeze(['machine-a', 'machine-b', 'web-client']);
const MACHINE_ROLES = Object.freeze(['machine-a', 'machine-b']);
const LEASE_KEYS = Object.freeze([
  'schemaVersion', 'leaseId', 'pairId', 'deviceId', 'peerDeviceId', 'endpointRole',
  'mtlsFingerprint', 'generation', 'issuedAtMs', 'expiresAtMs', 'nonce',
  'ephemeralX25519PublicKey', 'capabilityDigest', 'signature'
]);
const LEASE_SIGNED_KEYS = Object.freeze(LEASE_KEYS.filter(key => key !== 'signature'));
const MAX_LEASE_TTL_MS = 15 * 60 * 1000;
const MAX_CLOCK_SKEW_MS = 5_000;
const DEFAULT_CLOCK_SKEW_MS = 0;
const DEFAULT_MAX_FRAME_BYTES = 64 * 1024;
const DEFAULT_MAX_QUEUED_BYTES_PER_CONNECTION = 128 * 1024;
const DEFAULT_MAX_QUEUED_BYTES_PER_DEVICE = 128 * 1024;
const DEFAULT_MAX_QUEUED_BYTES_PER_PAIR = 256 * 1024;
const DEFAULT_MAX_CONNECTIONS_PER_DEVICE = 1;
const DEFAULT_MAX_CONNECTIONS_PER_PAIR = 2;
const CONNECTION_ID_BYTES = 16;
const MAX_BYTE_CAPACITY = 16 * 1024 * 1024;
const MAX_CONNECTION_CAPACITY = 1024;

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function plainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}

function exactKeys(value, keys, code) {
  if (!plainObject(value) || Object.keys(value).length !== keys.length
      || Object.keys(value).some(key => !keys.includes(key))) fail(code);
  return value;
}

function identifier(value, code) {
  if (typeof value !== 'string' || !/^[a-z][a-z0-9_-]{2,95}$/.test(value)) fail(code);
  return value;
}

function reasonCode(value, code) {
  if (typeof value !== 'string' || !/^[A-Za-z][A-Za-z0-9_.-]{2,95}$/.test(value)) fail(code);
  return value;
}

function digest(value, code) {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) fail(code);
  return value;
}

function integer(value, code, min, max = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < min || value > max) fail(code);
  return value;
}

function base64url(value, code, { minBytes = 1, maxBytes = 4096 } = {}) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) fail(code);
  let decoded;
  try { decoded = Buffer.from(value, 'base64url'); } catch { fail(code); }
  if (decoded.length < minBytes || decoded.length > maxBytes || decoded.toString('base64url') !== value) fail(code);
  return decoded;
}

function pairKey(pairId, generation) {
  return `${pairId}:${generation}`;
}

// A SOLO PAIR is a pair whose B side is null. Owner ruling: one connected
// computer is served in the interface too, so it needs a relay pair of its
// own, and the relay's part is purely permissive -- accept it, admit it,
// change nothing about a two-machine pair. The key must be PRESENT and
// exactly null: exactKeys above still refuses an absent key, so a caller
// that merely forgot machineBId is never taken as solo by accident, and an
// undefined value is not null either. Everything else about the shape is
// the two-machine one.
function normalizedPair(value, seenDevices) {
  exactKeys(value, ['pairId', 'machineAId', 'machineBId', 'capabilityDigest'], 'ONLINE_FRA_RELAY_PAIR_INVALID');
  const pairId = identifier(value.pairId, 'ONLINE_FRA_RELAY_PAIR_INVALID');
  const machineAId = identifier(value.machineAId, 'ONLINE_FRA_RELAY_PAIR_INVALID');
  const machineBId = value.machineBId === null ? null : identifier(value.machineBId, 'ONLINE_FRA_RELAY_PAIR_INVALID');
  if (machineAId === machineBId || seenDevices.has(machineAId) || (machineBId !== null && seenDevices.has(machineBId))) fail('ONLINE_FRA_RELAY_PAIR_INVALID');
  seenDevices.add(machineAId);
  if (machineBId !== null) seenDevices.add(machineBId);
  return Object.freeze({ pairId, machineAId, machineBId, capabilityDigest: digest(value.capabilityDigest, 'ONLINE_FRA_RELAY_PAIR_INVALID') });
}

function leaseSigningBytes(lease) {
  const source = exactKeys(lease, LEASE_KEYS, 'ONLINE_FRA_LEASE_INVALID');
  const ordered = {};
  for (const key of LEASE_SIGNED_KEYS) ordered[key] = source[key];
  return Buffer.from(JSON.stringify(ordered), 'utf8');
}

function validateLeaseShape(lease) {
  const source = exactKeys(lease, LEASE_KEYS, 'ONLINE_FRA_LEASE_INVALID');
  if (source.schemaVersion !== LEASE_SCHEMA_VERSION) fail('ONLINE_FRA_LEASE_INVALID');
  identifier(source.leaseId, 'ONLINE_FRA_LEASE_INVALID');
  identifier(source.pairId, 'ONLINE_FRA_LEASE_INVALID');
  identifier(source.deviceId, 'ONLINE_FRA_LEASE_INVALID');
  // A machine lease on a SOLO pair has no peer and says so with null; every
  // other lease -- a two-machine lease, and every web lease -- names one.
  // The null is admitted here by ROLE only, so a web lease still has to name
  // the machine it drives; whether null is RIGHT for the pair is the binding
  // check's question (validateLease), not the shape's.
  if (source.peerDeviceId !== null || !MACHINE_ROLES.includes(source.endpointRole)) identifier(source.peerDeviceId, 'ONLINE_FRA_LEASE_INVALID');
  if (!ENDPOINT_ROLES.includes(source.endpointRole)) fail('ONLINE_FRA_LEASE_INVALID');
  digest(source.mtlsFingerprint, 'ONLINE_FRA_LEASE_INVALID');
  integer(source.generation, 'ONLINE_FRA_LEASE_INVALID', 1);
  integer(source.issuedAtMs, 'ONLINE_FRA_LEASE_INVALID', 1);
  integer(source.expiresAtMs, 'ONLINE_FRA_LEASE_INVALID', 1);
  base64url(source.nonce, 'ONLINE_FRA_LEASE_INVALID', { minBytes: 16, maxBytes: 64 });
  const ephemeral = base64url(source.ephemeralX25519PublicKey, 'ONLINE_FRA_LEASE_INVALID', { minBytes: 32, maxBytes: 512 });
  try {
    const key = crypto.createPublicKey({ key: ephemeral, format: 'der', type: 'spki' });
    if (key.asymmetricKeyType !== 'x25519') fail('ONLINE_FRA_LEASE_INVALID');
  } catch (error) {
    if (error && error.code === 'ONLINE_FRA_LEASE_INVALID') throw error;
    fail('ONLINE_FRA_LEASE_INVALID');
  }
  digest(source.capabilityDigest, 'ONLINE_FRA_LEASE_INVALID');
  base64url(source.signature, 'ONLINE_FRA_LEASE_INVALID', { minBytes: 64, maxBytes: 64 });
  return source;
}

function verifyEd25519Lease({ authorityPublicKey, lease }) {
  const signature = base64url(lease.signature, 'ONLINE_FRA_LEASE_INVALID', { minBytes: 64, maxBytes: 64 });
  try { return crypto.verify(null, leaseSigningBytes(lease), authorityPublicKey, signature); }
  catch { return false; }
}

function capacity(value, fallback, minimum = 1, maximum = MAX_BYTE_CAPACITY) {
  const actual = value === undefined ? fallback : value;
  return integer(actual, 'ONLINE_FRA_RELAY_CAPACITY_INVALID', minimum, maximum);
}

function createOnlineFraRendezvousRelay(options = {}) {
  const enabled = options.enabled === true;
  const clock = options.clock || (() => Date.now());
  const randomBytes = options.randomBytes || crypto.randomBytes;
  if (typeof clock !== 'function' || typeof randomBytes !== 'function') fail('ONLINE_FRA_RELAY_OPTIONS_INVALID');
  if (typeof options.eventSink !== 'function') fail('ONLINE_FRA_EVENT_SINK_REQUIRED');
  let authorityPublicKey;
  try {
    authorityPublicKey = options.authorityPublicKey && options.authorityPublicKey.type === 'public'
      ? options.authorityPublicKey
      : crypto.createPublicKey(options.authorityPublicKey);
  }
  catch { fail('ONLINE_FRA_AUTHORITY_INVALID'); }
  if (authorityPublicKey.asymmetricKeyType !== 'ed25519') fail('ONLINE_FRA_AUTHORITY_INVALID');
  const verifyLease = options.verifyLease || verifyEd25519Lease;
  if (typeof verifyLease !== 'function') fail('ONLINE_FRA_RELAY_OPTIONS_INVALID');
  const leaseState = options.leaseState;
  if (enabled && (leaseState === undefined || leaseState === null)) fail('ONLINE_FRA_LEASE_STATE_REQUIRED');
  if (enabled && (typeof leaseState !== 'object'
      || typeof leaseState.admitLease !== 'function'
      || typeof leaseState.pairState !== 'function'
      || typeof leaseState.revokePair !== 'function')) {
    fail('ONLINE_FRA_LEASE_STATE_INVALID');
  }
  const generation = integer(options.generation === undefined ? 1 : options.generation, 'ONLINE_FRA_RELAY_OPTIONS_INVALID', 1);
  const maxLeaseTtlMs = capacity(options.maxLeaseTtlMs, MAX_LEASE_TTL_MS);
  if (maxLeaseTtlMs > MAX_LEASE_TTL_MS) fail('ONLINE_FRA_RELAY_OPTIONS_INVALID');
  const maxClockSkewMs = capacity(options.maxClockSkewMs, DEFAULT_CLOCK_SKEW_MS, 0, MAX_CLOCK_SKEW_MS);
  const maxFrameBytes = capacity(options.maxFrameBytes, DEFAULT_MAX_FRAME_BYTES);
  const maxQueuedBytesPerConnection = capacity(options.maxQueuedBytesPerConnection, DEFAULT_MAX_QUEUED_BYTES_PER_CONNECTION);
  const maxQueuedBytesPerDevice = capacity(options.maxQueuedBytesPerDevice, DEFAULT_MAX_QUEUED_BYTES_PER_DEVICE);
  const maxQueuedBytesPerPair = capacity(options.maxQueuedBytesPerPair, DEFAULT_MAX_QUEUED_BYTES_PER_PAIR);
  const maxConnectionsPerDevice = capacity(options.maxConnectionsPerDevice, DEFAULT_MAX_CONNECTIONS_PER_DEVICE, 1, MAX_CONNECTION_CAPACITY);
  const maxConnectionsPerPair = capacity(options.maxConnectionsPerPair, DEFAULT_MAX_CONNECTIONS_PER_PAIR, 2, MAX_CONNECTION_CAPACITY);
  if (maxFrameBytes > maxQueuedBytesPerConnection || maxQueuedBytesPerConnection > maxQueuedBytesPerDevice
      || maxQueuedBytesPerDevice > maxQueuedBytesPerPair) fail('ONLINE_FRA_RELAY_OPTIONS_INVALID');
  // maxPairs: 16 remains the default -- the shape every existing deployment and
  // test was built against -- and raising it is an explicit hosted-deployment
  // decision, never an accident. The ceiling exists because every pair costs
  // slots/queue map entries and the instance is single-process: a hosted relay
  // that needs more than the ceiling needs more instances, not a bigger map.
  const maxPairs = capacity(options.maxPairs, 16, 1, 4096);
  // Zero pairs is a legitimate STARTING state for a hosted instance -- it
  // onboards through registerPair() -- while the two-machine self-host shape
  // still constructs with its pair inline. Nothing admits on an empty relay:
  // every lease fails the binding check until a registration lands.
  if (!Array.isArray(options.pairs) || options.pairs.length > maxPairs) fail('ONLINE_FRA_RELAY_PAIR_INVALID');
  const seenDevices = new Set();
  const pairs = new Map();
  for (const input of options.pairs) {
    const pair = normalizedPair(input, seenDevices);
    if (pairs.has(pair.pairId)) fail('ONLINE_FRA_RELAY_PAIR_INVALID');
    pairs.set(pair.pairId, pair);
  }

  // The account-routing seam, deliberately shaped so it does not decide the
  // one architecture question both lanes agreed not to decide from one side:
  // whether the relay ASKS the account server per admission, or is TOLD at
  // lease time and merely verifies. Under ASK, this hook is where an
  // accountForPair lookup binds; under TOLD, it is omitted and the signed
  // lease remains the entire proof. Synchronous like every other injected
  // dependency here (a promise is a refusal), consulted after the lease is
  // fully validated and before the nonce is durably consumed, so a refusal
  // costs nothing durable. Anything but `true` -- false, throw, a promise --
  // refuses admission with its own named code.
  const admissionAuthority = options.admissionAuthority === undefined ? null : options.admissionAuthority;
  if (admissionAuthority !== null && typeof admissionAuthority !== 'function') fail('ONLINE_FRA_RELAY_OPTIONS_INVALID');

  // FAIR USE, LAYER 1: a token bucket per pair. ABSENT BY DEFAULT -- a
  // self-hosted relay is unmetered, and metering it is a hosted-deployment
  // decision made in the shell's config, never a library surprise. The
  // published figures (20 MB burst, 1 MB/minute refill) are ~10x the measured
  // heavy rate: the burst is what keeps it invisible to real work, and only
  // sustained abuse ever sees the floor.
  //
  // OVER BUDGET IS THROTTLED, NEVER A THROW. route() answers
  // { delivered:false, throttled:true, retryAfterMs } and consumes nothing --
  // the caller (the websocket edge) pauses the SOURCE socket and retries after
  // the refill, so the connection lives. A dropped connection is a support
  // ticket; a delayed frame is physics.
  const pairRateLimit = options.pairRateLimit === undefined ? null : options.pairRateLimit;
  if (pairRateLimit !== null) {
    exactKeys(pairRateLimit, ['burstBytes', 'refillBytesPerMinute'], 'ONLINE_FRA_RELAY_OPTIONS_INVALID');
    integer(pairRateLimit.burstBytes, 'ONLINE_FRA_RELAY_OPTIONS_INVALID', 1, MAX_BYTE_CAPACITY);
    integer(pairRateLimit.refillBytesPerMinute, 'ONLINE_FRA_RELAY_OPTIONS_INVALID', 1, MAX_BYTE_CAPACITY);
    // A burst smaller than one frame could never pass anything.
    if (pairRateLimit.burstBytes < maxFrameBytes) fail('ONLINE_FRA_RELAY_OPTIONS_INVALID');
  }
  // pairKey -> { tokens, lastRefillMs }. Entries die with the pair's last
  // connection (cleaned in closePair's wake by being keyed per generation);
  // memory is O(active pairs), same as every other map here.
  const pairBuckets = new Map();

  function throttleVerdict(key, bytes, atMs) {
    if (!pairRateLimit) return null;
    let bucket = pairBuckets.get(key);
    if (!bucket) {
      bucket = { tokens: pairRateLimit.burstBytes, lastRefillMs: atMs };
      pairBuckets.set(key, bucket);
    }
    const refill = ((atMs - bucket.lastRefillMs) / 60_000) * pairRateLimit.refillBytesPerMinute;
    if (refill > 0) {
      bucket.tokens = Math.min(pairRateLimit.burstBytes, bucket.tokens + refill);
      bucket.lastRefillMs = atMs;
    }
    if (bucket.tokens >= bytes) {
      bucket.tokens -= bytes;
      return null;
    }
    const deficit = bytes - bucket.tokens;
    const retryAfterMs = Math.max(1, Math.ceil((deficit / pairRateLimit.refillBytesPerMinute) * 60_000));
    return Object.freeze({ delivered: false, throttled: true, retryAfterMs, bytes });
  }

  const connections = new Map();
  const slots = new Map();
  const deviceConnections = new Map();
  const pairConnections = new Map();
  const deviceQueuedBytes = new Map();
  const pairQueuedBytes = new Map();
  let eventSequence = 0;

  function now() {
    const value = clock();
    return integer(value, 'ONLINE_FRA_CLOCK_INVALID', 1);
  }

  function metadata(type, fields = {}) {
    return Object.freeze({ schemaVersion: 'online-fra-rendezvous-event.v1', sequence: ++eventSequence, type, atMs: now(), ...fields });
  }

  function sink(type, fields) {
    const event = metadata(type, fields);
    try {
      const result = options.eventSink(event);
      if (result && typeof result.then === 'function') fail('ONLINE_FRA_EVENT_SINK_INVALID');
      return event;
    } catch (error) {
      if (error && error.code === 'ONLINE_FRA_EVENT_SINK_INVALID') throw error;
      fail('ONLINE_FRA_EVENT_SINK_FAILED');
    }
  }

  function increment(map, key, amount = 1) {
    map.set(key, (map.get(key) || 0) + amount);
  }

  function decrement(map, key, amount = 1) {
    const next = (map.get(key) || 0) - amount;
    if (next <= 0) map.delete(key); else map.set(key, next);
  }

  function leaseStateUnavailable() {
    fail('ONLINE_FRA_LEASE_STATE_UNAVAILABLE');
  }

  // This adapter is the persistence boundary.  admitLease must atomically
  // check pair-generation revocation and consume the nonce durably, before
  // returning accepted.  There is deliberately no process-local fallback.
  function callLeaseState(method, request) {
    let result;
    try {
      result = leaseState[method](Object.freeze(request));
      if (result && typeof result.then === 'function') leaseStateUnavailable();
    }
    catch { leaseStateUnavailable(); }
    return result;
  }

  function admitLease(lease) {
    const result = callLeaseState('admitLease', {
      leaseId: lease.leaseId, pairId: lease.pairId, generation: lease.generation,
      deviceId: lease.deviceId, peerDeviceId: lease.peerDeviceId,
      capabilityDigest: lease.capabilityDigest, nonce: lease.nonce,
      expiresAtMs: lease.expiresAtMs
    });
    let keys;
    let affirmative;
    let outcome;
    let isPlain = false;
    try {
      isPlain = plainObject(result);
      keys = Object.keys(result);
      affirmative = result.ok;
      outcome = result.outcome;
    } catch { leaseStateUnavailable(); }
    if (!isPlain || keys.length !== 2 || affirmative !== true
        || !['accepted', 'replayed', 'revoked'].includes(outcome)) leaseStateUnavailable();
    return outcome;
  }

  function pairState(pairId, targetGeneration) {
    const result = callLeaseState('pairState', { pairId, generation: targetGeneration });
    let keys;
    let affirmative;
    let revoked;
    let isPlain = false;
    try {
      isPlain = plainObject(result);
      keys = Object.keys(result);
      affirmative = result.ok;
      revoked = result.revoked;
    } catch { leaseStateUnavailable(); }
    if (!isPlain || keys.length !== 2 || affirmative !== true || typeof revoked !== 'boolean') leaseStateUnavailable();
    return revoked;
  }

  function persistRevocation(pairId, targetGeneration, reason) {
    const result = callLeaseState('revokePair', { pairId, generation: targetGeneration, reason });
    let keys;
    let affirmative;
    let revoked;
    let isPlain = false;
    try {
      isPlain = plainObject(result);
      keys = Object.keys(result);
      affirmative = result.ok;
      revoked = result.revoked;
    } catch { leaseStateUnavailable(); }
    if (!isPlain || keys.length !== 2 || affirmative !== true || revoked !== true) leaseStateUnavailable();
  }

  /* WHY A CONNECTION WENT, KEPT JUST LONG ENOUGH TO BE ASKED.
   *
   * Closing a connection is a lifecycle event with a REASON -- displaced by a
   * newer tab, pair revoked, lease expired -- and until now that reason went
   * only to the event sink, which by design keeps no reasons. So the edge asked
   * about a connection the relay had deliberately closed a moment earlier, got
   * an unqualified "unknown", and reported it to the browser as an internal
   * error. The page could then only say the person's computer had not answered.
   * It had; a second tab had taken the slot, exactly as intended.
   *
   * Bounded and evicted oldest-first: this is a hint for a socket that has not
   * noticed yet, not a record. The reasons are the same closed set of constants
   * the sink already receives, so nothing new is retained and no identifier is. */
  const closedReasons = new Map();
  const MAX_CLOSED_REASONS = 256;
  function rememberClosed(connectionId, reason) {
    if (typeof reason !== 'string' || !/^ONLINE_FRA_[A-Z0-9_]{1,48}$/.test(reason)) return;
    closedReasons.delete(connectionId);
    closedReasons.set(connectionId, reason);
    while (closedReasons.size > MAX_CLOSED_REASONS) closedReasons.delete(closedReasons.keys().next().value);
  }

  function recordFor(connectionId) {
    const value = connections.get(connectionId);
    if (!value || value.closed) fail(closedReasons.get(connectionId) || 'ONLINE_FRA_CONNECTION_UNKNOWN');
    return value;
  }

  function pairSlotKey(record) {
    return pairKey(record.pairId, record.generation);
  }

  function discard(record, reason, emit = true) {
    if (!record || record.closed) return false;
    record.closed = true;
    for (const item of record.queue) {
      decrement(deviceQueuedBytes, record.deviceId, item.length);
      decrement(pairQueuedBytes, pairSlotKey(record), item.length);
    }
    record.queue = [];
    record.queuedBytes = 0;
    connections.delete(record.connectionId);
    decrement(deviceConnections, record.deviceId);
    // pairConnections is the MACHINE budget; the web slot never incremented it.
    if (record.endpointRole !== 'web-client') decrement(pairConnections, pairSlotKey(record));
    const pairSlots = slots.get(pairSlotKey(record));
    if (pairSlots) {
      pairSlots.delete(record.endpointRole);
      if (pairSlots.size === 0) slots.delete(pairSlotKey(record));
    }
    const peer = record.peerConnectionId ? connections.get(record.peerConnectionId) : null;
    if (peer && peer.peerConnectionId === record.connectionId) peer.peerConnectionId = null;
    record.peerConnectionId = null;
    rememberClosed(record.connectionId, reason);
    if (emit) sink('online_fra.connection.closed', { connectionId: record.connectionId, pairId: record.pairId, deviceId: record.deviceId, reason });
    return true;
  }

  function closePair(pairId, targetGeneration, reason, emit = true) {
    const toClose = [...connections.values()].filter(record => record.pairId === pairId && record.generation === targetGeneration);
    for (const record of toClose) discard(record, reason, false);
    if (emit) sink('online_fra.pair.closed', { pairId, generation: targetGeneration, reason, connectionCount: toClose.length });
  }

  function expireConnections(atMs) {
    const expired = [...connections.values()].filter(record => record.expiresAtMs <= atMs);
    for (const record of expired) {
      try { discard(record, 'ONLINE_FRA_LEASE_EXPIRED'); }
      catch (error) {
        closePair(record.pairId, record.generation, 'ONLINE_FRA_EVENT_SINK_FAILED', false);
        throw error;
      }
    }
  }

  function connectionId() {
    for (let attempt = 0; attempt < 16; attempt += 1) {
      let bytes;
      try { bytes = randomBytes(CONNECTION_ID_BYTES); } catch { fail('ONLINE_FRA_RANDOM_INVALID'); }
      if (!Buffer.isBuffer(bytes) || bytes.length !== CONNECTION_ID_BYTES) fail('ONLINE_FRA_RANDOM_INVALID');
      const id = `conn_${Buffer.from(bytes).toString('base64url')}`;
      if (!connections.has(id)) return id;
    }
    fail('ONLINE_FRA_CONNECTION_ID_COLLISION');
  }

  function validateIdentity(identity, lease) {
    exactKeys(identity, ['verified', 'authType', 'deviceId', 'mtlsFingerprint'], 'ONLINE_FRA_MTLS_IDENTITY_INVALID');
    // Machine roles present a client certificate (nginx-verified mTLS). The
    // web role CANNOT -- browsers have no reasonable client-cert UX -- so its
    // edge admits on the signed lease plus a possession proof (the browser
    // signs a nonce with the key whose SPKI SHA-256 sits in the lease's
    // fingerprint slot) and attests that here as authType 'web-lease'. The
    // consistency checks below are identical for both: same fields, same
    // meaning -- 'the fingerprint of the identity this endpoint presented'.
    // ONE MORE AUTH TYPE, FOR EVERY ROLE: 'key-lease' -- the endpoint proved
    // possession of the key whose SPKI SHA-256 the lease commits to, by signing
    // the edge's nonce (online-fra-web-admission.js). It was built for the web
    // role because browsers cannot present a client certificate. It is now
    // accepted for MACHINE roles too, and the reason is the one device-ca.js
    // records against itself: under the mTLS path the client private key is
    // generated on the server and travels to the machine, because the engine
    // cannot build a CSR. Under key-lease the machine signs with the Ed25519
    // identity key it generated and never sent anywhere -- the same key peer
    // introduction pins. That is the stronger shape, not the weaker one, and it
    // needs no CA to operate. 'mtls' stays valid for machines; nothing that
    // admitted before stops admitting now.
    const role = lease.endpointRole;
    const acceptedAuth = role === 'web-client' ? ['web-lease', 'key-lease'] : ['mtls', 'key-lease'];
    if (identity.verified !== true || !acceptedAuth.includes(identity.authType)) fail('ONLINE_FRA_MTLS_IDENTITY_INVALID');
    if (identifier(identity.deviceId, 'ONLINE_FRA_MTLS_IDENTITY_INVALID') !== lease.deviceId
        || digest(identity.mtlsFingerprint, 'ONLINE_FRA_MTLS_IDENTITY_INVALID') !== lease.mtlsFingerprint) {
      fail('ONLINE_FRA_MTLS_IDENTITY_MISMATCH');
    }
  }

  function validateLease(lease, identity) {
    const source = validateLeaseShape(lease);
    const atMs = now();
    if (source.issuedAtMs > atMs + maxClockSkewMs || source.expiresAtMs <= atMs
        || source.expiresAtMs <= source.issuedAtMs || source.expiresAtMs - source.issuedAtMs > maxLeaseTtlMs) {
      fail('ONLINE_FRA_LEASE_TIME_INVALID');
    }
    const pair = pairs.get(source.pairId);
    if (!pair || source.generation !== generation || source.capabilityDigest !== pair.capabilityDigest) fail('ONLINE_FRA_LEASE_BINDING_INVALID');
    if (source.endpointRole === 'web-client') {
      // The web endpoint is a THIRD party: its device id is minted per lease
      // by the account box and must not collide with either machine, and its
      // peerDeviceId names one of the pair's machines (which one is
      // informational -- routing may address either). On a SOLO pair
      // machineBId is null and a web peerDeviceId is never null (shape), so
      // the only machine it can name is machineAId -- the only machine.
      if (source.deviceId === pair.machineAId || source.deviceId === pair.machineBId
          || (source.peerDeviceId !== pair.machineAId && source.peerDeviceId !== pair.machineBId)) {
        fail('ONLINE_FRA_LEASE_BINDING_INVALID');
      }
    } else {
      // On a SOLO pair the B side is null and this is the whole of the solo
      // binding rule: machine-a presents deviceId === machineAId and
      // peerDeviceId === null (a lease naming a peer the pair does not have
      // is refused here, with this code); machine-b has no device id to
      // equal, so a machine-b lease against a solo pair is refused here too.
      const expectedDevice = source.endpointRole === 'machine-a' ? pair.machineAId : pair.machineBId;
      const expectedPeer = source.endpointRole === 'machine-a' ? pair.machineBId : pair.machineAId;
      if (source.deviceId !== expectedDevice || source.peerDeviceId !== expectedPeer) fail('ONLINE_FRA_LEASE_BINDING_INVALID');
    }
    validateIdentity(identity, source);
    let signed = false;
    try { signed = verifyLease({ authorityPublicKey, lease: source, signingBytes: leaseSigningBytes(source) }); }
    catch { signed = false; }
    if (signed !== true) fail('ONLINE_FRA_LEASE_SIGNATURE_INVALID');
    return { lease: source, pair, atMs };
  }

  function assertPairActive(record) {
    let revoked;
    try { revoked = pairState(record.pairId, record.generation); }
    catch (error) {
      closePair(record.pairId, record.generation, 'ONLINE_FRA_LEASE_STATE_UNAVAILABLE', false);
      throw error;
    }
    if (revoked) {
      closePair(record.pairId, record.generation, 'ONLINE_FRA_PAIR_REVOKED', false);
      fail('ONLINE_FRA_PAIR_REVOKED');
    }
  }

  function connect({ identity, lease } = {}) {
    if (!enabled) fail('ONLINE_FRA_RELAY_DISABLED');
    const validated = validateLease(lease, identity);
    const { pair, atMs } = validated;
    const leaseValue = validated.lease;
    expireConnections(atMs);
    const key = pairKey(pair.pairId, generation);
    const isWeb = leaseValue.endpointRole === 'web-client';
    // maxConnectionsPerPair is the MACHINE budget (its floor is 2 for exactly
    // that reason); the single web slot sits beside it, so the pair-capacity
    // check counts machine connections only and the web role's own cap is the
    // one-slot displacement below.
    if ((deviceConnections.get(leaseValue.deviceId) || 0) >= maxConnectionsPerDevice
        || (!isWeb && (pairConnections.get(key) || 0) >= maxConnectionsPerPair)) fail('ONLINE_FRA_CONNECTION_CAPACITY_EXCEEDED');
    const pairSlots = slots.get(key) || new Map();
    if (isWeb && pairSlots.has('web-client')) {
      // DISPLACEMENT, not refusal: a new signed web lease is the account
      // holder opening a newer tab or a different browser, and the account
      // side already displaces web SESSIONS the same way. The old endpoint is
      // closed with its own reason so the page can say what happened.
      discard(pairSlots.get('web-client'), 'ONLINE_FRA_WEB_DISPLACED');
    } else if (pairSlots.has(leaseValue.endpointRole)) fail('ONLINE_FRA_DUPLICATE_ENDPOINT_ROLE');
    // Consulted before admitLease on purpose: an authority refusal must not
    // consume the nonce, or a transient account-side outage would burn every
    // lease presented during it and the customer would need fresh leases for
    // no fault of their own. Sits after validateLease equally on purpose --
    // the authority only ever sees claims the signature already proved.
    if (admissionAuthority) {
      let authorized = false;
      try {
        authorized = admissionAuthority(Object.freeze({
          pairId: pair.pairId, deviceId: leaseValue.deviceId,
          endpointRole: leaseValue.endpointRole, generation
        }));
      } catch { authorized = false; }
      if (authorized !== true) fail('ONLINE_FRA_PAIR_UNAUTHORIZED');
    }
    const id = connectionId();
    const admission = admitLease(leaseValue);
    if (admission === 'replayed') fail('ONLINE_FRA_LEASE_REPLAYED');
    if (admission === 'revoked') fail('ONLINE_FRA_PAIR_REVOKED');
    // Event before mutating the connection state: an unavailable audit/event
    // sink must not leave an unaudited live endpoint.
    sink('online_fra.connection.accepted', {
      connectionId: id, pairId: pair.pairId, deviceId: leaseValue.deviceId,
      endpointRole: leaseValue.endpointRole, generation, leaseId: leaseValue.leaseId,
      expiresAtMs: leaseValue.expiresAtMs
    });
    const record = {
      connectionId: id, pairId: pair.pairId, deviceId: leaseValue.deviceId,
      peerDeviceId: leaseValue.peerDeviceId, endpointRole: leaseValue.endpointRole,
      generation, leaseId: leaseValue.leaseId, nonce: leaseValue.nonce,
      expiresAtMs: leaseValue.expiresAtMs, queuedBytes: 0, queue: [],
      peerConnectionId: null, closed: false
    };
    connections.set(id, record);
    increment(deviceConnections, record.deviceId);
    if (!isWeb) increment(pairConnections, key);
    pairSlots.set(record.endpointRole, record);
    slots.set(key, pairSlots);
    // The web role does not pair: machines link mutually and emit
    // online_fra.pair.paired exactly as before; a web endpoint addresses
    // either machine per frame, via route().
    const otherRole = record.endpointRole === 'machine-a' ? 'machine-b'
      : record.endpointRole === 'machine-b' ? 'machine-a' : null;
    const peer = otherRole === null ? null : pairSlots.get(otherRole);
    if (peer) {
      record.peerConnectionId = peer.connectionId;
      peer.peerConnectionId = record.connectionId;
      try {
        sink('online_fra.pair.paired', {
          pairId: record.pairId, generation, machineAConnectionId: record.endpointRole === 'machine-a' ? record.connectionId : peer.connectionId,
          machineBConnectionId: record.endpointRole === 'machine-b' ? record.connectionId : peer.connectionId
        });
      } catch (error) {
        closePair(record.pairId, generation, 'ONLINE_FRA_EVENT_SINK_FAILED', false);
        throw error;
      }
    }
    return Object.freeze({ connectionId: id, pairId: record.pairId, deviceId: record.deviceId, endpointRole: record.endpointRole, generation, paired: Boolean(record.peerConnectionId) });
  }

  function connectionMetadata(connectionId) {
    expireConnections(now());
    const record = recordFor(connectionId);
    assertPairActive(record);
    // EVERY LEG OF THIS PAIR, BY ROLE. The edge needs this to address a frame:
    // a machine talks to its peer machine AND to the pair's web slot over one
    // socket, and a browser talks to either machine. peerConnectionId stays
    // exactly what it was -- the machine<->machine link -- so nothing that
    // read it before reads anything different now.
    const pairSlots = slots.get(pairSlotKey(record));
    const legOf = role => { const leg = pairSlots ? pairSlots.get(role) : undefined; return leg && !leg.closed ? leg.connectionId : null; };
    return Object.freeze({
      connectionId: record.connectionId, pairId: record.pairId, deviceId: record.deviceId,
      peerDeviceId: record.peerDeviceId, endpointRole: record.endpointRole, generation: record.generation,
      peerConnectionId: record.peerConnectionId, queuedBytes: record.queuedBytes, expiresAtMs: record.expiresAtMs,
      legs: Object.freeze({ 'machine-a': legOf('machine-a'), 'machine-b': legOf('machine-b'), 'web-client': legOf('web-client') })
    });
  }

  function route({ connectionId: sourceId, peerConnectionId, frame } = {}) {
    const atMs = now();
    expireConnections(atMs);
    const source = recordFor(sourceId);
    if (!Buffer.isBuffer(frame) || frame.length < 1 || frame.length > maxFrameBytes) fail('ONLINE_FRA_OPAQUE_FRAME_INVALID');
    if (typeof peerConnectionId !== 'string') fail('ONLINE_FRA_ROUTE_PEER_MISMATCH');
    const peer = recordFor(peerConnectionId);
    const webLeg = source.endpointRole === 'web-client' || peer.endpointRole === 'web-client';
    if (!webLeg) {
      // The machine<->machine contract, byte-for-byte as it always was:
      // mutual, verified linkage.
      if (source.peerConnectionId !== peerConnectionId) fail('ONLINE_FRA_ROUTE_PEER_MISMATCH');
      if (peer.pairId !== source.pairId || peer.generation !== source.generation || peer.peerConnectionId !== source.connectionId) fail('ONLINE_FRA_ROUTE_PEER_MISMATCH');
    } else {
      // A web leg has no mutual link: the browser addresses EITHER machine of
      // its own pair per frame, and a machine addresses the pair's one web
      // slot. Same pair, same generation, exactly one end web -- a
      // web-to-web frame has no meaning and is refused.
      if (source.endpointRole === 'web-client' && peer.endpointRole === 'web-client') fail('ONLINE_FRA_ROUTE_PEER_MISMATCH');
      if (peer.pairId !== source.pairId || peer.generation !== source.generation) fail('ONLINE_FRA_ROUTE_PEER_MISMATCH');
    }
    assertPairActive(source);
    const key = pairSlotKey(peer);
    if (peer.queuedBytes + frame.length > maxQueuedBytesPerConnection
        || (deviceQueuedBytes.get(peer.deviceId) || 0) + frame.length > maxQueuedBytesPerDevice
        || (pairQueuedBytes.get(key) || 0) + frame.length > maxQueuedBytesPerPair) {
      fail('ONLINE_FRA_BACKPRESSURE');
    }
    // The throttle sits AFTER every validity check (an invalid frame must
    // still be named invalid, not throttled) and BEFORE the sink and the
    // queues (a throttled frame was not routed and consumes nothing durable).
    const throttled = throttleVerdict(key, frame.length, atMs);
    if (throttled) return throttled;
    try {
      sink('online_fra.frame.routed', {
        connectionId: source.connectionId, peerConnectionId: peer.connectionId,
        pairId: source.pairId, deviceId: source.deviceId, peerDeviceId: peer.deviceId, bytes: frame.length
      });
    } catch (error) {
      closePair(source.pairId, source.generation, 'ONLINE_FRA_EVENT_SINK_FAILED', false);
      throw error;
    }
    // Copy only opaque bytes.  No parser, decoder, or crypto operation is
    // permitted in this module.
    peer.queue.push(Buffer.from(frame));
    peer.queuedBytes += frame.length;
    increment(deviceQueuedBytes, peer.deviceId, frame.length);
    increment(pairQueuedBytes, key, frame.length);
    return Object.freeze({ delivered: true, bytes: frame.length });
  }

  function take(connectionId) {
    expireConnections(now());
    const record = recordFor(connectionId);
    assertPairActive(record);
    const item = record.queue.shift();
    if (!item) return null;
    record.queuedBytes -= item.length;
    decrement(deviceQueuedBytes, record.deviceId, item.length);
    decrement(pairQueuedBytes, pairSlotKey(record), item.length);
    try {
      sink('online_fra.frame.dequeued', { connectionId: record.connectionId, pairId: record.pairId, deviceId: record.deviceId, bytes: item.length });
    } catch (error) {
      closePair(record.pairId, record.generation, 'ONLINE_FRA_EVENT_SINK_FAILED', false);
      throw error;
    }
    return Buffer.from(item);
  }

  function close(connectionId, reason = 'ONLINE_FRA_CONNECTION_CLOSED') {
    const record = recordFor(connectionId);
    try { return discard(record, reasonCode(reason, 'ONLINE_FRA_CLOSE_REASON_INVALID')); }
    catch (error) {
      closePair(record.pairId, record.generation, 'ONLINE_FRA_EVENT_SINK_FAILED', false);
      throw error;
    }
  }

  function revokePair({ pairId, generation: requestedGeneration, reason = 'ONLINE_FRA_PAIR_REVOKED' } = {}) {
    identifier(pairId, 'ONLINE_FRA_REVOCATION_INVALID');
    integer(requestedGeneration, 'ONLINE_FRA_REVOCATION_INVALID', 1);
    reasonCode(reason, 'ONLINE_FRA_REVOCATION_INVALID');
    if (!pairs.has(pairId) || requestedGeneration !== generation) fail('ONLINE_FRA_REVOCATION_INVALID');
    try { persistRevocation(pairId, requestedGeneration, reason); }
    catch (error) {
      closePair(pairId, requestedGeneration, 'ONLINE_FRA_LEASE_STATE_UNAVAILABLE', false);
      throw error;
    }
    closePair(pairId, requestedGeneration, reason, false);
    // Unlike the sink() calls elsewhere in this file (take(), close(),
    // above), there is nothing left to clean up if this one throws:
    // closePair() already ran unconditionally just above and the
    // revocation is already durably persisted. A try/catch that only
    // rethrows the same error was dead code -- let it propagate directly.
    sink('online_fra.pair.revoked', { pairId, generation: requestedGeneration, reason });
    return true;
  }

  // Runtime pair registration -- what makes a HOSTED relay possible at all.
  //
  // The pair list was construction-only, which is exactly right for the
  // two-machine self-host shape and exactly wrong for a service: a relay that
  // must be torn down and rebuilt to onboard a customer is a relay that drops
  // every live customer to add one. Registration is the account layer telling
  // the relay its topology; it grants nothing by itself, because admission
  // still requires an authority-signed lease naming the pair (and, when the
  // admissionAuthority hook is present, a live yes from it).
  //
  // Same validation as construction, one atom at a time: exact keys, the
  // identifier grammar, device ids globally unique across ALL pairs on the
  // instance, the cap. The event goes to the sink BEFORE the map mutates, so
  // an unauditable registration never becomes an admissible one -- the same
  // ordering connect() uses for the same reason.
  function registerPair(input) {
    if (pairs.size >= maxPairs) fail('ONLINE_FRA_RELAY_PAIR_CAPACITY_EXCEEDED');
    const staged = new Set(seenDevices);
    const pair = normalizedPair(input, staged);
    if (pairs.has(pair.pairId)) fail('ONLINE_FRA_RELAY_PAIR_INVALID');
    sink('online_fra.pair.registered', { pairId: pair.pairId, generation });
    seenDevices.add(pair.machineAId);
    if (pair.machineBId !== null) seenDevices.add(pair.machineBId);
    pairs.set(pair.pairId, pair);
    return Object.freeze({ pairId: pair.pairId, generation, pairCount: pairs.size });
  }

  // Retirement is TOPOLOGY removal (account closed, machine removed), and it
  // is deliberately not revocation, which is durable CREDENTIAL invalidation
  // in the lease store. A retired pairId fails admission at the binding check
  // (`pairs.get` misses), so no store write is needed for safety; an
  // account-side "remove this machine" flow that also wants outstanding
  // leases dead in the durable record calls revokePair first, then this.
  // Freed device ids may be reused by a later registration -- the store's
  // nonce history still applies to a re-registered pairId, by design.
  function retirePair({ pairId, reason = 'ONLINE_FRA_PAIR_RETIRED' } = {}) {
    identifier(pairId, 'ONLINE_FRA_RETIREMENT_INVALID');
    reasonCode(reason, 'ONLINE_FRA_RETIREMENT_INVALID');
    const pair = pairs.get(pairId);
    if (!pair) fail('ONLINE_FRA_RETIREMENT_INVALID');
    closePair(pairId, generation, reason, false);
    pairs.delete(pairId);
    seenDevices.delete(pair.machineAId);
    if (pair.machineBId !== null) seenDevices.delete(pair.machineBId);
    // After the maps mutate, mirroring revokePair: nothing is left to undo,
    // and a sink failure here must surface rather than resurrect the pair.
    sink('online_fra.pair.retired', { pairId, generation, reason });
    return true;
  }

  function snapshot() {
    expireConnections(now());
    return Object.freeze({
      schemaVersion: 'online-fra-rendezvous-state.v1', enabled, generation,
      activeConnections: connections.size, activePairs: [...slots.values()].filter(value => value.size === 2).length,
      authoritativeLeaseState: enabled,
      pairCount: pairs.size, maxPairs,
      queuedBytes: [...pairQueuedBytes.values()].reduce((sum, value) => sum + value, 0),
      maxFrameBytes, maxQueuedBytesPerConnection, maxQueuedBytesPerDevice, maxQueuedBytesPerPair,
      maxConnectionsPerDevice, maxConnectionsPerPair, secretValuesEmitted: false
    });
  }

  return Object.freeze({
    connect, connectionMetadata, route, take, close, revokePair, snapshot,
    registerPair, retirePair,
    constants: Object.freeze({ LEASE_SCHEMA_VERSION, MAX_LEASE_TTL_MS, ENDPOINT_ROLES })
  });
}

module.exports = Object.freeze({
  LEASE_SCHEMA_VERSION, ENDPOINT_ROLES, MAX_LEASE_TTL_MS, leaseSigningBytes,
  createOnlineFraRendezvousRelay
});
