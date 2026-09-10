'use strict';

// Pure, opt-in WebSocket edge adapter for the separately authenticated online
// FRA session. It creates no HTTP listener itself; a deployment supplies an
// already-bound HTTPS server whose trusted proxy verifier attests mTLS/SNI.
//
// THE LEG BYTE. Every binary frame on the wire carries ONE leading byte naming
// a leg of the pair -- 0x01 machine-a, 0x02 machine-b, 0x03 web-client:
//
//   endpoint -> edge   [target leg][sealed payload]
//   edge -> endpoint   [source leg][sealed payload]
//
// It exists because the relay routes a pair as THREE legs (two machines and
// one web slot) while each endpoint holds ONE socket. A machine must be able
// to answer its peer and the browser through the same connection, and a
// browser must be able to address either machine; with no per-frame address
// the adapter could only ever route to one peer. The byte is the address and
// nothing else -- the payload after it is sealed above this layer and the
// edge neither reads nor alters it. The relay carries the source-stamped frame
// opaquely, so a frame taken for delivery is already in edge->endpoint form.
// A target that is not a live leg of the sender's own pair, or is the sender's
// own role, is refused and closes the socket.
const crypto = require('node:crypto');
const net = require('node:net');

const SAFE_ID = /^[a-z][a-z0-9_-]{2,95}$/;
const HEX = /^[a-f0-9]{64}$/;
const CONNECTION_ID = /^[A-Za-z0-9._-]{1,128}$/;
const LEG_BYTE = Object.freeze({ 'machine-a': 0x01, 'machine-b': 0x02, 'web-client': 0x03 });
const LEG_ROLE = Object.freeze({ 0x01: 'machine-a', 0x02: 'machine-b', 0x03: 'web-client' });
/* OUR OWN CLOSE CODE FOR "A NEWER TAB TOOK YOUR SLOT", in the private range
   (4000-4999) because it is ours and not the protocol's. The browser client
   reads it and says so; without a code of its own this arrived as a generic
   internal error and the page could only guess. */
const CLOSE_DISPLACED = 4001;
const MIN_RENEWAL_INTERVAL_MS = 1000;
/* Reasons the relay closes a connection deliberately. Each is a normal end to a
   connection, not a fault of this edge, and each closes 1000 rather than 1011 so
   an operator counting internal errors is counting real ones. */
const RELAY_ENDED_IT = new Set([
  'ONLINE_FRA_LEASE_EXPIRED', 'ONLINE_FRA_PAIR_REVOKED', 'ONLINE_FRA_PAIR_RETIRED', 'ONLINE_FRA_CONNECTION_UNKNOWN'
]);
const DEFAULTS = Object.freeze({
  enabled: false, maxFrameBytes: 262144, maxAdmissionBytes: 8192, maxSockets: 512,
  /* PER-IP LIMITS ARE ABUSE CONTROLS, AND THE OLD ONES WERE SET AGAINST THE
     WRONG PICTURE OF A CUSTOMER.
     Four sockets and twelve admissions a minute assumes one person per address.
     This product's premise is the opposite: every customer holds at least TWO
     persistent sockets, one per computer, plus a socket for each browser tab
     driving them -- and a household, an office or a university shares a single
     public address between all of them. A family with two computers and two
     tabs open was at the ceiling.
     Measured 2026-08-22, on a deployment where the proxy was not forwarding a
     client address at all, so the whole service shared ONE budget of four: four
     sockets from one house, and the fifth destroyed mid-upgrade -- which nginx
     reports as 502, so the browser said the connection could not be opened and
     had nothing to point at.
     These are still bounded, and the global ceiling above is what protects the
     process. What changed is that the per-address numbers now describe a
     building rather than a person. */
  maxSocketsPerIp: 64, maxAdmissionsPerIp: 120, admissionWindowMs: 60_000,
  admissionTimeoutMs: 10_000, pingIntervalMs: 30_000, idleTimeoutMs: 75_000,
  maxBufferedBytes: 524288, maxDrainPerTick: 16,
  /* An operator's line, off by default. The service passes one; tests and
     embedders that pass nothing behave exactly as they did. */
  log: () => {}
});

// Recheck admitted authority even when no frames arrive or a socket is full.
const SESSION_RECHECK_MS = 1_000;
const MAX_RATE_ENTRIES = 8192;

class OnlineFraWebSocketAdapterError extends Error {
  constructor(code) { super(code); this.name = 'OnlineFraWebSocketAdapterError'; this.code = code; }
}
function fail(code) { throw new OnlineFraWebSocketAdapterError(code); }
function plain(value) { return Boolean(value) && typeof value === 'object' && !Array.isArray(value) && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null); }
function integer(value, code, min, max) { if (!Number.isSafeInteger(value) || value < min || value > max) fail(code); return value; }
function sync(value, code) { if (value && typeof value.then === 'function') fail(code); return value; }
function safeHostname(value) { if (typeof value !== 'string' || !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(value)) fail('ONLINE_FRA_WS_OPTIONS_INVALID'); return value; }
function safeIp(value) { return typeof value === 'string' && net.isIP(value) !== 0; }
function metadataFingerprint(attestation) { return crypto.createHash('sha256').update(`${attestation.deviceId}|${attestation.fingerprint}|${attestation.ip}`, 'utf8').digest('hex').slice(0, 16); }

function createOnlineFraWebSocketAdapter(options = {}) {
  const allowed = new Set([
    'WebSocketServer', 'enabled', 'eventSink', 'hostname', 'httpServer', 'relay', 'verifyProxyRequest',
    'keyAdmission', 'clientIpFor', 'log',
    'clock', 'setTimer', 'clearTimer', 'maxFrameBytes', 'maxAdmissionBytes', 'maxSockets', 'maxSocketsPerIp',
    'maxAdmissionsPerIp', 'admissionWindowMs', 'admissionTimeoutMs', 'pingIntervalMs', 'idleTimeoutMs',
    'maxBufferedBytes', 'maxDrainPerTick'
  ]);
  if (!plain(options) || Object.keys(options).some(key => !allowed.has(key))) fail('ONLINE_FRA_WS_OPTIONS_INVALID');
  const config = { ...DEFAULTS, ...options };
  if (typeof config.WebSocketServer !== 'function' || !config.httpServer || typeof config.httpServer.on !== 'function'
    || typeof config.httpServer.off !== 'function'
    || typeof config.verifyProxyRequest !== 'function' || typeof config.eventSink !== 'function'
    || !config.relay || typeof config.relay.connect !== 'function' || typeof config.relay.route !== 'function'
    || typeof config.relay.take !== 'function' || typeof config.relay.connectionMetadata !== 'function'
    || typeof config.relay.close !== 'function'
    || typeof config.clock !== 'function' || typeof config.setTimer !== 'function' || typeof config.clearTimer !== 'function'
    || typeof config.enabled !== 'boolean') fail('ONLINE_FRA_WS_OPTIONS_INVALID');
  if (config.eventSink.constructor && config.eventSink.constructor.name === 'AsyncFunction') fail('ONLINE_FRA_WS_EVENT_SINK');
  // KEY-POSSESSION ADMISSION, OPT-IN. When `keyAdmission` is supplied (an
  // online-fra-web-admission instance) a request that carries NO mTLS
  // attestation is admitted by a signed-nonce dance instead of rejected at
  // upgrade: the edge sends a challenge as its first frame, the endpoint's
  // first frame carries the lease, its public key, the nonce and a signature,
  // and keyAdmission.admit() verifies all of it BEFORE relay.connect(). This
  // is how browsers connect (no client-cert UX) and, since 2026-08-20, how
  // machines may connect too, signing with the identity key they generated.
  // Without `keyAdmission` the adapter behaves exactly as before: mTLS only.
  if (config.keyAdmission !== undefined && (!config.keyAdmission || typeof config.keyAdmission.challenge !== 'function'
    || typeof config.keyAdmission.admit !== 'function')) fail('ONLINE_FRA_WS_OPTIONS_INVALID');
  if (config.clientIpFor !== undefined && typeof config.clientIpFor !== 'function') fail('ONLINE_FRA_WS_OPTIONS_INVALID');
  config.hostname = safeHostname(config.hostname);
  for (const [key, min, max] of [
    ['maxFrameBytes', 1024, 1024 * 1024], ['maxAdmissionBytes', 128, 16 * 1024], ['maxSockets', 1, 4096],
    ['maxSocketsPerIp', 1, 256], ['maxAdmissionsPerIp', 1, 10000], ['admissionWindowMs', 1, 3600000],
    ['admissionTimeoutMs', 1, 120000], ['pingIntervalMs', 1, 300000], ['idleTimeoutMs', 2, 600000],
    ['maxBufferedBytes', 1024, 4 * 1024 * 1024], ['maxDrainPerTick', 1, 1024]
  ]) config[key] = integer(config[key], 'ONLINE_FRA_WS_OPTIONS_INVALID', min, max);
  if (config.idleTimeoutMs <= config.pingIntervalMs) fail('ONLINE_FRA_WS_OPTIONS_INVALID');

  let started = false;
  let wss = null;
  const live = new Set();
  const rate = new Map();
  let nextRateSweepAt = 0;

  function emit(type, metadata = {}) {
    const event = Object.freeze({ type, atMs: Math.floor(config.clock()), ...metadata });
    let result;
    try { result = config.eventSink(event); }
    catch (error) { if (error instanceof OnlineFraWebSocketAdapterError) throw error; fail('ONLINE_FRA_WS_EVENT_SINK'); }
    if (result && typeof result.then === 'function') {
      try { Promise.resolve(result).catch(() => {}); } catch {}
      fail('ONLINE_FRA_WS_EVENT_SINK');
    }
  }
  function reject(socket) { try { socket.destroy(); } catch {} }
  function attestationFor(req) {
    let value;
    try { value = sync(config.verifyProxyRequest(req), 'ONLINE_FRA_WS_PROXY_ASYNC'); }
    catch { return null; }
    if (!plain(value) || value.ok !== true || value.tlsSni !== config.hostname || value.clientVerify !== 'SUCCESS'
      || !SAFE_ID.test(value.deviceId) || !HEX.test(value.fingerprint) || !safeIp(value.ip)) return keyAttestationFor(req);
    return Object.freeze({ mode: 'mtls', deviceId: value.deviceId, fingerprint: value.fingerprint, ip: value.ip });
  }
  // No certificate was presented. If key admission is configured, the socket
  // is accepted PROVISIONALLY: identity is unknown until the possession proof,
  // and the rate-limit slot is keyed on the client IP alone. The IP comes from
  // the proxy (X-Real-IP) -- trustworthy only because this server binds
  // loopback and nothing but nginx reaches it -- or from the socket itself.
  function keyAttestationFor(req) {
    if (!config.keyAdmission) return null;
    let ip = null;
    try { ip = typeof config.clientIpFor === 'function' ? config.clientIpFor(req) : defaultClientIp(req); } catch { ip = null; }
    if (!safeIp(ip)) return null;
    return Object.freeze({ mode: 'key', deviceId: 'pending', fingerprint: '0'.repeat(64), ip });
  }
  /* WHOSE BUDGET THIS SOCKET SPENDS.
   *
   * Behind a reverse proxy the socket's own peer is the PROXY, so without a
   * forwarded address every visitor on earth resolves to 127.0.0.1 and shares
   * ONE per-address budget. Measured on production 2026-08-22: the whole relay
   * was capped at four concurrent sockets and twelve admissions a minute for all
   * customers together. Machines already through the door kept working, which is
   * what made it invisible; the next connection was destroyed mid-upgrade and
   * nginx reported that as 502, so a browser said the connection could not be
   * opened and had nothing to point at.
   *
   * TWO HEADERS, BECAUSE THIS PROJECT ALREADY SENDS THE SECOND ONE. The nginx
   * config this very repository generates sets X-FRA-Client-Address, and only
   * the certificate door was reading it -- through the proxy attestation. The
   * key door read x-real-ip and nothing else, so a deployment following our own
   * reference config had no client address on the door it actually uses. The
   * two halves of one project disagreed about the name.
   *
   * Both are trusted because both are set by the proxy in front, which
   * overwrites whatever a client sent. A deployment that forwards neither gets
   * the socket's peer, which is correct when there is no proxy and is the
   * conservative answer when there is one -- everybody shares a budget, which
   * is a service that refuses rather than a limit that does not apply. */
  function defaultClientIp(req) {
    const headers = req && req.headers ? req.headers : {};
    for (const name of ['x-real-ip', 'x-fra-client-address']) {
      const value = headers[name];
      if (typeof value === 'string' && safeIp(value.trim())) return value.trim();
    }
    return req && req.socket ? req.socket.remoteAddress : null;
  }
  function admissionSlot(ip) {
    const now = config.clock();
    // An unauthenticated socket may close before its IP window ends. Reclaim
    // those inactive windows, and bound retained distinct addresses without
    // evicting unexpired limits. Sweep at most once per second under churn.
    if (now >= nextRateSweepAt) {
      for (const [address, entry] of rate) {
        if (entry.active === 0 && now - entry.windowStart >= config.admissionWindowMs) rate.delete(address);
      }
      nextRateSweepAt = now + Math.min(config.admissionWindowMs, 1000);
    }
    let state = rate.get(ip);
    if (!state && rate.size >= MAX_RATE_ENTRIES) return null;
    if (!state || now - state.windowStart >= config.admissionWindowMs) state = { windowStart: now, admissions: 0, active: state ? state.active : 0 };
    if (state.admissions >= config.maxAdmissionsPerIp || state.active >= config.maxSocketsPerIp) return null;
    state.admissions += 1;
    state.active += 1;
    rate.set(ip, state);
    return state;
  }
  function releaseSlot(ip) {
    const state = rate.get(ip);
    if (!state) return;
    state.active = Math.max(0, state.active - 1);
    if (state.active === 0 && config.clock() - state.windowStart >= config.admissionWindowMs) rate.delete(ip);
  }
  function isOpen(ws) { return ws && (ws.readyState === undefined || ws.readyState === 1); }
  function relayCall(method, ...args) {
    try { return sync(config.relay[method](...args), 'ONLINE_FRA_WS_RELAY_ASYNC'); }
    catch (error) {
      if (error instanceof OnlineFraWebSocketAdapterError) throw error;
      /* CARRY THE RELAY'S REASON ALONGSIDE, without changing this error's own
         code -- every existing caller and test still sees the same
         ONLINE_FRA_WS_RELAY_FAILED. It is carried because this wrapper was
         throwing away the one fact the caller needed: the relay closes a
         connection deliberately (a newer browser tab displacing an older one,
         an expired lease, a retired pair) and, with the reason gone, drain()
         could only report every one of them as an internal error. A person's
         displaced tab then told them their computer had not answered.
         Shape-guarded, so only a relay constant travels -- never a message. */
      const wrapped = new OnlineFraWebSocketAdapterError('ONLINE_FRA_WS_RELAY_FAILED');
      wrapped.relayCode = typeof error === 'object' && error !== null && typeof error.code === 'string'
        && /^ONLINE_FRA_[A-Z0-9_]{1,48}$/.test(error.code) ? error.code : null;
      throw wrapped;
    }
  }
  function closeRelay(context) {
    if (!context.connectionId || context.relayClosed) return;
    context.relayClosed = true;
    try { relayCall('close', context.connectionId, 'ONLINE_FRA_WS_CONNECTION_CLOSED'); } catch {}
  }
  function closeContext(context, reason, code = 1008, socketAlreadyClosed = false) {
    if (!context || context.cleaned) return;
    context.cleaned = true;
    forgetChallenge(context, 'challengeNonce');
    forgetChallenge(context, 'renewalNonce');
    if (context.timer !== null) config.clearTimer(context.timer);
    live.delete(context);
    releaseSlot(context.attestation.ip);
    closeRelay(context);
    try { emit('online_fra.ws.closed', { reason, session: context.meta }); } catch {}
    /* SAY WHY, WHERE AN OPERATOR CAN READ IT. The metadata sink counts closes
       by type and keeps no reason, which is right for a privacy-preserving
       record and useless when a machine will not stay connected. Diagnosing
       three separate causes tonight -- a lost pair topology, an exhausted
       per-device connection budget, and an admission the client believed had
       succeeded -- each required hand-patching this function on the live box,
       because the machine end cannot tell a refusal from a network fault and
       the relay was the only party that knew.
       Identifier-free by construction: a reason from the closed set above, the
       close code, whether admission had completed, and the leg's role. No
       device id, no pair id, no address, nothing the sink itself would
       refuse to keep. */
    try {
      /* The drop tally rides along on the close line: a socket that spent its
         whole life talking to a leg that was not there is the single most
         useful thing this log can say about it. */
      const dropped = context.dropped
        ? Object.keys(context.dropped).map(role => `${role}x${context.dropped[role]}`).join(',')
        : 'none';
      config.log(`connection closed: reason=${reason} code=${code} admitted=${Boolean(context.admitted)} role=${context.role || 'none'} detail=${context.detail || 'none'} dropped=${dropped}`);
    } catch { /* a logger that throws must not stop a close */ }
    if (!socketAlreadyClosed) {
      try { if (context.ws && typeof context.ws.close === 'function') context.ws.close(code); } catch {}
      try {
        if (context.ws && context.ws.readyState !== 3 && typeof context.ws.terminate === 'function') context.ws.terminate();
      } catch {}
    }
  }
  function schedule(context) {
    if (context.cleaned) return;
    context.timer = config.setTimer(() => {
      context.timer = null;
      if (context.cleaned) return;
      const now = config.clock();
      if (!context.admitted && now >= context.admissionDeadline) return closeContext(context, 'admission_timeout');
      if (context.admitted && now - context.lastActivity >= config.idleTimeoutMs) return closeContext(context, 'idle_timeout', 1001);
      if (context.admitted && now - context.lastPing >= config.pingIntervalMs) {
        try { if (typeof context.ws.ping !== 'function') fail('ONLINE_FRA_WS_PING_UNAVAILABLE'); context.ws.ping(); context.lastPing = now; }
        catch { return closeContext(context, 'ping_failed', 1011); }
      }
      if (context.admitted) drain(context);
      schedule(context);
    }, Math.min(config.admissionTimeoutMs, config.pingIntervalMs, SESSION_RECHECK_MS));
  }
  function refreshPeer(context) {
    const metadata = relayCall('connectionMetadata', context.connectionId);
    if (!plain(metadata) || !Object.hasOwn(metadata, 'peerConnectionId')
      || (metadata.peerConnectionId !== null && !CONNECTION_ID.test(metadata.peerConnectionId))) {
      fail('ONLINE_FRA_WS_RELAY_CONNECT_INVALID');
    }
    context.peerConnectionId = metadata.peerConnectionId;
    if (typeof metadata.endpointRole === 'string') context.role = metadata.endpointRole;
    return context.peerConnectionId !== null;
  }
  function drain(context) {
    if (context.cleaned || !context.admitted || !isOpen(context.ws)) return;
    try {
      // refreshPeer() keeps the machine link current for the metadata it
      // reports; its answer no longer gates delivery, because a web endpoint
      // has no machine-peer link and still has frames queued for it.
      refreshPeer(context);
      // Revocation and expiry must still run when a receiver stops reading.
      if (Number(context.ws.bufferedAmount || 0) > config.maxBufferedBytes) return;
      for (let count = 0; count < config.maxDrainPerTick && Number(context.ws.bufferedAmount || 0) <= config.maxBufferedBytes; count += 1) {
        const frame = relayCall('take', context.connectionId);
        if (frame === null || frame === undefined) return;
        if (!Buffer.isBuffer(frame) || frame.length < 1 || frame.length > config.maxFrameBytes) fail('ONLINE_FRA_WS_RELAY_FRAME_INVALID');
        if (typeof context.ws.send !== 'function') fail('ONLINE_FRA_WS_SEND_UNAVAILABLE');
        context.ws.send(Buffer.from(frame), { binary: true });
      }
    } catch (error) {
      /* A CONNECTION THE RELAY CLOSED ON PURPOSE IS NOT AN INTERNAL ERROR.
         Everything here closed as 1011 relay_drain_failed, including the most
         ordinary event on this edge: a person's newer browser tab displacing
         their older one. The older tab's page could then only report that the
         computer had not answered, which was false and unactionable. The relay
         now names the reason it closed a connection, so the ones it MEANT are
         reported as what they are and the browser can say the true thing. */
      const code = typeof error === 'object' && error !== null ? error.relayCode : null;
      if (code === 'ONLINE_FRA_WEB_DISPLACED') { context.detail = code; return closeContext(context, 'displaced', CLOSE_DISPLACED); }
      if (code === 'ONLINE_FRA_WEB_SESSION_REVOKED') { context.detail = code; return closeContext(context, 'session_revoked', 1008); }
      if (code === 'ONLINE_FRA_CONNECTION_UNAUTHORIZED') { context.detail = code; return closeContext(context, 'authorization_revoked', 1008); }
      if (RELAY_ENDED_IT.has(code)) { context.detail = code; return closeContext(context, 'relay_ended_connection', 1000); }
      closeContext(context, 'relay_drain_failed', 1011);
    }
  }
  /* DELIVER TO THE RECEIVER, WHICH IS THE WHOLE POINT OF HAVING ROUTED.
   *
   * A routed frame is queued against the TARGET's connection, and only that
   * target's own drain() takes it off the queue. Routing used to drain the
   * SENDER and nobody else, which left the sole periodic drain as schedule()'s
   * timer at min(admissionTimeoutMs, pingIntervalMs) -- ten seconds at the
   * shipped defaults. So a request handed to a machine that was sitting idle
   * (which is what a machine waiting for work IS) waited up to ten seconds to
   * be delivered, and its answer up to ten seconds more. Twenty seconds for a
   * round trip the tunnel itself completes in single-digit milliseconds.
   *
   * It was invisible everywhere it was tested: every in-process test drives
   * both legs through a synchronous shim, where each leg is drained by its own
   * next send. Only two real sockets with one idle end show it, which is
   * exactly the shape of the product.
   *
   * The lookup is a scan of the live set, bounded by maxSockets. The periodic
   * timer stays as the backstop for a receiver that was over its buffer ceiling
   * when the frame arrived. */
  function deliverTo(connectionId) {
    let target = null;
    for (const candidate of live) {
      if (candidate.connectionId === connectionId) { target = candidate; break; }
    }
    /* Drained outside the loop: drain() can close a context, and closing
       removes it from the set being iterated. */
    if (target) drain(target);
  }
  function forgetChallenge(context, field) {
    const nonce = context[field];
    context[field] = null;
    if (nonce && config.keyAdmission && typeof config.keyAdmission.cancelChallenge === 'function') {
      try { config.keyAdmission.cancelChallenge(nonce); } catch {}
    }
  }

  // Renewal control frames never enter the opaque routing queues. Possession
  // must be proved again against a fresh challenge on this socket; the core
  // then validates a new signed lease for the very same endpoint. Refusal
  // leaves the old lease's deadline intact, including during account outages.
  function renew(context, data) {
    if (!Buffer.isBuffer(data) || data.length < 1 || data.length > config.maxAdmissionBytes
        || Number(context.ws.bufferedAmount || 0) > config.maxBufferedBytes) fail('ONLINE_FRA_WS_RENEWAL_INVALID');
    let parsed;
    try { parsed = JSON.parse(data.toString('utf8')); } catch { fail('ONLINE_FRA_WS_RENEWAL_INVALID'); }
    if (!plain(parsed) || !Object.hasOwn(parsed, 'renew')) fail('ONLINE_FRA_WS_RENEWAL_INVALID');
    const refuse = code => {
      context.ws.send(JSON.stringify({ renewalRefused: { code } }));
      // Revocation/expiry may have closed the core while refusing this lease.
      // Carry that closure through to the socket before accepting more data.
      drain(context);
    };
    if (context.attestation.mode !== 'key' || typeof config.keyAdmission?.renew !== 'function') {
      return refuse('ONLINE_FRA_WS_RENEWAL_UNSUPPORTED');
    }
    if (parsed.renew === 'request') {
      if (Object.keys(parsed).length !== 1) fail('ONLINE_FRA_WS_RENEWAL_INVALID');
      const atMs = config.clock();
      if (context.renewalNonce && atMs < context.renewalDeadline) return refuse('ONLINE_FRA_WS_RENEWAL_BUSY');
      forgetChallenge(context, 'renewalNonce');
      if (context.lastRenewalRequestAtMs !== null && atMs - context.lastRenewalRequestAtMs < MIN_RENEWAL_INTERVAL_MS) {
        return refuse('ONLINE_FRA_WS_RENEWAL_THROTTLED');
      }
      // No challenge for an endpoint that has expired or been withdrawn.
      relayCall('connectionMetadata', context.connectionId);
      context.lastRenewalRequestAtMs = atMs;
      const issued = sync(config.keyAdmission.challenge({ connectionId: context.connectionId }), 'ONLINE_FRA_WS_RELAY_ASYNC');
      if (!plain(issued) || typeof issued.nonce !== 'string' || issued.nonce.length < 16
          || !Number.isSafeInteger(issued.expiresAtMs) || issued.expiresAtMs <= atMs) fail('ONLINE_FRA_WS_RENEWAL_INVALID');
      context.renewalNonce = issued.nonce;
      context.renewalDeadline = Math.min(issued.expiresAtMs, atMs + config.admissionTimeoutMs);
      context.ws.send(JSON.stringify({ challenge: issued.nonce, expiresAtMs: context.renewalDeadline, renewal: true }));
      return;
    }
    const keys = ['renew', 'publicKeySpki', 'nonce', 'signature'];
    if (Object.keys(parsed).length !== keys.length || keys.some(key => !Object.hasOwn(parsed, key))
        || !plain(parsed.renew)) fail('ONLINE_FRA_WS_RENEWAL_INVALID');
    if (typeof parsed.nonce !== 'string' || !context.renewalNonce || parsed.nonce !== context.renewalNonce) {
      return refuse('ONLINE_FRA_WS_RENEWAL_NONCE_MISMATCH');
    }
    if (config.clock() >= context.renewalDeadline) {
      forgetChallenge(context, 'renewalNonce');
      return refuse('ONLINE_FRA_WS_RENEWAL_EXPIRED');
    }
    let renewed;
    try {
      renewed = sync(config.keyAdmission.renew({ connectionId: context.connectionId,
        lease: parsed.renew, browserPublicKeySpki: parsed.publicKeySpki,
        nonce: parsed.nonce, signature: parsed.signature }), 'ONLINE_FRA_WS_RELAY_ASYNC');
    } catch (error) {
      const code = typeof error?.code === 'string' && /^ONLINE_FRA_[A-Z0-9_]{1,48}$/.test(error.code)
        ? error.code : 'ONLINE_FRA_WS_RENEWAL_REFUSED';
      return refuse(code);
    } finally {
      forgetChallenge(context, 'renewalNonce');
    }
    if (!plain(renewed) || typeof renewed.leaseId !== 'string' || !SAFE_ID.test(renewed.leaseId)
        || !Number.isSafeInteger(renewed.expiresAtMs) || renewed.expiresAtMs <= config.clock()) fail('ONLINE_FRA_WS_RENEWAL_INVALID');
    context.ws.send(JSON.stringify({ renewed: { leaseId: renewed.leaseId, expiresAtMs: renewed.expiresAtMs } }));
    drain(context);
  }

  function admit(context, data, binary) {
    if (binary || !Buffer.isBuffer(data) || data.length < 1 || data.length > config.maxAdmissionBytes) fail('ONLINE_FRA_WS_ADMISSION_INVALID');
    let parsed;
    try { parsed = JSON.parse(data.toString('utf8')); } catch { fail('ONLINE_FRA_WS_ADMISSION_INVALID'); }
    let connected;
    if (context.attestation.mode === 'key') {
      // The possession proof. Exactly four keys, and the nonce must be the one
      // THIS socket was challenged with -- a valid proof for some other
      // socket's nonce admits nothing here, whatever keyAdmission would say.
      const keys = ['lease', 'publicKeySpki', 'nonce', 'signature'];
      if (!plain(parsed) || Object.keys(parsed).length !== keys.length || keys.some(key => !Object.hasOwn(parsed, key))
        || parsed.lease === null || typeof parsed.nonce !== 'string' || parsed.nonce !== context.challengeNonce) fail('ONLINE_FRA_WS_ADMISSION_INVALID');
      try {
        connected = sync(config.keyAdmission.admit({ lease: parsed.lease, browserPublicKeySpki: parsed.publicKeySpki, nonce: parsed.nonce, signature: parsed.signature }), 'ONLINE_FRA_WS_RELAY_ASYNC');
      } catch (error) { if (error instanceof OnlineFraWebSocketAdapterError) throw error;
        /* KEEP THE REASON, AND ONLY THE REASON. keyAdmission refuses with a
           code from a closed set -- a bad signature, a lease bound to another
           pair, an exhausted per-device budget -- and collapsing all three
           into `admission_failed` is what made this take three nights. The
           shape guard is the privacy line: a SCREAMING_CASE constant is kept,
           anything else (a message, a path, an address) becomes 'unknown'. */
        context.detail = typeof error === 'object' && error !== null && typeof error.code === 'string'
          && /^[A-Z][A-Z0-9_]{2,63}$/.test(error.code) ? error.code : 'unknown';
        fail('ONLINE_FRA_WS_ADMISSION_INVALID'); }
      if (!plain(connected) || !CONNECTION_ID.test(connected.connectionId)) fail('ONLINE_FRA_WS_RELAY_CONNECT_INVALID');
      // Identity is known now; the session label follows it.
      context.attestation = Object.freeze({ mode: 'key', deviceId: String(parsed.lease.deviceId), fingerprint: String(parsed.lease.mtlsFingerprint), ip: context.attestation.ip });
      context.meta = metadataFingerprint(context.attestation);
      context.role = parsed.lease.endpointRole;
    } else {
      if (!plain(parsed) || Object.keys(parsed).length !== 1 || !Object.hasOwn(parsed, 'lease') || parsed.lease === null) fail('ONLINE_FRA_WS_ADMISSION_INVALID');
      const identity = Object.freeze({ verified: true, authType: 'mtls', deviceId: context.attestation.deviceId, mtlsFingerprint: context.attestation.fingerprint });
      connected = relayCall('connect', { identity, lease: parsed.lease });
      if (!plain(connected) || !CONNECTION_ID.test(connected.connectionId)) fail('ONLINE_FRA_WS_RELAY_CONNECT_INVALID');
      context.role = parsed.lease && parsed.lease.endpointRole;
    }

    context.connectionId = connected.connectionId;
    forgetChallenge(context, 'challengeNonce');
    refreshPeer(context);
    // THE ROLE COMES FROM THE RELAY (refreshPeer reads it off the metadata the
    // relay reports for the connection it just admitted); the lease in hand is
    // the fallback for a relay double that reports none. A role the leg table
    // does not know cannot be addressed, so it cannot be admitted.
    if (!Object.hasOwn(LEG_BYTE, context.role)) fail('ONLINE_FRA_WS_RELAY_CONNECT_INVALID');
    context.admitted = true;
    context.lastActivity = config.clock();
    context.lastPing = context.lastActivity;
    try { emit('online_fra.ws.admitted', { session: context.meta }); }
    catch { closeContext(context, 'event_sink_failed', 1011); return; }
    drain(context);
  }
  function onMessage(context, data, binary) {
    if (context.cleaned) return;
    try {
      context.lastActivity = config.clock();
      if (!context.admitted) return admit(context, data, binary);
      if (!binary) return renew(context, data);
      if (!binary || !Buffer.isBuffer(data) || data.length < 2 || data.length > config.maxFrameBytes
        || Number(context.ws.bufferedAmount || 0) > config.maxBufferedBytes) fail('ONLINE_FRA_WS_FRAME_INVALID');
      // The leg byte is the address. Resolve it against the pair's live legs
      // as the relay reports them NOW, not as they were at admission.
      const targetRole = LEG_ROLE[data[0]];
      if (!targetRole || targetRole === context.role) fail('ONLINE_FRA_WS_FRAME_INVALID');
      const metadata = relayCall('connectionMetadata', context.connectionId);
      if (!plain(metadata) || !plain(metadata.legs)) fail('ONLINE_FRA_WS_RELAY_CONNECT_INVALID');
      const targetId = metadata.legs[targetRole];
      if (targetId === null || targetId === undefined) {
        // AN ABSENT LEG IS A NORMAL STATE, NOT A VIOLATION. The peer has not
        // connected yet, or the browser tab is closed. A hello sent a moment
        // early must not cost the sender its socket and a fresh lease; it is
        // dropped, counted, and the sender retries on its own schedule. The
        // relay never delivered it, so nothing sealed went anywhere.
        context.lastActivity = config.clock();
        try { emit('online_fra.ws.frame_dropped', { reason: 'leg_absent', session: context.meta }); } catch {}
        /* AND IT IS SAID OUT LOUD, ONCE, because "normal" and "silent" are not
           the same thing and treating them as one cost a day.
           A browser whose machine is missing retries its hello every second for
           thirty seconds and every one of those was dropped here without a
           trace, so the machine looked switched off while it was connected and
           the relay looked healthy while it was delivering nothing. The event
           above has existed the whole time; nothing was listening to it.
           Bounded on purpose: the FIRST drop per socket per missing leg gets a
           line, the rest are counted and reported when the socket closes. Thirty
           identical lines per dial would be its own kind of silence. */
        context.dropped = context.dropped || Object.create(null);
        context.dropped[targetRole] = (context.dropped[targetRole] || 0) + 1;
        if (context.dropped[targetRole] === 1) {
          config.log(`frame dropped: no ${targetRole} leg on this pair to deliver to`
            + ` (from ${context.role || 'none'})`);
        }
        return;
      }
      if (!CONNECTION_ID.test(targetId)) fail('ONLINE_FRA_WS_RELAY_CONNECT_INVALID');
      context.peerConnectionId = metadata.peerConnectionId;
      // Stamp the SOURCE leg in place of the target byte: same length, and the
      // receiver learns who sent it without the edge adding a second frame.
      const frame = Buffer.from(data);
      frame[0] = LEG_BYTE[context.role];
      relayCall('route', { connectionId: context.connectionId, peerConnectionId: targetId, frame });
      drain(context);
      deliverTo(targetId);
    } catch (error) {
      // An independently authorized sender survives a destination's account
      // revocation between routing lookups; the revoked source still closes.
      if (context.admitted && error && error.relayCode === 'ONLINE_FRA_CONNECTION_UNAUTHORIZED') {
        try { relayCall('connectionMetadata', context.connectionId); return; } catch {}
      }
      if (error instanceof OnlineFraWebSocketAdapterError && !context.detail) context.detail = error.code;
      closeContext(context, context.admitted ? 'frame_invalid' : 'admission_failed');
    }
  }
  function attach(ws, attestation) {
    const context = { ws, attestation, meta: metadataFingerprint(attestation), timer: null, cleaned: false, admitted: false,
      relayClosed: false, challengeNonce: null, renewalNonce: null, renewalDeadline: null,
      lastRenewalRequestAtMs: null, role: null, detail: null,
      connectionId: null, peerConnectionId: null, admissionDeadline: config.clock() + config.admissionTimeoutMs,
      lastActivity: config.clock(), lastPing: config.clock() };
    live.add(context);
    if (attestation.mode === 'key') {
      // FIRST FRAME FROM THE EDGE: the challenge. The endpoint has until the
      // admission deadline to answer with the proof; an unanswered challenge
      // costs the nonce store one entry for NONCE_TTL_MS and nothing else.
      let issued;
      try { issued = sync(config.keyAdmission.challenge(), 'ONLINE_FRA_WS_RELAY_ASYNC'); }
      catch { return closeContext(context, 'challenge_failed', 1011); }
      if (!plain(issued) || typeof issued.nonce !== 'string' || issued.nonce.length < 16) return closeContext(context, 'challenge_failed', 1011);
      context.challengeNonce = issued.nonce;
      try {
        if (typeof ws.send !== 'function') fail('ONLINE_FRA_WS_SEND_UNAVAILABLE');
        ws.send(JSON.stringify({ challenge: issued.nonce, expiresAtMs: issued.expiresAtMs }));
      } catch { return closeContext(context, 'challenge_failed', 1011); }
    }
    const once = (event, handler) => { if (typeof ws.once === 'function') ws.once(event, handler); else if (typeof ws.on === 'function') ws.on(event, handler); };
    if (typeof ws.on !== 'function') return closeContext(context, 'socket_invalid');
    ws.on('message', (data, binary) => onMessage(context, data, binary));
    ws.on('pong', () => { if (!context.cleaned) context.lastActivity = config.clock(); });
    once('close', () => closeContext(context, 'socket_close', 1000, true));
    once('error', () => closeContext(context, 'socket_error'));
    try { emit('online_fra.ws.connected', { session: context.meta }); }
    catch { return closeContext(context, 'event_sink_failed', 1011); }
    schedule(context);
  }
  function upgrade(req, socket, head) {
    if (!started || !req || req.method !== 'GET' || req.url !== '/v1/rendezvous' || !Buffer.isBuffer(head) || head.length !== 0 || live.size >= config.maxSockets) return reject(socket);
    const attestation = attestationFor(req);
    if (!attestation || !admissionSlot(attestation.ip)) return reject(socket);
    try {
      wss.handleUpgrade(req, socket, head, ws => attach(ws, attestation));
    } catch {
      releaseSlot(attestation.ip);
      reject(socket);
    }
  }
  const api = {
    start() {
      if (!config.enabled || started) return false;
      wss = new config.WebSocketServer({ noServer: true, maxPayload: config.maxFrameBytes, perMessageDeflate: false });
      config.httpServer.on('upgrade', upgrade);
      started = true;
      return true;
    },
    stop() {
      for (const context of [...live]) closeContext(context, 'adapter_stop', 1001);
      if (started) config.httpServer.off('upgrade', upgrade);
      try { if (wss && typeof wss.close === 'function') wss.close(); } catch {}
      wss = null;
      rate.clear();
      nextRateSweepAt = 0;
      started = false;
      return true;
    },
    revoke() { for (const context of [...live]) closeContext(context, 'revoked', 1008); return true; },
    kill() { return this.revoke(); },
    drain() { for (const context of [...live]) drain(context); },
    snapshot() { return Object.freeze({ enabled: config.enabled, started, sockets: live.size, rateEntries: rate.size }); }
  };
  return Object.freeze(api);
}

module.exports = Object.freeze({ DEFAULTS, OnlineFraWebSocketAdapterError, createOnlineFraWebSocketAdapter });
