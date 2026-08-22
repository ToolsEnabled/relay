'use strict';

// The relay service shell -- the thing that finally RUNS the library.
//
// Composition, all existing pieces: SQLite lease state -> metadata sink (the
// privacy-true one) -> rendezvous relay with the ASK ruling's admission
// authority -> optionally the websocket adapter on an injected HTTP server.
// Plus the one new piece: the CONTROL CHANNEL, a loopback-only HTTP listener
// the account service calls so that enrolment registers pairs, removal cuts
// live connections, and account deletion reaches the durable pair record.
//
// THE ASK CHECK reads the ACCOUNT DATABASE READ-ONLY, in-process, one
// synchronous SELECT -- which is what the relay's synchronous
// admissionAuthority hook needs, and what the account server's ONE-PROCESS
// invariant allows: that invariant protects WRITE races (the allowance
// count-then-insert), and a WAL reader holds no write lock. Opened with
// readOnly so this process CANNOT hold one, by construction. Fail closed: an
// unreadable database refuses admission rather than guessing.
//
// The SQL restates device-registry.js accountForRelayPair() semantics -- a
// pair resolves only while BOTH machines are unrevoked, or, for a SOLO pair
// (one computer: a relay_pairs row with b_pair_id NULL), while its one
// machine is -- and the cross-repo seam test is what keeps the restatement
// honest.

const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const { DatabaseSync } = require('node:sqlite');

const { createOnlineFraRendezvousRelay } = require('./online-fra-rendezvous-relay');
const { createOnlineFraSqliteLeaseState } = require('./online-fra-sqlite-lease-state');
const { createOnlineFraMetadataSink } = require('./online-fra-metadata-sink');

/* THE B MACHINE IS A LEFT JOIN, because a pair may be SOLO. The account side
   (the server half's contract) stores a solo pair as a relay_pairs row with
   b_pair_id NULL -- one computer, no half; every other column is unchanged.
   The WHERE clause is what keeps the old rule intact for every row that DOES
   name a B: a non-null b_pair_id whose device is missing or revoked leaves
   b.pair_id NULL and is refused exactly as the inner join refused it. Only a
   NULL b_pair_id is excused from needing one, and revoking a solo's one
   machine refuses at the A join exactly as a revoked half does. */
const ASK_SQL = `SELECT rp.account_id AS accountId FROM relay_pairs rp
  JOIN devices a ON a.pair_id = rp.a_pair_id AND a.revoked_at_ms IS NULL
  LEFT JOIN devices b ON b.pair_id = rp.b_pair_id AND b.revoked_at_ms IS NULL
  WHERE rp.relay_pair_id = ? AND (rp.b_pair_id IS NULL OR b.pair_id IS NOT NULL)`;

/* EVERY LIVE PAIR, FOR THE RECOVERY BELOW. The same joins the ASK authority
   makes, without the id filter: a pair is live when both its machines are
   still enrolled -- or, for a SOLO row (b_pair_id NULL), when its one machine
   is -- and the account service is the one that decides that. A solo row
   comes back with machineBId NULL, which is exactly the shape registerPair
   takes for a solo pair; a row naming a B that is missing, revoked or not yet
   carrying a device id is excluded exactly as before. */
const LIVE_PAIRS_SQL = `SELECT rp.relay_pair_id AS pairId, rp.capability_digest AS capabilityDigest,
    a.device_id AS machineAId, b.device_id AS machineBId
  FROM relay_pairs rp
  JOIN devices a ON a.pair_id = rp.a_pair_id AND a.revoked_at_ms IS NULL
  LEFT JOIN devices b ON b.pair_id = rp.b_pair_id AND b.revoked_at_ms IS NULL
  WHERE a.device_id IS NOT NULL AND (rp.b_pair_id IS NULL OR b.device_id IS NOT NULL)`;

class OnlineFraRelayServiceError extends Error {
  constructor(code, message) {
    super(message || code);
    this.name = 'OnlineFraRelayServiceError';
    this.code = code;
  }
}

function fail(code, message) { throw new OnlineFraRelayServiceError(code, message); }

function requireString(value, code, message) {
  if (typeof value !== 'string' || value.length === 0) fail(code, message);
  return value;
}

/**
 * Build one relay service from config. Nothing listens until start().
 *
 * config:
 *   accountDbPath        the account service's device database (read-only here)
 *   leaseStatePath       this service's own SQLite lease state
 *   authorityPublicKeyPem  the minting authority's public half (PEM string)
 *   generation           relay instance generation (matches the minter's)
 *   control: { host='127.0.0.1', port=4820, token }  token REQUIRED, >=32 chars
 *   maxPairs             optional; relay default (16) unless raised
 *   pathTrustAttestor    Windows only, forwarded to the lease state
 *   eventSink            optional; DEFAULTS to the metadata sink. Anything
 *                        else is a deliberate retention decision by the
 *                        deployer, named in the privacy review.
 */
function createOnlineFraRelayService(config = {}) {
  const accountDbPath = requireString(config.accountDbPath, 'RELAY_SERVICE_CONFIG_INVALID', 'accountDbPath is required.');
  const leaseStatePath = requireString(config.leaseStatePath, 'RELAY_SERVICE_CONFIG_INVALID', 'leaseStatePath is required.');
  const authorityPem = requireString(config.authorityPublicKeyPem, 'RELAY_SERVICE_CONFIG_INVALID', 'authorityPublicKeyPem is required.');
  const control = config.control || {};
  const controlHost = control.host || '127.0.0.1';
  const controlPort = Number.isInteger(control.port) ? control.port : 4820;
  const controlToken = requireString(control.token, 'RELAY_SERVICE_CONFIG_INVALID',
    'control.token is required: an unauthenticated control channel is an unauthenticated revoke-everything.');
  if (controlToken.length < 32) fail('RELAY_SERVICE_CONFIG_INVALID', 'control.token must be at least 32 characters.');
  // Loopback only, structurally. The control channel cuts customer
  // connections and deletes durable records; exposing it beyond this box is a
  // different design, not a config value.
  if (controlHost !== '127.0.0.1' && controlHost !== '::1') {
    fail('RELAY_SERVICE_CONFIG_INVALID', 'control.host must be loopback.');
  }
  if (!fs.existsSync(accountDbPath)) fail('RELAY_SERVICE_ACCOUNT_DB_ABSENT', `No account database at ${accountDbPath}.`);

  // --- the ASK authority: read-only, fail-closed ---------------------------
  let accountDb = null;
  function openAccountDb() {
    // readOnly by construction: this process must never be able to take a
    // write lock on the account database (the ONE-PROCESS invariant is a
    // write-side property, and this keeps it provably untouched).
    accountDb = new DatabaseSync(accountDbPath, { readOnly: true });
  }
  function admissionAuthority(request) {
    try {
      if (!accountDb) return false;
      const row = accountDb.prepare(ASK_SQL).get(request.pairId);
      return Boolean(row && typeof row.accountId === 'string' && row.accountId.length > 0);
    } catch {
      // Unreadable is a refusal, never a guess -- and never a crash: a
      // throwing authority would refuse with a stack instead of a code.
      return false;
    }
  }

  // --- the composition ------------------------------------------------------
  const metadataSink = createOnlineFraMetadataSink();

  // SEAM C + FAIR-USE LAYER 2: the reporter, a SECOND consumer BESIDE the
  // sink, never a change to it. The identifier-free sink and the tests that
  // grep its own source stay exactly as they are; legal's <<SPEC>> binds
  // deployments to "the default sink + the monthly total and nothing richer",
  // and this satisfies it by construction.
  //
  // Two things cross this channel, both to the account box, both with a
  // NARROW bearer token that is deliberately not the control token (whose
  // blast radius includes delete-pair):
  //   - admission outcomes: { deviceId, outcome, refusedBy } -- named codes
  //     only, on admission events only, never per frame. This is the whole of
  //     what AI support gets to see.
  //   - the monthly relayed-volume total per pair, for the published 10 GB
  //     figure -- a byte count, not a log.
  //
  // FAIL-OPEN, CONCRETELY: a bounded queue that drops OLDEST on overflow. An
  // unbounded "fail-open" queue turns a dead account box into relay memory
  // pressure, which is a worse outcome than the lost support answer this
  // channel is allowed to cost. Absent config = no reporting (self-host).
  const report = config.report || null;
  if (report !== null) {
    if (typeof report.baseUrl !== 'string' || !/^https?:\/\//.test(report.baseUrl)) {
      fail('RELAY_SERVICE_CONFIG_INVALID', 'report.baseUrl must be an http(s) origin.');
    }
    if (typeof report.token !== 'string' || report.token.length < 32) {
      fail('RELAY_SERVICE_CONFIG_INVALID', 'report.token must be at least 32 characters.');
    }
    if (report.token === controlToken) {
      fail('RELAY_SERVICE_CONFIG_INVALID', 'report.token must not be the control token: a diagnostic reporter must not be able to delete anything.');
    }
  }
  const REPORT_QUEUE_MAX = 256;
  const reportQueue = [];
  const monthlyPairBytes = new Map(); // pairId -> { month: 'YYYY-MM', bytes }
  let reportTimer = null;

  function enqueueReport(kind, payload) {
    if (!report) return;
    if (reportQueue.length >= REPORT_QUEUE_MAX) reportQueue.shift(); // drop OLDEST
    reportQueue.push({ kind, payload });
  }

  // LAYER 2 IS PARKED, DELIBERATELY. The monthly per-pair byte total has no
  // destination: the account service's live route is connection-outcomes only.
  // It is kept here and surfaced on /control/health so the figure exists the
  // day they add a route -- posting it into a shape that does not exist would
  // earn a 400 and lose the number.
  function meterConsumer(event) {
    if (!event || typeof event !== 'object') return;
    if (event.type === 'online_fra.frame.routed' && typeof event.pairId === 'string') {
      const month = new Date(event.atMs || Date.now()).toISOString().slice(0, 7);
      const entry = monthlyPairBytes.get(event.pairId);
      if (!entry || entry.month !== month) monthlyPairBytes.set(event.pairId, { month, bytes: event.bytes || 0 });
      else entry.bytes += event.bytes || 0;
    }
    if (event.type === 'online_fra.pair.paired') {
      enqueueReport('connection-outcome', { pairId: event.pairId, outcome: 'paired', refusedBy: null });
    }
  }

  // THE ACCOUNT SERVICE'S CONTRACT, and this was wrong once: an earlier draft
  // here sent a BATCHED body ({outcomes:[…], volumes:[…]}). The route
  // (verified 2026-08-20) takes ONE object per POST:
  // { deviceId, outcome, refusedBy? }, and refuses anything else with 400.
  //
  // Two mechanisms keep that class of mistake from going quiet, and they are
  // the reason fail-open is safe to have: the pre-send validation in
  // flushReports() below, which never puts an unattributable report on the
  // wire, and the 4xx branch in postOutcome(), which counts and logs a
  // contract disagreement rather than discarding it. Fail-open covers the
  // account box being unreachable. It was never meant to cover the two sides
  // disagreeing about the payload.
  //
  // refusedBy is 'account' | 'relay' | OMITTED -- never null.
  // outcome must match OUTCOME_SHAPE.
  // deviceId must be real: the account side translates device -> machine, and
  // a refusal too malformed to name a device cannot be attributed at all.
  const OUTCOME_SHAPE = /^[A-Za-z][A-Za-z0-9_.]{1,63}$/;
  let reportsDropped = 0;
  let reportsRejected = 0;

  async function postOutcome(payload) {
    const body = { deviceId: payload.deviceId, outcome: payload.outcome };
    if (payload.refusedBy === 'account' || payload.refusedBy === 'relay') body.refusedBy = payload.refusedBy;
    let response;
    try {
      response = await fetch(`${report.baseUrl}/v1/relay-reports/connection-outcome`, {
        method: 'POST',
        headers: { authorization: `Bearer ${report.token}`, 'content-type': 'application/json' },
        body: JSON.stringify(body)
      });
    } catch {
      // Transport failure -- the account box down, DNS, TLS. The report is
      // dropped rather than retried, and that is the deliberate order of
      // priorities: this channel is diagnostic, and a diagnostic must never
      // block, delay or fail a customer's connection. The cost is bounded to
      // one support answer.
      return;
    }
    // A 4xx is NOT a transport failure -- it is a contract disagreement, and
    // a shape mismatch is exactly the thing that must not pass unnoticed.
    // 202 {"recorded": false} is the documented account-side fail-open for
    // unknown/revoked devices and is a success here.
    if (response.status >= 400 && response.status < 500) {
      reportsRejected += 1;
      // eslint-disable-next-line no-console -- the SHELL may log; the relay core may not.
      console.error(`[relay-report] REJECTED ${response.status} -- the account service refused this report shape. Contract drift; diagnostics are not arriving.`);
    }
  }

  async function flushReports() {
    if (!report || reportQueue.length === 0) return;
    const batch = reportQueue.splice(0, reportQueue.length);
    for (const item of batch) {
      if (item.kind !== 'connection-outcome') continue;
      const payload = item.payload;
      if (typeof payload.deviceId !== 'string' || payload.deviceId.length === 0
        || !OUTCOME_SHAPE.test(String(payload.outcome))) {
        // Unattributable or unnameable: counted, never sent. Sending it would
        // earn a 400 and teach us nothing.
        reportsDropped += 1;
        continue;
      }
      await postOutcome(payload);
    }
  }

  const baseSink = typeof config.eventSink === 'function' ? config.eventSink : metadataSink.sink;
  const eventSink = event => {
    baseSink(event);
    try { meterConsumer(event); } catch { /* the reporter must never take down routing */ }
  };

  const leaseState = createOnlineFraSqliteLeaseState({
    enabled: true,
    dbPath: leaseStatePath,
    ...(config.pathTrustAttestor ? { pathTrustAttestor: config.pathTrustAttestor } : {})
  });

  // THE FRAME CEILING IS PINNED HERE, BECAUSE HERE IS THE DEPLOYMENT.
  //
  // The engine's sealing session builds frames up to 256 KiB (its own comment:
  // "Keep the serialized base64url frame below the edge/relay 256 KiB
  // ceiling"), and the websocket edge defaults to 256 KiB -- but the relay
  // CORE'S library default is a conservative 64 KiB. Deployed on defaults, a
  // full-size sealed frame passed the edge, was refused by route() as
  // ONLINE_FRA_OPAQUE_FRAME_INVALID, and the adapter closed the connection: at
  // shipped defaults, a large tool result could not cross the hosted relay AT
  // ALL. Found by the paid lane, 2026-08-19.
  //
  // The library default stays conservative on purpose (docs/CROSS-REPO.md
  // calls the layering deliberate, and it is). A DEFAULT is not a DEPLOYMENT:
  // the shell is the one place that knows it is composing the hosted stack, so
  // the shell is where the client's ceiling is made the configured truth. The
  // queue chain moves with it to satisfy the core's own ordering invariant
  // (maxFrame <= perConnection <= perDevice <= perPair).
  const maxFrameBytes = Number.isInteger(config.maxFrameBytes) ? config.maxFrameBytes : 256 * 1024;
  const maxQueuedBytesPerConnection = Number.isInteger(config.maxQueuedBytesPerConnection)
    ? config.maxQueuedBytesPerConnection : Math.max(maxFrameBytes, 256 * 1024);
  const maxQueuedBytesPerDevice = Number.isInteger(config.maxQueuedBytesPerDevice)
    ? config.maxQueuedBytesPerDevice : maxQueuedBytesPerConnection;
  const maxQueuedBytesPerPair = Number.isInteger(config.maxQueuedBytesPerPair)
    ? config.maxQueuedBytesPerPair : maxQueuedBytesPerDevice * 2;

  const relay = createOnlineFraRendezvousRelay({
    enabled: true,
    authorityPublicKey: crypto.createPublicKey(authorityPem),
    generation: Number.isInteger(config.generation) ? config.generation : 1,
    pairs: [],
    ...(Number.isInteger(config.maxPairs) ? { maxPairs: config.maxPairs } : {}),
    ...(config.pairRateLimit ? { pairRateLimit: config.pairRateLimit } : {}),
    maxFrameBytes,
    maxQueuedBytesPerConnection,
    maxQueuedBytesPerDevice,
    maxQueuedBytesPerPair,
    eventSink,
    leaseState,
    admissionAuthority
  });

  // Admission outcomes come from wrapping connect() -- the event stream never
  // sees refusals (connect throws before any event), and the edge is the only
  // other place that knows, so the shell records them here. refusedBy is the
  // closed two-value set: the ASK refusal is the account's; everything else
  // (expiry, replay, capacity, protocol) is the relay's.
  const servedRelay = !report ? relay : Object.freeze({
    ...relay,
    connect(request) {
      try {
        const receipt = relay.connect(request);
        enqueueReport('connection-outcome', { deviceId: receipt.deviceId, outcome: 'accepted', refusedBy: null });
        return receipt;
      } catch (error) {
        const deviceId = request && request.lease && typeof request.lease.deviceId === 'string' ? request.lease.deviceId : null;
        enqueueReport('connection-outcome', {
          deviceId,
          outcome: (error && error.code) || 'ONLINE_FRA_REFUSED',
          refusedBy: error && error.code === 'ONLINE_FRA_PAIR_UNAUTHORIZED' ? 'account' : 'relay'
        });
        throw error;
      }
    }
  });

  // --- the control channel --------------------------------------------------
  function authorized(request) {
    const header = request.headers.authorization || '';
    if (!header.startsWith('Bearer ')) return false;
    const presented = Buffer.from(header.slice(7), 'utf8');
    const expected = Buffer.from(controlToken, 'utf8');
    return presented.length === expected.length && crypto.timingSafeEqual(presented, expected);
  }

  function readJson(request) {
    return new Promise((resolve, reject) => {
      const chunks = [];
      let size = 0;
      request.on('data', chunk => {
        size += chunk.length;
        if (size > 16 * 1024) { reject(new Error('oversized')); request.destroy(); return; }
        chunks.push(chunk);
      });
      request.on('end', () => {
        try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); }
        catch { reject(new Error('unreadable')); }
      });
      request.on('error', reject);
    });
  }

  // Each action answers with what ACTUALLY happened, never with what was
  // asked. Deletion composes the full teardown: cut live connections, drop
  // the topology, remove the durable record -- the account service calls ONE
  // route and the privacy policy's "end to end" is this route being complete.
  const actions = {
    'register-pair': body => {
      const initialized = leaseState.initializePair({
        pairId: body.pairId, generation: body.generation, capabilityDigest: body.capabilityDigest
      });
      if (initialized.outcome === 'conflict') return { ok: false, outcome: 'conflict' };
      let receipt;
      try {
        receipt = relay.registerPair({
          pairId: body.pairId, machineAId: body.machineAId,
          machineBId: body.machineBId, capabilityDigest: body.capabilityDigest
        });
      } catch (error) {
        /* ALREADY REGISTERED IS A SUCCESS, NOT A REFUSAL -- and since the boot
           recovery below, it is the ordinary case rather than a strange one:
           this service rebuilds its topology from the account database at
           start, so a pair formed before a restart is already here the next
           time the account service speaks about it. Answering 409 would make
           the account service undo a person's connection over a retry it was
           right to make.

           Narrow on purpose. initializePair has already compared the
           generation and the capability digest against the durable record and
           answered `conflict` if either moved, so reaching this line means it
           is the same pair. Every other failure still refuses. */
        if (error.code !== 'ONLINE_FRA_RELAY_PAIR_INVALID') throw error;
        return { ok: true, outcome: 'already-registered', pairCount: relay.snapshot().pairCount };
      }
      return { ok: true, outcome: 'registered', pairCount: receipt.pairCount };
    },
    'retire-pair': body => {
      relay.retirePair({ pairId: body.pairId });
      return { ok: true, outcome: 'retired' };
    },
    'revoke-pair': body => {
      relay.revokePair({ pairId: body.pairId, generation: body.generation });
      return { ok: true, outcome: 'revoked' };
    },
    'delete-pair': body => {
      try { relay.retirePair({ pairId: body.pairId }); }
      catch (error) { if (error.code !== 'ONLINE_FRA_RETIREMENT_INVALID') throw error; }
      const removed = leaseState.deletePair({ pairId: body.pairId });
      return { ok: true, outcome: removed.outcome };
    }
  };

  let controlServer = null;

  function handleControl(request, response) {
    const answer = (status, body) => {
      response.writeHead(status, { 'content-type': 'application/json' });
      response.end(JSON.stringify(body));
    };
    if (!authorized(request)) return answer(401, { ok: false, code: 'CONTROL_UNAUTHORIZED' });
    if (request.method === 'GET' && request.url === '/control/health') {
      return answer(200, {
        ok: true,
        relay: relay.snapshot(),
        events: metadataSink.snapshot(),
        reporting: {
          configured: Boolean(report),
          queued: reportQueue.length,
          dropped: reportsDropped,
          rejected: reportsRejected,
          // Parked until the account service has a route for it; see meterConsumer.
          monthlyVolumes: [...monthlyPairBytes].map(([pairId, entry]) => ({ pairId, month: entry.month, bytes: entry.bytes }))
        }
      });
    }
    const name = request.method === 'POST' && request.url.startsWith('/control/')
      ? request.url.slice('/control/'.length) : null;
    const action = name && actions[name];
    if (!action) return answer(404, { ok: false, code: 'CONTROL_UNKNOWN' });
    readJson(request).then(body => {
      try { answer(200, action(body)); }
      catch (error) { answer(409, { ok: false, code: error.code || 'CONTROL_REFUSED' }); }
    }).catch(() => answer(400, { ok: false, code: 'CONTROL_BODY_INVALID' }));
  }

  /* THE PAIR TOPOLOGY SURVIVES A RESTART, BECAUSE IT NEVER DID.
   *
   * A pair reached this process exactly one way: the account service calling
   * `register-pair` over the control channel the moment a person connected two
   * computers. `relay.registerPair` puts it in an in-memory map. The lease
   * state beneath it is durable sqlite; the topology on top of it was not.
   *
   * So every restart of this service -- a deploy, a crash, a reboot -- silently
   * dropped every pair on the box. Machines then presented perfectly valid,
   * freshly minted leases and were refused ONLINE_FRA_LEASE_BINDING_INVALID at
   * `pairs.get(source.pairId)`, which reads to the machine as an admission
   * failure it cannot explain and to the person as a computer that stopped
   * answering for no reason. Nothing recovered: the account service only calls
   * register-pair when a pair is FORMED, so a person's machines stayed dark
   * until they deleted the connection and made it again. Measured, not
   * theorised: restarting this service mid-session turned a working pair into
   * an admission failure on the next connect, every time.
   *
   * The account database is already open here, read-only, for the ASK
   * authority. It holds the same three facts register-pair carries. So the
   * topology is rebuilt from it at boot, and the durable lease state is
   * re-initialised alongside -- `initializePair` answers `conflict` only when a
   * digest CHANGED, which is a real generation conflict and is skipped and
   * counted rather than forced.
   *
   * Read-only, fail-soft, and loud in the boot banner: a relay that cannot
   * rebuild its topology must still start and refuse honestly, because a relay
   * that refuses to boot serves nobody at all. */
  function recoverPairs() {
    const outcome = { recovered: 0, conflicts: 0, skipped: 0, readable: false };
    if (!accountDb) return outcome;
    let rows;
    try { rows = accountDb.prepare(LIVE_PAIRS_SQL).all(); } catch { return outcome; }
    outcome.readable = true;
    /* Taken from the relay rather than from config, so the durable lease state
       is initialised with exactly the generation the relay will later compare a
       lease against. Reading it twice from two places is how those two numbers
       start to differ. */
    const relayGeneration = relay.snapshot().generation;
    for (const row of rows) {
      try {
        const initialized = leaseState.initializePair({
          pairId: row.pairId, generation: relayGeneration, capabilityDigest: row.capabilityDigest,
        });
        if (initialized.outcome === 'conflict') { outcome.conflicts += 1; continue; }
        relay.registerPair({
          pairId: row.pairId, machineAId: row.machineAId,
          machineBId: row.machineBId, capabilityDigest: row.capabilityDigest,
        });
        outcome.recovered += 1;
      } catch { outcome.skipped += 1; }
    }
    return outcome;
  }

  function start() {
    openAccountDb();
    leaseState.open();
    const recovery = recoverPairs();
    if (report) {
      reportTimer = setInterval(() => { flushReports(); }, Number.isInteger(report.flushMs) ? report.flushMs : 30_000);
      if (reportTimer.unref) reportTimer.unref();
    }
    controlServer = http.createServer(handleControl);
    return new Promise((resolve, reject) => {
      controlServer.once('error', reject);
      controlServer.listen(controlPort, controlHost, () => resolve({ controlPort: controlServer.address().port, recovery }));
    });
  }

  async function stop() {
    if (reportTimer) { clearInterval(reportTimer); reportTimer = null; }
    await flushReports(); // best effort; a dead account box costs the batch, nothing else
    const closing = controlServer
      ? new Promise(resolve => controlServer.close(() => resolve())) : Promise.resolve();
    controlServer = null;
    if (accountDb) { try { accountDb.close(); } catch { /* already closed */ } accountDb = null; }
    try { leaseState.close(); } catch { /* already closed */ }
    return closing;
  }

  return Object.freeze({
    start, stop, relay: servedRelay, leaseState, metadataSink, admissionAuthority,
    // Test seams for the reporting channel; harmless to expose, and proving
    // fail-open needs to see the queue bound from outside.
    flushReports,
    reportQueueSize: () => reportQueue.length,
    reportStats: () => ({ dropped: reportsDropped, rejected: reportsRejected })
  });
}

module.exports = Object.freeze({ OnlineFraRelayServiceError, createOnlineFraRelayService, ASK_SQL });
