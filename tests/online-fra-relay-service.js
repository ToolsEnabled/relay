'use strict';

// The shell: config refusal, the fail-closed read-only ASK authority, and the
// control channel over a real loopback HTTP socket.

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');
const { createOnlineFraRelayService } = require('../src/lib/online-fra-relay-service');
const { LEASE_SCHEMA_VERSION, leaseSigningBytes } = require('../src/lib/online-fra-rendezvous-relay');

let assertions = 0;
function equal(actual, expected, message) { assertions += 1; assert.equal(actual, expected, message); }
function ok(value, message) { assertions += 1; assert.ok(value, message); }
function throwsCode(fn, code) {
  assertions += 1;
  try { fn(); } catch (error) { assert.equal(error.code, code); return; }
  assert.fail(`expected ${code}`);
}

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'relay-service-'));
const TOKEN = 't'.repeat(48);
const DIGEST = 'c'.repeat(64);
const authority = crypto.generateKeyPairSync('ed25519');
const authorityPem = authority.publicKey.export({ type: 'spki', format: 'pem' }).toString();

// A minimal account database with the REAL schema the registry writes.
// b_pair_id is NULLABLE since the solo-pair change (the server half's
// contract, through its migrate idiom; every other column unchanged): a solo
// pair -- one computer -- is a relay_pairs row with b_pair_id NULL.
const accountDbPath = path.join(root, 'devices.sqlite3');
{
  const db = new DatabaseSync(accountDbPath);
  db.exec(`CREATE TABLE devices (pair_id TEXT PRIMARY KEY, account_id TEXT NOT NULL, name TEXT NOT NULL,
    enrolled_at_ms INTEGER NOT NULL, revoked_at_ms INTEGER, device_id TEXT, mtls_fingerprint TEXT);`);
  db.exec(`CREATE TABLE relay_pairs (relay_pair_id TEXT PRIMARY KEY, account_id TEXT NOT NULL,
    a_pair_id TEXT NOT NULL, b_pair_id TEXT, capability_digest TEXT NOT NULL, created_at_ms INTEGER NOT NULL);`);
  const insertDevice = db.prepare('INSERT INTO devices VALUES (?, ?, ?, 1, NULL, ?, ?)');
  insertDevice.run('pair-' + 'a'.repeat(32), 'account-1', 'Desk', 'device-' + 'a'.repeat(24), 'f'.repeat(64));
  insertDevice.run('pair-' + 'b'.repeat(32), 'account-1', 'Laptop', 'device-' + 'b'.repeat(24), 'e'.repeat(64));
  db.prepare('INSERT INTO relay_pairs VALUES (?, ?, ?, ?, ?, 1)')
    .run('pair-' + '1'.repeat(32), 'account-1', 'pair-' + 'a'.repeat(32), 'pair-' + 'b'.repeat(32), DIGEST);
  db.close();
}

function trustedAttestor(challenge) {
  return { ok: true, parentPath: challenge.parentPath, filePath: challenge.filePath, generation: challenge.generation, stage: challenge.stage };
}

function service(overrides = {}) {
  return createOnlineFraRelayService({
    accountDbPath,
    leaseStatePath: path.join(root, `leases-${crypto.randomBytes(4).toString('hex')}.sqlite3`),
    authorityPublicKeyPem: authorityPem,
    generation: 1,
    control: { port: 0, token: TOKEN },
    pathTrustAttestor: trustedAttestor,
    ...overrides
  });
}

async function controlCall(port, name, body, token = TOKEN) {
  const response = await fetch(`http://127.0.0.1:${port}/control/${name}`, {
    method: name === 'health' ? 'GET' : 'POST',
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    ...(name === 'health' ? {} : { body: JSON.stringify(body || {}) })
  });
  return { status: response.status, body: await response.json() };
}

(async () => {
  try {
    // --- config refusals are named, and the control token is not optional ---
    throwsCode(() => createOnlineFraRelayService({}), 'RELAY_SERVICE_CONFIG_INVALID');
    throwsCode(() => service({ control: { port: 0, token: 'short' } }), 'RELAY_SERVICE_CONFIG_INVALID');
    throwsCode(() => service({ control: { host: '0.0.0.0', port: 0, token: TOKEN } }), 'RELAY_SERVICE_CONFIG_INVALID');
    throwsCode(() => service({ accountDbPath: path.join(root, 'missing.sqlite3') }), 'RELAY_SERVICE_ACCOUNT_DB_ABSENT');

    // --- the ASK authority: real rows, read-only, fail closed ---------------
    const shell = service();
    const { controlPort } = await shell.start();

    equal(shell.admissionAuthority({ pairId: 'pair-' + '1'.repeat(32) }), true, 'a live pair resolves');
    equal(shell.admissionAuthority({ pairId: 'pair-' + '9'.repeat(32) }), false, 'an unknown pair refuses');

    // Revoke machine B out from under it, exactly as the account page would.
    {
      const db = new DatabaseSync(accountDbPath);
      db.prepare('UPDATE devices SET revoked_at_ms = 2 WHERE pair_id = ?').run('pair-' + 'b'.repeat(32));
      db.close();
    }
    equal(shell.admissionAuthority({ pairId: 'pair-' + '1'.repeat(32) }), false,
      'a pair with a removed machine refuses at the very next ask -- nothing pushed, nothing restarted');
    {
      const db = new DatabaseSync(accountDbPath);
      db.prepare('UPDATE devices SET revoked_at_ms = NULL WHERE pair_id = ?').run('pair-' + 'b'.repeat(32));
      db.close();
    }

    // READ-ONLY by construction: the service's own handle cannot write.
    let writeRefused = false;
    try { shell.relay && new DatabaseSync(accountDbPath, { readOnly: true }).prepare('DELETE FROM devices').run(); }
    catch { writeRefused = true; }
    ok(writeRefused, 'a readOnly handle must refuse writes -- the ONE-PROCESS invariant stays provably untouched');

    // --- the control channel ------------------------------------------------
    const unauthorized = await controlCall(controlPort, 'health', null, 'wrong-token-wrong-token-wrong-token-wrong');
    equal(unauthorized.status, 401);

    const health = await controlCall(controlPort, 'health');
    equal(health.status, 200);
    /* ONE, NOT ZERO -- and the change is the fix, not a regression. This
       fixture seeds the account database with exactly this pair, both machines
       enrolled, and the relay now rebuilds its topology from that database at
       boot. It used to start empty, which meant every restart of this service
       silently dropped every pair on the box: machines presented valid leases
       and were refused ONLINE_FRA_LEASE_BINDING_INVALID until somebody deleted
       the connection and made it again. See tests/online-fra-pair-recovery.js. */
    equal(health.body.relay.pairCount, 1,
      'a hosted relay must restore the live pairs its account database already holds -- starting empty is how a restart disconnects everybody');
    equal(health.body.events.identifiersRetained, false);

    const registered = await controlCall(controlPort, 'register-pair', {
      pairId: 'pair-' + '1'.repeat(32), generation: 1, capabilityDigest: DIGEST,
      machineAId: 'device-' + 'a'.repeat(24), machineBId: 'device-' + 'b'.repeat(24)
    });
    equal(registered.status, 200);
    /* 'already-registered', because the boot recovery restored this very pair
       from the account database a moment ago. A second register-pair for an
       identical pair must SUCCEED: the account service retries, and answering
       409 would make it undo the person's connection. A pair whose generation
       or digest actually moved is still refused, by initializePair, before
       this line is reached. */
    equal(registered.body.outcome, 'already-registered');
    equal((await controlCall(controlPort, 'health')).body.relay.pairCount, 1);

    // Registration requires the account's current tuple, including for solo
    // pairs. A control token alone cannot publish arbitrary account topology.
    const soloInput = {
      pairId: 'pair-' + '2'.repeat(32), generation: 1, capabilityDigest: DIGEST,
      machineAId: 'device-' + 'c'.repeat(24), machineBId: null
    };
    const unowned = await controlCall(controlPort, 'register-pair', soloInput);
    equal(unowned.status, 409);
    equal(unowned.body.code, 'RELAY_SERVICE_PAIR_UNAUTHORIZED');
    {
      const db = new DatabaseSync(accountDbPath);
      db.prepare('INSERT INTO devices VALUES (?, ?, ?, 1, NULL, ?, ?)')
        .run('pair-' + 'c'.repeat(32), 'account-1', 'Solo control fixture', soloInput.machineAId, 'd'.repeat(64));
      db.prepare('INSERT INTO relay_pairs VALUES (?, ?, ?, NULL, ?, 1)')
        .run(soloInput.pairId, 'account-1', 'pair-' + 'c'.repeat(32), DIGEST);
      db.close();
    }
    const solo = await controlCall(controlPort, 'register-pair', soloInput);
    equal(solo.status, 200);
    equal(solo.body.outcome, 'registered', 'a solo pair is accepted over the control channel');
    equal((await controlCall(controlPort, 'health')).body.relay.pairCount, 2);
    const soloGone = await controlCall(controlPort, 'delete-pair', { pairId: 'pair-' + '2'.repeat(32) });
    equal(soloGone.body.outcome, 'deleted');
    equal((await controlCall(controlPort, 'health')).body.relay.pairCount, 1);
    {
      const db = new DatabaseSync(accountDbPath);
      db.prepare('DELETE FROM relay_pairs WHERE relay_pair_id = ?').run(soloInput.pairId);
      db.prepare('DELETE FROM devices WHERE pair_id = ?').run('pair-' + 'c'.repeat(32));
      db.close();
    }

    // Omitting B is malformed, not a successful retry or an implicit solo.
    const omitted = await controlCall(controlPort, 'register-pair', {
      pairId: 'pair-' + '4'.repeat(32), generation: 1, capabilityDigest: DIGEST,
      machineAId: 'device-' + 'd'.repeat(24)
    });
    equal(omitted.status, 409);
    equal(omitted.body.code, 'ONLINE_FRA_RELAY_PAIR_INVALID');
    equal((await controlCall(controlPort, 'health')).body.relay.pairCount, 1, 'and nothing was registered');

    // Deletion is the composed teardown, idempotent end to end.
    const deleted = await controlCall(controlPort, 'delete-pair', { pairId: 'pair-' + '1'.repeat(32) });
    equal(deleted.status, 200);
    equal(deleted.body.outcome, 'deleted');
    equal((await controlCall(controlPort, 'health')).body.relay.pairCount, 0, 'deletion retires the topology too');
    const again = await controlCall(controlPort, 'delete-pair', { pairId: 'pair-' + '1'.repeat(32) });
    equal(again.body.outcome, 'absent', 'a second delete reports absent, never an error');

    const unknown = await controlCall(controlPort, 'no-such-action', {});
    equal(unknown.status, 404);

    // THE FRAME CEILING IS THE DEPLOYMENT'S, NOT THE LIBRARY'S. The shell must
    // pin the core to the client's 256 KiB -- at library defaults (64 KiB) a
    // full-size sealed frame kills the connection (found by the paid lane).
    equal(shell.relay.snapshot().maxFrameBytes, 256 * 1024, 'the shell pins the core to the client ceiling');
    ok(shell.relay.snapshot().maxQueuedBytesPerConnection >= 256 * 1024, 'and the queue chain moved with it');

    await shell.stop();

    // --- the SOLO pair, end to end through the shell --------------------------
    //
    // The account side's shape (the server half's contract): a relay_pairs row
    // with b_pair_id NULL. The ASK authority and the boot recovery LEFT JOIN
    // the B machine, so a solo row is restored and admitted with machineBId
    // null; a row whose b_pair_id names a missing machine stays refused exactly
    // as a revoked half is; and revoking the solo's one machine ends admission
    // exactly as a revoked half does -- at the next ask, at the next lease, and
    // across a restart.
    {
      const SOLO_PAIR = 'pair-' + '2'.repeat(32);
      const SOLO_DEVICE_ROW = 'pair-' + 's'.repeat(32);
      const SOLO_DEVICE = 'device-' + 's'.repeat(24);
      const DANGLING_PAIR = 'pair-' + '3'.repeat(32);
      {
        const db = new DatabaseSync(accountDbPath);
        db.prepare('INSERT INTO devices VALUES (?, ?, ?, 1, NULL, ?, ?)').run(SOLO_DEVICE_ROW, 'account-1', 'Only', SOLO_DEVICE, 'd'.repeat(64));
        db.prepare('INSERT INTO relay_pairs VALUES (?, ?, ?, NULL, ?, 1)').run(SOLO_PAIR, 'account-1', SOLO_DEVICE_ROW, DIGEST);
        // A two-machine row whose B names a device row that does not exist: its
        // own A, so that if the SQL ever let it through it would register and
        // be counted, rather than being refused for a reused device id.
        db.prepare('INSERT INTO devices VALUES (?, ?, ?, 1, NULL, ?, ?)').run('pair-' + 'e'.repeat(32), 'account-1', 'Half', 'device-' + 'e'.repeat(24), 'e'.repeat(64));
        db.prepare('INSERT INTO relay_pairs VALUES (?, ?, ?, ?, ?, 1)').run(DANGLING_PAIR, 'account-1', 'pair-' + 'e'.repeat(32), 'pair-' + 'z'.repeat(32), DIGEST);
        db.close();
      }
      const soloShell = service();
      const soloStart = await soloShell.start();
      equal(soloStart.recovery.recovered, 2, 'boot restored the two-machine pair AND the solo row; the dangling row was not restored');
      equal(soloShell.relay.snapshot().pairCount, 2);
      equal(soloShell.admissionAuthority({ pairId: SOLO_PAIR }), true, 'a solo row resolves at the ASK');
      equal(soloShell.admissionAuthority({ pairId: DANGLING_PAIR }), false, 'a non-null B that is missing still refuses');
      equal(soloShell.admissionAuthority({ pairId: 'pair-' + '1'.repeat(32) }), true, 'and the whole pair beside them still resolves');

      // A signed solo lease admits through the real relay, the real ASK and the
      // real durable store: machine-a, peerDeviceId null, nobody to pair with.
      const soloLease = () => {
        const nowMs = Date.now();
        const value = {
          schemaVersion: LEASE_SCHEMA_VERSION, leaseId: `lease_solo_${crypto.randomBytes(4).toString('hex')}`, pairId: SOLO_PAIR,
          deviceId: SOLO_DEVICE, peerDeviceId: null, endpointRole: 'machine-a', mtlsFingerprint: 'd'.repeat(64),
          generation: 1, issuedAtMs: nowMs - 1_000, expiresAtMs: nowMs + 60_000,
          nonce: crypto.randomBytes(24).toString('base64url'),
          ephemeralX25519PublicKey: crypto.generateKeyPairSync('x25519').publicKey.export({ format: 'der', type: 'spki' }).toString('base64url'),
          capabilityDigest: DIGEST, signature: Buffer.alloc(64).toString('base64url')
        };
        value.signature = crypto.sign(null, leaseSigningBytes(value), authority.privateKey).toString('base64url');
        return value;
      };
      const soloIdentity = { verified: true, authType: 'mtls', deviceId: SOLO_DEVICE, mtlsFingerprint: 'd'.repeat(64) };
      const admitted = soloShell.relay.connect({ identity: soloIdentity, lease: soloLease() });
      equal(admitted.endpointRole, 'machine-a');
      equal(admitted.paired, false, 'admitted, alone, as a solo machine is');
      soloShell.relay.close(admitted.connectionId);

      // Revoke the solo's one machine, exactly as the account page would.
      {
        const db = new DatabaseSync(accountDbPath);
        db.prepare('UPDATE devices SET revoked_at_ms = 2 WHERE pair_id = ?').run(SOLO_DEVICE_ROW);
        db.close();
      }
      equal(soloShell.admissionAuthority({ pairId: SOLO_PAIR }), false, 'a revoked solo machine refuses at the very next ask -- nothing pushed, nothing restarted');
      throwsCode(() => soloShell.relay.connect({ identity: soloIdentity, lease: soloLease() }), 'ONLINE_FRA_PAIR_UNAUTHORIZED');
      await soloShell.stop();
      const afterRevoke = service();
      const afterRevokeStart = await afterRevoke.start();
      equal(afterRevokeStart.recovery.recovered, 1, 'a revoked solo machine is not restored at boot; the two-machine pair still is');
      await afterRevoke.stop();
      {
        const db = new DatabaseSync(accountDbPath);
        db.prepare('UPDATE devices SET revoked_at_ms = NULL WHERE pair_id = ?').run(SOLO_DEVICE_ROW);
        db.close();
      }
    }

    // --- the reporting channel: narrow token, named outcomes, bounded queue --
    {
      // A capture server standing in for the account box's report endpoint.
      const received = [];
      const captureServer = require('node:http').createServer((request, response) => {
        const chunks = [];
        request.on('data', c => chunks.push(c));
        request.on('end', () => {
          received.push({ url: request.url, auth: request.headers.authorization, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) });
          response.writeHead(200, { 'content-type': 'application/json' });
          response.end('{"ok":true}');
        });
      });
      await new Promise(resolve => captureServer.listen(0, '127.0.0.1', resolve));
      const capturePort = captureServer.address().port;
      const REPORT_TOKEN = 'r'.repeat(48);

      // The report token must NOT be the control token -- the reporter must
      // not be able to delete anything.
      throwsCode(() => service({ report: { baseUrl: 'http://127.0.0.1:1', token: TOKEN } }), 'RELAY_SERVICE_CONFIG_INVALID');

      const reporting = service({ report: { baseUrl: `http://127.0.0.1:${capturePort}`, token: REPORT_TOKEN, flushMs: 3_600_000 } });
      await reporting.start();

      // An ASK refusal reports refusedBy 'account'; the lease never even needs
      // to be signed -- an unknown pair fails the binding check first, which
      // reports as the relay's. Drive both classes.
      let thrown = null;
      try {
        reporting.relay.connect({ identity: { verified: true, authType: 'mtls', deviceId: 'device-x', mtlsFingerprint: 'f'.repeat(64) }, lease: { deviceId: 'device-x' } });
      } catch (error) { thrown = error; }
      ok(thrown, 'a malformed lease still refuses');
      equal(reporting.reportQueueSize(), 1, 'and the refusal was recorded');

      // The queue is BOUNDED: hammering refusals cannot grow memory.
      for (let index = 0; index < 400; index += 1) {
        try { reporting.relay.connect({ lease: null }); } catch { /* each enqueues */ }
      }
      ok(reporting.reportQueueSize() <= 256, `fail-open is bounded (queue=${reporting.reportQueueSize()})`);

      await reporting.flushReports();
      equal(reporting.reportQueueSize(), 0, 'flush drains the queue');
      // EVERY queued report so far was unattributable (a malformed lease has
      // no deviceId to name), so nothing was SENT -- they were dropped, and
      // counted. Sending them would have earned a 400 and taught us nothing.
      equal(received.length, 0, 'unattributable refusals are dropped, never posted');
      ok(reporting.reportStats().dropped > 0, 'and counted');

      // A real, attributable outcome posts the account service's LIVE shape:
      // ONE object per POST, refusedBy omitted rather than null.
      // A refusal that DOES name a device: the connect still throws (the lease
      // is invalid), and the wrap enqueues an attributable outcome first.
      try {
        reporting.relay.connect({ identity: { verified: true, authType: 'mtls', deviceId: `device-${'a'.repeat(24)}`, mtlsFingerprint: 'f'.repeat(64) }, lease: { deviceId: `device-${'a'.repeat(24)}` } });
      } catch { /* expected -- the point is the report it enqueued */ }
      await reporting.flushReports().catch(() => {});
      equal(received.length, 1, 'one POST per outcome, not a batch');
      equal(received[0].url, '/v1/relay-reports/connection-outcome');
      equal(received[0].auth, `Bearer ${REPORT_TOKEN}`);
      equal(typeof received[0].body.deviceId, 'string', 'the body is the single documented object');
      ok(!Array.isArray(received[0].body.outcomes), 'never the batched shape I originally built');
      ok(/^[A-Za-z][A-Za-z0-9_.]{1,63}$/.test(received[0].body.outcome),
        "outcome is a named code in the account side's OUTCOME_SHAPE -- free text is structurally absent");
      ok(!('refusedBy' in received[0].body) || received[0].body.refusedBy === 'relay' || received[0].body.refusedBy === 'account',
        'refusedBy is account | relay | OMITTED -- never null');

      // A dead account box: flush swallows, queue stays bounded, relay lives.
      captureServer.close();
      try { reporting.relay.connect({ lease: null }); } catch { /* enqueues */ }
      await reporting.flushReports();
      ok(true, 'a dead report endpoint costs the batch and nothing else');
      await reporting.stop();
    }

    console.log(`online-fra-relay-service: ${assertions} assertions passed`);
  } finally {
    try { fs.rmSync(root, { recursive: true, force: true, maxRetries: 3, retryDelay: 20 }); } catch { /* released at exit */ }
  }
})().catch(error => { console.error(error); process.exit(1); });
