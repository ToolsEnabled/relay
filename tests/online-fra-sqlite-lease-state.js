'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');
const {
  createOnlineFraSqliteLeaseState,
  SCHEMA_VERSION,
  APPLICATION_ID
} = require('../src/lib/online-fra-sqlite-lease-state');
const { createOnlineFraRendezvousRelay, LEASE_SCHEMA_VERSION } = require('../src/lib/online-fra-rendezvous-relay');

let assertions = 0;
const equal = (...args) => { assertions += 1; return assert.equal(...args); };
const deepEqual = (...args) => { assertions += 1; return assert.deepEqual(...args); };
const ok = (...args) => { assertions += 1; return assert.ok(...args); };
function throws(run, predicate) { assertions += 1; return assert.throws(run, predicate); }

const DIGEST = 'a'.repeat(64);
const OTHER_DIGEST = 'b'.repeat(64);
const MARKER = 'PRIVATE-MARKER-NOT-FOR-SQLITE-923847';
let now = 5_000_000;
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'online-fra-lease-state-'));
const file = name => path.join(root, `${name}.sqlite`);
const request = (overrides = {}) => ({
  leaseId: 'lease-alpha', pairId: 'pair-alpha', generation: 1,
  deviceId: 'device-alpha', peerDeviceId: 'device-bravo', capabilityDigest: DIGEST,
  nonce: Buffer.alloc(16, 7).toString('base64url'), expiresAtMs: now + 60_000,
  ...overrides
});
const pair = (overrides = {}) => ({ pairId: 'pair-alpha', generation: 1, capabilityDigest: DIGEST, ...overrides });
function trustedPathTrustAttestor(challenge) {
  return {
    ok: true,
    parentPath: challenge.parentPath,
    filePath: challenge.filePath,
    generation: challenge.generation,
    stage: challenge.stage
  };
}
const state = (name, options = {}) => createOnlineFraSqliteLeaseState({
  enabled: true,
  dbPath: file(name),
  clock: () => now,
  pathTrustAttestor: trustedPathTrustAttestor,
  ...options
});

try {
  equal(SCHEMA_VERSION, 1);
  ok(Number.isSafeInteger(APPLICATION_ID));

  {
    const disabledFile = file('disabled');
    const disabled = createOnlineFraSqliteLeaseState({ enabled: false, dbPath: disabledFile, clock: () => now });
    equal(fs.existsSync(disabledFile), false);
    equal(disabled.open(), false);
    equal(fs.existsSync(disabledFile), false);
    throws(() => disabled.pairState({ pairId: 'pair-alpha', generation: 1 }), error => error && error.code === 'ONLINE_FRA_SQLITE_DISABLED');
    throws(() => disabled.initializePair(pair()), error => error && error.code === 'ONLINE_FRA_SQLITE_DISABLED');
  }

  {
    const primary = state('primary');
    equal(primary.open(), true);
    equal(primary.open(), true);
    deepEqual(primary.initializePair(pair()), { ok: true, outcome: 'initialized', generation: 1 });
    deepEqual(primary.initializePair(pair()), { ok: true, outcome: 'existing', generation: 1 });
    deepEqual(primary.initializePair(pair({ capabilityDigest: OTHER_DIGEST })), { ok: true, outcome: 'conflict', generation: 1 });
    deepEqual(primary.pairState({ pairId: 'pair-alpha', generation: 1 }), { ok: true, revoked: false });
    deepEqual(primary.pairState({ pairId: 'pair-alpha', generation: 2 }), { ok: true, revoked: true });
    const inspection = new DatabaseSync(file('primary'));
    equal(inspection.prepare('PRAGMA journal_mode').get().journal_mode, 'wal');
    equal(inspection.prepare('PRAGMA trusted_schema').get().trusted_schema, 1, 'trusted_schema is connection-local and defaults on for an unrelated inspector');
    equal(inspection.prepare('PRAGMA synchronous').get().synchronous, 2);
    equal(inspection.prepare('PRAGMA integrity_check').get().integrity_check, 'ok');
    inspection.close();
    deepEqual(primary.pairState({ pairId: 'pair-bravo', generation: 1 }), { ok: true, revoked: true });
    const accepted = primary.admitLease(request());
    deepEqual(accepted, { ok: true, outcome: 'accepted' });
    equal(Object.isFrozen(accepted), true);
    deepEqual(primary.admitLease(request()), { ok: true, outcome: 'replayed' });
    deepEqual(primary.revokePair({ pairId: 'pair-alpha', generation: 1, reason: 'ONLINE_FRA_OWNER_REVOKED' }), { ok: true, revoked: true });
    deepEqual(primary.revokePair({ pairId: 'pair-alpha', generation: 1, reason: 'ONLINE_FRA_OWNER_REVOKED' }), { ok: true, revoked: true });
    deepEqual(primary.pairState({ pairId: 'pair-alpha', generation: 1 }), { ok: true, revoked: true });
    deepEqual(primary.admitLease(request({ leaseId: 'lease-bravo', nonce: Buffer.alloc(16, 8).toString('base64url') })), { ok: true, outcome: 'revoked' });
    equal(primary.close(), true);
    equal(primary.close(), false);
    throws(() => primary.pairState({ pairId: 'pair-alpha', generation: 1 }), error => error && error.code === 'ONLINE_FRA_SQLITE_CLOSED');
    const reopened = state('primary');
    equal(reopened.open(), true);
    deepEqual(reopened.pairState({ pairId: 'pair-alpha', generation: 1 }), { ok: true, revoked: true });
    deepEqual(reopened.admitLease(request()), { ok: true, outcome: 'revoked' });
    equal(reopened.close(), true);
  }

  {
    const first = state('atomic');
    const second = state('atomic');
    equal(first.open(), true);
    equal(second.open(), true);
    deepEqual(first.initializePair(pair()), { ok: true, outcome: 'initialized', generation: 1 });
    const identical = request({ nonce: Buffer.alloc(16, 9).toString('base64url') });
    const firstAdmission = first.admitLease(identical);
    const secondAdmission = second.admitLease(identical);
    deepEqual(firstAdmission, { ok: true, outcome: 'accepted' });
    deepEqual(secondAdmission, { ok: true, outcome: 'replayed' });
    const hashDb = new DatabaseSync(file('atomic'));
    const hashes = hashDb.prepare('SELECT nonce_hash, lease_hash FROM fra_lease_nonce WHERE pair_id = ?').get('pair-alpha');
    ok(hashes.nonce_hash !== hashes.lease_hash, 'nonce and lease-id hash domains are distinct');
    hashDb.close();
    equal(first.close(), true);
    equal(second.close(), true);
  }

  {
    const rotating = state('rotation');
    equal(rotating.open(), true);
    deepEqual(rotating.initializePair(pair()), { ok: true, outcome: 'initialized', generation: 1 });
    deepEqual(rotating.rotatePair({ pairId: 'pair-alpha', expectedGeneration: 1, nextGeneration: 2, capabilityDigest: OTHER_DIGEST }), { ok: true, outcome: 'rotated', generation: 2 });
    deepEqual(rotating.pairState({ pairId: 'pair-alpha', generation: 1 }), { ok: true, revoked: true });
    deepEqual(rotating.pairState({ pairId: 'pair-alpha', generation: 2 }), { ok: true, revoked: false });
    deepEqual(rotating.revokePair({ pairId: 'pair-alpha', generation: 1, reason: 'ONLINE_FRA_STALE_REVOKE' }), { ok: false, outcome: 'conflict' });
    deepEqual(rotating.admitLease(request({ generation: 1 })), { ok: true, outcome: 'revoked' });
    deepEqual(rotating.admitLease(request({ generation: 2, capabilityDigest: OTHER_DIGEST, nonce: Buffer.alloc(16, 10).toString('base64url') })), { ok: true, outcome: 'accepted' });
    deepEqual(rotating.rotatePair({ pairId: 'pair-alpha', expectedGeneration: 1, nextGeneration: 3, capabilityDigest: DIGEST }), { ok: true, outcome: 'conflict', generation: 2 });
    equal(rotating.close(), true);
    const restarted = state('rotation');
    equal(restarted.open(), true);
    deepEqual(restarted.pairState({ pairId: 'pair-alpha', generation: 1 }), { ok: true, revoked: true });
    deepEqual(restarted.pairState({ pairId: 'pair-alpha', generation: 2 }), { ok: true, revoked: false });
    equal(restarted.close(), true);
  }

  {
    const purging = state('purge', { purgeLimit: 1 });
    equal(purging.open(), true);
    deepEqual(purging.initializePair(pair()), { ok: true, outcome: 'initialized', generation: 1 });
    deepEqual(purging.admitLease(request({ leaseId: 'lease-purge-a', nonce: Buffer.alloc(16, 11).toString('base64url'), expiresAtMs: now + 1 })), { ok: true, outcome: 'accepted' });
    now += 2;
    deepEqual(purging.admitLease(request({ leaseId: 'lease-purge-b', nonce: Buffer.alloc(16, 12).toString('base64url'), expiresAtMs: now + 20_000 })), { ok: true, outcome: 'accepted' });
    const db = new DatabaseSync(file('purge'));
    equal(db.prepare('SELECT count(*) AS count FROM fra_lease_nonce').get().count, 1);
    db.close();
    throws(() => purging.admitLease(request({ leaseId: 'lease-expired', nonce: Buffer.alloc(16, 13).toString('base64url'), expiresAtMs: now })), error => error && error.code === 'ONLINE_FRA_SQLITE_REQUEST_INVALID');
    equal(purging.close(), true);
  }

  {
    const malformed = state('malformed');
    equal(malformed.open(), true);
    deepEqual(malformed.initializePair(pair()), { ok: true, outcome: 'initialized', generation: 1 });
    throws(() => malformed.admitLease(request({ leaseId: MARKER })), error => error && error.code === 'ONLINE_FRA_SQLITE_REQUEST_INVALID' && !error.message.includes(MARKER));
    throws(() => malformed.admitLease(request({ generation: Number.MAX_SAFE_INTEGER + 1 })), error => error && error.code === 'ONLINE_FRA_SQLITE_REQUEST_INVALID');
    throws(() => malformed.admitLease(request({ expiresAtMs: 8_640_000_000_000_001 })), error => error && error.code === 'ONLINE_FRA_SQLITE_REQUEST_INVALID');
    throws(() => malformed.admitLease({ ...request(), extra: true }), error => error && error.code === 'ONLINE_FRA_SQLITE_REQUEST_INVALID');
    throws(() => malformed.revokePair({ pairId: 'pair-alpha', generation: 1, reason: `${MARKER} !` }), error => error && error.code === 'ONLINE_FRA_SQLITE_REQUEST_INVALID');
    const hostileRequest = new Proxy(request(), { get(target, key) { if (key === 'nonce') throw new Error(MARKER); return target[key]; } });
    throws(() => malformed.admitLease(hostileRequest), error => error && error.code === 'ONLINE_FRA_SQLITE_REQUEST_INVALID' && !error.message.includes(MARKER));
    // A SOLO pair's machine lease carries peerDeviceId null (it has no peer):
    // the store admits it -- it never stored the peer anyway -- while a peer
    // that is the device itself, or an undefined one, is still refused.
    deepEqual(malformed.admitLease(request({ leaseId: 'lease-solo', peerDeviceId: null, nonce: Buffer.alloc(16, 31).toString('base64url') })), { ok: true, outcome: 'accepted' });
    throws(() => malformed.admitLease(request({ peerDeviceId: 'device-alpha', nonce: Buffer.alloc(16, 32).toString('base64url') })), error => error && error.code === 'ONLINE_FRA_SQLITE_REQUEST_INVALID');
    throws(() => malformed.admitLease(request({ peerDeviceId: undefined })), error => error && error.code === 'ONLINE_FRA_SQLITE_REQUEST_INVALID');
    equal(malformed.close(), true);
  }

  {
    throws(() => createOnlineFraSqliteLeaseState({ enabled: true, dbPath: 'relative.sqlite' }).open(), error => error && error.code === 'ONLINE_FRA_SQLITE_PATH_INVALID');
    throws(() => createOnlineFraSqliteLeaseState({ enabled: true, dbPath: path.join(root, 'state', 'forbidden.sqlite') }).open(), error => error && error.code === 'ONLINE_FRA_SQLITE_PATH_INVALID');
    throws(() => createOnlineFraSqliteLeaseState({ enabled: true, dbPath: path.join(root, 'no-parent', 'missing.sqlite') }).open(), error => error && error.code === 'ONLINE_FRA_SQLITE_PATH_INVALID');
    throws(() => createOnlineFraSqliteLeaseState({ enabled: true, dbPath: file('async-open'), openDatabase: () => Promise.resolve({}), pathTrustAttestor: trustedPathTrustAttestor }).open(), error => error && error.code === 'ONLINE_FRA_SQLITE_UNAVAILABLE');
    const corrupt = file('corrupt');
    fs.writeFileSync(corrupt, 'not a sqlite database');
    throws(() => state('corrupt').open(), error => error && ['ONLINE_FRA_SQLITE_UNAVAILABLE', 'ONLINE_FRA_SQLITE_SCHEMA_INVALID'].includes(error.code) && !error.message.includes(corrupt));
    const schema = file('schema');
    const wrong = new DatabaseSync(schema);
    wrong.exec('PRAGMA application_id = 7; PRAGMA user_version = 99; CREATE TABLE unrelated(x INTEGER);');
    wrong.close();
    throws(() => state('schema').open(), error => error && error.code === 'ONLINE_FRA_SQLITE_SCHEMA_INVALID');
    const partial = file('partial');
    const interrupted = new DatabaseSync(partial);
    interrupted.exec('CREATE TABLE fra_pair_state(pair_id TEXT PRIMARY KEY);');
    interrupted.close();
    throws(() => state('partial').open(), error => error && error.code === 'ONLINE_FRA_SQLITE_SCHEMA_INVALID');
    const malformedSchema = file('malformed-schema');
    const malformedDb = new DatabaseSync(malformedSchema);
    malformedDb.exec(`
      PRAGMA application_id = ${APPLICATION_ID}; PRAGMA user_version = ${SCHEMA_VERSION};
      CREATE TABLE fra_pair_state (pair_id TEXT PRIMARY KEY, generation INTEGER NOT NULL, capability_digest TEXT NOT NULL, revoked INTEGER NOT NULL, updated_at_ms INTEGER NOT NULL) STRICT;
      CREATE TABLE fra_lease_nonce (pair_id TEXT NOT NULL, generation INTEGER NOT NULL, nonce_hash TEXT NOT NULL, lease_hash TEXT NOT NULL, expires_at_ms INTEGER NOT NULL, consumed_at_ms INTEGER NOT NULL) STRICT;
      CREATE INDEX fra_lease_nonce_expiry_idx ON fra_lease_nonce(expires_at_ms);
    `);
    malformedDb.prepare('INSERT INTO fra_pair_state VALUES(?, ?, ?, ?, ?)').run('pair-alpha', 1, DIGEST, 0, now);
    malformedDb.prepare('INSERT INTO fra_lease_nonce VALUES(?, ?, ?, ?, ?, ?)').run('pair-alpha', 1, 'd'.repeat(64), 'e'.repeat(64), now + 10_000, now);
    malformedDb.prepare('INSERT INTO fra_lease_nonce VALUES(?, ?, ?, ?, ?, ?)').run('pair-alpha', 1, 'd'.repeat(64), 'f'.repeat(64), now + 10_000, now);
    equal(malformedDb.prepare('SELECT count(*) AS count FROM fra_lease_nonce').get().count, 2, 'the malformed matching-name nonce table permits duplicate admissions');
    malformedDb.close();
    throws(() => state('malformed-schema').open(), error => error && error.code === 'ONLINE_FRA_SQLITE_SCHEMA_INVALID');

    // Exact exploit regression: the extra BEFORE INSERT trigger suppresses an
    // insert without an error.  The legacy name-filtered attestation admitted
    // this database, so two identical lease admissions each reported accepted
    // while no nonce row existed.  A secure state must refuse it at open.
    const triggerSeed = state('schema-trigger-exploit');
    equal(triggerSeed.open(), true);
    deepEqual(triggerSeed.initializePair(pair()), { ok: true, outcome: 'initialized', generation: 1 });
    equal(triggerSeed.close(), true);
    const triggerDb = new DatabaseSync(file('schema-trigger-exploit'));
    triggerDb.exec(`
      CREATE TRIGGER fra_ignore_lease_insert BEFORE INSERT ON fra_lease_nonce
      BEGIN
        SELECT RAISE(IGNORE);
      END;
      CREATE VIEW fra_lease_nonce_shadow AS SELECT pair_id, generation FROM fra_lease_nonce;
      CREATE INDEX fra_lease_nonce_pair_idx ON fra_lease_nonce(pair_id);
    `);
    const ignoredInsert = 'INSERT INTO fra_lease_nonce(pair_id, generation, nonce_hash, lease_hash, expires_at_ms, consumed_at_ms) VALUES(?, ?, ?, ?, ?, ?)';
    equal(triggerDb.prepare(ignoredInsert).run('pair-alpha', 1, 'c'.repeat(64), 'd'.repeat(64), now + 10_000, now).changes, 0);
    equal(triggerDb.prepare(ignoredInsert).run('pair-alpha', 1, 'c'.repeat(64), 'd'.repeat(64), now + 10_000, now).changes, 0);
    equal(triggerDb.prepare('SELECT count(*) AS count FROM fra_lease_nonce').get().count, 0);
    triggerDb.close();
    throws(() => state('schema-trigger-exploit').open(), error => error && error.code === 'ONLINE_FRA_SQLITE_SCHEMA_INVALID');

    const junction = path.join(root, 'junction');
    fs.symlinkSync(root, junction, 'junction');
    throws(() => createOnlineFraSqliteLeaseState({ enabled: true, dbPath: path.join(junction, 'junction.sqlite') }).open(), error => error && error.code === 'ONLINE_FRA_SQLITE_PATH_INVALID');
    throws(() => createOnlineFraSqliteLeaseState({ enabled: true, dbPath: '\\\\server\\share\\lease.sqlite' }).open(), error => error && error.code === 'ONLINE_FRA_SQLITE_PATH_INVALID');
    throws(() => createOnlineFraSqliteLeaseState({ enabled: true, dbPath: '\\\\?\\C:\\lease.sqlite' }).open(), error => error && error.code === 'ONLINE_FRA_SQLITE_PATH_INVALID');
  }

  if (process.platform === 'win32') {
    const requiredReceiptFile = file('windows-trust-receipt-required');
    throws(() => createOnlineFraSqliteLeaseState({ enabled: true, dbPath: requiredReceiptFile, clock: () => now }).open(), error => error && error.code === 'ONLINE_FRA_SQLITE_PATH_INVALID');
    equal(fs.existsSync(requiredReceiptFile), false, 'Windows path trust is required before SQLite creates the database');
    throws(() => state('windows-trust-receipt-invalid', { pathTrustAttestor: () => true }).open(), error => error && error.code === 'ONLINE_FRA_SQLITE_PATH_INVALID');
    throws(() => state('windows-trust-receipt-async', { pathTrustAttestor: () => Promise.resolve(true) }).open(), error => error && error.code === 'ONLINE_FRA_SQLITE_PATH_INVALID');
    const challenges = [];
    const receiptState = state('windows-trust-receipt', {
      pathTrustAttestor: challenge => {
        challenges.push(challenge);
        return trustedPathTrustAttestor(challenge);
      }
    });
    equal(receiptState.open(), true);
    equal(challenges.length, 3);
    deepEqual(challenges.map(challenge => challenge.stage), ['pre-open', 'post-open', 'post-schema']);
    for (const challenge of challenges) {
      equal(challenge.parentPath, fs.realpathSync.native(root));
      equal(challenge.filePath, file('windows-trust-receipt'));
      ok(/^[a-f0-9]{64}$/.test(challenge.generation));
    }
    equal(receiptState.close(), true);
  }

  {
    const processFile = file('process-rotation');
    const setup = state('process-rotation');
    equal(setup.open(), true);
    deepEqual(setup.initializePair(pair()), { ok: true, outcome: 'initialized', generation: 1 });
    equal(setup.close(), true);
    const moduleFile = path.resolve(__dirname, '../src/lib/online-fra-sqlite-lease-state.js');
    const childRotate = childProcess.spawnSync(process.execPath, ['-e', `const { createOnlineFraSqliteLeaseState } = require(${JSON.stringify(moduleFile)}); const pathTrustAttestor = challenge => ({ ok: true, parentPath: challenge.parentPath, filePath: challenge.filePath, generation: challenge.generation, stage: challenge.stage }); const s = createOnlineFraSqliteLeaseState({ enabled: true, dbPath: process.argv[1], pathTrustAttestor }); s.open(); const r = s.rotatePair({ pairId: 'pair-alpha', expectedGeneration: 1, nextGeneration: 2, capabilityDigest: '${OTHER_DIGEST}' }); s.close(); if (r.outcome !== 'rotated') process.exit(4);`, processFile], { encoding: 'utf8' });
    equal(childRotate.status, 0, childRotate.stderr);
    const parent = state('process-rotation');
    equal(parent.open(), true);
    deepEqual(parent.pairState({ pairId: 'pair-alpha', generation: 2 }), { ok: true, revoked: false });
    deepEqual(parent.rotatePair({ pairId: 'pair-alpha', expectedGeneration: 1, nextGeneration: 3, capabilityDigest: DIGEST }), { ok: true, outcome: 'conflict', generation: 2 });
    equal(parent.close(), true);

    const processLock = file('process-lock');
    const lockSetup = state('process-lock');
    equal(lockSetup.open(), true);
    deepEqual(lockSetup.initializePair(pair()), { ok: true, outcome: 'initialized', generation: 1 });
    equal(lockSetup.close(), true);
    const ready = path.join(root, 'process-lock.ready');
    const childLock = childProcess.spawn(process.execPath, ['-e', `const fs=require('node:fs');const {DatabaseSync}=require('node:sqlite');const db=new DatabaseSync(process.argv[1]);db.exec('BEGIN EXCLUSIVE');fs.writeFileSync(process.argv[2], 'ready');setTimeout(()=>{db.exec('ROLLBACK');db.close();}, 800);`, processLock, ready], { stdio: 'ignore' });
    const sleeper = new Int32Array(new SharedArrayBuffer(4));
    const deadline = Date.now() + 2_000;
    while (!fs.existsSync(ready) && Date.now() < deadline) Atomics.wait(sleeper, 0, 0, 10);
    ok(fs.existsSync(ready), 'child process acquired its SQLite lock');
    const blocked = state('process-lock', { busyTimeoutMs: 1 });
    equal(blocked.open(), true);
    throws(() => blocked.admitLease(request({ leaseId: 'lease-process-lock', nonce: Buffer.alloc(16, 16).toString('base64url') })), error => error && error.code === 'ONLINE_FRA_SQLITE_UNAVAILABLE');
    equal(blocked.close(), true);
    Atomics.wait(sleeper, 0, 0, 900);
    childLock.kill();
  }

  {
    const lockedFile = file('locked');
    const setup = state('locked');
    equal(setup.open(), true);
    deepEqual(setup.initializePair(pair()), { ok: true, outcome: 'initialized', generation: 1 });
    equal(setup.close(), true);
    const lock = new DatabaseSync(lockedFile);
    lock.exec('BEGIN EXCLUSIVE');
    const blocked = state('locked', { busyTimeoutMs: 1 });
    equal(blocked.open(), true);
    throws(() => blocked.admitLease(request({ leaseId: 'lease-locked', nonce: Buffer.alloc(16, 15).toString('base64url') })), error => error && error.code === 'ONLINE_FRA_SQLITE_UNAVAILABLE');
    lock.exec('ROLLBACK');
    equal(blocked.close(), true);
    lock.close();
  }

  {
    const leaseState = state('relay');
    equal(leaseState.open(), true);
    deepEqual(leaseState.initializePair(pair()), { ok: true, outcome: 'initialized', generation: 1 });
    const authority = crypto.generateKeyPairSync('ed25519');
    const ephemeral = crypto.generateKeyPairSync('x25519').publicKey.export({ format: 'der', type: 'spki' }).toString('base64url');
    const relayOptions = {
      enabled: true, authorityPublicKey: authority.publicKey, verifyLease: () => true, leaseState,
      clock: () => now, eventSink: () => {}, pairs: [
        { pairId: 'pair-alpha', machineAId: 'device-alpha', machineBId: 'device-bravo', capabilityDigest: DIGEST },
        { pairId: 'pair-solo', machineAId: 'device-solo', machineBId: null, capabilityDigest: DIGEST }
      ]
    };
    const relayA = createOnlineFraRendezvousRelay(relayOptions);
    const relayB = createOnlineFraRendezvousRelay(relayOptions);
    const lease = {
      schemaVersion: LEASE_SCHEMA_VERSION, leaseId: 'lease-relay', pairId: 'pair-alpha', deviceId: 'device-alpha', peerDeviceId: 'device-bravo', endpointRole: 'machine-a',
      mtlsFingerprint: 'c'.repeat(64), generation: 1, issuedAtMs: now - 1, expiresAtMs: now + 20_000,
      nonce: Buffer.alloc(16, 14).toString('base64url'), ephemeralX25519PublicKey: ephemeral, capabilityDigest: DIGEST, signature: Buffer.alloc(64, 1).toString('base64url')
    };
    const identity = { verified: true, authType: 'mtls', deviceId: 'device-alpha', mtlsFingerprint: 'c'.repeat(64) };
    ok(relayA.connect({ identity, lease }).connectionId.startsWith('conn_'));
    throws(() => relayB.connect({ identity, lease }), error => error && error.code === 'ONLINE_FRA_LEASE_REPLAYED');
    // The real store behind a SOLO pair: the relay hands it a machine lease
    // with no peer, and the admission -- and the replay refusal -- are the
    // same as for a pair.
    deepEqual(leaseState.initializePair(pair({ pairId: 'pair-solo' })), { ok: true, outcome: 'initialized', generation: 1 });
    const soloLease = { ...lease, leaseId: 'lease-solo-relay', pairId: 'pair-solo', deviceId: 'device-solo', peerDeviceId: null, nonce: Buffer.alloc(16, 33).toString('base64url') };
    const soloIdentity = { verified: true, authType: 'mtls', deviceId: 'device-solo', mtlsFingerprint: 'c'.repeat(64) };
    ok(relayA.connect({ identity: soloIdentity, lease: soloLease }).connectionId.startsWith('conn_'));
    throws(() => relayB.connect({ identity: soloIdentity, lease: soloLease }), error => error && error.code === 'ONLINE_FRA_LEASE_REPLAYED');
    equal(leaseState.close(), true);
  }

  // --- deletion: the end of the pairing identifier, not a mark on it --------
  //
  // The privacy policy says account deletion is end to end, and the pairing id
  // is the one identifier that crosses from the account database to the relay.
  // Revocation keeps the row (correct for credential invalidation); deletion
  // must actually remove it, nonces included, and be safely retryable.
  {
    const deletion = state('deletion');
    equal(deletion.open(), true);
    deepEqual(deletion.initializePair(pair({ pairId: 'pair-delete' })), { ok: true, outcome: 'initialized', generation: 1 });
    deepEqual(deletion.admitLease(request({ pairId: 'pair-delete', leaseId: 'lease-delete', nonce: Buffer.alloc(16, 9).toString('base64url') })), { ok: true, outcome: 'accepted' });
    const removed = deletion.deletePair({ pairId: 'pair-delete' });
    deepEqual(removed, { ok: true, outcome: 'deleted' });
    equal(Object.isFrozen(removed), true);
    // Idempotent: the account side retries until it hears deleted or absent.
    deepEqual(deletion.deletePair({ pairId: 'pair-delete' }), { ok: true, outcome: 'absent' });
    // A deleted pair refuses leases exactly like an unknown one -- absent and
    // revoked are deliberately indistinguishable to admission.
    deepEqual(deletion.pairState({ pairId: 'pair-delete', generation: 1 }), { ok: true, revoked: true });
    deepEqual(deletion.admitLease(request({ pairId: 'pair-delete', leaseId: 'lease-late', nonce: Buffer.alloc(16, 10).toString('base64url') })), { ok: true, outcome: 'revoked' });
    // The rows are GONE, not flagged -- checked in the file itself, not
    // through this adapter's own reporting.
    equal(deletion.close(), true);
    {
      const db = new DatabaseSync(file('deletion'));
      equal(db.prepare("SELECT count(*) AS n FROM fra_pair_state WHERE pair_id = 'pair-delete'").get().n, 0);
      equal(db.prepare("SELECT count(*) AS n FROM fra_lease_nonce WHERE pair_id = 'pair-delete'").get().n, 0);
      db.close();
    }
    const reopenedDeletion = state('deletion');
    equal(reopenedDeletion.open(), true);
    // After deletion the identity may exist again -- a NEW enrolment, with a
    // clean generation, exactly as a never-seen pair would.
    deepEqual(reopenedDeletion.initializePair(pair({ pairId: 'pair-delete' })), { ok: true, outcome: 'initialized', generation: 1 });
    throws(() => reopenedDeletion.deletePair({ pairId: 'pair delete' }), error => error && error.code === 'ONLINE_FRA_SQLITE_REQUEST_INVALID');
    throws(() => reopenedDeletion.deletePair({ pairId: 'pair-delete', generation: 1 }), error => error && error.code === 'ONLINE_FRA_SQLITE_REQUEST_INVALID');
    equal(reopenedDeletion.close(), true);
  }

  // Check that neither marker-like input nor caller error detail becomes a row.
  for (const name of ['primary', 'atomic', 'rotation', 'purge', 'malformed', 'relay']) {
    const db = new DatabaseSync(file(name));
    const dump = JSON.stringify(db.prepare("SELECT group_concat(pair_id || capability_digest || nonce_hash || lease_hash, '') AS content FROM fra_pair_state LEFT JOIN fra_lease_nonce USING(pair_id)").get());
    ok(!dump.includes(MARKER));
    db.close();
  }

  console.log(`online-fra-sqlite-lease-state: ${assertions} assertions passed`);
} finally {
  // A failing assertion may intentionally stop before a close assertion; do
  // not conceal that failure with Windows' transient SQLite file lock.
  try { fs.rmSync(root, { recursive: true, force: true, maxRetries: 3, retryDelay: 20 }); } catch { /* test process exit releases it */ }
}
