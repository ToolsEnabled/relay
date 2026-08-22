'use strict';
/* A PAIR MUST SURVIVE A RESTART OF THIS SERVICE.
 *
 * It did not, and the way it failed is the reason this file exists rather than
 * a line in an existing one.
 *
 * A pair reached the relay exactly one way: the account service calling
 * `register-pair` over the control channel at the moment a person connected two
 * computers. That call put it in an in-memory map. The lease state underneath
 * is durable sqlite; the topology on top of it was not. So a deploy, a crash or
 * a reboot dropped every pair on the box, and nothing ever put them back --
 * `register-pair` is only called when a pair is FORMED.
 *
 * What a person saw: nothing. Their machines had valid credentials and minted
 * perfectly good leases, and the relay refused every one of them at
 * `pairs.get(source.pairId)` with ONLINE_FRA_LEASE_BINDING_INVALID. The machine
 * reported "admitted" (its client resolves optimistically) and was closed 1008
 * a moment later. Their computers simply stopped answering, and the only cure
 * was deleting the connection and making it again.
 *
 * Measured on the live box: a pair formed at 05:26 worked; after the service
 * restarted at 05:35 every connect failed with that code, for hours, until the
 * topology was rebuilt from the account database at boot.
 *
 * So this drives the real service twice over ONE account database and ONE lease
 * state -- the shape a restart actually has -- and requires the pair to be
 * usable after the second start WITHOUT anybody calling register-pair again.
 */
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');

const { createOnlineFraRelayService } = require('../src/lib/online-fra-relay-service');

let assertions = 0;
const equal = (a, b, m) => { assertions += 1; assert.equal(a, b, m); };
const ok = (v, m) => { assertions += 1; assert.ok(v, m); };

process.exitCode = 1;

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pair-recovery-'));
const accountDbPath = path.join(root, 'devices.sqlite3');
const leaseStatePath = path.join(root, 'leases.sqlite3');
const CONTROL_TOKEN = 'c'.repeat(48);
const DIGEST = 'a'.repeat(64);
const PAIR = 'pair-recovery-0001';
const DEVICE_A = 'device-aaaa0000aaaa0000aaaa0000';
const DEVICE_B = 'device-bbbb1111bbbb1111bbbb1111';
/* The SOLO shapes: one computer is a relay_pairs row with b_pair_id NULL (the
   server half's contract); a row whose b_pair_id names a machine that does not
   exist is NOT solo and must stay refused exactly as a revoked half is. */
const PAIR_SOLO = 'pair-recovery-solo';
const DEVICE_S = 'device-ssss2222ssss2222ssss2222';
const PAIR_DANGLING = 'pair-recovery-dangling';
const DEVICE_E = 'device-eeee3333eeee3333eeee3333';

/* The account service's own schema, as the relay reads it. Written here rather
   than imported because the relay must keep working against the database the
   account service already has -- if these columns drift, this test is where the
   relay finds out, which is the point. b_pair_id is NULLABLE since the solo-pair
   change (the server half makes it so through its migrate idiom; every other
   column is unchanged): a solo pair is a row with b_pair_id NULL. */
function seedAccountDb({ revokeB = false, solo = false, revokeSolo = false, danglingB = false } = {}) {
  const db = new DatabaseSync(accountDbPath);
  db.exec(`CREATE TABLE IF NOT EXISTS devices (
    pair_id TEXT PRIMARY KEY, account_id TEXT NOT NULL, name TEXT NOT NULL,
    enrolled_at_ms INTEGER NOT NULL, revoked_at_ms INTEGER, device_id TEXT,
    mtls_fingerprint TEXT, ed25519_public_key TEXT)`);
  db.exec(`CREATE TABLE IF NOT EXISTS relay_pairs (
    relay_pair_id TEXT PRIMARY KEY, account_id TEXT NOT NULL,
    a_pair_id TEXT NOT NULL, b_pair_id TEXT,
    capability_digest TEXT NOT NULL, created_at_ms INTEGER NOT NULL)`);
  db.exec('DELETE FROM relay_pairs');
  db.exec('DELETE FROM devices');
  const device = db.prepare('INSERT INTO devices (pair_id, account_id, name, enrolled_at_ms, revoked_at_ms, device_id) VALUES (?,?,?,?,?,?)');
  const relayPair = db.prepare('INSERT INTO relay_pairs (relay_pair_id, account_id, a_pair_id, b_pair_id, capability_digest, created_at_ms) VALUES (?,?,?,?,?,?)');
  device.run('pair-a', 'acct-1', 'Desk', 1, null, DEVICE_A);
  device.run('pair-b', 'acct-1', 'Laptop', 1, revokeB ? 2 : null, DEVICE_B);
  relayPair.run(PAIR, 'acct-1', 'pair-a', 'pair-b', DIGEST, 1);
  if (solo) {
    device.run('pair-s', 'acct-1', 'Only', 1, revokeSolo ? 2 : null, DEVICE_S);
    relayPair.run(PAIR_SOLO, 'acct-1', 'pair-s', null, DIGEST, 1);
  }
  if (danglingB) {
    device.run('pair-e', 'acct-1', 'Half', 1, null, DEVICE_E);
    relayPair.run(PAIR_DANGLING, 'acct-1', 'pair-e', 'pair-missing', DIGEST, 1);
  }
  db.close();
}

function makeService() {
  return createOnlineFraRelayService({
    accountDbPath,
    leaseStatePath,
    authorityPublicKeyPem: crypto.generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    generation: 1,
    control: { port: 0, token: CONTROL_TOKEN },
    /* Windows requires an external attestor for the durable lease state; the
       suite's other files supply the same echoing one. */
    pathTrustAttestor: (c) => ({ ok: true, parentPath: c.parentPath, filePath: c.filePath, generation: c.generation, stage: c.stage }),
  });
}

(async () => {
  seedAccountDb();

  // --- first boot: the pair is recovered from the account database alone -----
  const first = makeService();
  const firstStart = await first.start();
  equal(first.relay.snapshot().pairCount, 1,
    'the FIRST boot did not recover the pair from the account database -- nobody has called register-pair, and that is the whole point');
  ok(firstStart.recovery && firstStart.recovery.readable, 'start() did not report whether the account database was readable');
  equal(firstStart.recovery.recovered, 1, 'the recovery did not count the pair it restored');
  equal(firstStart.recovery.conflicts, 0);
  await first.stop();

  // --- the restart: same database, same lease state, a brand-new process ----
  const second = makeService();
  const secondStart = await second.start();
  equal(second.relay.snapshot().pairCount, 1,
    'the pair did not survive a restart. This is the defect: a deploy or a reboot silently disconnected every machine on the box, and nothing put the topology back.');
  equal(secondStart.recovery.recovered, 1, 'the second boot did not restore the pair');
  equal(secondStart.recovery.conflicts, 0,
    're-initialising a pair with the SAME digest must not read as a generation conflict -- every restart would count one');
  await second.stop();

  // --- a revoked machine is not a live pair --------------------------------
  seedAccountDb({ revokeB: true });
  const third = makeService();
  const thirdStart = await third.start();
  equal(third.relay.snapshot().pairCount, 0,
    'a pair whose machine has been revoked was restored; the account service is the authority on who is still enrolled, and it said no');
  equal(thirdStart.recovery.recovered, 0);
  await third.stop();

  // --- a SOLO pair -- b_pair_id NULL -- is restored beside the pair, and survives a restart ---
  seedAccountDb({ solo: true });
  const soloFirst = makeService();
  const soloFirstStart = await soloFirst.start();
  equal(soloFirst.relay.snapshot().pairCount, 2,
    'the solo row -- one machine, b_pair_id NULL -- was not restored beside the two-machine pair; a person with one computer stays dark after every restart');
  equal(soloFirstStart.recovery.recovered, 2);
  equal(soloFirstStart.recovery.conflicts, 0);
  equal(soloFirstStart.recovery.skipped, 0, 'restored as a SOLO pair (machineBId null), not skipped as a malformed one');
  equal(soloFirst.admissionAuthority({ pairId: PAIR_SOLO }), true, 'and the ASK authority resolves the solo row');
  await soloFirst.stop();
  const soloAgain = makeService();
  const soloAgainStart = await soloAgain.start();
  equal(soloAgain.relay.snapshot().pairCount, 2, 'the solo pair did not survive a restart');
  equal(soloAgainStart.recovery.recovered, 2);
  equal(soloAgainStart.recovery.conflicts, 0);
  await soloAgain.stop();

  // --- revoking a solo's ONE machine ends it exactly as a revoked half ends a pair ---
  seedAccountDb({ solo: true, revokeSolo: true });
  const soloRevoked = makeService();
  const soloRevokedStart = await soloRevoked.start();
  equal(soloRevoked.relay.snapshot().pairCount, 1,
    'a solo pair whose one machine has been revoked was restored; the account service said no and the relay must not say yes');
  equal(soloRevokedStart.recovery.recovered, 1);
  equal(soloRevoked.admissionAuthority({ pairId: PAIR_SOLO }), false);
  await soloRevoked.stop();

  // --- a non-null B that names a missing machine is NOT a solo pair: refused, not restored ---
  seedAccountDb({ danglingB: true });
  const dangling = makeService();
  const danglingStart = await dangling.start();
  equal(dangling.relay.snapshot().pairCount, 1,
    'a two-machine row whose B device is missing was restored as if it were solo -- the LEFT JOIN must excuse only a NULL b_pair_id');
  equal(danglingStart.recovery.recovered, 1);
  equal(dangling.admissionAuthority({ pairId: PAIR_DANGLING }), false);
  equal(dangling.admissionAuthority({ pairId: PAIR }), true, 'while the whole pair beside it still resolves');
  await dangling.stop();

  // --- an unreadable account database refuses honestly and still boots ------
  fs.rmSync(accountDbPath);
  fs.writeFileSync(accountDbPath, 'this is not a database');
  const fourth = makeService();
  const fourthStart = await fourth.start();
  equal(fourth.relay.snapshot().pairCount, 0, 'an unreadable database must restore nothing rather than guess');
  equal(fourthStart.recovery.readable, false,
    'an unreadable account database must SAY it was unreadable -- a silent zero looks exactly like a box with no pairs on it');
  ok(fourthStart.controlPort > 0,
    'the service refused to start because it could not rebuild its topology. A relay that will not boot serves nobody: it must come up and refuse honestly.');
  await fourth.stop();

  fs.rmSync(root, { recursive: true, force: true });
  console.log(`online-fra-pair-recovery: ${assertions} assertions passed`);
  process.exitCode = 0;
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
