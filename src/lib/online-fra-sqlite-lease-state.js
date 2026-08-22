'use strict';

// The rendezvous relay intentionally has no in-memory replay fallback.  This
// small adapter is its synchronous, durable authority for pair generation and
// nonce consumption.  It stores only opaque identifiers/digests and hashes of
// lease identifiers/nonces; signed leases and command material never cross this
// boundary.

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const SCHEMA_VERSION = 1;
const APPLICATION_ID = 0x4f46524c; // "OFRL"
const IDENTIFIER = /^[a-z][a-z0-9_-]{2,95}$/;
const DIGEST = /^[a-f0-9]{64}$/;
const NONCE = /^[A-Za-z0-9_-]{22,86}$/;
const REASON = /^[A-Za-z][A-Za-z0-9_.-]{2,95}$/;
const MAX_TIMESTAMP = 8_640_000_000_000_000;
const MAX_BUSY_TIMEOUT_MS = 10_000;
const DEFAULT_BUSY_TIMEOUT_MS = 2_000;
const MAX_PURGE_LIMIT = 1_000;
const DEFAULT_PURGE_LIMIT = 128;
const PROTECTED_SEGMENT = /^(?:vault|vaults|profile|profiles|log|logs|state|owner|owners|protected|\.git|node_modules)$/i;

class OnlineFraSqliteLeaseStateError extends Error {
  constructor(code) {
    super(code);
    this.name = 'OnlineFraSqliteLeaseStateError';
    this.code = code;
  }
}

function fail(code) { throw new OnlineFraSqliteLeaseStateError(code); }

function loadDatabaseSync() {
  const original = process.emitWarning;
  process.emitWarning = function emitWarning(warning, ...args) {
    const message = warning instanceof Error ? warning.message : String(warning);
    const type = warning instanceof Error ? warning.name : args[0];
    if (type === 'ExperimentalWarning' && message === 'SQLite is an experimental feature and might change at any time') return;
    return Reflect.apply(original, this, [warning, ...args]);
  };
  try { return require('node:sqlite').DatabaseSync; }
  finally { process.emitWarning = original; }
}

function plainObject(value) {
  try {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
  } catch { return false; }
}

function exactKeys(value, keys, code) {
  if (!plainObject(value)) fail(code);
  let actual;
  try { actual = Object.keys(value); } catch { fail(code); }
  if (actual.length !== keys.length || actual.some((key, index) => key !== keys[index])) fail(code);
}

function field(value, key, code) {
  try { return value[key]; } catch { fail(code); }
}

function safeInteger(value, code, minimum, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) fail(code);
  return value;
}

function identifier(value, code) {
  if (typeof value !== 'string' || !IDENTIFIER.test(value)) fail(code);
  return value;
}

function digest(value, code) {
  if (typeof value !== 'string' || !DIGEST.test(value)) fail(code);
  return value;
}

function nonce(value, code) {
  if (typeof value !== 'string' || !NONCE.test(value)) fail(code);
  return value;
}

function hashed(domain, value) {
  return crypto.createHash('sha256')
    .update('online-fra-sqlite-lease-state.v1\0', 'utf8')
    .update(domain, 'utf8').update('\0', 'utf8').update(value, 'utf8').digest('hex');
}

function pathIsAllowed(file) {
  if (typeof file !== 'string' || !path.isAbsolute(file)) return false;
  // A UNC share, Win32 device namespace, or extended-length path bypasses the
  // local ownership/traversal checks below.  This adapter has no safe network
  // filesystem mode, so its path opener is deliberately local-drive only.
  if (/^(?:\\\\[?.]|\\\\\.\\|\\\\[^\\])/.test(file)) return false;
  let resolved;
  try { resolved = path.resolve(file); } catch { return false; }
  if (resolved !== file || path.basename(resolved) !== file.split(/[\\/]/).pop()) return false;
  const pieces = resolved.split(/[\\/]+/).filter(Boolean);
  return pieces.length > 1 && !pieces.some(piece => PROTECTED_SEGMENT.test(piece));
}

function assertTrustedParent(file) {
  const parsed = path.parse(file);
  let current = parsed.root;
  const components = path.relative(parsed.root, path.dirname(file)).split(path.sep).filter(Boolean);
  try {
    for (const component of components) {
      current = path.join(current, component);
      const status = fs.lstatSync(current);
      // Junctions are surfaced as symlinks by Node on supported Windows
      // builds; realpath comparison additionally catches reparse traversal.
      if (status.isSymbolicLink() || fs.realpathSync.native(current) !== path.resolve(current)) fail('ONLINE_FRA_SQLITE_PATH_INVALID');
    }
    const parent = fs.statSync(path.dirname(file));
    if (!parent.isDirectory()) fail('ONLINE_FRA_SQLITE_PATH_INVALID');
    fs.accessSync(path.dirname(file), fs.constants.R_OK | fs.constants.W_OK);
    if (process.platform !== 'win32') {
      const uid = typeof process.geteuid === 'function' ? process.geteuid() : null;
      if (!Number.isSafeInteger(uid) || uid === 0 || parent.uid !== uid || (parent.mode & 0o077) !== 0) {
        fail('ONLINE_FRA_SQLITE_PATH_INVALID');
      }
    }
    if (fs.existsSync(file)) {
      const target = fs.lstatSync(file);
      if (!target.isFile() || target.isSymbolicLink() || fs.realpathSync.native(file) !== path.resolve(file)) fail('ONLINE_FRA_SQLITE_PATH_INVALID');
      fs.accessSync(file, fs.constants.R_OK | fs.constants.W_OK);
      if (process.platform !== 'win32') {
        const uid = process.geteuid();
        if (target.uid !== uid || (target.mode & 0o077) !== 0) fail('ONLINE_FRA_SQLITE_PATH_INVALID');
      }
    }
  } catch (error) {
    if (error instanceof OnlineFraSqliteLeaseStateError) throw error;
    fail('ONLINE_FRA_SQLITE_PATH_INVALID');
  }
}

// Deployment-critical Windows boundary: Node cannot prove the owner/DACL of
// this path, and DatabaseSync cannot be handed an O_NOFOLLOW-style descriptor.
// A Windows deployment must therefore provide a trusted, synchronous attestor
// that performs its own DACL/reparse policy check.  A bare boolean is not an
// attestation: the receipt has to echo the canonical parent/file identity and
// a fresh generation.  This narrows, but cannot eliminate, replacement races
// after the final check; keep the database directory ACL-exclusive to the
// service identity and retain the external attestor in production.
function attestWindowsPathTrust(file, pathTrustAttestor, stage) {
  if (process.platform !== 'win32') return;
  if (typeof pathTrustAttestor !== 'function') fail('ONLINE_FRA_SQLITE_PATH_INVALID');
  try {
    const parentPath = fs.realpathSync.native(path.dirname(file));
    const filePath = fs.existsSync(file)
      ? fs.realpathSync.native(file)
      : path.join(parentPath, path.basename(file));
    const generation = crypto.randomBytes(32).toString('hex');
    const challenge = Object.freeze({ parentPath, filePath, generation, stage });
    const result = pathTrustAttestor(challenge);
    if (result && typeof result.then === 'function') fail('ONLINE_FRA_SQLITE_PATH_INVALID');
    exactKeys(result, ['ok', 'parentPath', 'filePath', 'generation', 'stage'], 'ONLINE_FRA_SQLITE_PATH_INVALID');
    if (field(result, 'ok', 'ONLINE_FRA_SQLITE_PATH_INVALID') !== true
        || field(result, 'parentPath', 'ONLINE_FRA_SQLITE_PATH_INVALID') !== parentPath
        || field(result, 'filePath', 'ONLINE_FRA_SQLITE_PATH_INVALID') !== filePath
        || field(result, 'generation', 'ONLINE_FRA_SQLITE_PATH_INVALID') !== generation
        || field(result, 'stage', 'ONLINE_FRA_SQLITE_PATH_INVALID') !== stage) {
      fail('ONLINE_FRA_SQLITE_PATH_INVALID');
    }
  } catch (error) {
    if (error instanceof OnlineFraSqliteLeaseStateError) throw error;
    fail('ONLINE_FRA_SQLITE_PATH_INVALID');
  }
}

function receipt(outcome, generation) {
  return Object.freeze({ ok: true, outcome, generation });
}

function relayReceipt(outcome) { return Object.freeze({ ok: true, outcome }); }
function revokedReceipt(revoked) { return Object.freeze({ ok: true, revoked }); }
function revokeConflictReceipt() { return Object.freeze({ ok: false, outcome: 'conflict' }); }

const PAIR_TABLE_SQL = `CREATE TABLE fra_pair_state (
    pair_id TEXT PRIMARY KEY CHECK(length(pair_id) BETWEEN 3 AND 96),
    generation INTEGER NOT NULL CHECK(generation BETWEEN 1 AND 9007199254740991),
    capability_digest TEXT NOT NULL CHECK(length(capability_digest) = 64 AND capability_digest NOT GLOB '*[^0-9a-f]*'),
    revoked INTEGER NOT NULL CHECK(revoked IN (0, 1)),
    updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms BETWEEN 1 AND 8640000000000000)
  ) STRICT`;
const NONCE_TABLE_SQL = `CREATE TABLE fra_lease_nonce (
    pair_id TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK(generation BETWEEN 1 AND 9007199254740991),
    nonce_hash TEXT NOT NULL CHECK(length(nonce_hash) = 64 AND nonce_hash NOT GLOB '*[^0-9a-f]*'),
    lease_hash TEXT NOT NULL CHECK(length(lease_hash) = 64 AND lease_hash NOT GLOB '*[^0-9a-f]*'),
    expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms BETWEEN 1 AND 8640000000000000),
    consumed_at_ms INTEGER NOT NULL CHECK(consumed_at_ms BETWEEN 1 AND 8640000000000000),
    PRIMARY KEY(pair_id, generation, nonce_hash),
    FOREIGN KEY(pair_id) REFERENCES fra_pair_state(pair_id) ON DELETE CASCADE
  ) STRICT`;
const NONCE_INDEX_SQL = 'CREATE INDEX fra_lease_nonce_expiry_idx ON fra_lease_nonce(expires_at_ms)';
const SCHEMA = `${PAIR_TABLE_SQL};\n${NONCE_TABLE_SQL};\n${NONCE_INDEX_SQL};`;
const CANONICAL_OBJECTS = Object.freeze([
  Object.freeze({ type: 'index', name: 'fra_lease_nonce_expiry_idx', table: 'fra_lease_nonce', sql: NONCE_INDEX_SQL }),
  Object.freeze({ type: 'table', name: 'fra_lease_nonce', table: 'fra_lease_nonce', sql: NONCE_TABLE_SQL }),
  Object.freeze({ type: 'table', name: 'fra_pair_state', table: 'fra_pair_state', sql: PAIR_TABLE_SQL })
]);

function normalizedDdl(sql) {
  return String(sql).replace(/\s+/g, ' ').trim().replace(/;$/, '');
}

function createOnlineFraSqliteLeaseState(options = {}) {
  if (!plainObject(options)) fail('ONLINE_FRA_SQLITE_OPTIONS_INVALID');
  const optionKeys = ['enabled', 'dbPath', 'clock', 'openDatabase', 'busyTimeoutMs', 'purgeLimit', 'pathTrustAttestor'];
  let suppliedOptionKeys;
  try { suppliedOptionKeys = Object.keys(options); } catch { fail('ONLINE_FRA_SQLITE_OPTIONS_INVALID'); }
  if (suppliedOptionKeys.some(key => !optionKeys.includes(key))) fail('ONLINE_FRA_SQLITE_OPTIONS_INVALID');
  const enabled = field(options, 'enabled', 'ONLINE_FRA_SQLITE_OPTIONS_INVALID') === true;
  const file = field(options, 'dbPath', 'ONLINE_FRA_SQLITE_OPTIONS_INVALID');
  const configuredClock = field(options, 'clock', 'ONLINE_FRA_SQLITE_OPTIONS_INVALID');
  const configuredOpenDatabase = field(options, 'openDatabase', 'ONLINE_FRA_SQLITE_OPTIONS_INVALID');
  const configuredBusyTimeout = field(options, 'busyTimeoutMs', 'ONLINE_FRA_SQLITE_OPTIONS_INVALID');
  const configuredPurgeLimit = field(options, 'purgeLimit', 'ONLINE_FRA_SQLITE_OPTIONS_INVALID');
  const configuredPathTrustAttestor = field(options, 'pathTrustAttestor', 'ONLINE_FRA_SQLITE_OPTIONS_INVALID');
  const clock = configuredClock === undefined ? (() => Date.now()) : configuredClock;
  const openDatabase = configuredOpenDatabase === undefined ? null : configuredOpenDatabase;
  const busyTimeoutMs = configuredBusyTimeout === undefined ? DEFAULT_BUSY_TIMEOUT_MS
    : safeInteger(configuredBusyTimeout, 'ONLINE_FRA_SQLITE_OPTIONS_INVALID', 1, MAX_BUSY_TIMEOUT_MS);
  const purgeLimit = configuredPurgeLimit === undefined ? DEFAULT_PURGE_LIMIT
    : safeInteger(configuredPurgeLimit, 'ONLINE_FRA_SQLITE_OPTIONS_INVALID', 1, MAX_PURGE_LIMIT);
  const pathTrustAttestor = configuredPathTrustAttestor === undefined ? null : configuredPathTrustAttestor;
  if (typeof clock !== 'function' || (openDatabase !== null && typeof openDatabase !== 'function')
      || (pathTrustAttestor !== null && typeof pathTrustAttestor !== 'function')) {
    fail('ONLINE_FRA_SQLITE_OPTIONS_INVALID');
  }
  let database = null;
  let opened = false;

  function now() {
    let value;
    try { value = clock(); } catch { fail('ONLINE_FRA_SQLITE_UNAVAILABLE'); }
    return safeInteger(value, 'ONLINE_FRA_SQLITE_UNAVAILABLE', 1, MAX_TIMESTAMP);
  }

  function unavailable(fn) {
    try { return fn(); }
    catch (error) {
      if (error instanceof OnlineFraSqliteLeaseStateError) throw error;
      fail('ONLINE_FRA_SQLITE_UNAVAILABLE');
    }
  }

  function requireOpen() {
    if (!enabled) fail('ONLINE_FRA_SQLITE_DISABLED');
    if (!opened || !database) fail('ONLINE_FRA_SQLITE_CLOSED');
    return database;
  }

  function prepare(sql) { return unavailable(() => requireOpen().prepare(sql)); }
  function one(sql, ...values) { return unavailable(() => prepare(sql).get(...values)); }
  function run(sql, ...values) { return unavailable(() => prepare(sql).run(...values)); }
  function transaction(fn) {
    const db = requireOpen();
    unavailable(() => db.exec('BEGIN IMMEDIATE'));
    try {
      const before = attestSchema(db);
      const result = fn();
      attestSchema(db);
      assertSchemaIdentityStable(db, before);
      unavailable(() => db.exec('COMMIT'));
      return result;
    } catch (error) {
      try { db.exec('ROLLBACK'); } catch { /* fail closed below */ }
      throw error;
    }
  }

  function schemaIdentity(db) {
    return unavailable(() => {
      const application = db.prepare('PRAGMA application_id').get();
      const version = db.prepare('PRAGMA user_version').get();
      const schema = db.prepare('PRAGMA schema_version').get();
      const data = db.prepare('PRAGMA data_version').get();
      return Object.freeze({
        applicationId: safeInteger(application && application.application_id, 'ONLINE_FRA_SQLITE_SCHEMA_INVALID', 0),
        userVersion: safeInteger(version && version.user_version, 'ONLINE_FRA_SQLITE_SCHEMA_INVALID', 0),
        schemaVersion: safeInteger(schema && schema.schema_version, 'ONLINE_FRA_SQLITE_SCHEMA_INVALID', 0),
        dataVersion: safeInteger(data && data.data_version, 'ONLINE_FRA_SQLITE_SCHEMA_INVALID', 0)
      });
    });
  }

  function assertSchemaIdentityStable(db, expected) {
    const actual = schemaIdentity(db);
    if (actual.applicationId !== expected.applicationId || actual.userVersion !== expected.userVersion
        || actual.schemaVersion !== expected.schemaVersion || actual.dataVersion !== expected.dataVersion) {
      fail('ONLINE_FRA_SQLITE_SCHEMA_INVALID');
    }
    return actual;
  }

  function schemaObjects(db) {
    // sqlite_autoindex_* and other sqlite_* rows are SQLite-owned internals.
    // Every non-internal persistent object is part of this adapter's authority
    // and must be in the exact allowlist below: no triggers, views, or extras.
    return unavailable(() => db.prepare("SELECT type, name, tbl_name AS table_name, sql FROM sqlite_master WHERE name NOT GLOB 'sqlite_*' ORDER BY type, name").all());
  }

  function attestSchema(db) {
    const before = schemaIdentity(db);
    const actual = schemaObjects(db);
    if (!Array.isArray(actual) || actual.length !== CANONICAL_OBJECTS.length) fail('ONLINE_FRA_SQLITE_SCHEMA_INVALID');
    for (let index = 0; index < CANONICAL_OBJECTS.length; index += 1) {
      const expected = CANONICAL_OBJECTS[index];
      const value = actual[index];
      if (!value || value.type !== expected.type || value.name !== expected.name || value.table_name !== expected.table
          || normalizedDdl(value.sql) !== normalizedDdl(expected.sql)) fail('ONLINE_FRA_SQLITE_SCHEMA_INVALID');
    }
    const integrity = unavailable(() => db.prepare('PRAGMA integrity_check').all());
    if (!Array.isArray(integrity) || integrity.length !== 1 || integrity[0].integrity_check !== 'ok') fail('ONLINE_FRA_SQLITE_SCHEMA_INVALID');
    const foreignKeys = unavailable(() => db.prepare('PRAGMA foreign_keys').get());
    const journal = unavailable(() => db.prepare('PRAGMA journal_mode').get());
    const synchronous = unavailable(() => db.prepare('PRAGMA synchronous').get());
    const trustedSchema = unavailable(() => db.prepare('PRAGMA trusted_schema').get());
    const tempStore = unavailable(() => db.prepare('PRAGMA temp_store').get());
    if (!foreignKeys || foreignKeys.foreign_keys !== 1 || !journal || journal.journal_mode !== 'wal'
        || !synchronous || synchronous.synchronous !== 2 || !trustedSchema || trustedSchema.trusted_schema !== 0
        || !tempStore || tempStore.temp_store !== 2) fail('ONLINE_FRA_SQLITE_SCHEMA_INVALID');
    return assertSchemaIdentityStable(db, before);
  }

  function verifySchema(db) {
    const initial = schemaIdentity(db);
    if (initial.applicationId !== 0 || initial.userVersion !== 0) {
      if (initial.applicationId !== APPLICATION_ID || initial.userVersion !== SCHEMA_VERSION) fail('ONLINE_FRA_SQLITE_SCHEMA_INVALID');
      attestSchema(db);
      return assertSchemaIdentityStable(db, initial);
    }
    unavailable(() => db.exec('BEGIN IMMEDIATE'));
    try {
      const before = schemaIdentity(db);
      if (before.applicationId === 0 && before.userVersion === 0) {
        // A fresh database is initialized as one transaction.  A partial table
        // left by a killed creator is never "repaired" in place: it fails the
        // attestation instead of becoming an authority with ambiguous state.
        if (schemaObjects(db).length !== 0) fail('ONLINE_FRA_SQLITE_SCHEMA_INVALID');
        db.exec(SCHEMA);
        db.exec(`PRAGMA application_id = ${APPLICATION_ID}`);
        db.exec(`PRAGMA user_version = ${SCHEMA_VERSION}`);
        const created = attestSchema(db);
        if (created.applicationId !== APPLICATION_ID || created.userVersion !== SCHEMA_VERSION) fail('ONLINE_FRA_SQLITE_SCHEMA_INVALID');
        unavailable(() => db.exec('COMMIT'));
        return created;
      }
      if (before.applicationId !== APPLICATION_ID || before.userVersion !== SCHEMA_VERSION) fail('ONLINE_FRA_SQLITE_SCHEMA_INVALID');
      attestSchema(db);
      const verified = assertSchemaIdentityStable(db, before);
      unavailable(() => db.exec('COMMIT'));
      return verified;
    } catch (error) {
      try { db.exec('ROLLBACK'); } catch { /* fail closed with the original fault */ }
      throw error;
    }
  }

  function assertOpenIdentity(db) {
    const databaseList = unavailable(() => db.prepare('PRAGMA database_list').all());
    const main = databaseList.find(row => row && row.name === 'main');
    if (!main || main.file !== file) fail('ONLINE_FRA_SQLITE_PATH_INVALID');
  }

  function open() {
    if (!enabled) return false;
    if (opened) return true;
    if (!pathIsAllowed(file)) fail('ONLINE_FRA_SQLITE_PATH_INVALID');
    assertTrustedParent(file);
    attestWindowsPathTrust(file, pathTrustAttestor, 'pre-open');
    unavailable(() => {
      const DatabaseSync = openDatabase === null ? loadDatabaseSync() : null;
      let candidate = null;
      try {
        candidate = openDatabase === null
          ? new DatabaseSync(file, { allowExtension: false, enableForeignKeyConstraints: true, timeout: busyTimeoutMs })
          : openDatabase(file, { allowExtension: false, enableForeignKeyConstraints: true, timeout: busyTimeoutMs });
        if (!candidate || typeof candidate.prepare !== 'function' || typeof candidate.exec !== 'function' || typeof candidate.close !== 'function') fail('ONLINE_FRA_SQLITE_UNAVAILABLE');
        if (candidate && typeof candidate.then === 'function') fail('ONLINE_FRA_SQLITE_UNAVAILABLE');
        if (typeof candidate.enableLoadExtension !== 'function') fail('ONLINE_FRA_SQLITE_UNAVAILABLE');
        candidate.enableLoadExtension(false);
        candidate.exec('PRAGMA foreign_keys = ON');
        candidate.exec(`PRAGMA busy_timeout = ${busyTimeoutMs}`);
        candidate.exec('PRAGMA journal_mode = WAL');
        candidate.exec('PRAGMA synchronous = FULL');
        candidate.exec('PRAGMA trusted_schema = OFF');
        candidate.exec('PRAGMA temp_store = MEMORY');
        if (process.platform !== 'win32') fs.chmodSync(file, 0o600);
        // Re-attest after SQLite has opened/created the file.  This catches a
        // path replacement between preflight and open on filesystems where
        // Node cannot request an O_NOFOLLOW SQLite descriptor.
        const beforeIdentity = schemaIdentity(candidate);
        assertOpenIdentity(candidate);
        assertTrustedParent(file);
        attestWindowsPathTrust(file, pathTrustAttestor, 'post-open');
        assertSchemaIdentityStable(candidate, beforeIdentity);
        const verifiedSchema = verifySchema(candidate);
        assertOpenIdentity(candidate);
        assertTrustedParent(file);
        attestWindowsPathTrust(file, pathTrustAttestor, 'post-schema');
        assertSchemaIdentityStable(candidate, verifiedSchema);
        database = candidate;
        opened = true;
      } catch (error) {
        if (candidate && typeof candidate.close === 'function') {
          try { candidate.close(); } catch { /* normalize the original error */ }
        }
        throw error;
      }
    });
    return true;
  }

  function close() {
    const current = database;
    database = null;
    opened = false;
    if (!current) return false;
    unavailable(() => current.close());
    return true;
  }

  function initializePair(input) {
    exactKeys(input, ['pairId', 'generation', 'capabilityDigest'], 'ONLINE_FRA_SQLITE_REQUEST_INVALID');
    const pairId = identifier(field(input, 'pairId', 'ONLINE_FRA_SQLITE_REQUEST_INVALID'), 'ONLINE_FRA_SQLITE_REQUEST_INVALID');
    const generation = safeInteger(field(input, 'generation', 'ONLINE_FRA_SQLITE_REQUEST_INVALID'), 'ONLINE_FRA_SQLITE_REQUEST_INVALID', 1);
    const capabilityDigest = digest(field(input, 'capabilityDigest', 'ONLINE_FRA_SQLITE_REQUEST_INVALID'), 'ONLINE_FRA_SQLITE_REQUEST_INVALID');
    const atMs = now();
    return transaction(() => {
      const current = one('SELECT generation, capability_digest, revoked FROM fra_pair_state WHERE pair_id = ?', pairId);
      if (!current) {
        run('INSERT INTO fra_pair_state(pair_id, generation, capability_digest, revoked, updated_at_ms) VALUES(?, ?, ?, 0, ?)', pairId, generation, capabilityDigest, atMs);
        return receipt('initialized', generation);
      }
      if (current.generation === generation && current.capability_digest === capabilityDigest && current.revoked === 0) return receipt('existing', generation);
      return receipt('conflict', current.generation);
    });
  }

  function rotatePair(input) {
    exactKeys(input, ['pairId', 'expectedGeneration', 'nextGeneration', 'capabilityDigest'], 'ONLINE_FRA_SQLITE_REQUEST_INVALID');
    const pairId = identifier(field(input, 'pairId', 'ONLINE_FRA_SQLITE_REQUEST_INVALID'), 'ONLINE_FRA_SQLITE_REQUEST_INVALID');
    const expected = safeInteger(field(input, 'expectedGeneration', 'ONLINE_FRA_SQLITE_REQUEST_INVALID'), 'ONLINE_FRA_SQLITE_REQUEST_INVALID', 1);
    const next = safeInteger(field(input, 'nextGeneration', 'ONLINE_FRA_SQLITE_REQUEST_INVALID'), 'ONLINE_FRA_SQLITE_REQUEST_INVALID', expected + 1);
    const capabilityDigest = digest(field(input, 'capabilityDigest', 'ONLINE_FRA_SQLITE_REQUEST_INVALID'), 'ONLINE_FRA_SQLITE_REQUEST_INVALID');
    const atMs = now();
    return transaction(() => {
      const result = run('UPDATE fra_pair_state SET generation = ?, capability_digest = ?, revoked = 0, updated_at_ms = ? WHERE pair_id = ? AND generation = ? AND revoked = 0', next, capabilityDigest, atMs, pairId, expected);
      if (result.changes === 1) return receipt('rotated', next);
      const current = one('SELECT generation FROM fra_pair_state WHERE pair_id = ?', pairId);
      return receipt('conflict', current ? current.generation : 0);
    });
  }

  function pairState(input) {
    exactKeys(input, ['pairId', 'generation'], 'ONLINE_FRA_SQLITE_REQUEST_INVALID');
    const pairId = identifier(field(input, 'pairId', 'ONLINE_FRA_SQLITE_REQUEST_INVALID'), 'ONLINE_FRA_SQLITE_REQUEST_INVALID');
    const generation = safeInteger(field(input, 'generation', 'ONLINE_FRA_SQLITE_REQUEST_INVALID'), 'ONLINE_FRA_SQLITE_REQUEST_INVALID', 1);
    const current = one('SELECT generation, revoked FROM fra_pair_state WHERE pair_id = ?', pairId);
    return revokedReceipt(!current || current.generation !== generation || current.revoked !== 0);
  }

  // DELETION, as distinct from revocation -- and the privacy policy is why the
  // distinction exists at all. Revocation flips a flag and bumps a timestamp:
  // the row keyed to the customer's pairing identifier SURVIVES, which is
  // exactly right for credential invalidation and exactly wrong for the
  // policy's sentence that account deletion is "end to end". The pairing id is
  // the one identifier that crosses from the account database to the relay, so
  // when the account goes, this row is the last thing anywhere still keyed to
  // that person, and it has to actually go -- not be marked.
  //
  // Nonce rows are removed explicitly rather than trusted to the schema's
  // ON DELETE CASCADE, because cascade only fires when the connection has
  // foreign_keys enabled and this must hold with or without that pragma.
  // No generation parameter, deliberately: revocation is generation-scoped
  // (invalidate THESE credentials), deletion is identity-scoped (this pair no
  // longer exists, at any generation). Idempotent -- a delete button pressed
  // twice reports 'absent', never an error, so the account side can retry
  // safely until it hears 'deleted' or 'absent'.
  function deletePair(input) {
    exactKeys(input, ['pairId'], 'ONLINE_FRA_SQLITE_REQUEST_INVALID');
    const pairId = identifier(field(input, 'pairId', 'ONLINE_FRA_SQLITE_REQUEST_INVALID'), 'ONLINE_FRA_SQLITE_REQUEST_INVALID');
    return transaction(() => {
      run('DELETE FROM fra_lease_nonce WHERE pair_id = ?', pairId);
      const result = run('DELETE FROM fra_pair_state WHERE pair_id = ?', pairId);
      return relayReceipt(result.changes === 1 ? 'deleted' : 'absent');
    });
  }

  function revokePair(input) {
    exactKeys(input, ['pairId', 'generation', 'reason'], 'ONLINE_FRA_SQLITE_REQUEST_INVALID');
    const pairId = identifier(field(input, 'pairId', 'ONLINE_FRA_SQLITE_REQUEST_INVALID'), 'ONLINE_FRA_SQLITE_REQUEST_INVALID');
    const generation = safeInteger(field(input, 'generation', 'ONLINE_FRA_SQLITE_REQUEST_INVALID'), 'ONLINE_FRA_SQLITE_REQUEST_INVALID', 1);
    const reason = field(input, 'reason', 'ONLINE_FRA_SQLITE_REQUEST_INVALID');
    if (typeof reason !== 'string' || !REASON.test(reason)) fail('ONLINE_FRA_SQLITE_REQUEST_INVALID');
    const atMs = now();
    const changed = transaction(() => {
      // The reason is intentionally validated then discarded: this table is
      // security state, not a command/audit payload store.
      return run('UPDATE fra_pair_state SET revoked = 1, updated_at_ms = ? WHERE pair_id = ? AND generation = ?', atMs, pairId, generation).changes === 1;
    });
    // A stale/unknown generation must never look like a durable revocation to
    // the relay.  The relay treats this non-affirmative receipt as unavailable.
    return changed ? revokedReceipt(true) : revokeConflictReceipt();
  }

  function admitLease(input) {
    exactKeys(input, ['leaseId', 'pairId', 'generation', 'deviceId', 'peerDeviceId', 'capabilityDigest', 'nonce', 'expiresAtMs'], 'ONLINE_FRA_SQLITE_REQUEST_INVALID');
    const leaseId = identifier(field(input, 'leaseId', 'ONLINE_FRA_SQLITE_REQUEST_INVALID'), 'ONLINE_FRA_SQLITE_REQUEST_INVALID');
    const pairId = identifier(field(input, 'pairId', 'ONLINE_FRA_SQLITE_REQUEST_INVALID'), 'ONLINE_FRA_SQLITE_REQUEST_INVALID');
    const generation = safeInteger(field(input, 'generation', 'ONLINE_FRA_SQLITE_REQUEST_INVALID'), 'ONLINE_FRA_SQLITE_REQUEST_INVALID', 1);
    const deviceId = identifier(field(input, 'deviceId', 'ONLINE_FRA_SQLITE_REQUEST_INVALID'), 'ONLINE_FRA_SQLITE_REQUEST_INVALID');
    // null is a SOLO pair's machine: it has no peer, and the relay's lease
    // binding has already said so before this is reached. Anything else must
    // be an identifier and must not be the device itself. Nothing below
    // stores the peer either way -- only the pair, the nonce hash and the
    // lease-id hash are written.
    const peerDeviceId = field(input, 'peerDeviceId', 'ONLINE_FRA_SQLITE_REQUEST_INVALID');
    if (peerDeviceId !== null) {
      identifier(peerDeviceId, 'ONLINE_FRA_SQLITE_REQUEST_INVALID');
      if (deviceId === peerDeviceId) fail('ONLINE_FRA_SQLITE_REQUEST_INVALID');
    }
    const capabilityDigest = digest(field(input, 'capabilityDigest', 'ONLINE_FRA_SQLITE_REQUEST_INVALID'), 'ONLINE_FRA_SQLITE_REQUEST_INVALID');
    const nonceValue = nonce(field(input, 'nonce', 'ONLINE_FRA_SQLITE_REQUEST_INVALID'), 'ONLINE_FRA_SQLITE_REQUEST_INVALID');
    const expiresAtMs = safeInteger(field(input, 'expiresAtMs', 'ONLINE_FRA_SQLITE_REQUEST_INVALID'), 'ONLINE_FRA_SQLITE_REQUEST_INVALID', 1, MAX_TIMESTAMP);
    const atMs = now();
    if (expiresAtMs <= atMs) fail('ONLINE_FRA_SQLITE_REQUEST_INVALID');
    const nonceHash = hashed('nonce', nonceValue);
    const leaseHash = hashed('lease-id', leaseId);
    return transaction(() => {
      run('DELETE FROM fra_lease_nonce WHERE rowid IN (SELECT rowid FROM fra_lease_nonce WHERE expires_at_ms <= ? LIMIT ?)', atMs, purgeLimit);
      const current = one('SELECT generation, capability_digest, revoked FROM fra_pair_state WHERE pair_id = ?', pairId);
      if (!current || current.generation !== generation || current.revoked !== 0 || current.capability_digest !== capabilityDigest) return relayReceipt('revoked');
      try {
        run('INSERT INTO fra_lease_nonce(pair_id, generation, nonce_hash, lease_hash, expires_at_ms, consumed_at_ms) VALUES(?, ?, ?, ?, ?, ?)', pairId, generation, nonceHash, leaseHash, expiresAtMs, atMs);
      } catch (error) {
        // A constraint violation is the one expected error path; use a
        // parameterized existence check so no driver error reaches callers.
        const existing = one('SELECT nonce_hash FROM fra_lease_nonce WHERE pair_id = ? AND generation = ? AND nonce_hash = ?', pairId, generation, nonceHash);
        if (existing) return relayReceipt('replayed');
        throw error;
      }
      return relayReceipt('accepted');
    });
  }

  return Object.freeze({
    open,
    close,
    initializePair,
    rotatePair,
    pairState,
    revokePair,
    deletePair,
    admitLease
  });
}

module.exports = Object.freeze({
  createOnlineFraSqliteLeaseState,
  OnlineFraSqliteLeaseStateError,
  SCHEMA_VERSION,
  APPLICATION_ID
});
