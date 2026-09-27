'use strict';

// Pure, disabled-by-default deployment gate for the future online FRA nginx
// vhost. `nginx-t-expanded` means a trusted nginx -T capture has first been
// flattened so no include directive remains. It consumes that full text, a
// signed backend capability statement, an independently signed Unix-socket
// ownership receipt, and a signed certificate-identity mapping plan. It never opens
// nginx, a certificate, a socket, or a filesystem path.
const crypto = require('node:crypto');

const ATTESTATION_VERSION = 'online-fra-backend-capability.v1';
const PROXY_BOUNDARY_ATTESTATION_VERSION = 'online-fra-unix-socket-boundary.v1';
const IDENTITY_MAPPING_VERSION = 'online-fra-certificate-identity-map.v1';
const ROUTE = '/v1/rendezvous';
const MAX_CONFIG_BYTES = 1024 * 1024;
const MAX_TOKENS = 40_000;
const MAX_ATTESTATION_AGE_MS = 5 * 60 * 1000;
const MAX_CLOCK_SKEW_MS = 5_000;
const MAX_TIMESTAMP = 8_640_000_000_000_000;
const MAX_BODY_BYTES = 8192;
const HEADER_BUFFER_BYTES = 4096;
const PROXY_CONNECT_TIMEOUT_SECONDS = 5;
const PROXY_SEND_TIMEOUT_SECONDS = 30;
const PROXY_READ_TIMEOUT_SECONDS = 75;
const HOST = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const ZONE = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
const DIGEST = /^[a-f0-9]{64}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const SOCKET_PATH = /^\/(?:[A-Za-z0-9._-]+\/)*[A-Za-z0-9._-]+\.sock$/;
const IDENTITY = /^[a-z_][a-z0-9_-]{0,31}$/;
const ATTESTATION_KEYS = Object.freeze([
  'schemaVersion', 'relayHostname', 'route', 'upstreamPort', 'maxFrameBytes',
  'generation', 'buildDigest', 'proxyBoundaryDigest', 'certificateIdentityMappingDigest',
  'issuedAtMs', 'expiresAtMs', 'nonce', 'signature'
]);
const PROXY_BOUNDARY_ATTESTATION_KEYS = Object.freeze([
  'schemaVersion', 'transport', 'socketPath', 'socketOwner', 'socketGroup', 'socketMode',
  'generation', 'buildDigest', 'issuedAtMs', 'expiresAtMs', 'nonce', 'signature'
]);
const IDENTITY_MAPPING_KEYS = Object.freeze([
  'schemaVersion', 'digestSource', 'digestAlgorithm', 'digestEncoding',
  'backendCertificateInput', 'generation', 'buildDigest'
]);

class OnlineFraNginxDeploymentVerifierError extends Error {
  constructor(code) { super(code); this.name = 'OnlineFraNginxDeploymentVerifierError'; this.code = code; }
}
function fail(code) { throw new OnlineFraNginxDeploymentVerifierError(code); }
function plain(value) {
  try {
    return Boolean(value) && typeof value === 'object' && !Array.isArray(value)
      && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
  } catch { return false; }
}
function exact(value, keys, code) {
  if (!plain(value)) fail(code);
  let actual;
  try { actual = Reflect.ownKeys(value); } catch { fail(code); }
  if (actual.length !== keys.length || actual.some(key => typeof key !== 'string' || !keys.includes(key))) fail(code);
  for (const key of actual) {
    let descriptor;
    try { descriptor = Object.getOwnPropertyDescriptor(value, key); } catch { fail(code); }
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) fail(code);
  }
  return value;
}
function string(value, code, expression, maximum) {
  if (typeof value !== 'string' || value.length < 1 || value.length > maximum || !expression.test(value)) fail(code);
  return value;
}
function integer(value, code, minimum, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) fail(code);
  return value;
}
function hostname(value, code) { return string(value, code, HOST, 253); }
function digest(value, code) { return string(value, code, DIGEST, 64); }
function zone(value, code) { return string(value, code, ZONE, 64); }
function socketPath(value, code) {
  const result = string(value, code, SOCKET_PATH, 512);
  if (result.split('/').includes('..') || result.includes('//')) fail(code);
  return result;
}
function identity(value, code) {
  const result = string(value, code, IDENTITY, 32);
  if (result === 'root') fail(code);
  return result;
}
function socketMode(value, code) {
  if (value !== '0600' && value !== '0660') fail(code);
  return value;
}
function base64url(value, code, minimum, maximum) {
  if (typeof value !== 'string' || !BASE64URL.test(value)) fail(code);
  let bytes;
  try { bytes = Buffer.from(value, 'base64url'); } catch { fail(code); }
  if (bytes.length < minimum || bytes.length > maximum || bytes.toString('base64url') !== value) fail(code);
  return bytes;
}

function canonicalBytes(value, keys, code) {
  const source = exact(value, keys, code);
  const ordered = {};
  for (const key of keys) if (key !== 'signature') ordered[key] = source[key];
  return Buffer.from(JSON.stringify(ordered), 'utf8');
}
function canonicalDigest(value, keys, code) {
  return crypto.createHash('sha256').update(canonicalBytes(value, keys, code)).digest('hex');
}

function backendAttestationSigningBytes(value) {
  return canonicalBytes(value, ATTESTATION_KEYS, 'ONLINE_FRA_NGINX_ATTESTATION_INVALID');
}
function proxyBoundaryAttestationSigningBytes(value) {
  return canonicalBytes(value, PROXY_BOUNDARY_ATTESTATION_KEYS, 'ONLINE_FRA_NGINX_PROXY_BOUNDARY_INVALID');
}

function tokenize(text) {
  if (typeof text !== 'string' || text.length < 1 || Buffer.byteLength(text, 'utf8') > MAX_CONFIG_BYTES || /[\0\x01-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(text)) {
    fail('ONLINE_FRA_NGINX_CONFIG_INVALID');
  }
  const tokens = []; let current = ''; let quote = null;
  function flush() { if (current.length) { tokens.push(current); current = ''; } }
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (quote) {
      if (character === '\\') {
        const next = text[++index];
        if (next === undefined || /[\r\n]/.test(next)) fail('ONLINE_FRA_NGINX_CONFIG_INVALID');
        current += next;
      } else if (character === quote) { tokens.push(current); current = ''; quote = null; }
      else { current += character; }
      continue;
    }
    if (character === '#' && !current.length) { while (index < text.length && text[index] !== '\n') index += 1; continue; }
    if (character === '"' || character === "'") { flush(); quote = character; continue; }
    if (/\s/.test(character)) { flush(); continue; }
    if (character === ';' || character === '{' || character === '}') { flush(); tokens.push(character); continue; }
    current += character;
  }
  if (quote) fail('ONLINE_FRA_NGINX_CONFIG_INVALID');
  flush();
  if (!tokens.length || tokens.length > MAX_TOKENS) fail('ONLINE_FRA_NGINX_CONFIG_INVALID');
  return tokens;
}

function parse(text) {
  const tokens = tokenize(text); let cursor = 0;
  function block(expectClose) {
    const statements = [];
    while (cursor < tokens.length) {
      if (tokens[cursor] === '}') {
        if (!expectClose) fail('ONLINE_FRA_NGINX_CONFIG_INVALID');
        cursor += 1; return statements;
      }
      const head = [];
      while (cursor < tokens.length && ![';', '{', '}'].includes(tokens[cursor])) head.push(tokens[cursor++]);
      if (!head.length || cursor >= tokens.length || tokens[cursor] === '}') fail('ONLINE_FRA_NGINX_CONFIG_INVALID');
      const ending = tokens[cursor++];
      if (ending === ';') statements.push(Object.freeze({ args: Object.freeze(head.slice(1)), children: null, name: head[0] }));
      else if (ending === '{') statements.push(Object.freeze({ args: Object.freeze(head.slice(1)), children: Object.freeze(block(true)), name: head[0] }));
      else fail('ONLINE_FRA_NGINX_CONFIG_INVALID');
    }
    if (expectClose) fail('ONLINE_FRA_NGINX_CONFIG_INVALID');
    return statements;
  }
  const root = Object.freeze(block(false));
  if (cursor !== tokens.length) fail('ONLINE_FRA_NGINX_CONFIG_INVALID');
  return root;
}

function direct(nodes, name) { return nodes.filter(node => node.name === name); }
function one(nodes, name, code) { const found = direct(nodes, name); if (found.length !== 1 || found[0].children !== null) fail(code); return found[0]; }
function oneBlock(nodes, name, code) { const found = direct(nodes, name); if (found.length !== 1 || found[0].children === null) fail(code); return found[0]; }
function has(nodes, name, args) { return direct(nodes, name).some(node => node.children === null && node.args.length === args.length && node.args.every((value, index) => value === args[index])); }
function descend(nodes) { return nodes.flatMap(node => [node, ...(node.children ? descend(node.children) : [])]); }
function wildcardMatches(name, host) {
  if (name === host) return true;
  if (name.startsWith('*.')) return host.endsWith(name.slice(1));
  if (name.startsWith('.')) return host === name.slice(1) || host.endsWith(name);
  return false;
}
function checkUnique(nodes, name, args, code) { if (!has(nodes, name, args) || direct(nodes, name).length !== 1) fail(code); }
function checkExactOne(nodes, name, args, code) {
  const matches = direct(nodes, name).filter(node => node.children === null && node.args.length === args.length && node.args.every((value, index) => value === args[index]));
  if (matches.length !== 1) fail(code);
}
function checkHeader(headers, key, value, code) {
  const keyHeaders = headers.filter(node => node.args[0] === key);
  if (keyHeaders.length !== 1 || keyHeaders[0].args.length !== 2 || keyHeaders[0].args[1] !== value) fail(code);
}

function verifyAttestation(input, now) {
  const source = exact(input.backendAttestation, ATTESTATION_KEYS, 'ONLINE_FRA_NGINX_ATTESTATION_INVALID');
  if (source.schemaVersion !== ATTESTATION_VERSION || hostname(source.relayHostname, 'ONLINE_FRA_NGINX_ATTESTATION_INVALID') !== input.relayHostname
      || source.route !== ROUTE || source.upstreamPort !== input.upstreamPort || source.maxFrameBytes !== input.maxFrameBytes
      || source.generation !== input.backendGeneration || digest(source.buildDigest, 'ONLINE_FRA_NGINX_ATTESTATION_INVALID') !== input.backendBuildDigest
      || digest(source.proxyBoundaryDigest, 'ONLINE_FRA_NGINX_ATTESTATION_INVALID') !== input.proxyBoundaryDigest
      || digest(source.certificateIdentityMappingDigest, 'ONLINE_FRA_NGINX_ATTESTATION_INVALID') !== input.certificateIdentityMappingDigest) {
    fail('ONLINE_FRA_NGINX_ATTESTATION_INVALID');
  }
  const issuedAtMs = integer(source.issuedAtMs, 'ONLINE_FRA_NGINX_ATTESTATION_INVALID', 1, MAX_TIMESTAMP);
  const expiresAtMs = integer(source.expiresAtMs, 'ONLINE_FRA_NGINX_ATTESTATION_INVALID', 1, MAX_TIMESTAMP);
  if (issuedAtMs > now + MAX_CLOCK_SKEW_MS || expiresAtMs <= now || expiresAtMs <= issuedAtMs || expiresAtMs - issuedAtMs > MAX_ATTESTATION_AGE_MS) {
    fail('ONLINE_FRA_NGINX_ATTESTATION_STALE');
  }
  const signature = base64url(source.signature, 'ONLINE_FRA_NGINX_ATTESTATION_INVALID', 64, 64);
  base64url(source.nonce, 'ONLINE_FRA_NGINX_ATTESTATION_INVALID', 16, 64);
  let publicKey;
  try { publicKey = input.backendAttestationPublicKey && input.backendAttestationPublicKey.type === 'public' ? input.backendAttestationPublicKey : crypto.createPublicKey(input.backendAttestationPublicKey); }
  catch { fail('ONLINE_FRA_NGINX_ATTESTATION_INVALID'); }
  if (publicKey.asymmetricKeyType !== 'ed25519') fail('ONLINE_FRA_NGINX_ATTESTATION_INVALID');
  try { if (!crypto.verify(null, backendAttestationSigningBytes(source), publicKey, signature)) fail('ONLINE_FRA_NGINX_ATTESTATION_INVALID'); }
  catch (error) { if (error instanceof OnlineFraNginxDeploymentVerifierError) throw error; fail('ONLINE_FRA_NGINX_ATTESTATION_INVALID'); }
}

function verifyProxyBoundaryAttestation(input, now) {
  const source = exact(input.backendProxyBoundaryAttestation, PROXY_BOUNDARY_ATTESTATION_KEYS, 'ONLINE_FRA_NGINX_PROXY_BOUNDARY_INVALID');
  const expected = input.backendSocket;
  if (source.schemaVersion !== PROXY_BOUNDARY_ATTESTATION_VERSION || source.transport !== 'unix-domain-socket'
      || socketPath(source.socketPath, 'ONLINE_FRA_NGINX_PROXY_BOUNDARY_INVALID') !== expected.path
      || identity(source.socketOwner, 'ONLINE_FRA_NGINX_PROXY_BOUNDARY_INVALID') !== expected.owner
      || identity(source.socketGroup, 'ONLINE_FRA_NGINX_PROXY_BOUNDARY_INVALID') !== expected.group
      || socketMode(source.socketMode, 'ONLINE_FRA_NGINX_PROXY_BOUNDARY_INVALID') !== expected.mode
      || source.generation !== input.backendGeneration
      || digest(source.buildDigest, 'ONLINE_FRA_NGINX_PROXY_BOUNDARY_INVALID') !== input.backendBuildDigest) {
    fail('ONLINE_FRA_NGINX_PROXY_BOUNDARY_INVALID');
  }
  const issuedAtMs = integer(source.issuedAtMs, 'ONLINE_FRA_NGINX_PROXY_BOUNDARY_INVALID', 1, MAX_TIMESTAMP);
  const expiresAtMs = integer(source.expiresAtMs, 'ONLINE_FRA_NGINX_PROXY_BOUNDARY_INVALID', 1, MAX_TIMESTAMP);
  if (issuedAtMs > now + MAX_CLOCK_SKEW_MS || expiresAtMs <= now || expiresAtMs <= issuedAtMs || expiresAtMs - issuedAtMs > MAX_ATTESTATION_AGE_MS) {
    fail('ONLINE_FRA_NGINX_PROXY_BOUNDARY_STALE');
  }
  const signature = base64url(source.signature, 'ONLINE_FRA_NGINX_PROXY_BOUNDARY_INVALID', 64, 64);
  base64url(source.nonce, 'ONLINE_FRA_NGINX_PROXY_BOUNDARY_INVALID', 16, 64);
  let publicKey;
  try { publicKey = input.backendAttestationPublicKey && input.backendAttestationPublicKey.type === 'public' ? input.backendAttestationPublicKey : crypto.createPublicKey(input.backendAttestationPublicKey); }
  catch { fail('ONLINE_FRA_NGINX_PROXY_BOUNDARY_INVALID'); }
  if (publicKey.asymmetricKeyType !== 'ed25519') fail('ONLINE_FRA_NGINX_PROXY_BOUNDARY_INVALID');
  try { if (!crypto.verify(null, proxyBoundaryAttestationSigningBytes(source), publicKey, signature)) fail('ONLINE_FRA_NGINX_PROXY_BOUNDARY_INVALID'); }
  catch (error) { if (error instanceof OnlineFraNginxDeploymentVerifierError) throw error; fail('ONLINE_FRA_NGINX_PROXY_BOUNDARY_INVALID'); }
  return canonicalDigest(source, PROXY_BOUNDARY_ATTESTATION_KEYS, 'ONLINE_FRA_NGINX_PROXY_BOUNDARY_INVALID');
}

function verifyCertificateIdentityMapping(input) {
  const source = exact(input.certificateIdentityMapping, IDENTITY_MAPPING_KEYS, 'ONLINE_FRA_NGINX_IDENTITY_MAPPING_INVALID');
  if (source.schemaVersion !== IDENTITY_MAPPING_VERSION
      || !['leaf-der', 'leaf-spki'].includes(source.digestSource)
      || source.digestAlgorithm !== 'sha256'
      || source.digestEncoding !== 'lowercase-hex-64'
      || source.backendCertificateInput !== 'trusted-nginx-client-certificate'
      || source.generation !== input.backendGeneration
      || digest(source.buildDigest, 'ONLINE_FRA_NGINX_IDENTITY_MAPPING_INVALID') !== input.backendBuildDigest) {
    fail('ONLINE_FRA_NGINX_IDENTITY_MAPPING_INVALID');
  }
  return canonicalDigest(source, IDENTITY_MAPPING_KEYS, 'ONLINE_FRA_NGINX_IDENTITY_MAPPING_INVALID');
}

function verifyNginxDeployment(options = {}) {
  if (!plain(options)) fail('ONLINE_FRA_NGINX_DEPLOYMENT_OPTIONS_INVALID');
  let enabledDescriptor;
  try { enabledDescriptor = Object.getOwnPropertyDescriptor(options, 'enabled'); } catch { fail('ONLINE_FRA_NGINX_DEPLOYMENT_OPTIONS_INVALID'); }
  if (enabledDescriptor && (!enabledDescriptor.enumerable || !Object.hasOwn(enabledDescriptor, 'value'))) fail('ONLINE_FRA_NGINX_DEPLOYMENT_OPTIONS_INVALID');
  const enabled = enabledDescriptor ? enabledDescriptor.value : false;
  if (enabled !== true && enabled !== false) fail('ONLINE_FRA_NGINX_DEPLOYMENT_OPTIONS_INVALID');
  if (!enabled) return Object.freeze({ ok: true, status: 'disabled' });
  const keys = [
    'enabled', 'captureKind', 'nginxConfigText', 'relayHostname', 'upstreamPort', 'maxFrameBytes', 'backendGeneration', 'backendBuildDigest',
    'backendAttestation', 'backendProxyBoundaryAttestation', 'backendAttestationPublicKey', 'backendSocket',
    'certificateIdentityMapping', 'clock', 'limitConn', 'limitReq'
  ];
  exact(options, keys, 'ONLINE_FRA_NGINX_DEPLOYMENT_OPTIONS_INVALID');
  if (!['full-rendered', 'nginx-t-expanded'].includes(options.captureKind) || typeof options.clock !== 'function') fail('ONLINE_FRA_NGINX_DEPLOYMENT_OPTIONS_INVALID');
  const relayHostname = hostname(options.relayHostname, 'ONLINE_FRA_NGINX_DEPLOYMENT_OPTIONS_INVALID');
  const upstreamPort = integer(options.upstreamPort, 'ONLINE_FRA_NGINX_DEPLOYMENT_OPTIONS_INVALID', 1, 65535);
  const maxFrameBytes = integer(options.maxFrameBytes, 'ONLINE_FRA_NGINX_DEPLOYMENT_OPTIONS_INVALID', 1024, 262144);
  const backendGeneration = integer(options.backendGeneration, 'ONLINE_FRA_NGINX_DEPLOYMENT_OPTIONS_INVALID', 1);
  const backendBuildDigest = digest(options.backendBuildDigest, 'ONLINE_FRA_NGINX_DEPLOYMENT_OPTIONS_INVALID');
  const backendSocket = exact(options.backendSocket, ['path', 'owner', 'group', 'mode'], 'ONLINE_FRA_NGINX_DEPLOYMENT_OPTIONS_INVALID');
  const backendSocketPath = socketPath(backendSocket.path, 'ONLINE_FRA_NGINX_PROXY_BOUNDARY_INVALID');
  const backendSocketOwner = identity(backendSocket.owner, 'ONLINE_FRA_NGINX_PROXY_BOUNDARY_INVALID');
  const backendSocketGroup = identity(backendSocket.group, 'ONLINE_FRA_NGINX_PROXY_BOUNDARY_INVALID');
  const backendSocketMode = socketMode(backendSocket.mode, 'ONLINE_FRA_NGINX_PROXY_BOUNDARY_INVALID');
  const limitConn = exact(options.limitConn, ['key', 'maxConnections', 'sharedMemoryBytes', 'zone'], 'ONLINE_FRA_NGINX_DEPLOYMENT_OPTIONS_INVALID');
  const limitReq = exact(options.limitReq, ['burst', 'key', 'ratePerSecond', 'sharedMemoryBytes', 'zone'], 'ONLINE_FRA_NGINX_DEPLOYMENT_OPTIONS_INVALID');
  if (limitConn.key !== '$ssl_client_serial' || limitReq.key !== '$ssl_client_serial') fail('ONLINE_FRA_NGINX_LIMIT_INVALID');
  const limitConnZone = zone(limitConn.zone, 'ONLINE_FRA_NGINX_LIMIT_INVALID');
  const limitReqZone = zone(limitReq.zone, 'ONLINE_FRA_NGINX_LIMIT_INVALID');
  const limitConnMaximum = integer(limitConn.maxConnections, 'ONLINE_FRA_NGINX_LIMIT_INVALID', 1, 4);
  const limitReqBurst = integer(limitReq.burst, 'ONLINE_FRA_NGINX_LIMIT_INVALID', 1, 10);
  const limitReqRate = integer(limitReq.ratePerSecond, 'ONLINE_FRA_NGINX_LIMIT_INVALID', 1, 60);
  const limitConnMemory = integer(limitConn.sharedMemoryBytes, 'ONLINE_FRA_NGINX_LIMIT_INVALID', 1024 * 1024, 64 * 1024 * 1024);
  const limitReqMemory = integer(limitReq.sharedMemoryBytes, 'ONLINE_FRA_NGINX_LIMIT_INVALID', 1024 * 1024, 64 * 1024 * 1024);
  if (limitConnMemory % (1024 * 1024) !== 0 || limitReqMemory % (1024 * 1024) !== 0) fail('ONLINE_FRA_NGINX_LIMIT_INVALID');
  let now;
  try { now = options.clock(); } catch { fail('ONLINE_FRA_NGINX_DEPLOYMENT_UNAVAILABLE'); }
  integer(now, 'ONLINE_FRA_NGINX_DEPLOYMENT_UNAVAILABLE', 1, MAX_TIMESTAMP);
  const attestationInput = {
    ...options, relayHostname, upstreamPort, maxFrameBytes, backendGeneration, backendBuildDigest,
    backendSocket: { path: backendSocketPath, owner: backendSocketOwner, group: backendSocketGroup, mode: backendSocketMode }
  };
  // Bind the exact separately supplied receipt into the capability before
  // checking its signature. A receipt that is not what the capability signed
  // is a capability failure; a correctly bound but bad/stale receipt is a
  // boundary failure below.
  const proxyBoundaryDigest = canonicalDigest(
    attestationInput.backendProxyBoundaryAttestation,
    PROXY_BOUNDARY_ATTESTATION_KEYS,
    'ONLINE_FRA_NGINX_PROXY_BOUNDARY_INVALID'
  );
  const certificateIdentityMappingDigest = verifyCertificateIdentityMapping(attestationInput);
  verifyAttestation({ ...attestationInput, proxyBoundaryDigest, certificateIdentityMappingDigest }, now);
  verifyProxyBoundaryAttestation(attestationInput, now);
  const root = parse(options.nginxConfigText);
  if (descend(root).some(node => node.name === 'include')) fail('ONLINE_FRA_NGINX_CONFIG_INCOMPLETE');
  const http = oneBlock(root, 'http', 'ONLINE_FRA_NGINX_CONFIG_INCOMPLETE');
  if (direct(root, 'http').length !== 1 || descend(root).some(node => node.name === 'server' && !http.children.includes(node))) fail('ONLINE_FRA_NGINX_CONFIG_AMBIGUOUS');
  const connZone = one(http.children, 'limit_conn_zone', 'ONLINE_FRA_NGINX_LIMIT_INVALID');
  const reqZone = one(http.children, 'limit_req_zone', 'ONLINE_FRA_NGINX_LIMIT_INVALID');
  const expectedConnZone = [`$ssl_client_serial`, `zone=${limitConnZone}:${limitConnMemory / (1024 * 1024)}m`];
  const expectedReqZone = [`$ssl_client_serial`, `zone=${limitReqZone}:${limitReqMemory / (1024 * 1024)}m`, `rate=${limitReqRate}r/s`];
  if (connZone.args.length !== expectedConnZone.length || connZone.args.some((item, index) => item !== expectedConnZone[index])
      || reqZone.args.length !== expectedReqZone.length || reqZone.args.some((item, index) => item !== expectedReqZone[index])) fail('ONLINE_FRA_NGINX_LIMIT_INVALID');
  const servers = direct(http.children, 'server');
  if (!servers.length) fail('ONLINE_FRA_NGINX_CONFIG_INCOMPLETE');
  let fraServer = null;
  for (const server of servers) {
    const names = direct(server.children, 'server_name').flatMap(node => node.args);
    if (!names.length) fail('ONLINE_FRA_NGINX_CONFIG_AMBIGUOUS');
    if (names.some(name => name.startsWith('~'))) fail('ONLINE_FRA_NGINX_CONFIG_AMBIGUOUS');
    if (names.some(name => wildcardMatches(name, relayHostname))) {
      if (fraServer) fail('ONLINE_FRA_NGINX_HOSTNAME_COLLISION');
      fraServer = server;
    }
  }
  if (!fraServer) fail('ONLINE_FRA_NGINX_HOSTNAME_MISSING');
  const fraNames = direct(fraServer.children, 'server_name').flatMap(node => node.args);
  if (fraNames.length !== 1 || fraNames[0] !== relayHostname) fail('ONLINE_FRA_NGINX_HOSTNAME_COLLISION');
  const fraServerDirectives = new Set([
    'listen', 'server_name', 'ssl_protocols', 'ssl_early_data', 'ssl_certificate',
    'ssl_certificate_key', 'ssl_client_certificate', 'ssl_verify_client', 'ssl_verify_depth',
    'error_log', 'access_log', 'client_max_body_size', 'client_header_buffer_size',
    'large_client_header_buffers', 'location'
  ]);
  if (fraServer.children.some(node => !fraServerDirectives.has(node.name))) fail('ONLINE_FRA_NGINX_ROUTE_INVALID');
  const fraListen = one(fraServer.children, 'listen', 'ONLINE_FRA_NGINX_TLS_INVALID');
  if (fraListen.args.length !== 2 || fraListen.args[0] !== '443' || fraListen.args[1] !== 'ssl' || fraListen.args.includes('default_server')) fail('ONLINE_FRA_NGINX_TLS_INVALID');
  if (direct(fraServer.children, 'listen').length !== 1) fail('ONLINE_FRA_NGINX_TLS_INVALID');
  checkUnique(fraServer.children, 'ssl_protocols', ['TLSv1.3'], 'ONLINE_FRA_NGINX_TLS_INVALID');
  checkUnique(fraServer.children, 'ssl_early_data', ['off'], 'ONLINE_FRA_NGINX_TLS_INVALID');
  checkUnique(fraServer.children, 'ssl_verify_client', ['on'], 'ONLINE_FRA_NGINX_MTLS_INVALID');
  checkUnique(fraServer.children, 'ssl_verify_depth', ['2'], 'ONLINE_FRA_NGINX_MTLS_INVALID');
  const certificate = one(fraServer.children, 'ssl_certificate', 'ONLINE_FRA_NGINX_TLS_INVALID');
  const certificateKey = one(fraServer.children, 'ssl_certificate_key', 'ONLINE_FRA_NGINX_TLS_INVALID');
  if (certificate.args.length !== 1 || certificateKey.args.length !== 1 || !certificate.args[0].startsWith('/') || !certificateKey.args[0].startsWith('/')) fail('ONLINE_FRA_NGINX_TLS_INVALID');
  const clientCa = one(fraServer.children, 'ssl_client_certificate', 'ONLINE_FRA_NGINX_MTLS_INVALID');
  if (clientCa.args.length !== 1 || !clientCa.args[0].startsWith('/')) fail('ONLINE_FRA_NGINX_MTLS_INVALID');
  checkUnique(fraServer.children, 'access_log', ['off'], 'ONLINE_FRA_NGINX_LOGGING_INVALID');
  const errorLog = one(fraServer.children, 'error_log', 'ONLINE_FRA_NGINX_LOGGING_INVALID');
  if (errorLog.args.length !== 2 || !errorLog.args[0].startsWith('/') || errorLog.args[1] !== 'crit') fail('ONLINE_FRA_NGINX_LOGGING_INVALID');
  checkUnique(fraServer.children, 'client_max_body_size', [String(MAX_BODY_BYTES)], 'ONLINE_FRA_NGINX_ROUTE_INVALID');
  checkUnique(fraServer.children, 'client_header_buffer_size', [String(HEADER_BUFFER_BYTES)], 'ONLINE_FRA_NGINX_ROUTE_INVALID');
  checkUnique(fraServer.children, 'large_client_header_buffers', ['2', String(HEADER_BUFFER_BYTES)], 'ONLINE_FRA_NGINX_ROUTE_INVALID');
  const locations = direct(fraServer.children, 'location');
  if (locations.length !== 2) fail('ONLINE_FRA_NGINX_ROUTE_INVALID');
  const endpoint = locations.find(node => node.args.length === 2 && node.args[0] === '=' && node.args[1] === ROUTE);
  const catchAll = locations.find(node => node.args.length === 1 && node.args[0] === '/');
  if (!endpoint || !catchAll || catchAll.children.length !== 1 || !has(catchAll.children, 'return', ['404'])) fail('ONLINE_FRA_NGINX_ROUTE_INVALID');
  if (descend(fraServer.children).filter(node => node.name === 'proxy_pass').length !== 1) fail('ONLINE_FRA_NGINX_ROUTE_INVALID');
  if (descend(fraServer.children).some(node => node.args.includes('$ssl_client_fingerprint'))) fail('ONLINE_FRA_NGINX_IDENTITY_MAPPING_INVALID');
  const endpointDirectives = new Set([
    'access_log', 'limit_conn', 'limit_req', 'if', 'proxy_http_version', 'proxy_set_header',
    'proxy_buffering', 'proxy_request_buffering', 'proxy_connect_timeout', 'proxy_send_timeout',
    'proxy_read_timeout', 'proxy_pass'
  ]);
  if (endpoint.children.some(node => !endpointDirectives.has(node.name))) fail('ONLINE_FRA_NGINX_ROUTE_INVALID');
  checkUnique(endpoint.children, 'access_log', ['off'], 'ONLINE_FRA_NGINX_LOGGING_INVALID');
  checkUnique(endpoint.children, 'limit_conn', [limitConnZone, String(limitConnMaximum)], 'ONLINE_FRA_NGINX_LIMIT_INVALID');
  checkUnique(endpoint.children, 'limit_req', [`zone=${limitReqZone}`, `burst=${limitReqBurst}`, 'nodelay'], 'ONLINE_FRA_NGINX_LIMIT_INVALID');
  const guards = direct(endpoint.children, 'if');
  const sniGuard = guards.find(node => node.args.length === 3 && node.args[0] === '($ssl_server_name' && node.args[1] === '!=' && node.args[2] === `${relayHostname})` && node.children.length === 1 && has(node.children, 'return', ['421']));
  const mtlsGuard = guards.find(node => node.args.length === 3 && node.args[0] === '($ssl_client_verify' && node.args[1] === '!=' && node.args[2] === 'SUCCESS)' && node.children.length === 1 && has(node.children, 'return', ['403']));
  if (!sniGuard || !mtlsGuard || guards.length !== 2) fail('ONLINE_FRA_NGINX_MTLS_INVALID');
  checkUnique(endpoint.children, 'proxy_http_version', ['1.1'], 'ONLINE_FRA_NGINX_ROUTE_INVALID');
  checkExactOne(endpoint.children, 'proxy_set_header', ['Upgrade', '$http_upgrade'], 'ONLINE_FRA_NGINX_ROUTE_INVALID');
  const headers = direct(endpoint.children, 'proxy_set_header');
  if (headers.length !== 13) fail('ONLINE_FRA_NGINX_ROUTE_INVALID');
  checkHeader(headers, 'Connection', 'upgrade', 'ONLINE_FRA_NGINX_ROUTE_INVALID');
  checkHeader(headers, 'Host', relayHostname, 'ONLINE_FRA_NGINX_ROUTE_INVALID');
  checkHeader(headers, 'X-FRA-Client-Verify', '$ssl_client_verify', 'ONLINE_FRA_NGINX_ROUTE_INVALID');
  checkHeader(headers, 'X-FRA-Client-Certificate', '$ssl_client_escaped_cert', 'ONLINE_FRA_NGINX_IDENTITY_MAPPING_INVALID');
  checkHeader(headers, 'X-FRA-Client-Address', '$remote_addr', 'ONLINE_FRA_NGINX_IDENTITY_MAPPING_INVALID');
  /* EVERY HEADER THE EDGE TRUSTS MUST BE ATTESTED HERE, and X-Real-IP was not.
     online-fra-websocket-adapter.js reads both X-FRA-Client-Address and X-Real-IP
     for the per-IP budget. A header this vhost does not SET is one nginx forwards
     from the client, so leaving X-Real-IP unset made it attacker-chosen -- measured
     on the published tree as a complete per-IP limit bypass. Requiring it here is
     what makes "the edge only trusts attested addresses" a checked property of a
     deployment rather than a convention somebody has to remember. */
  checkHeader(headers, 'X-Real-IP', '$remote_addr', 'ONLINE_FRA_NGINX_IDENTITY_MAPPING_INVALID');
  checkHeader(headers, 'X-FRA-Max-Frame-Bytes', String(maxFrameBytes), 'ONLINE_FRA_NGINX_ROUTE_INVALID');
  // These names are cleared rather than relayed. The backend's sole certificate
  // identity input is the server-derived escaped leaf certificate above; it
  // computes the SHA-256 DER/SPKI digest itself after the Unix-peer boundary.
  checkHeader(headers, 'X-FRA-Client-Subject', '', 'ONLINE_FRA_NGINX_IDENTITY_MAPPING_INVALID');
  checkHeader(headers, 'X-FRA-Client-Serial', '', 'ONLINE_FRA_NGINX_IDENTITY_MAPPING_INVALID');
  checkHeader(headers, 'X-FRA-Client-Fingerprint', '', 'ONLINE_FRA_NGINX_IDENTITY_MAPPING_INVALID');
  checkHeader(headers, 'X-FRA-Device-Fingerprint', '', 'ONLINE_FRA_NGINX_IDENTITY_MAPPING_INVALID');
  checkHeader(headers, 'X-FRA-Proxy-Auth', '', 'ONLINE_FRA_NGINX_PROXY_BOUNDARY_INVALID');
  checkUnique(endpoint.children, 'proxy_buffering', ['off'], 'ONLINE_FRA_NGINX_ROUTE_INVALID');
  checkUnique(endpoint.children, 'proxy_request_buffering', ['off'], 'ONLINE_FRA_NGINX_ROUTE_INVALID');
  checkUnique(endpoint.children, 'proxy_connect_timeout', [`${PROXY_CONNECT_TIMEOUT_SECONDS}s`], 'ONLINE_FRA_NGINX_ROUTE_INVALID');
  checkUnique(endpoint.children, 'proxy_send_timeout', [`${PROXY_SEND_TIMEOUT_SECONDS}s`], 'ONLINE_FRA_NGINX_ROUTE_INVALID');
  checkUnique(endpoint.children, 'proxy_read_timeout', [`${PROXY_READ_TIMEOUT_SECONDS}s`], 'ONLINE_FRA_NGINX_ROUTE_INVALID');
  const proxyPass = one(endpoint.children, 'proxy_pass', 'ONLINE_FRA_NGINX_ROUTE_INVALID');
  if (proxyPass.args.length !== 1 || proxyPass.args[0] !== `http://unix:${backendSocketPath}:${ROUTE}`) fail('ONLINE_FRA_NGINX_PROXY_BOUNDARY_INVALID');
  return Object.freeze({
    ok: true, relayHostname, route: ROUTE, maxFrameBytes, backendGeneration, backendBuildDigest,
    backendTransport: 'unix-domain-socket', certificateIdentityDigest: 'sha256', status: 'verified'
  });
}

module.exports = Object.freeze({
  ATTESTATION_VERSION, PROXY_BOUNDARY_ATTESTATION_VERSION, IDENTITY_MAPPING_VERSION,
  OnlineFraNginxDeploymentVerifierError, backendAttestationSigningBytes,
  proxyBoundaryAttestationSigningBytes, verifyNginxDeployment
});
