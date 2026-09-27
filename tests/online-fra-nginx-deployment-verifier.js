'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const {
  ATTESTATION_VERSION,
  PROXY_BOUNDARY_ATTESTATION_VERSION,
  IDENTITY_MAPPING_VERSION,
  backendAttestationSigningBytes,
  proxyBoundaryAttestationSigningBytes,
  verifyNginxDeployment
} = require('../src/lib/online-fra-nginx-deployment-verifier');
const { render: renderNginxVhost } = require('../src/lib/online-fra-nginx-config');

let assertions = 0;
const equal = (...args) => { assertions += 1; return assert.equal(...args); };
const ok = (...args) => { assertions += 1; return assert.ok(...args); };
const deepEqual = (...args) => { assertions += 1; return assert.deepEqual(...args); };
const throws = (fn, code) => { assertions += 1; assert.throws(fn, error => error && error.code === code); };

const authority = crypto.generateKeyPairSync('ed25519');
const relayHostname = 'fra-relay.devices.example.net';
const buildDigest = 'a'.repeat(64);
const now = 4_000_000_000;

function config(overrides = {}) {
  const values = {
    host: relayHostname, port: 9443, socketPath: '/run/fra/rendezvous.sock', connZone: 'fra_relay_conn', reqZone: 'fra_relay_req',
    connSize: '10m', reqSize: '10m', reqRate: '5r/s', maxConnections: 4, burst: 10,
    frame: 262144, tls: 'TLSv1.3', earlyData: 'off', verify: 'on', serverName: relayHostname,
    sniGuard: relayHostname, mtlsValue: 'SUCCESS', upstreamHost: '127.0.0.1', accessLog: 'off',
    body: 8192, header: 4096, connectTimeout: '5s', sendTimeout: '30s', readTimeout: '75s',
    extraHttp: '', extraServer: '', extraLocation: '', websiteName: 'example.com'
  };
  Object.assign(values, overrides);
  return `
events { worker_connections 128; }
http {
  limit_conn_zone $ssl_client_serial zone=${values.connZone}:${values.connSize};
  limit_req_zone $ssl_client_serial zone=${values.reqZone}:${values.reqSize} rate=${values.reqRate};
  ${values.extraHttp}
  server {
    listen 443 ssl default_server;
    server_name ${values.websiteName};
    location / { return 404; }
  }
  server {
    listen 443 ssl;
    server_name ${values.serverName};
    ssl_protocols ${values.tls};
    ssl_early_data ${values.earlyData};
    ssl_certificate /etc/nginx/fra/fra.crt;
    ssl_certificate_key /etc/nginx/fra/fra.key;
    ssl_client_certificate /etc/nginx/fra/device-ca.pem;
    ssl_verify_client ${values.verify};
    ssl_verify_depth 2;
    error_log /var/log/nginx/fra-error.log crit;
    access_log ${values.accessLog};
    client_max_body_size ${values.body};
    client_header_buffer_size ${values.header};
    large_client_header_buffers 2 ${values.header};
    ${values.extraServer}
    location = /v1/rendezvous {
      access_log off;
      limit_conn ${values.connZone} ${values.maxConnections};
      limit_req zone=${values.reqZone} burst=${values.burst} nodelay;
      if ($ssl_server_name != ${values.sniGuard}) { return 421; }
      if ($ssl_client_verify != ${values.mtlsValue}) { return 403; }
      proxy_http_version 1.1;
      proxy_set_header Upgrade $http_upgrade;
      proxy_set_header Connection "upgrade";
      proxy_set_header Host ${values.host};
      proxy_set_header X-FRA-Client-Verify $ssl_client_verify;
      proxy_set_header X-FRA-Client-Certificate $ssl_client_escaped_cert;
      proxy_set_header X-FRA-Client-Address $remote_addr;
      proxy_set_header X-Real-IP $remote_addr;
      proxy_set_header X-FRA-Max-Frame-Bytes ${values.frame};
      proxy_set_header X-FRA-Client-Subject "";
      proxy_set_header X-FRA-Client-Serial "";
      proxy_set_header X-FRA-Client-Fingerprint "";
      proxy_set_header X-FRA-Device-Fingerprint "";
      proxy_set_header X-FRA-Proxy-Auth "";
      ${values.extraLocation}
      proxy_buffering off;
      proxy_request_buffering off;
      proxy_connect_timeout ${values.connectTimeout};
      proxy_send_timeout ${values.sendTimeout};
      proxy_read_timeout ${values.readTimeout};
      proxy_pass http://unix:${values.socketPath}:/v1/rendezvous;
    }
    location / { return 404; }
  }
}`;
}

function proxyBoundaryAttestation(overrides = {}) {
  const value = {
    schemaVersion: PROXY_BOUNDARY_ATTESTATION_VERSION,
    transport: 'unix-domain-socket',
    socketPath: '/run/fra/rendezvous.sock',
    socketOwner: 'fra_relay',
    socketGroup: 'nginx',
    socketMode: '0660',
    generation: 7,
    buildDigest,
    issuedAtMs: now - 100,
    expiresAtMs: now + 60_000,
    nonce: Buffer.alloc(24, 8).toString('base64url'),
    signature: Buffer.alloc(64).toString('base64url'),
    ...overrides
  };
  value.signature = crypto.sign(null, proxyBoundaryAttestationSigningBytes(value), authority.privateKey).toString('base64url');
  return value;
}

function certificateIdentityMapping(overrides = {}) {
  return {
    schemaVersion: IDENTITY_MAPPING_VERSION,
    digestSource: 'leaf-der',
    digestAlgorithm: 'sha256',
    digestEncoding: 'lowercase-hex-64',
    backendCertificateInput: 'trusted-nginx-client-certificate',
    generation: 7,
    buildDigest,
    ...overrides
  };
}

function certificateIdentityMappingDigest(value) {
  const ordered = {};
  for (const key of ['schemaVersion', 'digestSource', 'digestAlgorithm', 'digestEncoding', 'backendCertificateInput', 'generation', 'buildDigest']) ordered[key] = value[key];
  return crypto.createHash('sha256').update(JSON.stringify(ordered), 'utf8').digest('hex');
}

function attestation(overrides = {}, bindings = {}) {
  const boundary = bindings.proxyBoundary || proxyBoundaryAttestation();
  const mapping = bindings.certificateIdentityMapping || certificateIdentityMapping();
  const value = {
    schemaVersion: ATTESTATION_VERSION,
    relayHostname,
    route: '/v1/rendezvous',
    upstreamPort: 9443,
    maxFrameBytes: 262144,
    generation: 7,
    buildDigest,
    proxyBoundaryDigest: crypto.createHash('sha256').update(proxyBoundaryAttestationSigningBytes(boundary)).digest('hex'),
    certificateIdentityMappingDigest: certificateIdentityMappingDigest(mapping),
    issuedAtMs: now - 100,
    expiresAtMs: now + 60_000,
    nonce: Buffer.alloc(24, 9).toString('base64url'),
    signature: Buffer.alloc(64).toString('base64url'),
    ...overrides
  };
  value.signature = crypto.sign(null, backendAttestationSigningBytes(value), authority.privateKey).toString('base64url');
  return value;
}

function input(overrides = {}) {
  const boundary = overrides.backendProxyBoundaryAttestation || proxyBoundaryAttestation();
  const mapping = overrides.certificateIdentityMapping || certificateIdentityMapping();
  const capability = overrides.backendAttestation || attestation({}, { proxyBoundary: boundary, certificateIdentityMapping: mapping });
  return {
    enabled: true,
    captureKind: 'nginx-t-expanded',
    nginxConfigText: config(),
    relayHostname,
    upstreamPort: 9443,
    maxFrameBytes: 262144,
    backendGeneration: 7,
    backendBuildDigest: buildDigest,
    backendAttestation: capability,
    backendProxyBoundaryAttestation: boundary,
    backendAttestationPublicKey: authority.publicKey,
    backendSocket: { path: '/run/fra/rendezvous.sock', owner: 'fra_relay', group: 'nginx', mode: '0660' },
    certificateIdentityMapping: mapping,
    clock: () => now,
    limitConn: { key: '$ssl_client_serial', zone: 'fra_relay_conn', maxConnections: 4, sharedMemoryBytes: 10 * 1024 * 1024 },
    limitReq: { key: '$ssl_client_serial', zone: 'fra_relay_req', burst: 10, ratePerSecond: 5, sharedMemoryBytes: 10 * 1024 * 1024 },
    ...overrides
  };
}

equal(verifyNginxDeployment().status, 'disabled');
equal(verifyNginxDeployment({ enabled: false, forgedBoolean: true }).status, 'disabled');
{
  const getter = {};
  Object.defineProperty(getter, 'enabled', { enumerable: true, get() { throw Error('marker'); } });
  throws(() => verifyNginxDeployment(getter), 'ONLINE_FRA_NGINX_DEPLOYMENT_OPTIONS_INVALID');
}
{
  const verified = verifyNginxDeployment(input());
  deepEqual(verified, {
    ok: true, relayHostname, route: '/v1/rendezvous', maxFrameBytes: 262144, backendGeneration: 7,
    backendBuildDigest: buildDigest, backendTransport: 'unix-domain-socket', certificateIdentityDigest: 'sha256', status: 'verified'
  });
  equal(Object.isFrozen(verified), true);
}
{
  const renderedVhost = renderNginxVhost({
    relayHostname,
    deviceCaPath: '/etc/nginx/fra/device-ca.pem',
    certificatePath: '/etc/nginx/fra/fra.crt',
    certificateKeyPath: '/etc/nginx/fra/fra.key',
    errorLogPath: '/var/log/nginx/fra-error.log',
    backendSocketPath: '/run/fra/rendezvous.sock',
    limitConnZone: 'fra_relay_conn', limitReqZone: 'fra_relay_req',
    httpLimitZonesDeclared: true, websocketFrameLimitEnforced: true,
    existingServerNames: ['example.com'], existingVhostInventoryVerified: true
  });
  const fullConfig = `events { worker_connections 128; }\nhttp {\n`
    + 'limit_conn_zone $ssl_client_serial zone=fra_relay_conn:10m;\n'
    + 'limit_req_zone $ssl_client_serial zone=fra_relay_req:10m rate=5r/s;\n'
    + 'server { listen 443 ssl default_server; server_name example.com; location / { return 404; } }\n'
    + `${renderedVhost}\n}`;
  equal(verifyNginxDeployment(input({ nginxConfigText: fullConfig })).status, 'verified');
}

throws(() => verifyNginxDeployment(input({ httpLimitZonesDeclared: true })), 'ONLINE_FRA_NGINX_DEPLOYMENT_OPTIONS_INVALID');
throws(() => verifyNginxDeployment(input({ websocketFrameLimitEnforced: true })), 'ONLINE_FRA_NGINX_DEPLOYMENT_OPTIONS_INVALID');
throws(() => verifyNginxDeployment(input({ existingVhostInventoryVerified: true })), 'ONLINE_FRA_NGINX_DEPLOYMENT_OPTIONS_INVALID');
throws(() => verifyNginxDeployment(input({ captureKind: 'rendered-vhost' })), 'ONLINE_FRA_NGINX_DEPLOYMENT_OPTIONS_INVALID');
throws(() => verifyNginxDeployment(input({ nginxConfigText: config({ extraHttp: 'include /etc/nginx/conf.d/*.conf;' }) })), 'ONLINE_FRA_NGINX_CONFIG_INCOMPLETE');
throws(() => verifyNginxDeployment(input({ nginxConfigText: config({ websiteName: '~^fra-relay\\.devices\\.example\\.net$' }) })), 'ONLINE_FRA_NGINX_CONFIG_AMBIGUOUS');
throws(() => verifyNginxDeployment(input({ nginxConfigText: config({ websiteName: '.devices.example.net' }) })), 'ONLINE_FRA_NGINX_HOSTNAME_COLLISION');
throws(() => verifyNginxDeployment(input({ nginxConfigText: config({ websiteName: relayHostname }) })), 'ONLINE_FRA_NGINX_HOSTNAME_COLLISION');
throws(() => verifyNginxDeployment(input({ nginxConfigText: config({ serverName: '*.devices.example.net' }) })), 'ONLINE_FRA_NGINX_HOSTNAME_COLLISION');

throws(() => verifyNginxDeployment(input({ nginxConfigText: config({ tls: 'TLSv1.2 TLSv1.3' }) })), 'ONLINE_FRA_NGINX_TLS_INVALID');
throws(() => verifyNginxDeployment(input({ nginxConfigText: config({ earlyData: 'on' }) })), 'ONLINE_FRA_NGINX_TLS_INVALID');
throws(() => verifyNginxDeployment(input({ nginxConfigText: config({ verify: 'optional' }) })), 'ONLINE_FRA_NGINX_MTLS_INVALID');
throws(() => verifyNginxDeployment(input({ nginxConfigText: config().replace('if ($ssl_client_verify != SUCCESS) { return 403; }', '') })), 'ONLINE_FRA_NGINX_MTLS_INVALID');
throws(() => verifyNginxDeployment(input({ nginxConfigText: config({ sniGuard: 'other.example.net' }) })), 'ONLINE_FRA_NGINX_MTLS_INVALID');
throws(() => verifyNginxDeployment(input({ nginxConfigText: config({ mtlsValue: 'NONE' }) })), 'ONLINE_FRA_NGINX_MTLS_INVALID');
throws(() => verifyNginxDeployment(input({ nginxConfigText: config({ host: 'attacker.example.net' }) })), 'ONLINE_FRA_NGINX_ROUTE_INVALID');
throws(() => verifyNginxDeployment(input({ nginxConfigText: config({ socketPath: '/run/fra/attacker.sock' }) })), 'ONLINE_FRA_NGINX_PROXY_BOUNDARY_INVALID');
throws(() => verifyNginxDeployment(input({ nginxConfigText: config({ accessLog: 'on' }) })), 'ONLINE_FRA_NGINX_LOGGING_INVALID');
throws(() => verifyNginxDeployment(input({ nginxConfigText: config({ body: 16384 }) })), 'ONLINE_FRA_NGINX_ROUTE_INVALID');
throws(() => verifyNginxDeployment(input({ nginxConfigText: config({ header: 8192 }) })), 'ONLINE_FRA_NGINX_ROUTE_INVALID');
throws(() => verifyNginxDeployment(input({ nginxConfigText: config({ connectTimeout: '10s' }) })), 'ONLINE_FRA_NGINX_ROUTE_INVALID');
throws(() => verifyNginxDeployment(input({ nginxConfigText: config({ sendTimeout: '60s' }) })), 'ONLINE_FRA_NGINX_ROUTE_INVALID');
throws(() => verifyNginxDeployment(input({ nginxConfigText: config({ readTimeout: '300s' }) })), 'ONLINE_FRA_NGINX_ROUTE_INVALID');
throws(() => verifyNginxDeployment(input({ nginxConfigText: config({ connZone: 'other_conn' }) })), 'ONLINE_FRA_NGINX_LIMIT_INVALID');
throws(() => verifyNginxDeployment(input({ nginxConfigText: config({ reqRate: '100r/s' }) })), 'ONLINE_FRA_NGINX_LIMIT_INVALID');
throws(() => verifyNginxDeployment(input({ nginxConfigText: config({ frame: 131072 }) })), 'ONLINE_FRA_NGINX_ROUTE_INVALID');
throws(() => verifyNginxDeployment(input({ nginxConfigText: config({ extraLocation: 'proxy_set_header Host attacker.example.net;' }) })), 'ONLINE_FRA_NGINX_ROUTE_INVALID');
throws(() => verifyNginxDeployment(input({ nginxConfigText: config({ extraLocation: 'proxy_pass http://127.0.0.1:9443;' }) })), 'ONLINE_FRA_NGINX_ROUTE_INVALID');
throws(() => verifyNginxDeployment(input({ nginxConfigText: config({ extraServer: 'location /admin { proxy_pass http://127.0.0.1:9443; }' }) })), 'ONLINE_FRA_NGINX_ROUTE_INVALID');

throws(() => verifyNginxDeployment(input({ backendAttestation: attestation({ generation: 8 }) })), 'ONLINE_FRA_NGINX_ATTESTATION_INVALID');
throws(() => verifyNginxDeployment(input({ backendAttestation: attestation({ buildDigest: 'b'.repeat(64) }) })), 'ONLINE_FRA_NGINX_ATTESTATION_INVALID');
throws(() => verifyNginxDeployment(input({ backendAttestation: attestation({ maxFrameBytes: 131072 }) })), 'ONLINE_FRA_NGINX_ATTESTATION_INVALID');
throws(() => verifyNginxDeployment(input({ backendAttestation: attestation({ expiresAtMs: now - 1, issuedAtMs: now - 1000 }) })), 'ONLINE_FRA_NGINX_ATTESTATION_STALE');
throws(() => verifyNginxDeployment(input({ backendAttestation: attestation({ nonce: 'shortnonce' }) })), 'ONLINE_FRA_NGINX_ATTESTATION_INVALID');
{
  const forged = attestation(); forged.signature = Buffer.alloc(64, 1).toString('base64url');
  throws(() => verifyNginxDeployment(input({ backendAttestation: forged })), 'ONLINE_FRA_NGINX_ATTESTATION_INVALID');
}
{
  const wrongAuthority = crypto.generateKeyPairSync('ed25519');
  throws(() => verifyNginxDeployment(input({ backendAttestationPublicKey: wrongAuthority.publicKey })), 'ONLINE_FRA_NGINX_ATTESTATION_INVALID');
}
throws(() => verifyNginxDeployment(input({ limitConn: { key: '$binary_remote_addr', zone: 'fra_relay_conn', maxConnections: 4, sharedMemoryBytes: 10 * 1024 * 1024 } })), 'ONLINE_FRA_NGINX_LIMIT_INVALID');
throws(() => verifyNginxDeployment(input({ limitReq: { key: '$ssl_client_serial', zone: 'fra_relay_req', burst: 10, ratePerSecond: 5, sharedMemoryBytes: 10 * 1024 * 1024 + 1 } })), 'ONLINE_FRA_NGINX_LIMIT_INVALID');
throws(() => verifyNginxDeployment(input({ nginxConfigText: config().replace('location = /v1/rendezvous', 'location /v1/rendezvous') })), 'ONLINE_FRA_NGINX_ROUTE_INVALID');

// The backend must be an attested protected Unix-domain peer. A loopback
// listener and caller-controlled headers are not a proxy-authentication boundary.
throws(() => verifyNginxDeployment(input({
  nginxConfigText: config().replace('http://unix:/run/fra/rendezvous.sock:/v1/rendezvous', 'http://127.0.0.1:9443')
})), 'ONLINE_FRA_NGINX_PROXY_BOUNDARY_INVALID');
throws(() => verifyNginxDeployment(input({
  nginxConfigText: config()
    .replace('proxy_set_header X-FRA-Client-Certificate $ssl_client_escaped_cert;', 'proxy_set_header X-FRA-Client-Subject $ssl_client_s_dn;')
    .replace('http://unix:/run/fra/rendezvous.sock:/v1/rendezvous', 'http://127.0.0.1:9443')
})), 'ONLINE_FRA_NGINX_IDENTITY_MAPPING_INVALID');
throws(() => verifyNginxDeployment(input({
  nginxConfigText: config({ extraLocation: 'proxy_set_header X-FRA-Proxy-Auth forged-literal;' })
    .replace('proxy_set_header X-FRA-Client-Certificate $ssl_client_escaped_cert;', 'proxy_set_header X-FRA-Client-Subject $ssl_client_s_dn;')
    .replace('http://unix:/run/fra/rendezvous.sock:/v1/rendezvous', 'http://127.0.0.1:9443')
})), 'ONLINE_FRA_NGINX_ROUTE_INVALID');
throws(() => verifyNginxDeployment(input({
  nginxConfigText: config().replace('$ssl_client_escaped_cert', '$ssl_client_fingerprint')
})), 'ONLINE_FRA_NGINX_IDENTITY_MAPPING_INVALID');
throws(() => verifyNginxDeployment(input({
  certificateIdentityMapping: certificateIdentityMapping({ digestAlgorithm: 'sha1' })
})), 'ONLINE_FRA_NGINX_IDENTITY_MAPPING_INVALID');
throws(() => verifyNginxDeployment(input({
  backendProxyBoundaryAttestation: proxyBoundaryAttestation({ socketOwner: 'attacker' })
})), 'ONLINE_FRA_NGINX_PROXY_BOUNDARY_INVALID');
throws(() => verifyNginxDeployment(input({
  backendProxyBoundaryAttestation: proxyBoundaryAttestation({ socketMode: '0666' })
})), 'ONLINE_FRA_NGINX_PROXY_BOUNDARY_INVALID');
throws(() => verifyNginxDeployment(input({
  backendSocket: { path: '/run/fra/../evil.sock', owner: 'fra_relay', group: 'nginx', mode: '0660' }
})), 'ONLINE_FRA_NGINX_PROXY_BOUNDARY_INVALID');
throws(() => verifyNginxDeployment(input({
  backendProxyBoundaryAttestation: proxyBoundaryAttestation({ issuedAtMs: now - 1000, expiresAtMs: now - 1 })
})), 'ONLINE_FRA_NGINX_PROXY_BOUNDARY_STALE');
{
  const forged = proxyBoundaryAttestation();
  forged.signature = Buffer.alloc(64, 2).toString('base64url');
  throws(() => verifyNginxDeployment(input({ backendProxyBoundaryAttestation: forged })), 'ONLINE_FRA_NGINX_PROXY_BOUNDARY_INVALID');
}
throws(() => verifyNginxDeployment(input({
  nginxConfigText: config({ extraLocation: 'set $fra_proxy_auth literal-secret;' })
})), 'ONLINE_FRA_NGINX_ROUTE_INVALID');
{
  const receiptWithSecret = proxyBoundaryAttestation();
  receiptWithSecret.proxyAuthSecret = 'literal-secret';
  throws(() => verifyNginxDeployment(input({
    backendAttestation: attestation(), backendProxyBoundaryAttestation: receiptWithSecret
  })), 'ONLINE_FRA_NGINX_PROXY_BOUNDARY_INVALID');
}

console.log(`online FRA nginx deployment verifier tests passed (${assertions} assertions).`);
