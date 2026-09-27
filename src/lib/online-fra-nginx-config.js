'use strict';

// Pure renderer for the future online FRA relay. It does not read config,
// certificates, environment variables, or the network, and it never writes a
// vhost. Tunnel remains chat only and Bridge remains ToolsEnabled coverage;
// this produces a separate FRA rendezvous vhost for a later deployment phase.
const RELAY_ROUTE = '/v1/rendezvous';
const TLS_PROTOCOL = 'TLSv1.3';
const DEFAULTS = Object.freeze({
  listenPort: 443,
  tlsProtocols: TLS_PROTOCOL,
  clientVerify: 'on',
  earlyData: false,
  accessLog: false,
  maxBodyBytes: 8192,
  headerBufferBytes: 4096,
  proxyConnectTimeoutSeconds: 5,
  proxySendTimeoutSeconds: 30,
  proxyReadTimeoutSeconds: 75,
  websocketFrameLimitBytes: 262144
});

class OnlineFraNginxConfigError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'OnlineFraNginxConfigError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new OnlineFraNginxConfigError(code, message);
}

function plainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}

function integer(value, name, { min, max }) {
  if (!Number.isSafeInteger(value) || value < min || value > max) fail('FRA_NGINX_VALUE_INVALID', `${name} is invalid.`);
  return value;
}

// Shape only. Which hostnames are FORBIDDEN is not a property of this module:
// it is whatever the operator's verified vhost inventory already serves, and
// validate() derives it from existingServerNames.
function hostname(value) {
  if (typeof value !== 'string' || value.length > 253 || value !== value.toLowerCase()
    || value.includes('*') || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)
    || !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(value)) {
    fail('FRA_NGINX_HOSTNAME_INVALID', 'relayHostname must be a lower-case DNS hostname, not a wildcard or an IP.');
  }
  return value;
}

function safeSocketPath(value) {
  if (typeof value !== 'string' || value.length > 512
    || value.split('/').includes('..') || value.includes('//')
    || !/^\/(?:[A-Za-z0-9._-]+\/)*[A-Za-z0-9._-]+\.sock$/.test(value)) {
    fail('FRA_NGINX_PROXY_BOUNDARY_INVALID', 'backendSocketPath must be one fixed absolute Unix-domain socket path.');
  }
  return value;
}

function inventoryName(value) {
  if (typeof value !== 'string' || value.length > 253 || value !== value.toLowerCase()
    || !/^(?:\*\.)?(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(value)) {
    fail('FRA_NGINX_INVENTORY_INVALID', 'existingServerNames must be a normalized literal hostname or leading wildcard hostname.');
  }
  return value;
}

function zoneName(value, label) {
  if (typeof value !== 'string' || !/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(value)) {
    fail('FRA_NGINX_LIMIT_INVALID', `${label} must be a safe nginx zone identifier.`);
  }
  return value;
}

function safeAbsolutePath(value, name) {
  if (typeof value !== 'string' || value.length < 2 || value.length > 512 || !value.startsWith('/')
    || /[\s;#{}$`"'\\\r\n\0]/.test(value) || value.includes('//') || value.split('/').includes('..')
    || !/^\/[A-Za-z0-9._/-]+$/.test(value)) {
    fail('FRA_NGINX_PATH_INVALID', `${name} must be a safe absolute POSIX path.`);
  }
  return value;
}

function route(value) {
  if (value !== RELAY_ROUTE) fail('FRA_NGINX_ROUTE_INVALID', `route must be exactly ${RELAY_ROUTE}.`);
  return value;
}

function allowedInput(value = {}) {
  if (!plainObject(value)) fail('FRA_NGINX_INPUT_INVALID', 'FRA relay configuration must be an object.');
  const allowed = new Set([
    'relayHostname', 'deviceCaPath', 'certificatePath', 'certificateKeyPath', 'errorLogPath',
    'backendSocketPath', 'route', 'listenPort', 'tlsProtocols', 'clientVerify', 'earlyData',
    'accessLog', 'maxBodyBytes', 'headerBufferBytes', 'proxyConnectTimeoutSeconds',
    'proxySendTimeoutSeconds', 'proxyReadTimeoutSeconds', 'limitConnZone', 'limitReqZone',
    'httpLimitZonesDeclared', 'websocketFrameLimitBytes', 'websocketFrameLimitEnforced',
    'existingServerNames', 'existingVhostInventoryVerified'
  ]);
  for (const key of Object.keys(value)) if (!allowed.has(key)) fail('FRA_NGINX_INPUT_INVALID', 'FRA relay configuration contains an unsupported field.');
  return value;
}

function validate(value = {}) {
  const input = allowedInput(value);
  const config = { ...DEFAULTS, ...input };
  const requiredPaths = ['deviceCaPath', 'certificatePath', 'certificateKeyPath', 'errorLogPath', 'backendSocketPath'];
  for (const key of requiredPaths) if (config[key] === undefined) fail('FRA_NGINX_INPUT_INVALID', `${key} is required.`);
  for (const key of ['limitConnZone', 'limitReqZone', 'httpLimitZonesDeclared', 'websocketFrameLimitEnforced', 'existingServerNames', 'existingVhostInventoryVerified']) {
    if (config[key] === undefined) fail('FRA_NGINX_INPUT_INVALID', `${key} is required.`);
  }
  if (config.listenPort !== 443) fail('FRA_NGINX_TLS_INVALID', 'FRA relay listenPort must be 443.');
  if (config.tlsProtocols !== TLS_PROTOCOL) fail('FRA_NGINX_TLS_INVALID', 'FRA relay permits TLSv1.3 only.');
  if (config.clientVerify !== 'on') fail('FRA_NGINX_MTLS_REQUIRED', 'FRA relay requires mandatory client certificate verification.');
  if (config.earlyData !== false) fail('FRA_NGINX_TLS_INVALID', 'FRA relay must disable TLS early data.');
  if (config.accessLog !== false) fail('FRA_NGINX_LOGGING_INVALID', 'FRA relay access logging must remain disabled to avoid recording control data.');
  if (config.httpLimitZonesDeclared !== true) fail('FRA_NGINX_LIMIT_INVALID', 'FRA relay requires verified http-context limit zones.');
  if (config.websocketFrameLimitEnforced !== true) fail('FRA_NGINX_FRAME_LIMIT_REQUIRED', 'FRA relay requires backend WebSocket frame-limit enforcement.');
  if (config.existingVhostInventoryVerified !== true || !Array.isArray(config.existingServerNames) || config.existingServerNames.length > 256) {
    fail('FRA_NGINX_INVENTORY_INVALID', 'FRA relay requires a verified bounded current-vhost inventory.');
  }
  const relayHostname = hostname(config.relayHostname);
  const existingServerNames = config.existingServerNames.map(inventoryName);
  // The relay gets its OWN hostname, always. The set it must not take is the
  // caller's verified inventory of what this nginx already serves -- so the
  // rule protects whatever site is on the box, without this module having to
  // know the name of any of them.
  if (existingServerNames.some(name => name === relayHostname || (name.startsWith('*.') && relayHostname.endsWith(name.slice(1))))) {
    fail('FRA_NGINX_HOSTNAME_COLLISION', 'relayHostname collides with a verified existing nginx server_name.');
  }
  const validated = {
    relayHostname,
    deviceCaPath: safeAbsolutePath(config.deviceCaPath, 'deviceCaPath'),
    certificatePath: safeAbsolutePath(config.certificatePath, 'certificatePath'),
    certificateKeyPath: safeAbsolutePath(config.certificateKeyPath, 'certificateKeyPath'),
    errorLogPath: safeAbsolutePath(config.errorLogPath, 'errorLogPath'),
    backendSocketPath: safeSocketPath(config.backendSocketPath),
    route: route(config.route === undefined ? RELAY_ROUTE : config.route),
    listenPort: config.listenPort,
    tlsProtocols: config.tlsProtocols,
    clientVerify: config.clientVerify,
    earlyData: config.earlyData,
    accessLog: config.accessLog,
    maxBodyBytes: integer(config.maxBodyBytes, 'maxBodyBytes', { min: 1, max: 8192 }),
    headerBufferBytes: integer(config.headerBufferBytes, 'headerBufferBytes', { min: 1024, max: 8192 }),
    proxyConnectTimeoutSeconds: integer(config.proxyConnectTimeoutSeconds, 'proxyConnectTimeoutSeconds', { min: 1, max: 10 }),
    proxySendTimeoutSeconds: integer(config.proxySendTimeoutSeconds, 'proxySendTimeoutSeconds', { min: 1, max: 60 }),
    proxyReadTimeoutSeconds: integer(config.proxyReadTimeoutSeconds, 'proxyReadTimeoutSeconds', { min: 10, max: 300 }),
    limitConnZone: zoneName(config.limitConnZone, 'limitConnZone'), limitReqZone: zoneName(config.limitReqZone, 'limitReqZone'),
    httpLimitZonesDeclared: true, websocketFrameLimitBytes: integer(config.websocketFrameLimitBytes, 'websocketFrameLimitBytes', { min: 1024, max: 262144 }),
    websocketFrameLimitEnforced: true, existingServerNames: Object.freeze(existingServerNames), existingVhostInventoryVerified: true
  };
  if (validated.proxyReadTimeoutSeconds < validated.proxySendTimeoutSeconds) {
    fail('FRA_NGINX_TIMEOUT_INVALID', 'proxyReadTimeoutSeconds must be at least proxySendTimeoutSeconds.');
  }
  return Object.freeze(validated);
}

function render(value = {}) {
  const config = validate(value);
  return [
    '# Generated FRA relay vhost. Tunnel=chat only; Bridge=ToolsEnabled coverage; FRA=complete secure agentic control.',
    '# This is a future server relay configuration only. Apply and certificate-provision separately.',
    'server {',
    `    listen ${config.listenPort} ssl;`,
    `    server_name ${config.relayHostname};`,
    '',
    `    ssl_protocols ${config.tlsProtocols};`,
    '    ssl_early_data off;',
    `    ssl_certificate ${config.certificatePath};`,
    `    ssl_certificate_key ${config.certificateKeyPath};`,
    `    ssl_client_certificate ${config.deviceCaPath};`,
    '    ssl_verify_client on;',
    '    ssl_verify_depth 2;',
    '',
    `    error_log ${config.errorLogPath} crit;`,
    '    access_log off;',
    `    client_max_body_size ${config.maxBodyBytes};`,
    `    client_header_buffer_size ${config.headerBufferBytes};`,
    `    large_client_header_buffers 2 ${config.headerBufferBytes};`,
    '',
    `    location = ${config.route} {`,
    '        access_log off;',
    `        # The named zones must be declared in nginx http{} before this vhost is included.`,
    `        limit_conn ${config.limitConnZone} 4;`,
    `        limit_req zone=${config.limitReqZone} burst=10 nodelay;`,
    `        # Reject Host-based server reselection before an HTTP upgrade can reach FRA.`,
    `        if ($ssl_server_name != ${config.relayHostname}) { return 421; }`,
    '        if ($ssl_client_verify != SUCCESS) { return 403; }',
    '        proxy_http_version 1.1;',
    '        proxy_set_header Upgrade $http_upgrade;',
    '        proxy_set_header Connection "upgrade";',
    `        proxy_set_header Host ${config.relayHostname};`,
    '        # These overwrite, rather than forward, client-supplied identity headers.',
    '        proxy_set_header X-FRA-Client-Verify $ssl_client_verify;',
    '        proxy_set_header X-FRA-Client-Certificate $ssl_client_escaped_cert;',
    '        proxy_set_header X-FRA-Client-Address $remote_addr;',
    // X-Real-IP IS SET TOO, and not for nginx convention. The edge reads both
    // names, so any name it trusts must be OVERWRITTEN here -- a header this
    // config does not set is one nginx forwards from the client, and a client
    // that chooses its own rate-limit key has no rate limit. Attested, not
    // inherited.
    '        proxy_set_header X-Real-IP $remote_addr;',
    '        proxy_set_header X-FRA-Client-Subject "";',
    '        proxy_set_header X-FRA-Client-Serial "";',
    '        proxy_set_header X-FRA-Client-Fingerprint "";',
    '        proxy_set_header X-FRA-Device-Fingerprint "";',
    '        proxy_set_header X-FRA-Proxy-Auth "";',
    `        # Nginx cannot bound WebSocket messages after upgrade; the socket backend enforces this exact limit.`,
    `        proxy_set_header X-FRA-Max-Frame-Bytes ${config.websocketFrameLimitBytes};`,
    '        proxy_buffering off;',
    '        proxy_request_buffering off;',
    `        proxy_connect_timeout ${config.proxyConnectTimeoutSeconds}s;`,
    `        proxy_send_timeout ${config.proxySendTimeoutSeconds}s;`,
    `        proxy_read_timeout ${config.proxyReadTimeoutSeconds}s;`,
    `        proxy_pass http://unix:${config.backendSocketPath}:${config.route};`,
    '    }',
    '',
    '    # No catch-all proxy: this vhost exposes exactly one rendezvous route.',
    '    location / { return 404; }',
    '}',
    ''
  ].join('\n');
}

module.exports = Object.freeze({
  DEFAULTS, OnlineFraNginxConfigError, RELAY_ROUTE, TLS_PROTOCOL,
  render, validate
});
