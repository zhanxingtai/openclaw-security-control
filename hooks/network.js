#!/usr/bin/env node
// openclaw-hook: v1.0.1 (信息性注释；升级判定用全文内容哈希，勿依赖此值)
/**
 * OpenClaw Security Monitor - Node.js Network HTTP Hook
 *
 * Preload this module via NODE_OPTIONS to intercept HTTP/HTTPS requests
 * inside the OpenClaw agent / gateway process:
 *
 *   NODE_OPTIONS="-r /path/to/openclaw-security-monitor/hooks/node/network.js"
 *
 * Captured APIs:
 *   - http.request / http.get
 *   - https.request / https.get
 *   - global fetch (Node.js 18+)
 *
 * Events are appended to the file pointed at by OPENCLAW_MONITOR_LOG_PATH
 * (JSON Lines). If the file path is not configured, events are silently dropped
 * after stderr logging in debug mode.
 *
 * Event schema follows the network_http standard:
 *   {
 *     "comm": "openclaw",
 *     "event_id": "<uuid>",
 *     "event_type": "network_http",
 *     "ts": 1784277722604,
 *     "host_id": "...",
 *     "container_id": "...",
 *     "pid": 1,
 *     "layer": "system",
 *     "collection_method": "runtime",
 *     "run_id": "...",
 *     "content": "<body>",
 *     "content_length": 263,
 *     "service": "http",
 *     "direction": "send",
 *     "latency_ms": 21,
 *     "source": "openclaw.runtime-hooks.v1",
 *     "collector": {
 *       "hook_name": "network_http_req",
 *       "middleware_name": "openclaw-security-monitor",
 *       "collector_name": "security-http-middleware"
 *     },
 *     "method": "POST",
 *     "url": "/api/...",
 *     "host": "<host:port>",
 *     "code": 200,
 *     "header": "Host: ...",
 *     "body": "<body>"
 *   }
 */

'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const http = require('http');
const https = require('https');

const MODULE_NAME = 'openclaw-security-monitor-network-hook';
const DEBUG = process.env.OPENCLAW_NETWORK_HOOK_DEBUG === 'true' || process.env.OPENCLAW_NETWORK_HOOK_DEBUG === '1';
const MAX_BODY_LENGTH = parseInt(process.env.OPENCLAW_NETWORK_HOOK_MAX_BODY || '4096', 10);
const MAX_HEADER_LENGTH = parseInt(process.env.OPENCLAW_NETWORK_HOOK_MAX_HEADER || '2048', 10);
const MAX_CONTENT_LENGTH = parseInt(process.env.OPENCLAW_NETWORK_HOOK_MAX_CONTENT || '4096', 10);
const MAX_URL_LENGTH = parseInt(process.env.OPENCLAW_NETWORK_HOOK_MAX_URL || '4096', 10);
const STARTUP_GRACE_MS = parseInt(process.env.OPENCLAW_NETWORK_HOOK_STARTUP_GRACE_MS || '30000', 10);
// Hard cap on request/response body capture: a multi-MB LLM
// response was previously held per request. Beyond the cap the body is cut
// and downstream truncateBody semantics apply.
const CAPTURE_MAX_BYTES = 64 * 1024;

// NETWORK_ENFORCE is read lazily per check: the plugin sets it during its own
// initialize(), which runs after this hook was preloaded into the gateway
// process, so a preload-time const would never see it there.
//
// Once the plugin initializes it pins the authoritative values on
// globalThis (non-configurable descriptor; process.env itself cannot be
// frozen in Node). readHookEnv consults the pin first; before the pin exists
// the raw env read keeps the lazy semantics for preload windows.
const HOOK_ENV_PIN = '__OPENCLAW_SECURITY_HOOK_ENV__';

function readHookEnv(key) {
  const pin = globalThis[HOOK_ENV_PIN];
  if (typeof pin === 'function') {
    try {
      const pinned = pin();
      if (pinned && Object.prototype.hasOwnProperty.call(pinned, key)) {
        return pinned[key];
      }
    } catch {
      // fall back to the environment rather than crash the gateway
    }
  }
  return process.env[key];
}

function isNetworkEnforceEnabled() {
  const v = readHookEnv('OPENCLAW_NETWORK_ENFORCE');
  return v === 'true' || v === '1';
}

// Master switch mirrored from application.runtimeHooks.networkEnabled via
// OPENCLAW_NETWORK_HOOK_ENABLED. Also checked lazily: hook-mounter reads it at
// preload (before the plugin runs), so the already-loaded hook re-checks here
// to honor toggles in the gateway process itself. Unset means "on".
function isNetworkHookDisabled() {
  const v = readHookEnv('OPENCLAW_NETWORK_HOOK_ENABLED');
  return v === 'false' || v === '0';
}
// Default blocklist: loopback / RFC1918 / link-local and the cloud metadata
// endpoints — generic targets any deployment should cut off in enforce mode.
// Intentionally vendor-neutral: deployment-specific entries (vendor APIs,
// internal C2 domains, etc.) belong in OPENCLAW_NETWORK_BLOCKED_HOSTS, a
// comma-separated regex list read at module load.
const DEFAULT_BLOCKED_HOSTS = [
  '^127\\.',
  '^0\\.0\\.0\\.0',
  '^10\\.',
  '^172\\.(1[6-9]|2[0-9]|3[01])\\.',
  '^192\\.168\\.',
  '^169\\.254\\.',
  '^\\[::1\\]',
  '^metadata\\.google\\.internal',
  '^169\\.254\\.169\\.254',
].join(',');
const BLOCKED_HOSTS = (process.env.OPENCLAW_NETWORK_BLOCKED_HOSTS || DEFAULT_BLOCKED_HOSTS)
  .split(',')
  .map((h) => h.trim())
  .filter(Boolean);
// Precompile the host block patterns once at load: the old
// isBlockedHost did `new RegExp(pattern)` per pattern PER REQUEST on the
// hot path. A pattern that fails to compile keeps the literal-match fallback.
const BLOCKED_HOST_RES = BLOCKED_HOSTS.map((pattern) => {
  try {
    return new RegExp(pattern, 'i');
  } catch {
    return null;
  }
});
const DEFAULT_BLOCKED_URLS = [].join(',');
const BLOCKED_URLS = (process.env.OPENCLAW_NETWORK_BLOCKED_URLS || DEFAULT_BLOCKED_URLS)
  .split(',')
  .map((u) => u.trim())
  .filter(Boolean);
const MODULE_LOAD_TIME = Date.now();
// Default ignore list: high-volume, low-signal package-registry traffic.
// Deployment-specific ignores (IM vendor APIs, the local gateway port, ...)
// belong in OPENCLAW_NETWORK_HOOK_IGNORE_HOSTS — a comma-separated list read
// at module load — so the shipped defaults stay vendor-neutral.
const DEFAULT_IGNORE_HOSTS = [
  'registry.npmjs.org',
].join(',');
const IGNORE_HOSTS = (process.env.OPENCLAW_NETWORK_HOOK_IGNORE_HOSTS ?? DEFAULT_IGNORE_HOSTS)
  .split(',')
  .map((h) => h.trim().toLowerCase())
  .filter(Boolean);
const DEFAULT_IGNORE_URLS = [
  '/v1/chat/completions',
  '/ws/v2',
  '/callback/ws/endpoint',
  '/openclaw/latest',
].join(',');
const IGNORE_URLS = (process.env.OPENCLAW_NETWORK_HOOK_IGNORE_URLS ?? DEFAULT_IGNORE_URLS)
  .split(',')
  .map((u) => u.trim())
  .filter(Boolean);
const SENSITIVE_HEADERS = new Set([
  'authorization',
  'cookie',
  'set-cookie',
  'x-api-key',
  'api-key',
]);
const SENSITIVE_BODY_KEYS = new Set([
  'api_key',
  'apikey',
  'password',
  'passwd',
  'token',
  'access_token',
  'refresh_token',
  // Vendor-issued token keys whose full names never equal the generic
  // 'token' / 'access_token' — e.g. Feishu tenant_access_token leaked in
  // /open-apis/auth/v3/tenant_access_token/internal response bodies.
  'tenant_access_token',
  'app_access_token',
  'user_access_token',
  'session_token',
  'id_token',
  'auth_token',
  'bot_token',
  'secret',
  'secret_key',
  'client_secret',
  'app_secret',
  'authorization',
  'private_key',
  'access_key',
  'credential',
  'credentials',
]);

function getLogPath() {
  const raw = process.env.OPENCLAW_MONITOR_LOG_PATH || '';
  if (!raw) return '';
  if (raw === '~') return os.homedir();
  if (raw.startsWith('~/') || raw.startsWith('~\\')) {
    return path.join(os.homedir(), raw.slice(2));
  }
  return raw;
}

function log(level, message) {
  if (!DEBUG && level !== 'error') return;
  const line = `[${MODULE_NAME}] ${level}: ${message}`;
  if (level === 'error') {
    console.error(line);
  } else {
    console.log(line);
  }
}

function generateUUID() {
  // Use Node.js crypto.randomUUID when available (Node 14.17+/15.6+).
  if (typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

function getHostId() {
  return process.env.HOSTNAME || process.env.HOST || os.hostname() || '';
}

function getContainerId() {
  try {
    const cgroup = fs.readFileSync('/proc/self/cgroup', 'utf8');
    const lines = cgroup.trim().split('\n');
    for (const line of lines) {
      const parts = line.split(':');
      if (parts.length === 3) {
        const lastSegment = parts[2].split('/').pop();
        if (lastSegment && lastSegment.length >= 12) {
          return lastSegment.slice(0, 12);
        }
      }
    }
  } catch {
    // Not in container or permission denied
  }
  return process.env.CONTAINER_ID || '';
}

// Resolved once at module load: the container id cannot change
// for the life of this process, and the old code re-read /proc/self/cgroup
// synchronously for EVERY emitted event.
const CACHED_CONTAINER_ID = getContainerId();

function getGlobalContext() {
  return {
    session_id: global.__OPENCLAW_SESSION_ID__ || process.env.OPENCLAW_SESSION_ID || '',
    run_id: global.__OPENCLAW_RUN_ID__ || process.env.OPENCLAW_RUN_ID || '',
    agent_id: global.__OPENCLAW_AGENT_ID__ || process.env.OPENCLAW_AGENT_ID || '',
    tool_call_id: global.__OPENCLAW_TOOL_CALL_ID__ || process.env.OPENCLAW_TOOL_CALL_ID || '',
    tool_name: global.__OPENCLAW_TOOL_NAME__ || process.env.OPENCLAW_TOOL_NAME || '',
  };
}

function isSensitiveHeader(key) {
  return SENSITIVE_HEADERS.has(key.toLowerCase());
}

function redactHeaderValue(key, value) {
  if (typeof value !== 'string') return value;
  const lowerKey = key.toLowerCase();
  if (lowerKey === 'authorization') {
    // "Bearer token" or "Basic base64" -> redact credential part.
    return value.replace(/^((?:\S+\s+)?\S+\s+)\S+.*$/, '$1***');
  }
  if (lowerKey === 'cookie' || lowerKey === 'set-cookie') {
    return value.replace(/=([^;]+)/g, '=***');
  }
  return value;
}

function headersToRawString(headers) {
  if (!headers || typeof headers !== 'object') return '';
  const lines = [];
  for (const [key, value] of Object.entries(headers)) {
    if (isSensitiveHeader(key)) {
      if (Array.isArray(value)) {
        lines.push(`${key}: ${value.map((v) => redactHeaderValue(key, v)).join(', ')}`);
      } else {
        lines.push(`${key}: ${redactHeaderValue(key, value)}`);
      }
    } else if (Array.isArray(value)) {
      for (const v of value) {
        lines.push(`${key}: ${v}`);
      }
    } else if (value !== undefined && value !== null) {
      lines.push(`${key}: ${value}`);
    }
  }
  const raw = lines.join('\r\n');
  return raw.length > MAX_HEADER_LENGTH ? raw.slice(0, MAX_HEADER_LENGTH) + '...' : raw;
}

function redactSensitiveBody(body) {
  if (typeof body !== 'string') return body;
  try {
    const parsed = JSON.parse(body);
    const redacted = redactBodyObject(parsed);
    return JSON.stringify(redacted);
  } catch {
    // Not JSON: query strings and JSON fragments with broken encoding. The
    // pattern tolerates optional quotes around key/value so
    // `tenant_access_token":"t-…` and `app_secret=…` shapes both match.
    //
    // Hot-path guard: the replacement pattern backtracks
    // quadratically on long bodies that contain NO keyword — every start
    // position re-scans the remaining buffer. A keyword is a necessary
    // condition for any match (literal alternation with optional \w padding),
    // so bodies without one can skip the regex. The gate uses the same
    // substring semantics so redaction behavior is unchanged.
    if (!/password|passwd|pwd|token|secret|api[_-]?key|access[_-]?key|auth/i.test(body)) {
      return body;
    }
    return body.replace(
      /(["']?[\w-]*(?:password|passwd|pwd|token|secret|api[_-]?key|access[_-]?key|auth)[\w-]*(?:\\?["'])?\s*[:=]\s*(?:\\?["'])?)([^"'&\s\\]+)/gi,
      '$1***'
    );
  }
}

function redactBodyObject(obj) {
  if (Array.isArray(obj)) {
    return obj.map(redactBodyObject);
  }
  if (obj !== null && typeof obj === 'object') {
    const result = {};
    for (const [key, value] of Object.entries(obj)) {
      const lowerKey = key.toLowerCase();
      if (SENSITIVE_BODY_KEYS.has(lowerKey)) {
        result[key] = typeof value === 'string' && value.length <= 100 ? '***' : '***';
      } else if (typeof value === 'object' && value !== null) {
        result[key] = redactBodyObject(value);
      } else {
        result[key] = value;
      }
    }
    return result;
  }
  return obj;
}

function truncateBody(body) {
  if (typeof body !== 'string') return body;
  return body.length > MAX_BODY_LENGTH ? body.slice(0, MAX_BODY_LENGTH) + '...' : body;
}

function truncateContent(body) {
  if (typeof body !== 'string') return body;
  return body.length > MAX_CONTENT_LENGTH ? body.slice(0, MAX_CONTENT_LENGTH) + '...' : body;
}

function truncateUrl(value) {
  if (typeof value !== 'string') return value;
  return value.length > MAX_URL_LENGTH ? value.slice(0, MAX_URL_LENGTH) + '...' : value;
}

function buildUrlString(options) {
  if (typeof options === 'string') {
    try {
      const parsed = new URL(options);
      return {
        fullUrl: truncateUrl(options),
        pathname: truncateUrl(parsed.pathname),
        search: parsed.search,
        host: parsed.host,
        hostname: parsed.hostname,
        port: parsed.port,
        protocol: parsed.protocol,
      };
    } catch {
      // Treat as path only.
      return { fullUrl: truncateUrl(options), pathname: truncateUrl(options), host: '', hostname: '', port: '', protocol: '' };
    }
  }

  // fetch() (and http.request) accept URL / Request instances.
  // A Request carries the target in .url and has no .hostname of its own, so
  // the generic object branch below derived host='' and the host block list
  // silently passed. Parse the instance URL through the string branch so
  // blocking applies to every supported input shape.
  if (options instanceof URL) {
    return buildUrlString(options.href);
  }
  if (typeof Request !== 'undefined' && options instanceof Request) {
    return buildUrlString(options.url);
  }

  if (options && typeof options === 'object') {
    const protocol = options.protocol || 'http:';
    const hostname = options.hostname || options.host || '';
    const port = options.port ? `:${options.port}` : '';
    const path = options.path || options.pathname || '/';
    const fullUrl = `${protocol}//${hostname}${port}${path}`;
    return {
      fullUrl: truncateUrl(fullUrl),
      pathname: options.pathname || (typeof path === 'string' ? truncateUrl(path).split('?')[0] : '/'),
      search: typeof path === 'string' ? path.split('?')[1] || '' : '',
      host: `${hostname}${port}`,
      hostname: hostname,
      port: options.port || '',
      protocol: protocol,
    };
  }

  return { fullUrl: '', pathname: '', host: '', hostname: '', port: '', protocol: '' };
}

function buildNetworkEvent(reqInfo, resInfo, startTime) {
  const ctx = getGlobalContext();
  const urlInfo = buildUrlString(reqInfo.options);
  const requestBody = reqInfo.body ? truncateBody(redactSensitiveBody(reqInfo.body)) : '';
  const responseBody = resInfo.body ? truncateBody(redactSensitiveBody(resInfo.body)) : '';
  // Use the response body as the canonical content, or request body if no response.
  const content = truncateContent(responseBody || requestBody);

  const event = {
    comm: 'openclaw',
    event_id: generateUUID(),
    event_type: 'network_http',
    ts: Date.now(),
    host_id: getHostId(),
    container_id: CACHED_CONTAINER_ID,
    pid: process.pid,
    layer: 'system',
    collection_method: 'runtime',
    content: content,
    content_length: content.length,
    service: 'http',
    // send = outbound request (the canonical event we emit on completion).
    // recv = a paired response follow-up event, if the caller chooses to emit
    // one alongside this. We default to 'send' so older single-event consumers
    // still see the correct direction.
    direction: 'send',
    latency_ms: resInfo.endTime ? resInfo.endTime - startTime : Date.now() - startTime,
    source: 'openclaw.runtime-hooks.v1',
    collector: {
      hook_name: 'network_http_req',
      middleware_name: 'openclaw-security-monitor',
      collector_name: 'security-http-middleware',
    },
    method: reqInfo.method,
    url: urlInfo.pathname,
    host: urlInfo.host,
    code: resInfo.statusCode || 0,
    header: headersToRawString(reqInfo.headers),
    body: requestBody,
  };

  event.session_id = ctx.session_id ?? null;
  event.run_id = ctx.run_id ?? null;
  event.agent_id = ctx.agent_id ?? null;
  event.tool_call_id = ctx.tool_call_id ?? null;
  event.tool_name = ctx.tool_name ?? null;
  if (responseBody && responseBody !== requestBody) event.response_body = responseBody;
  if (resInfo.statusMessage) event.status_message = resInfo.statusMessage;
  if (urlInfo.fullUrl) event.request_url = urlInfo.fullUrl;
  if (urlInfo.hostname) event.domain_name = urlInfo.hostname;
  // Five-tuple per network.json: local is our side, remote is the target.
  if (urlInfo.hostname) event.remote_ip = urlInfo.hostname;
  if (urlInfo.port) event.remote_port = parseInt(urlInfo.port, 10) || undefined;

  return event;
}

let writeErrorLogged = false;

// Batched event sink: the old path ran openSync/writeSync/
// closeSync (3 syscalls) per event. The sink keeps one fd per log path,
// buffers lines, and flushes on threshold, on a short unref'd interval, and
// synchronously at process exit — so per-event "no loss on shutdown"
// semantics are preserved (SIGKILL aside) while steady-state syscall cost
// drops to one batched write.
const eventSink = { fd: null, fdPath: '', queue: [] };
const EVENT_FLUSH_THRESHOLD = 16;
const EVENT_FLUSH_INTERVAL_MS = 250;
// Short debounce after the first queued event: consumers that read the log
// right after an activity burst (test harnesses, tail-at-exit sidecars) see
// events within ~20ms instead of waiting for the interval, while the steady
// state still batches.
const EVENT_FLUSH_DEBOUNCE_MS = 20;
let eventFlushDebounce = null;

function closeEventFd() {
  if (eventSink.fd != null) {
    try { fs.closeSync(eventSink.fd); } catch { /* already gone */ }
    eventSink.fd = null;
    eventSink.fdPath = '';
  }
}

function flushEventQueue() {
  if (eventSink.queue.length === 0) return;
  const batch = eventSink.queue;
  eventSink.queue = [];
  const targetPath = getLogPath();
  if (!targetPath) {
    // log path vanished between queue and flush — count like a noLogPath drop
    dropCounts.noLogPath += batch.length;
    return;
  }
  if (eventSink.fd == null || eventSink.fdPath !== targetPath) {
    closeEventFd();
    try {
      eventSink.fd = fs.openSync(targetPath, 'a');
      eventSink.fdPath = targetPath;
    } catch (err) {
      dropCounts.writeError += batch.length;
      if (!writeErrorLogged) {
        log('error', `failed to open event log ${targetPath}: ${err.message}`);
        writeErrorLogged = true;
      }
      return;
    }
  }
  try {
    fs.writeSync(eventSink.fd, batch.join(''), 'utf8');
    dropCounts.emitted += batch.length;
  } catch (err) {
    dropCounts.writeError += batch.length;
    if (!writeErrorLogged) {
      log('error', `failed to write event to ${targetPath}: ${err.message}`);
      writeErrorLogged = true;
    }
  }
}

// Periodic flush bounds the loss window on long-running gateways without
// keeping the process alive.
const eventFlushTimer = setInterval(() => {
  try { flushEventQueue(); } catch { /* never crash the host process */ }
}, EVENT_FLUSH_INTERVAL_MS);
if (typeof eventFlushTimer.unref === 'function') eventFlushTimer.unref();

function scheduleFlushDebounce() {
  if (eventFlushDebounce) return;
  eventFlushDebounce = setTimeout(() => {
    eventFlushDebounce = null;
    try { flushEventQueue(); } catch { /* never crash the host process */ }
  }, EVENT_FLUSH_DEBOUNCE_MS);
  if (typeof eventFlushDebounce.unref === 'function') eventFlushDebounce.unref();
}

// Synchronous final flush on every exit path that still runs JS (normal
// exit, uncaught exception, process.exit) so queued events are not lost.
process.once('exit', () => {
  try { flushEventQueue(); } catch { /* last-resort best effort */ }
  closeEventFd();
});

// Diagnostic counters — flushed at shutdown so an operator can confirm the
// filter is actually working without enabling DEBUG logging. These are the
// single most useful piece of evidence when "the install has noise data" is
// reported again: if startupFilterStatus prints N hosts and N URLs but
// dropCounts shows zero drops, then the events in the JSONL came from a
// different code path (or the bundle is stale).
const dropCounts = {
  selfReporting: 0,
  ignoredHost: 0,
  ignoredUrl: 0,
  startupGrace: 0,
  hookDisabled: 0,
  noLogPath: 0,
  writeError: 0,
  emitted: 0,
};

function logStartupFilterStatus() {
  // Always-on (not gated by DEBUG) so an operator can verify in journalctl
  // that the env vars didn't accidentally override the defaults to empty.
  console.error(
    `[network-hook] startup: ` +
      `IGNORE_HOSTS(n=${IGNORE_HOSTS.length})=${JSON.stringify(IGNORE_HOSTS)}; ` +
      `IGNORE_URLS(n=${IGNORE_URLS.length})=${JSON.stringify(IGNORE_URLS)}; ` +
      `startupGraceMs=${STARTUP_GRACE_MS}; ` +
      `endpoint=${process.env.OPENCLAW_MONITOR_ENDPOINT || '(unset)'}; ` +
      `logPath=${getLogPath() || '(unset)'}`
  );
}

function logDropSummary() {
  console.error(
    `[network-hook] shutdown drops: ` +
      `self=${dropCounts.selfReporting}, ` +
      `ignoredHost=${dropCounts.ignoredHost}, ` +
      `ignoredUrl=${dropCounts.ignoredUrl}, ` +
      `startupGrace=${dropCounts.startupGrace}, ` +
      `hookDisabled=${dropCounts.hookDisabled}, ` +
      `noLogPath=${dropCounts.noLogPath}, ` +
      `writeError=${dropCounts.writeError}, ` +
      `emitted=${dropCounts.emitted}`
  );
}

function isSelfReportingEvent(event) {
  const endpoint = process.env.OPENCLAW_MONITOR_ENDPOINT || '';
  if (!endpoint) return false;

  try {
    const endpointUrl = new URL(endpoint);
    const requestHost = event.host || '';
    const requestPath = event.url || event.request_url || '';
    if (!requestHost || !requestPath) return false;

    const endpointPath = endpointUrl.pathname || '/';
    return (
      requestHost === endpointUrl.host &&
      (requestPath === endpointPath || requestPath.startsWith(endpointPath.endsWith('/') ? endpointPath : `${endpointPath}/`))
    );
  } catch {
    return false;
  }
}

function isIgnoredEvent(event) {
  // Normalise: lowercase the host, strip trailing dot, separate port once.
  const requestHost = (event.host || '').toLowerCase().replace(/\.+$/, '');
  const requestHostname = requestHost.split(':')[0];
  if (IGNORE_HOSTS.length > 0 && IGNORE_HOSTS.some((h) => {
    const norm = h.toLowerCase().replace(/\.+$/, '');
    return requestHost === norm || requestHostname === norm || requestHost === `${norm}:${requestHost.split(':')[1] || ''}`;
  })) {
    return true;
  }
  // URL prefix-match: case-insensitive and trailing-slash tolerant.
  const requestPath = (event.url || event.request_url || '').toLowerCase();
  if (IGNORE_URLS.length > 0 && IGNORE_URLS.some((u) => {
    const norm = u.toLowerCase().replace(/\/+$/, '');
    return requestPath === norm || requestPath.startsWith(norm + '/');
  })) {
    return true;
  }
  return false;
}

/**
 * Pre-build ignore filter. The decision only needs host/url,
 * which are known before the response arrives — checking it BEFORE
 * buildNetworkEvent skips the expensive full-body JSON.parse + recursive
 * redact + stringify. Default ignore table covers the LLM main link, so
 * chat completion responses were fully parsed and then thrown away.
 *
 * Matching semantics mirror isIgnoredEvent exactly (host list first, then
 * url prefix list), so the pre-filter and the emitEvent backstop never
 * disagree.
 */
function isIgnoredTarget(reqInfo) {
  const urlInfo = buildUrlString(reqInfo.options);
  const requestHost = (urlInfo.host || '').toLowerCase().replace(/\.+$/, '');
  const requestHostname = requestHost.split(':')[0];
  if (IGNORE_HOSTS.length > 0 && IGNORE_HOSTS.some((h) => {
    const norm = h.toLowerCase().replace(/\.+$/, '');
    return requestHost === norm || requestHostname === norm || requestHost === `${norm}:${requestHost.split(':')[1] || ''}`;
  })) {
    return { ignored: true, kind: 'host', host: requestHost };
  }
  const requestPath = (urlInfo.pathname || urlInfo.fullUrl || '').toLowerCase();
  if (IGNORE_URLS.length > 0 && IGNORE_URLS.some((u) => {
    const norm = u.toLowerCase().replace(/\/+$/, '');
    return requestPath === norm || requestPath.startsWith(norm + '/');
  })) {
    return { ignored: true, kind: 'url', host: requestHost };
  }
  return { ignored: false, kind: '', host: requestHost };
}

/** Host-vs-url drop accounting shared by the pre-filter and emitEvent. */
function recordIgnoredDrop(requestHost) {
  const requestHostname = requestHost.split(':')[0];
  if (
    IGNORE_HOSTS.length > 0 &&
    IGNORE_HOSTS.some((h) => requestHost === h || requestHostname === h)
  ) {
    dropCounts.ignoredHost += 1;
  } else {
    dropCounts.ignoredUrl += 1;
  }
}

function isInStartupGracePeriod() {
  if (STARTUP_GRACE_MS <= 0) return false;
  return Date.now() - MODULE_LOAD_TIME < STARTUP_GRACE_MS;
}

function isBlockedHost(hostname) {
  if (!hostname) return false;
  const lower = String(hostname).toLowerCase();
  for (let i = 0; i < BLOCKED_HOSTS.length; i++) {
    const re = BLOCKED_HOST_RES[i];
    if (re ? re.test(lower) : lower === BLOCKED_HOSTS[i]) return true;
  }
  // Bug fix: 数值形态的 IPv4（`0x7f000001` hex / `2130706433` dec / 8 位
  // 八进制 `0177.0.0.1`）不在字面黑名单内。`net.isIP` 给的是 AF_INET 但
  // 不会把 hex/oct 归一；DNS 解析前必须先归一为点分十进制再走一次黑名单，
  // 否则对象分支（`{ hostname: '2130706433' }`）会绕过阻断。
  const normalized = normalizeNumericHost(lower);
  if (normalized && normalized !== lower) {
    for (let i = 0; i < BLOCKED_HOSTS.length; i++) {
      const re = BLOCKED_HOST_RES[i];
      if (re ? re.test(normalized) : normalized === BLOCKED_HOSTS[i]) return true;
    }
  }
  return false;
}

/**
 * 把数值形态的 IPv4 字面量（hex / dec / 8 位 oct）归一为点分十进制。
 * 返回 undefined 表示不是数值 IP；空字符串表示转换失败。
 *
 * 仅做语法层的 IP 归一，不做 DNS 解析（DNS 重绑定是另一个问题：
 * 对象参数分支不做主机名规范化（`{ hostname: '2130706433' }`
 * 形态的 block 判定））。
 */
function normalizeNumericHost(host) {
  if (!host || typeof host !== 'string') return undefined;
  // 纯十进制长整：2130706433
  if (/^[0-9]+$/.test(host)) {
    const n = Number(host);
    if (!Number.isFinite(n) || n < 0 || n > 0xffffffff) return undefined;
    return [
      (n >>> 24) & 0xff,
      (n >>> 16) & 0xff,
      (n >>> 8) & 0xff,
      n & 0xff,
    ].join('.');
  }
  // 0x 开头 hex：0x7f000001
  if (/^0x[0-9a-f]+$/i.test(host)) {
    const n = Number.parseInt(host.slice(2), 16);
    if (!Number.isFinite(n) || n < 0 || n > 0xffffffff) return undefined;
    return [
      (n >>> 24) & 0xff,
      (n >>> 16) & 0xff,
      (n >>> 8) & 0xff,
      n & 0xff,
    ].join('.');
  }
  // 8 位八进制分段：0177.0.0.01（每段 0 + 0~N octal digit → dec）。
  // `0[0-7]*` 接受裸 `0`（0 octal digit）与 `01`/`0177`（N digits）。
  if (/^0[0-7]*(\.0[0-7]*){3}$/.test(host)) {
    const parts = host.split('.').map((p) => Number.parseInt(p, 8));
    if (parts.some((p) => !Number.isFinite(p) || p < 0 || p > 0xff)) return undefined;
    return parts.join('.');
  }
  return undefined;
}

function isBlockedUrl(url) {
  if (!url) return false;
  const normalized = String(url);
  return BLOCKED_URLS.some((prefix) => normalized.startsWith(prefix));
}

/**
 * Determine whether a network_http event should be blocked based on configured
 * host / URL block lists. Returns a human-readable block reason, or undefined.
 */
function shouldBlockRequest(event) {
  if (!isNetworkEnforceEnabled() || isNetworkHookDisabled()) return undefined;
  const host = event.host || event.domain_name || '';
  const requestUrl = event.request_url || event.url || '';
  if (isBlockedHost(host)) {
    return `请求被 OpenClaw network hook 拦截（blocked host: ${host}）`;
  }
  if (isBlockedUrl(requestUrl)) {
    return `请求被 OpenClaw network hook 拦截（blocked url: ${requestUrl}）`;
  }
  return undefined;
}

/**
 * Check whether an outgoing request should be blocked before it is sent.
 * Returns a block reason, or undefined if the request is allowed.
 */
function checkRequestBlocked(reqInfo) {
  if (!isNetworkEnforceEnabled() || isNetworkHookDisabled()) return undefined;
  const urlInfo = buildUrlString(reqInfo.options);
  const host = urlInfo.host || urlInfo.hostname || '';
  const requestUrl = urlInfo.fullUrl || urlInfo.pathname || '';
  if (isBlockedHost(host)) {
    return `请求被 OpenClaw network hook 拦截（blocked host: ${host}）`;
  }
  if (isBlockedUrl(requestUrl)) {
    return `请求被 OpenClaw network hook 拦截（blocked url: ${requestUrl}）`;
  }
  return undefined;
}

function emitBlockedEvent(reqInfo, blockReason) {
  // Ignored targets are not monitored at all — skip the event build entirely
  // (pre-filter parity with the normal completion path).
  const pre = isIgnoredTarget(reqInfo);
  if (pre.ignored) {
    recordIgnoredDrop(pre.host);
    log('debug', `dropping ignored blocked request: ${reqInfo.method} ${pre.host}`);
    return;
  }
  const event = buildNetworkEvent(
    reqInfo,
    { statusCode: 0, statusMessage: '', body: '', endTime: Date.now() },
    Date.now()
  );
  event.blocked = true;
  event.block_reason = blockReason;
  emitEvent(event);
}

function emitEvent(event) {
  if (isNetworkHookDisabled()) {
    dropCounts.hookDisabled += 1;
    log('debug', `dropping event (network hook disabled): ${event.method} ${event.host}${event.url}`);
    return;
  }

  if (isInStartupGracePeriod()) {
    dropCounts.startupGrace += 1;
    log('debug', `dropping startup grace request: ${event.method} ${event.host}${event.url}`);
    return;
  }

  if (isSelfReportingEvent(event)) {
    dropCounts.selfReporting += 1;
    log('debug', `dropping self-reporting request: ${event.method} ${event.host}${event.url}`);
    return;
  }

  if (isIgnoredEvent(event)) {
    // Backstop for paths that build the event without the pre-filter; the
    // steady-state drop happens in isIgnoredTarget before buildNetworkEvent.
    recordIgnoredDrop((event.host || '').toLowerCase());
    log('debug', `dropping ignored request: ${event.method} ${event.host}${event.url}`);
    return;
  }

  const logPath = getLogPath();
  if (!logPath) {
    dropCounts.noLogPath += 1;
    log('debug', `event dropped (no OPENCLAW_MONITOR_LOG_PATH): ${event.method} ${event.url}`);
    return;
  }

  const line = JSON.stringify(event) + '\n';
  eventSink.queue.push(line);
  if (eventSink.queue.length >= EVENT_FLUSH_THRESHOLD) {
    flushEventQueue();
  } else {
    scheduleFlushDebounce();
  }
}

// HTTP/HTTPS request body capture

function captureRequestBody(req) {
  const chunks = [];
  // Bounded accumulation: without a cap a streaming upload
  // accumulated every chunk in memory before any truncation ran.
  let capturedBytes = 0;
  let truncated = false;
  const originalWrite = req.write.bind(req);
  const originalEnd = req.end.bind(req);

  function pushCapped(chunk, encoding) {
    if (!chunk) return;
    try {
      const buf = typeof chunk === 'string' ? Buffer.from(chunk, encoding) : chunk;
      if (capturedBytes < CAPTURE_MAX_BYTES) {
        const room = CAPTURE_MAX_BYTES - capturedBytes;
        chunks.push(buf.length > room ? buf.subarray(0, room) : buf);
        capturedBytes += buf.length;
        if (buf.length > room) truncated = true;
      } else {
        truncated = true;
      }
    } catch (err) {
      log('debug', `failed to capture request body chunk: ${err.message}`);
    }
  }

  req.write = function (chunk, encoding, callback) {
    pushCapped(chunk, typeof encoding === 'string' ? encoding : undefined);
    return originalWrite(chunk, encoding, callback);
  };

  req.end = function (chunk, encoding, callback) {
    pushCapped(chunk, typeof encoding === 'string' ? encoding : undefined);
    req.__openclaw_request_body = concatBuffers(chunks) + (truncated ? '...' : '');
    return originalEnd(chunk, encoding, callback);
  };
}

function concatBuffers(chunks) {
  if (chunks.length === 0) return '';
  try {
    return Buffer.concat(chunks).toString('utf8');
  } catch (err) {
    log('debug', `failed to concat request body buffers: ${err.message}`);
    return '';
  }
}

function wrapRequest(original, protocolName) {
  return function wrappedRequest(input, options, callback) {
    const startTime = Date.now();

    // Normalize Node.js http.request arguments.
    // Signatures: request(url[, options][, callback]) and request(options[, callback])
    let resolvedOptions;
    let resolvedCallback;

    if (typeof options === 'function') {
      resolvedCallback = options;
      resolvedOptions = typeof input === 'string' ? {} : input || {};
    } else if (typeof callback === 'function') {
      resolvedCallback = callback;
      resolvedOptions = options || {};
    } else {
      resolvedOptions = options || {};
      resolvedCallback = undefined;
    }

    // Build a single options object that contains the URL / method / headers.
    let finalOptions;
    if (typeof input === 'string') {
      finalOptions = { ...resolvedOptions };
    } else if (input && typeof input === 'object') {
      finalOptions = input;
    } else {
      finalOptions = resolvedOptions || {};
    }

    const method = (finalOptions.method || 'GET').toUpperCase();
    const headers = finalOptions.headers || {};

    const reqInfo = {
      options: input,
      method,
      headers,
      body: '',
    };

    // Enforce network-level policy before the request is sent.
    const blockReason = checkRequestBlocked(reqInfo);
    if (blockReason) {
      emitBlockedEvent(reqInfo, blockReason);
      throw new Error(blockReason);
    }

    const resInfo = {
      statusCode: 0,
      statusMessage: '',
      body: '',
      endTime: 0,
    };

    let responseStarted = false;

    function onResponse(res) {
      if (responseStarted) return;
      responseStarted = true;
      resInfo.statusCode = res.statusCode || 0;
      resInfo.statusMessage = res.statusMessage || '';

      const resChunks = [];
      // Bounded accumulation: a multi-MB response used to be
      // buffered in full here before any truncation ran.
      let resCapturedBytes = 0;
      let resTruncated = false;
      res.on('data', (chunk) => {
        try {
          if (resCapturedBytes < CAPTURE_MAX_BYTES) {
            const room = CAPTURE_MAX_BYTES - resCapturedBytes;
            resChunks.push(chunk.length > room ? chunk.subarray(0, room) : chunk);
            resCapturedBytes += chunk.length;
            if (chunk.length > room) resTruncated = true;
          } else {
            resTruncated = true;
          }
        } catch (err) {
          log('debug', `failed to capture response body chunk: ${err.message}`);
        }
      });

      res.on('end', () => {
        resInfo.endTime = Date.now();
        try {
          resInfo.body = Buffer.concat(resChunks).toString('utf8') + (resTruncated ? '...' : '');
        } catch (err) {
          log('debug', `failed to decode response body: ${err.message}`);
        }
        finalizeAndEmit();
      });

      res.on('error', () => {
        resInfo.endTime = Date.now();
        finalizeAndEmit();
      });

      res.on('aborted', () => {
        resInfo.endTime = Date.now();
        finalizeAndEmit();
      });
    }

    let emitted = false;
    function finalizeAndEmit() {
      if (emitted) return;
      emitted = true;
      reqInfo.body = req.__openclaw_request_body || '';
      // Pre-build ignore filter: skip the full-body
      // parse/redact/stringify in buildNetworkEvent for ignored targets.
      const pre = isIgnoredTarget(reqInfo);
      if (pre.ignored) {
        recordIgnoredDrop(pre.host);
        log('debug', `dropping ignored request (pre-filter): ${reqInfo.method} ${pre.host}`);
        return;
      }
      const event = buildNetworkEvent(reqInfo, resInfo, startTime);
      emitEvent(event);
    }

    // Wrap callback-style response handler.
    let wrappedCallback = resolvedCallback;
    if (typeof resolvedCallback === 'function') {
      wrappedCallback = function (res) {
        onResponse(res);
        resolvedCallback(res);
      };
    }

    let req;
    try {
      // Call the original request with the exact same argument shape.
      // Node.js 24 is strict about argument types: when the first argument is
      // an options object, the second argument must be the callback (if any),
      // not an empty options object.
      if (typeof input === 'string') {
        if (typeof resolvedCallback === 'function') {
          req = original.call(this, input, resolvedOptions, wrappedCallback);
        } else if (resolvedOptions && Object.keys(resolvedOptions).length > 0) {
          req = original.call(this, input, resolvedOptions);
        } else {
          req = original.call(this, input);
        }
      } else {
        // input is an options object.
        if (typeof resolvedCallback === 'function') {
          req = original.call(this, input, wrappedCallback);
        } else {
          req = original.call(this, input);
        }
      }
    } catch (err) {
      log('error', `${protocolName}.request wrapper error: ${err.message}`);
      throw err;
    }

    captureRequestBody(req);

    req.on('response', onResponse);
    req.on('error', () => {
      resInfo.endTime = Date.now();
      finalizeAndEmit();
    });
    req.on('abort', () => {
      resInfo.endTime = Date.now();
      finalizeAndEmit();
    });
    req.on('timeout', () => {
      resInfo.endTime = Date.now();
      finalizeAndEmit();
    });

    // Ensure we emit even if no response ever arrives (e.g., timeout, socket close).
    req.on('close', () => {
      if (!emitted) {
        resInfo.endTime = Date.now();
        finalizeAndEmit();
      }
    });

    return req;
  };
}

function wrapGet(original, protocolName) {
  return function wrappedGet(input, options, callback) {
    // http.get / https.get internally call request. To ensure they use the
    // patched request wrapper, call it explicitly and end the request.
    const mod = protocolName === 'http' ? http : https;
    let req;
    if (typeof input === 'string') {
      req = mod.request(input, options, callback);
    } else {
      // input is an options object; the second argument is the callback.
      req = mod.request(input, options);
    }
    req.end();
    return req;
  };
}

// Keep original references so uninstall/restore is possible.
const originalHttpMethods = {};
const originalHttpsMethods = {};

// F-01: defineProperty lock so injected code cannot `delete http.request`
// and re-export the unwrapped original. Same primitive lives in runtime.js
// for child_process / Module._load; kept duplicated (rather than shared)
// because the two hooks are independently --require'd into the host and
// must work without resolving a third module from a locked-down loader.
// The unwrapped originals are kept ONLY in module closures — never
// under Symbol.for('openclaw.originals'), which sat in the global symbol
// registry and handed in-process attackers a ready-made bypass handle.
function lockMethod(target, name, wrapped) {
  try {
    Object.defineProperty(target, name, {
      value: wrapped,
      writable: false,
      configurable: false,
      enumerable: true,
    });
  } catch (err) {
    log('warn', `failed to lock ${name} via defineProperty: ${err.message}`);
    try { target[name] = wrapped; } catch { /* truly frozen */ }
  }
}

function installHttpHooks() {
  if (http.__openclaw_network_hooked || http.request?.__openclaw_network_wrapper) return;
  http.__openclaw_network_hooked = true;

  originalHttpMethods.request = http.request;
  originalHttpMethods.get = http.get;
  const wrappedRequest = wrapRequest(http.request, 'http');
  wrappedRequest.__openclaw_network_wrapper = true;
  lockMethod(http, 'request', wrappedRequest);
  lockMethod(http, 'get', wrapGet(http.get, 'http'));

  log('info', 'http hooks installed (defineProperty locked)');
}

function installHttpsHooks() {
  if (https.__openclaw_network_hooked || https.request?.__openclaw_network_wrapper) return;
  https.__openclaw_network_hooked = true;

  originalHttpsMethods.request = https.request;
  originalHttpsMethods.get = https.get;
  const wrappedRequest = wrapRequest(https.request, 'https');
  wrappedRequest.__openclaw_network_wrapper = true;
  lockMethod(https, 'request', wrappedRequest);
  lockMethod(https, 'get', wrapGet(https.get, 'https'));

  log('info', 'https hooks installed (defineProperty locked)');
}

function uninstallHttpHooks() {
  if (!http.__openclaw_network_hooked) return;
  if (originalHttpMethods.request) http.request = originalHttpMethods.request;
  if (originalHttpMethods.get) http.get = originalHttpMethods.get;
  delete http.__openclaw_network_hooked;
}

function uninstallHttpsHooks() {
  if (!https.__openclaw_network_hooked) return;
  if (originalHttpsMethods.request) https.request = originalHttpsMethods.request;
  if (originalHttpsMethods.get) https.get = originalHttpsMethods.get;
  delete https.__openclaw_network_hooked;
}

// global fetch hook (Node.js 18+)

let originalFetch = undefined;

function installFetchHook() {
  if (typeof globalThis.fetch !== 'function' || globalThis.__openclaw_fetch_hooked) return;

  originalFetch = globalThis.fetch;
  globalThis.__openclaw_fetch_hooked = true;

  const wrappedFetch = async function wrappedFetch(input, init) {
    const startTime = Date.now();
    const urlInfo = buildUrlString(input);
    const method = (init && init.method ? init.method.toUpperCase() : 'GET');
    const headers = (init && init.headers) || {};

    const reqInfo = {
      options: input,
      method,
      headers: headersToRecord(headers),
      body: '',
    };

    // Enforce network-level policy before the request is sent.
    const blockReason = checkRequestBlocked(reqInfo);
    if (blockReason) {
      emitBlockedEvent(reqInfo, blockReason);
      throw new Error(blockReason);
    }

    const resInfo = {
      statusCode: 0,
      statusMessage: '',
      body: '',
      endTime: 0,
    };

    if (init && init.body) {
      try {
        if (typeof init.body === 'string') {
          reqInfo.body = init.body;
        } else if (init.body instanceof URLSearchParams) {
          reqInfo.body = init.body.toString();
        } else if (init.body instanceof Blob) {
          reqInfo.body = '<Blob>';
        } else if (init.body instanceof ArrayBuffer || ArrayBuffer.isView(init.body)) {
          reqInfo.body = '<Buffer>';
        } else if (init.body && typeof init.body.toString === 'function') {
          reqInfo.body = init.body.toString();
        }
      } catch (err) {
        log('debug', `failed to capture fetch request body: ${err.message}`);
      }
    }

    try {
      const response = await originalFetch.call(this, input, init);
      resInfo.statusCode = response.status || 0;
      resInfo.statusMessage = response.statusText || '';

      try {
        const cloned = response.clone();
        const text = await cloned.text();
        // Cap retained body; the '...' marker matches the
        // truncateBody semantics downstream.
        resInfo.body = text.length > CAPTURE_MAX_BYTES ? text.slice(0, CAPTURE_MAX_BYTES) + '...' : text;
      } catch (err) {
        log('debug', `failed to capture fetch response body: ${err.message}`);
      }
      resInfo.endTime = Date.now();

      // Pre-build ignore filter.
      const pre = isIgnoredTarget(reqInfo);
      if (pre.ignored) {
        recordIgnoredDrop(pre.host);
        log('debug', `dropping ignored fetch (pre-filter): ${reqInfo.method} ${pre.host}`);
        return response;
      }

      const event = buildNetworkEvent(reqInfo, resInfo, startTime);
      emitEvent(event);

      return response;
    } catch (err) {
      resInfo.endTime = Date.now();
      resInfo.statusCode = 0;
      const pre = isIgnoredTarget(reqInfo);
      if (!pre.ignored) {
        const event = buildNetworkEvent(reqInfo, resInfo, startTime);
        emitEvent(event);
      } else {
        recordIgnoredDrop(pre.host);
        log('debug', `dropping ignored failed fetch (pre-filter): ${reqInfo.method} ${pre.host}`);
      }
      throw err;
    }
  };

  // F-01: lock the property descriptor so post-hook user code cannot swap
  // `globalThis.fetch` back to a pristine implementation (the same hardening
  // we apply to child_process and Module._load in runtime.js). The original
  // stays in the module-level `originalFetch` closure only.
  try {
    Object.defineProperty(globalThis, 'fetch', {
      value: wrappedFetch,
      writable: false,
      configurable: false,
      enumerable: true,
    });
  } catch (err) {
    log('warn', `failed to lock globalThis.fetch descriptor: ${err && err.message}; falling back to assignment`);
    globalThis.fetch = wrappedFetch;
  }

  log('info', 'fetch hook installed');
}

function headersToRecord(headers) {
  if (!headers) return {};
  if (typeof headers === 'object' && !Array.isArray(headers)) {
    return headers;
  }
  if (typeof headers.entries === 'function') {
    const result = {};
    for (const [key, value] of headers.entries()) {
      result[key] = value;
    }
    return result;
  }
  if (typeof headers.forEach === 'function') {
    const result = {};
    headers.forEach((value, key) => {
      result[key] = value;
    });
    return result;
  }
  return {};
}

function uninstallFetchHook() {
  if (!globalThis.__openclaw_fetch_hooked) return;
  // The descriptor was installed with configurable: false so a plain
  // assignment is expected to throw in strict mode (and silently fail in
  // sloppy mode). We attempt the restore anyway for symmetry with the
  // runtime.js uninstall path; the original is preserved solely in the
  // module-level `originalFetch` closure.
  if (originalFetch) {
    try {
      globalThis.fetch = originalFetch;
    } catch (err) {
      log('debug', `failed to restore globalThis.fetch (descriptor locked): ${err && err.message}`);
    }
  }
  delete globalThis.__openclaw_fetch_hooked;
}

// Module load hook for lazy-loaded http/https modules.

function installModuleLoadHook() {
  if (global.__openclaw_network_module_hook_installed) return;
  global.__openclaw_network_module_hook_installed = true;

  try {
    const Module = require('module');
    const originalLoad = Module._load;

    Module._load = function hookedLoad(request, parent, isMain) {
      const result = originalLoad.apply(this, arguments);
      if (request === 'http' && result && !result.__openclaw_network_hooked) {
        installHttpHooks();
      }
      if (request === 'https' && result && !result.__openclaw_network_hooked) {
        installHttpsHooks();
      }
      return result;
    };

    log('info', 'Module._load network hook installed');
  } catch (err) {
    log('error', `failed to install Module._load hook: ${err.message}`);
  }
}

function uninstallModuleLoadHook() {
  global.__openclaw_network_module_hook_installed = false;
}

// Public install / uninstall API

function install() {
  if (global.__openclaw_network_hook_installed) {
    log('debug', 'network hook already installed, skipping');
    return;
  }
  global.__openclaw_network_hook_installed = true;

  try {
    installHttpHooks();
    installHttpsHooks();
    installFetchHook();
    installModuleLoadHook();
    log('info', 'Node.js network hooks installed');
    logStartupFilterStatus();
    // Register an exit handler so the drop summary is always printed when
    // the gateway process shuts down. This is the single most useful line
    // to grep for when "noise data after reinstall" is reported.
    process.once('exit', () => {
      try {
        logDropSummary();
      } catch {
        // ignore
      }
    });
  } catch (err) {
    log('error', `install failed: ${err.message}`);
  }
}

function uninstall() {
  global.__openclaw_network_hook_installed = false;
  try {
    uninstallHttpHooks();
    uninstallHttpsHooks();
    uninstallFetchHook();
    uninstallModuleLoadHook();
    // drain any queued events before the summary so counts are accurate
    flushEventQueue();
    closeEventFd();
    log('info', 'Node.js network hooks uninstalled');
    logDropSummary();
  } catch (err) {
    log('error', `uninstall failed: ${err.message}`);
  }
}

// Auto-install when this module is required via -r.
install();

module.exports = {
  install,
  uninstall,
  buildNetworkEvent,
  headersToRawString,
  redactSensitiveBody,
  buildUrlString,
  isIgnoredEvent,
  isIgnoredTarget,
  flushEventQueue,
  getEventSinkState: () => ({ queued: eventSink.queue.length, fdOpen: eventSink.fd != null, fdPath: eventSink.fdPath }),
  isSelfReportingEvent,
  shouldBlockRequest,
  checkRequestBlocked,
  getDropCounts: () => ({ ...dropCounts }),
  resetDropCounts: () => {
    dropCounts.selfReporting = 0;
    dropCounts.ignoredHost = 0;
    dropCounts.ignoredUrl = 0;
    dropCounts.startupGrace = 0;
    dropCounts.hookDisabled = 0;
    dropCounts.noLogPath = 0;
    dropCounts.writeError = 0;
    dropCounts.emitted = 0;
  },
};
