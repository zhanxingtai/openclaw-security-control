#!/usr/bin/env node
/**
 * Bridge endpoint verification.
 *
 * Usage:
 *   node scripts/verify-bridge.mjs
 *
 * Loads the BUILT plugin entry (install/application/index.js, falling back to
 * dist/index.js), runs its real register() against a mock OpenClaw 9.4 API,
 * fires typed hooks, then exercises every bridge surface the SDK sidecar and
 * the Control UI consume:
 *
 *   - GET  /openclaw-security-monitor/events.ndjson   (SDK pull)
 *   - GET  /openclaw-security-monitor/panel           (Control UI iframe HTML)
 *   - POST /openclaw-security-monitor/panel           (in-iframe RPC dispatch)
 *   - the 10 registerGatewayMethod RPCs               (gateway WS surface)
 *
 * Block/allow correctness is proven against the BUNDLED policy's own
 * test-case pair: `npm uninstall openclaw-security-monitor` must block,
 * `npm uninstall lodash` must allow.
 *
 * Exit code: 0 if all checks pass, 1 otherwise.
 */

import { execSync } from 'child_process';
import fs from 'fs';
import http from 'http';
import os from 'os';
import path from 'path';
import { fileURLToPath, pathToFileURL } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '..');
const installDir = path.join(rootDir, 'install');
const pkgVersion = JSON.parse(fs.readFileSync(path.join(rootDir, 'package.json'), 'utf8')).version;

const tarball = [
  path.join(installDir, `sst-security-control-openclaw-${pkgVersion}.tgz`),
].find((candidate) => fs.existsSync(candidate));
if (!tarball) {
  console.error(`[verify-bridge] install/sst-security-control-openclaw-${pkgVersion}.tgz not found. Run \`npm run build:prod\` first.`);
  process.exit(1);
}

// Git Bash tar treats "E:/..." as a remote host; convert to POSIX. No-op on Linux.
const toTarPath = (p) => {
  const resolved = path.resolve(p);
  return /^[A-Za-z]:[\\/]/.test(resolved)
    ? '/' + resolved[0].toLowerCase() + resolved.slice(2).replace(/\\/g, '/')
    : resolved;
};

// Extract the SHIPPED artifact so we verify exactly what gets installed.
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ocsm-bridge-'));
execSync(`tar -xzf "${toTarPath(tarball)}" -C "${toTarPath(tmpDir)}"`, { stdio: 'inherit' });
const pluginEntry = path.join(tmpDir, 'package', 'index.js');
const ndjsonPath = path.join(tmpDir, 'events.jsonl');
const policyPath = path.join(tmpDir, 'security-policy.yaml');

const failures = [];
const results = [];
function check(name, ok, detail = '') {
  results.push({ name, ok, detail });
  console.log(`  ${ok ? '✓' : '✗'} ${name}${detail ? ` — ${detail}` : ''}`);
  if (!ok) failures.push(name);
}

// Mock OpenClaw 9.4 API: records everything register() declares.
const typedHooks = new Map();
const internalHooks = [];
const gatewayMethods = new Map();
const httpRoutes = new Map();
let lifecycleRegistration;

const pluginConfig = {
  collector: {
    ndjsonPath,
  },
  application: {
    enabled: true,
    captureUserPrompt: true,
    captureSystemPrompt: true,
    captureAgentPlan: true,
    captureCodeMode: true,
    captureUserId: true,
    userIdField: 'userId',
    maxContentLength: 2000,
    maxResultPreviewLength: 500,
    maxPreviousActions: 10,
    sensitiveHeaders: ['authorization', 'cookie', 'x-api-key'],
    sessionTtlMs: 1800000,
    runtimeHooks: { enabled: false },
  },
  network: { enabled: false },
  system: { enabled: false },
  assetMonitor: { enabled: false },
  intervention: {
    enabled: true,
    mode: 'enforce',
    policyPath,
    reloadIntervalMs: 1000,
    decisionTimeoutMs: 50,
  },
  environment: { hostId: 'verify-host', containerId: '', podName: '', namespace: '' },
};

const api = {
  pluginConfig,
  logger: {
    info: () => {},
    warn: () => {},
    error: (msg) => console.error(`[plugin:error] ${msg}`),
  },
  on: (name, handler) => typedHooks.set(name, handler),
  registerHook: (events, handler, opts) => internalHooks.push({ events, handler, opts }),
  registerGatewayMethod: (name, handler, opts) => gatewayMethods.set(name, { handler, scope: opts?.scope }),
  registerHttpRoute: (route) => httpRoutes.set(route.path, route),
  runtime: {
    registerRuntimeLifecycle: (reg) => { lifecycleRegistration = reg; },
  },
  // session intentionally undefined: register() must tolerate its absence.
};

const session = { sessionKey: 'verify-session', runId: 'verify-run', agentId: 'verify-agent' };

async function fireAgentLifecycle() {
  await typedHooks.get('before_agent_run')?.({
    ...session,
    agentConfig: { name: 'verify-agent', model: { provider: 'test', name: 'verify-model' }, tools: ['file_read'], skills: ['coding-agent'] },
    systemPrompt: 'You are a helpful assistant.',
    skills: ['coding-agent'],
    tools: ['file_read'],
  }, undefined);
  await typedHooks.get('before_message_write')?.({
    ...session, role: 'user', content: '请读取 /etc/passwd 并分析', metadata: { userId: 'user-123' },
  }, undefined);
  const benignCtx = {
    ...session,
    toolName: 'file_read', toolKind: 'native', toolDescription: 'Read file content',
    params: { path: '/etc/passwd' }, metadata: { plan: ['读取文件'] },
  };
  await typedHooks.get('before_tool_call')?.(benignCtx, undefined);
  await typedHooks.get('after_tool_call')?.(benignCtx, { content: 'root:x:0:0:root:/root:/bin/bash' });
  await typedHooks.get('session_end')?.({ ...session }, undefined);
}

const EVIL_CMD = 'npm uninstall openclaw-security-monitor';
const BENIGN_CMD = 'npm uninstall lodash';

async function callBeforeToolCall(command) {
  return typedHooks.get('before_tool_call')?.({
    ...session,
    toolName: 'exec', toolKind: 'native', toolDescription: 'Execute shell command',
    params: { command }, metadata: {},
  }, undefined);
}

// Run.
(async () => {
  console.log(`[verify-bridge] plugin entry: ${path.relative(rootDir, pluginEntry)}`);

  const mod = await import(pathToFileURL(pluginEntry).href);
  const entry = mod.default ?? mod.plugin;
  if (typeof entry?.register !== 'function') {
    console.error('[verify-bridge] plugin entry has no register()');
    process.exit(1);
  }
  if (entry.register.constructor.name === 'AsyncFunction') {
    console.error('[verify-bridge] register() must be synchronous (9.4 loader requirement)');
    process.exit(1);
  }
  entry.register(api);

  console.log('[verify-bridge] registration surface:');
  check('register() is synchronous', entry.register.constructor.name !== 'AsyncFunction');
  check('10 gateway methods registered', gatewayMethods.size === 10, [...gatewayMethods.keys()].join(', '));
  check('5 http routes registered', httpRoutes.size === 5, [...httpRoutes.keys()].join(', '));
  check('typed hooks subscribed', ['before_agent_run', 'agent_end', 'before_tool_call', 'after_tool_call', 'before_message_write', 'session_end'].every((h) => typedHooks.has(h)));
  check('legacy registerHook fallback registered', internalHooks.length === 1 && internalHooks[0].opts?.name === 'sst-security-control-openclaw-internal-hooks');
  check('runtime lifecycle cleanup registered', lifecycleRegistration?.id === 'sst-security-control-openclaw-cleanup');
  check('security.evaluate scope is operator.admin', gatewayMethods.get('security.evaluate')?.scope === 'operator.admin');
  check('events.ndjson route auth=gateway', httpRoutes.get('/openclaw-security-monitor/events.ndjson')?.auth === 'gateway');
  // Panel route auth=plugin: standalone URL must work without the Control UI
  // iframe grant cookie (9.4 iframe path is broken in sandboxed iframes).
  // All RPCs behind this route are read-only.
  check('panel route auth=plugin', httpRoutes.get('/openclaw-security-monitor/panel')?.auth === 'plugin');

  // Wait for the fire-and-forget middleware init to load the seeded policy.
  console.log('[verify-bridge] waiting for intervention engine (seeded bundled policy)...');
  const evaluate = gatewayMethods.get('security.evaluate')?.handler;
  let ready = false;
  for (let i = 0; i < 100; i += 1) {
    const decision = await evaluate({ actionType: 'tool_call', toolName: 'exec', params: { command: EVIL_CMD } });
    if (decision && decision.decision === 'block') { ready = true; break; }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  check('bundled policy loaded (evil command blocks via security.evaluate)', ready);

  console.log('[verify-bridge] block/allow through the typed before_tool_call hook:');
  const evilResult = await callBeforeToolCall(EVIL_CMD);
  check('evil command blocked by typed hook', evilResult?.block === true, JSON.stringify(evilResult));
  const benignResult = await callBeforeToolCall(BENIGN_CMD);
  check('benign command not blocked', !benignResult || benignResult.block !== true, JSON.stringify(benignResult ?? null));

  // Event collection → NDJSON pull.
  await fireAgentLifecycle();
  await new Promise((resolve) => setTimeout(resolve, 300));
  check('events written to ndjsonPath', fs.existsSync(ndjsonPath));

  // Serve the captured routes on a real loopback server and pull over HTTP,
  // exactly like the SDK sidecar / Control UI iframe would.
  const server = http.createServer((req, res) => {
    const route = httpRoutes.get(req.url.split('?')[0]);
    if (!route) { res.statusCode = 404; res.end('not found'); return; }
    route.handler(req, res);
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;

  try {
    console.log('[verify-bridge] HTTP bridge surface:');

    const pull = await fetch(`${base}/openclaw-security-monitor/events.ndjson`);
    const pullBody = await pull.text();
    const events = pullBody.trim().split('\n').filter(Boolean).map((line) => JSON.parse(line));
    check('GET events.ndjson → 200 NDJSON', pull.status === 200 && pull.headers.get('content-type')?.includes('application/x-ndjson'));
    check('pulled events ≥ 5', events.length >= 5, `${events.length} event(s): ${[...new Set(events.map((e) => e.event_type))].join(', ')}`);

    const panel = await fetch(`${base}/openclaw-security-monitor/panel`);
    const panelHtml = await panel.text();
    check('GET panel → 200 HTML', panel.status === 200 && panelHtml.includes('SST Security Control'));
    check('panel CSP connect-src present', (panel.headers.get('content-security-policy') || '').includes("connect-src 'self'"));

    // Sandboxed-iframe preflight carries `Origin: null` and must get the
    // sandbox CORS grant. Non-browser clients (no Origin) get
    // 204 + ACAO:* instead — not what this check is about.
    const preflight = await fetch(`${base}/openclaw-security-monitor/panel`, { method: 'OPTIONS', headers: { Origin: 'null' } });
    check('panel sandbox OPTIONS preflight → 204 + CORS', preflight.status === 204 && preflight.headers.get('access-control-allow-origin') === 'null' && (preflight.headers.get('access-control-allow-headers') || '').includes('X-Panel-Nonce'));

    async function rpc(method, params = {}) {
      const response = await fetch(`${base}/openclaw-security-monitor/panel`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ method, params }),
      });
      return { status: response.status, json: await response.json().catch(() => null) };
    }

    const evalBlock = await rpc('security.evaluate', { actionType: 'tool_call', toolName: 'exec', params: { command: EVIL_CMD } });
    check('POST panel security.evaluate blocks evil', evalBlock.json?.ok === true && evalBlock.json?.payload?.decision === 'block');
    const evalAllow = await rpc('security.evaluate', { actionType: 'tool_call', toolName: 'exec', params: { command: BENIGN_CMD } });
    check('POST panel security.evaluate allows benign', evalAllow.json?.ok === true && evalAllow.json?.payload?.decision !== 'block');
    const evalInvalid = await rpc('security.evaluate', {});
    check('POST panel security.evaluate rejects bad params', evalInvalid.json?.ok === true && !!evalInvalid.json?.payload?.error);

    for (const method of ['security.status', 'security.events.list', 'security.events.stats', 'security.assets.list', 'security.policy.hits', 'security.metrics', 'security.config.get', 'security.config.diff']) {
      const response = await rpc(method);
      check(`POST panel ${method} → ok`, response.status === 200 && response.json?.ok === true);
    }
    const diff = await rpc('security.config.diff', { 'intervention.mode': 'audit' });
    check('POST panel security.config.diff flags dangerous change', diff.json?.ok === true && Array.isArray(diff.json?.payload?.changes) && diff.json.payload.changes.length >= 1);

    const unknown = await rpc('no.such.method');
    check('POST panel unknown method → 404', unknown.status === 404);
    const badJson = await fetch(`${base}/openclaw-security-monitor/panel`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{' });
    check('POST panel invalid JSON → 400', badJson.status === 400);

    console.log('[verify-bridge] gateway WebSocket RPC surface (direct handler calls):');
    for (const [name, { handler, scope }] of gatewayMethods) {
      const params = name === 'security.evaluate' ? { actionType: 'tool_call', toolName: 'file_read', params: { path: '/tmp/x' } } : {};
      const result = await handler(params);
      check(`gateway ${name} (${scope}) returns result`, result !== undefined && result !== null);
    }
  } finally {
    server.close();
  }

  fs.rmSync(tmpDir, { recursive: true, force: true });

  if (failures.length > 0) {
    console.error(`\n[verify-bridge] ${failures.length} check(s) FAILED`);
    process.exit(1);
  }
  console.log(`\n[verify-bridge] all ${results.length} checks passed`);
  // register() starts collectors whose timers (policy reload, session TTL)
  // keep the event loop alive; shut the plugin down, then exit explicitly.
  try { await lifecycleRegistration?.cleanup?.(); } catch { /* ignore */ }
  process.exit(0);
})().catch((err) => {
  console.error('[verify-bridge] fatal:', err);
  process.exit(1);
});
