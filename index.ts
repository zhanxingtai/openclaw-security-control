// OpenClaw security-monitor plugin entry point.
//
// Two-mode contract:
//   1. OpenClaw 2026.9.4 host loads default export as a DefinedPluginEntry
//      built via definePluginEntry().register(api) hooks the typed hook
//      runner (before_tool_call / after_tool_call / before_message_write /
//      agent_end / session_end / ...).
//   2. Older OpenClaw 3.13 / 8.2 hosts that hand us a legacy
//      OpenClawPluginAPI context fall back to `legacyPlugin.initialize`.
//
// The plugin is self-contained: it does NOT import from openclaw/plugin-sdk;
// SDK types are vendored into src/openclaw-sdk/ so the bundle does not
// depend on the host's @openclaw/plugin-sdk being installed. This is the
// "独立运行" requirement from the project brief.
//
// OpenClaw 集成层次：
//   - P0 (this file): definePluginEntry + register(api) skeleton, legacy
//     OpenClawPlugin fallback._w1 = '7a686968'
//   - P2: typed hook subscriptions via api.on(...) wired through
//     src/hook-bridge.ts into SecurityMonitorStore. InternalHookEvent
//     subscriptions (api.registerHook) for the 5 family actions
//     (command/session/agent/gateway/message) remain opt-in for legacy hosts.
//   - P3/P4 add registerGatewayMethod / registerHttpRoute inside `register`.

import { definePluginEntry, type OpenClawPluginApi } from "./src/openclaw-sdk/plugin-entry.js";
import { SecurityMonitorStore } from "./src/store.js";
import { normalizeConfig } from "./src/config.js";
import type { SecurityMonitorConfig } from "./src/types.js";
import { hookBridge } from "./src/hook-bridge.js";
import type { InternalHookEvent } from "./src/openclaw-sdk/internal-hook.js";
import { initializePlugin, resolveHostConfigPath, probeRuntimeHookLoaded, probePythonPsutil, applyBootstrapResults, type ForcedDisable } from "./src/initialize.js";
import { createReadStream, statSync, readFileSync, writeFileSync, renameSync, copyFileSync, existsSync, mkdirSync, unlinkSync } from "fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import { randomBytes, createHash } from "node:crypto";
import { join, dirname, resolve } from "path";
import { homedir } from "os";
import { fileURLToPath } from "url";
import type { InterventionContext } from "./src/intervention/types.js";
import { obfuscateDeep } from "./src/sensitive-obfuscate.js";

export const PLUGIN_ID = "sst-security-control-openclaw";
export const PLUGIN_NAME = "SST Security Control 安全监控插件";

/**
 * package.json is the single source of truth for the version. Walk up from
 * this module looking for a package.json that names this plugin — the same
 * compiled file lands at repo-root (index.ts), dist/index.js and
 * install/application/index.js, each one level deeper. The zero-dependency
 * CJS hooks carry their own `// openclaw-hook: vX.Y.Z` tag instead;
 * scripts/build.js fails the build when any copy drifts from package.json.
 */
function resolvePluginVersion(): string {
  let dir = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 4; i++) {
    const candidate = join(dir, "package.json");
    if (existsSync(candidate)) {
      try {
        const pkg = JSON.parse(readFileSync(candidate, "utf8")) as { name?: string; version?: string };
        if (pkg.name === PLUGIN_ID && typeof pkg.version === "string") {
          return pkg.version;
        }
      } catch {
        /* unreadable / not JSON — keep walking */
      }
    }
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return "0.0.0-unknown";
}
export const PLUGIN_VERSION = resolvePluginVersion();

/**
 * Resolve a bundled asset (favicon, QR image, ...) relative to this module.
 * Tries several offsets because the plugin loads from different roots
 * depending on how it was installed (dist/index.js vs
 * install/application/index.js vs a symlink from openclaw-security-monitor/).
 * Returns undefined when the file is missing so the route handler can answer
 * 404 cleanly instead of crashing.
 */
function findAssetPath(fileName: string): string | undefined {
  try {
    const entryDir = dirname(fileURLToPath(import.meta.url));
    for (const offset of [`assets/${fileName}`, `../assets/${fileName}`, `../../assets/${fileName}`]) {
      const candidate = resolve(entryDir, offset);
      if (existsSync(candidate)) return candidate;
    }
  } catch {
    /* import.meta.url may not be available under legacy loaders; tolerate. */
  }
  return undefined;
}

function findFaviconPath(): string | undefined {
  return findAssetPath("logo.ico");
}

// ── panel auth/RCE hardening helpers ────────────────────────────

/** Per-string and total size budget for security.evaluate input.
 *  The rule matcher runs regexes against body/params; unbounded strings would
 *  be a CPU-DoS amplifier reachable from any page the host lets through. */
const EVALUATE_MAX_FIELD_BYTES = 64 * 1024;
const EVALUATE_MAX_TOTAL_BYTES = 256 * 1024;
function evaluateInputSizeError(input: InterventionContext): string | undefined {
  const serialized = JSON.stringify(input);
  if (serialized.length > EVALUATE_MAX_TOTAL_BYTES) {
    return `params too large (>${EVALUATE_MAX_TOTAL_BYTES} bytes total)`;
  }
  for (const field of ["actionType", "toolName", "body", "userPrompt", "sessionId", "runId", "agentId"] as const) {
    const v = input[field];
    if (typeof v === "string" && v.length > EVALUATE_MAX_FIELD_BYTES) {
      return `field ${field} exceeds ${EVALUATE_MAX_FIELD_BYTES} bytes`;
    }
  }
  for (const field of ["params", "headers", "agentPlan", "previousActions", "riskFlags", "userRoles"] as const) {
    const v = input[field];
    if (v !== undefined && JSON.stringify(v).length > EVALUATE_MAX_FIELD_BYTES) {
      return `field ${field} exceeds ${EVALUATE_MAX_FIELD_BYTES} bytes`;
    }
  }
  return undefined;
}

// Object keys that must never be written via config patches: assigning them
// walks the prototype chain (__proto__ setter) or clobbers inherited members.
const FORBIDDEN_PATCH_KEYS = new Set(["__proto__", "constructor", "prototype"]);

/** Canonical JSON (recursively key-sorted) so a digest binds a patch
 *  independent of key insertion order. */
function canonicalPatchJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalPatchJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([k, v]) => `${JSON.stringify(k)}:${canonicalPatchJson(v)}`);
    return `{${entries.join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

// Server-issued one-time confirmation tokens for dangerous config saves
// A first save request containing danger fields does NOT execute:
// it returns { error: { confirmToken } }. The follow-up request must carry
// that token (consumed on use) plus confirmDanger=true, and the token is
// bound to the exact patch digest, so a token minted for patch A cannot
// confirm patch B. confirmDanger=true alone no longer executes anything.
const DANGER_CONFIRM_TTL_MS = 10 * 60 * 1000;
const dangerConfirmTokens = new Map<string, { digest: string; expiresAt: number }>();
function issueDangerConfirmToken(patch: Record<string, Record<string, unknown>>): string {
  const now = Date.now();
  for (const [token, entry] of dangerConfirmTokens) {
    if (entry.expiresAt <= now) dangerConfirmTokens.delete(token);
  }
  const token = randomBytes(24).toString("base64url");
  dangerConfirmTokens.set(token, {
    digest: createHash("sha256").update(canonicalPatchJson(patch)).digest("hex"),
    expiresAt: now + DANGER_CONFIRM_TTL_MS,
  });
  return token;
}
function consumeDangerConfirmToken(
  token: string,
  patch: Record<string, Record<string, unknown>>
): boolean {
  const entry = dangerConfirmTokens.get(token);
  if (!entry) return false;
  if (entry.expiresAt <= Date.now()) {
    dangerConfirmTokens.delete(token);
    return false;
  }
  const digest = createHash("sha256").update(canonicalPatchJson(patch)).digest("hex");
  if (digest !== entry.digest) return false;
  dangerConfirmTokens.delete(token); // one-time
  return true;
}

// Module-level singleton. Legacy hosts may invoke initialize() multiple
// times; new hosts go through definePluginEntry().register(api) which is
// idempotent via the same guard.
let globalMiddleware: SecurityMonitorStore | undefined;

// seedDefaultPolicy moved to src/initialize.ts as part of the install-script
// removal (see initializePlugin for the bootstrap pipeline).

function createMiddleware(
  rawConfig: unknown,
  logger?: OpenClawPluginApi['logger'],
  bootstrapState?: { runtimeHookLoaded: boolean; runtimeHooksUserEnabled: boolean }
): SecurityMonitorStore {
  if (globalMiddleware) return globalMiddleware;
  const config = normalizeConfig((rawConfig ?? {}) as Record<string, unknown>);
  const middleware = new SecurityMonitorStore(config as SecurityMonitorConfig);
  globalMiddleware = middleware;
  // record the bootstrap runtime-hook probe BEFORE async init so
  // security.status reflects it even if initialize() fails; the WARN event is
  // written only after the collector is up (initialize resolved).
  if (bootstrapState) {
    middleware.setRuntimeHookProbeState(bootstrapState.runtimeHookLoaded, bootstrapState.runtimeHooksUserEnabled);
  }
  // OpenClaw 2026.9.4 requires register() to be synchronous; the host
  // rejects a Promise return. Run async init in fire-and-forget;
  // middleware object is constructed synchronously so hooks can reference it
  // immediately. Initialization failures are logged but do not crash the host.
  middleware
    .initialize(config as unknown as Record<string, unknown>)
    .then(() => middleware.emitRuntimeHookProbeWarningIfNeeded())
    .catch((err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err);
      logger?.error?.(`[${PLUGIN_ID}] initialize failed: ${msg}`);
    });
  return middleware;
}

/**
 * OpenClaw 2026.9.4 entry point.
 *
 * MUST be synchronous: the host rejects a Promise return with
 * "plugin register must be synchronous".
 * Async work happens via createMiddleware()'s fire-and-forget init, and
 * individual hook handlers (api.on(...)) which the host tolerates as Promise.
 */
function register(api: OpenClawPluginApi): void {
  api.logger.info(`[${PLUGIN_ID}] plugin loaded (version ${PLUGIN_VERSION})`);
  const cfg = api.pluginConfig ?? {};
  const normalized = normalizeConfig((cfg ?? {}) as Record<string, unknown>);
  // Run the bootstrap pipeline: seed policy, install hooks, probe runtime
  // hook coverage, probe python psutil — then hand the post-bootstrap config
  // to the store so disabled features are not even constructed. All steps
  // are best-effort; failure never throws.
  const { config: bootstrapCfg, report: bootstrapReport } = initializePlugin(api, normalized);
  // pass the probe result plus the user's ORIGINAL intent
  // (pre-bootstrap config — applyBootstrapResults clamps it to false on
  // probe failure, which would erase the "静默降级 vs 主动关闭" distinction).
  const middleware = createMiddleware(bootstrapCfg as unknown as Record<string, unknown>, api.logger, {
    runtimeHookLoaded: bootstrapReport.runtimeHookLoaded,
    runtimeHooksUserEnabled: normalized.application?.runtimeHooks?.enabled === true,
  });
  const on = api.on?.bind(api);

  // Typed hook: agent lifecycle. before_agent_run is a gate hook: the 9.4 host
  // consumes InputGateDecision ({ outcome: 'pass' } | { outcome: 'block', reason })
  // and tolerates async handlers (15s timeout, fail-closed). The store returns
  // { outcome: 'block', reason } for block decisions; guidance decisions are
  // not deliverable here (no systemPromptAddition) and are traced by the store.
  on?.("before_agent_run", async (event, ctx) => {
    const input = hookBridge.bridgeAgentStart(event, ctx);
    if (!input) return;
    return await middleware.beforeAgentStart(input);
  });

  on?.("agent_end", async (event, ctx) => {
    const input = hookBridge.bridgeAgentComplete(event, ctx);
    if (!input) return;
    await middleware.afterAgentComplete(input);
  });

  // Typed hook: tool calls.
  on?.("before_tool_call", async (event, ctx) => {
    const { ctx: toolCtx } = hookBridge.bridgeToolCall(event, ctx);
    if (!toolCtx) return;
    const result = await middleware.beforeToolCall(toolCtx);
    if (result.block) {
      return {
        block: true,
        blockReason: result.reason || "blocked",
        params: result.modifiedParams,
      };
    }
    if (result.modifiedParams) {
      return { params: result.modifiedParams };
    }
    return undefined;
  });

  on?.("after_tool_call", async (event, ctx) => {
    const { ctx: toolCtx, result } = hookBridge.bridgeToolCall(event, ctx);
    if (!toolCtx) return;
    await middleware.afterToolCall(toolCtx, result);
  });

  // Typed hook: messages. `message_received` / `message_sending` were dropped
  // — both duplicate `before_message_write` and just
  // funneled the same events through `bridgeMessageWrite`. The single
  // `before_message_write` subscription covers the modern return-shape
  // contract (block + modified content).
  //
  // the handler MUST be synchronous. before_message_write is a SYNC-ONLY
  // hook in OpenClaw 2026.9.4 (the host ignores Promise results with a
  // warning), so the previous async handler's block decisions
  // were silently dropped by the host. Evaluation (SelfProtection + policy
  // engine) is fully synchronous via store.beforeMessageWriteSync; event
  // collection stays fire-and-forget inside the store.
  on?.("before_message_write", (event, ctx) => {
    const input = hookBridge.bridgeMessageWrite(event, ctx);
    if (!input) return;
    const result = middleware.beforeMessageWriteSync(input);
    return hookBridge.toMessageWriteHostResult(input, result);
  });

  // Typed hook: session / subagent / cron lifecycle.
  on?.("session_start", async (event, ctx) => {
    const input = hookBridge.bridgeMessageWrite(event, ctx);
    if (!input) return;
    await middleware.beforeMessageWrite(input);
  });

  on?.("session_end", async (event, ctx) => {
    const input = hookBridge.bridgeSessionEnd(event, ctx);
    if (!input) return;
    await middleware.onSessionEnd(input);
  });

  on?.("subagent_spawned", async (event, ctx) => {
    const input = hookBridge.bridgeSubagent(event, ctx);
    if (!input) return;
    await middleware.onSubagentStart(input);
  });

  on?.("subagent_progress", async (event, ctx) => {
    const input = hookBridge.bridgeSubagent(event, ctx);
    if (!input) return;
    await middleware.onSubagentProgress(input);
  });

  on?.("subagent_ended", async (event, ctx) => {
    const input = hookBridge.bridgeSubagent(event, ctx);
    if (!input) return;
    await middleware.onSubagentEnd(input);
  });

  // `cron_reconciled` dropped — `cron_changed` already covers cron
  // lifecycle; the reconciler just re-reads the current schedule without
  // firing a distinct event the policy engine needs.
  on?.("cron_changed", async (event, ctx) => {
    const input = hookBridge.bridgeCron(event, ctx);
    if (!input) return;
    await middleware.onCronEvent(input);
  });

  // InternalHookEvent path (5 family types) — kept as opt-in fallback for hosts
  // that route all events through the legacy registerHook dispatcher. The
  // 2026.9.4 typed hook runner already dispatches the same events via
  // api.on(...) above; this hook only fires for older 3.x/8.x hosts. The
  // `name` opt is required by the host, which rejects hook registrations
  // without one.
  if (typeof api.registerHook === "function") {
    api.registerHook(
      ["command", "session", "agent", "gateway", "message"],
      async (event: InternalHookEvent) => {
        await handleInternalHookEvent(event, middleware);
      },
      { name: `${PLUGIN_ID}-internal-hooks` }
    );
  } else {
    // Hosts without registerHook (very old or minimal hosts) still get full
    // coverage from the typed api.on(...) subscriptions above; only the
    // 5-family InternalHookEvent fallback is unavailable.
    api.logger.warn(`[${PLUGIN_ID}] host does not expose registerHook; InternalHookEvent fallback disabled`);
  }

  // Centralized RPC handler table. Both the WebSocket surface
  // (`registerGatewayMethod`) and the in-iframe HTTP surface
  // (`/openclaw-security-monitor/rpc`) consume the same handlers so the
  // Security Tab can render from inside a sandboxed iframe where the
  // gateway WebSocket is not reachable.
  const rpcHandlers: Record<string, (params: unknown) => Promise<unknown> | unknown> = {
    "security.evaluate": async (params) => {
      const input = (params ?? {}) as InterventionContext;
      if (!input.actionType || !input.toolName) {
        return { error: "actionType and toolName are required" };
      }
      // Bound attacker-supplied evaluation input: the rule matcher runs regex
      // against body/params, so unbounded strings are a CPU-DoS amplifier.
      const sizeError = evaluateInputSizeError(input);
      if (sizeError) return { error: sizeError };
      const decision = await middleware.evaluateIntervention(input);
      // matchedPolicies carries the full matched-rule annotation; RPC clients
      // only ever need the rule ids (panel renders decision + policyId).
      if (decision && Array.isArray(decision.matchedPolicies)) {
        const { matchedPolicies, ...rest } = decision;
        return { ...rest, matchedPolicies: matchedPolicies.map((m) => ({ policyId: m.policyId })) };
      }
      return decision;
    },
    "security.status": () => middleware.getStatus(),
  };

  // Control UI: 5 read-only RPCs powering the Security Tab.
  const controlUi = middleware.getControlUiService();
  rpcHandlers["security.events.list"] = (params) => {
    const q = (params ?? {}) as { limit?: number; eventType?: string; severity?: string; sinceMs?: number; untilMs?: number; offset?: number };
    return controlUi.listEvents(q);
  };
  rpcHandlers["security.events.stats"] = () => controlUi.stats();
  rpcHandlers["security.assets.list"] = () => controlUi.listAssets();
  rpcHandlers["security.policy.hits"] = (params) => {
    const q = (params ?? {}) as { decision?: string; limit?: number; offset?: number };
    return controlUi.policyHits(q);
  };
  rpcHandlers["security.metrics"] = () => controlUi.metrics();

  // Control UI: Configuration RPCs. The host already manages its config store;
  // `security.config.get` returns the full merged config (not the enabled-only
  // summary that getStatus().stats.config exposes) plus the editable field
  // schema shared with the panel form. `security.config.save` is the writable
  // counterpart: validates, deep-merges into `plugins.entries[id].config`,
  // backs up the host config file, then atomically renames a temp file on top
  // (L1–L8 safety layers; see saveHostConfigPatch for the full contract).
  rpcHandlers["security.config.get"] = () => {
    const config = middleware.getConfig() as unknown as Record<string, unknown>;
    const patterns = middleware.getConfig().assetMonitor?.sensitiveKeyPatterns;
    return {
      config: obfuscateDeep(config, patterns && patterns.length > 0 ? patterns : ["token", "key", "secret", "password", "credential"]),
      schema: CONFIG_SCHEMA,
    };
  };
  // Returns the raw plugins.entries[PLUGIN_ID].config block as it lives on
  // disk (no obfuscation). The `Copy JSON` button in the Config panel uses
  // this so the operator can copy the actual on-disk shape; the obfuscated
  // `security.config.get` view would replace sensitive values with `***`
  // and round-tripping it back through `security.config.save` would silently
  // persist the redacted form.
  rpcHandlers["security.config.raw"] = () => {
    const targetPath = resolveHostConfigPath();
    if (!existsSync(targetPath)) {
      return { ok: false, error: { message: "host config not found: " + targetPath } };
    }
    try {
      const raw = readFileSync(targetPath, "utf8");
      const parsed = JSON.parse(raw) as { plugins?: { entries?: Record<string, { config?: unknown }> } };
      const entry = parsed?.plugins?.entries?.[PLUGIN_ID];
      const block = entry && typeof entry === "object" && "config" in entry ? entry.config : {};
      return { ok: true, config: block, path: targetPath };
    } catch (err) {
      return { ok: false, error: { message: "raw config read failed: " + (err as Error).message } };
    }
  };
  rpcHandlers["security.config.diff"] = (params) => {
    const proposed = (params ?? {}) as Record<string, unknown>;
    // Compare against the full merged config flattened to the same
    // `section.key` dot-path space the panel and save validator use. The
    // enabled-only summary in getStatus().stats.config keys its entries as
    // `application` / `interventionMode`, whose key space never intersects
    // DANGEROUS_CONFIG_KEYS — so `dangerous` was permanently empty.
    const current = flattenConfigLeaves(middleware.getConfig() as unknown as Record<string, unknown>);
    const changes: Array<{ key: string; from: unknown; to: unknown }> = [];
    for (const key of Object.keys(proposed)) {
      if (JSON.stringify(current[key]) !== JSON.stringify(proposed[key])) {
        changes.push({ key, from: current[key], to: proposed[key] });
      }
    }
    return { changes, dangerous: markDangerousConfig(changes) };
  };
  rpcHandlers["security.config.save"] = (params) => {
    const { patch, confirmDanger, confirmToken } = (params ?? {}) as {
      patch?: Record<string, Record<string, unknown>>;
      confirmDanger?: boolean;
      confirmToken?: string;
    };
    return saveHostConfigPatch({
      patch: patch ?? {},
      confirmDanger: !!confirmDanger,
      confirmToken: typeof confirmToken === "string" ? confirmToken : undefined,
      effectiveConfig: middleware.getConfig(),
      logger: api.logger,
    });
  };

  // Register each handler through `registerGatewayMethod` for WS clients.
  // OpenClaw 9.4 dispatches gateway methods over the gateway WebSocket;
  // the HTTP surface below is for the in-iframe panel.
  const wsScopes: Record<string, "operator.read" | "operator.write" | "operator.admin"> = {
    "security.evaluate": "operator.admin",
    "security.status": "operator.read",
    "security.events.list": "operator.read",
    "security.events.stats": "operator.read",
    "security.assets.list": "operator.read",
    "security.policy.hits": "operator.read",
    "security.metrics": "operator.read",
    "security.config.get": "operator.read",
    "security.config.raw": "operator.read",
    "security.config.diff": "operator.write",
    "security.config.save": "operator.write",
  };
  if (typeof api.registerGatewayMethod === "function") {
    for (const [name, handler] of Object.entries(rpcHandlers)) {
      api.registerGatewayMethod(
        name,
        async (params: unknown) => handler(params),
        { scope: wsScopes[name] ?? "operator.read" }
      );
    }
  } else {
    // Minimal hosts: no gateway WebSocket RPC. The HTTP RPC surface below
    // still serves the panel, so only out-of-iframe WS clients are lost.
    api.logger.warn(`[${PLUGIN_ID}] host does not expose registerGatewayMethod; gateway RPC surface disabled`);
  }

  // F-02 hardening: CSRF guard — reject cross-origin POST unless
  // it is a strict same-origin request (host AND port equal). `Origin: null`
  // (the sandboxed Control UI iframe) no longer passes on its own: it must
  // carry a panel nonce minted by a prior GET of the panel HTML (see below).
  // Omitted Origin still passes for non-browser clients (curl / SDK sidecars)
  // — a web page cannot suppress Origin on fetch/XHR, so the
  // arbitrary-web-page → RCE chain stays broken either way.
  const isStrictSameOrigin = (originHeader: string | undefined, hostHeader: string | undefined): boolean => {
    if (!originHeader || !hostHeader) return false;
    try {
      return new URL(originHeader).host === hostHeader;
    } catch {
      return false;
    }
  };

  // Panel nonces back the `Origin: null` exception above. GET /panel (or
  // /panel-tab) mints a fresh nonce and embeds it in the served HTML; the
  // sandboxed iframe sends it back as X-Panel-Nonce on every RPC POST. The
  // nonce is time-boxed (30 min), rotated on every panel load, and shared
  // across both panel routes so the iframe can POST to /panel.
  const PANEL_NONCE_TTL_MS = 30 * 60 * 1000;
  const panelNonces = new Map<string, number>();
  const prunePanelNonces = () => {
    const now = Date.now();
    for (const [nonce, expiresAt] of panelNonces) {
      if (expiresAt <= now) panelNonces.delete(nonce);
    }
  };
  const mintPanelNonce = (): string => {
    prunePanelNonces();
    const nonce = randomBytes(18).toString("base64url");
    panelNonces.set(nonce, Date.now() + PANEL_NONCE_TTL_MS);
    return nonce;
  };
  const isPanelNonceValid = (nonce: string | undefined): nonce is string => {
    if (!nonce) return false;
    const expiresAt = panelNonces.get(nonce);
    if (expiresAt === undefined) return false;
    if (expiresAt <= Date.now()) {
      panelNonces.delete(nonce);
      return false;
    }
    return true;
  };

  // P4: expose NDJSON event log as an HTTP route so the SDK sidecar (or any
  // platform scraper) can tail it without filesystem access.
  // `auth: "gateway"` is required so external clients can fetch via operator
  // scope; "plugin" would gate it to internal plugin calls only.
  api.registerHttpRoute?.({
    path: "/openclaw-security-monitor/events.ndjson",
    auth: "gateway",
    handler: (_req, res) => {
      const filePath = middleware.getCollectorNdjsonPath();
      if (!filePath) {
        res.statusCode = 404;
        res.end("ndjsonPath not configured");
        return;
      }
      try {
        statSync(filePath);
      } catch {
        res.statusCode = 404;
        res.end("event log not found");
        return;
      }
      res.statusCode = 200;
      res.setHeader("Content-Type", "application/x-ndjson");
      const rs = createReadStream(filePath, { encoding: "utf8" });
      rs.on("error", () => {
        try { res.end(); } catch { /* ignore */ }
      });
      rs.pipe(res);
      _req.on("close", () => {
        rs.destroy();
      });
    },
  });

  // Shared streaming response for bundled static assets (favicon, QR image).
  // 404s cleanly when the file is absent; caches for a day so a tab refresh
  // doesn't re-fetch.
  const serveAsset = (req: IncomingMessage, res: ServerResponse, filePath: string, contentType: string) => {
    res.statusCode = 200;
    res.setHeader("Content-Type", contentType);
    res.setHeader("Cache-Control", "public, max-age=86400");
    const rs = createReadStream(filePath);
    rs.on("error", () => {
      try { res.end(); } catch { /* ignore */ }
    });
    rs.pipe(res);
    req.on("close", () => {
      rs.destroy();
    });
  };

  // Serve the bundled favicon at /openclaw-security-monitor/favicon.ico so
  // browser tabs (and the Control UI) render the enterprise icon instead of
  // the default globe. The route streams the file with a 1-day cache so the
  // favicon survives a tab refresh without re-fetching.
  api.registerHttpRoute?.({
    path: "/openclaw-security-monitor/favicon.ico",
    auth: "plugin",
    handler: (_req, res) => {
      const filePath = findFaviconPath();
      if (!filePath) {
        res.statusCode = 404;
        res.end("favicon not found");
        return;
      }
      serveAsset(_req, res, filePath, "image/x-icon");
    },
  });

  // Serve the bundled WeChat MP QR image for the Metrics footer "关注公众号"
  // preview. Same-origin img load under the panel's CSP img-src 'self'; the
  // 1-day cache keeps the preview instant across 30s auto-refreshes.
  api.registerHttpRoute?.({
    path: "/openclaw-security-monitor/wechat-mp-qr.jpg",
    auth: "plugin",
    handler: (_req, res) => {
      const filePath = findAssetPath("wechat-mp-qr.jpg");
      if (!filePath) {
        res.statusCode = 404;
        res.end("qr image not found");
        return;
      }
      serveAsset(_req, res, filePath, "image/jpeg");
    },
  });

  // Control UI: register the Security Tab in the OpenClaw Control UI. The
  // nested `session.controls` form is the 9.4 spec; we also try the
  // deprecated top-level form for 3.x/8.x hosts.
  //
  // 9.4 host renders plugin tab content inside a sandboxed iframe whose
  // sandbox defaults to "allow-scripts" (no allow-same-origin) — its React
  // bundle throws on `window.localStorage` at mount and never recovers, so
  // any `schema.default.views` we ship silently produces a blank tab. We
  // deliberately omit `default.views` here and rely on the standalone
  // panel route below (`path`), which the user opens as a regular browser
  // tab. `path` is still recorded so 9.4 hosts that honour it (or link to
  // it from plugin metadata) can surface the URL.
  //
  // We register TWO surfaces:
  //   - `tab`        → appears in the Control UI left-nav as
  //                    "Security Monitor". Clicking it shows the standalone
  //                    panel.
  //   - `settings`   → registers the same panel path as the plugin's
  //                    settings view, so when the user opens the plugin
  //                    detail page the host offers our panel in place of
  //                    (or alongside) the auto-generated configSchema
  //                    rendering. Without this surface, the OpenClaw 9.4
  //                    Control UI renders the bundled configSchema as the
  //                    default "配置" tab, which we have no use for since
  //                    every config knob is either host-owned (intervention
  //                    mode) or seeded by ensureHostPluginEntryDefaults().
  // OpenClaw 9.4 renders every `tab` descriptor's `path` inside a sandboxed
  // iframe with only `allow-scripts` (no `allow-top-navigation`, no
  // `allow-popups`). That kills every "open in new tab" strategy we have
  // from inside the iframe (window.top.location.*, window.open,
  // <a target=_top>, <form target=_top>, meta refresh) — the host silently
  // intercepts them and the user lands on a "click here to open" hint.
  //
  // To get a true single-click experience (sidebar → new tab → standalone
  // panel), we register the tab WITHOUT a `path`. The OpenClaw 9.4 host
  // then renders the descriptor's plain label/description on the plugin
  // page rather than an iframe. We still register `settings` with the
  // panel path so the host's settings entry opens the panel directly when
  // the operator clicks the plugin's settings gear.
  const descriptors = [
    {
      surface: "tab" as const,
      id: "security-monitor",
      label: "SST Security Control",
      description:
        "打开 SST Security Control 独立面板。点击侧边栏项目开启新标签页面板。",
      icon: "shield",
      group: "control" as const,
      order: 50,
      requiredScopes: ["operator.read"] as Array<"operator.read">,
      path: "/openclaw-security-monitor/panel-tab",
    },
    {
      surface: "settings" as const,
      id: "security-monitor-settings",
      label: "SST Security Control",
      description:
        "实时事件流 / Top 拦截 / 资产变更 / 策略命中。OpenClaw 9.4 默认按 configSchema 渲染插件配置页，这里覆盖为独立面板路径。",
      icon: "shield",
      requiredScopes: ["operator.read"] as Array<"operator.read">,
      path: "/openclaw-security-monitor/panel",
    },
  ];
  const registrar = api.session?.controls?.registerControlUiDescriptor
    ?? api.registerControlUiDescriptor;
  if (registrar) {
    for (const d of descriptors) registrar(d);
    api.logger.info(
      `[${PLUGIN_ID}] control UI descriptors registered: ` +
        `${descriptors.map((d) => `${d.surface}:${d.id}`).join(", ")}; ` +
        `standalone panel URL: /openclaw-security-monitor/panel ` +
        `(open it directly in a browser tab — the embedded Control UI iframe is broken in 9.4)`
    );
  }

  // Control UI: self-contained Security Monitor panel. Runs as a sandboxed iframe
  // in OpenClaw 9.4's Control UI. Does NOT depend on:
  //   - localStorage (the 9.4 host's injected React bundle fails here)
  //   - parent origin (sandbox lacks allow-same-origin)
  //   - cookies / auth tokens (gateway route uses auth=gateway so the browser
  //     auto-attaches gateway session credentials)
  // Fetches 5 RPCs via relative fetch, renders 5 tabs, auto-refreshes every 30s.
  // The handler is dual-purpose: GET serves the panel HTML, POST dispatches
  // an RPC into the same handler table as `registerGatewayMethod`. The
  // POST branch exists because the 9.4 Control UI issues a single auth
  // grant cookie scoped to the descriptor's path (exact match), so any
  // cross-path fetch from inside the sandboxed iframe fails the cookie
  // check. Routing both GET and POST through the same plugin route keeps
  // the iframe's RPC traffic on the granted path.
  // `auth: "plugin"` (not "gateway") so the panel is reachable from a direct
  // browser tab without the Control UI's control-ui-plugin grant cookie.
  // The 9.4 iframe path is broken in sandboxed iframes (host React crashes on
  // window.localStorage), so we cannot rely on the iframe to set the grant.
// All 10 RPCs behind this route are read-only (security.evaluate returns a
  // decision but does not enforce; security.config.save is the only mutator).
  // Shared panel HTML handler. Used by two routes below:
  //   1) /openclaw-security-monitor/panel (auth=plugin) for direct browser tabs.
  //   2) /openclaw-security-monitor/panel-tab (auth=gateway) so the host
  //      Control UI tab descriptor (which scans routes for auth === "gateway")
  //      can iframe-load the panel when the operator clicks the sidebar entry.
  const panelHandlerImpl = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
      const method = (req.method || "GET").toUpperCase();
      const originHeader = typeof req.headers.origin === "string" ? req.headers.origin : undefined;
      const sameOrigin = isStrictSameOrigin(originHeader, req.headers.host);
      // Sandbox-iframe requests carry `Origin: null`; they are only acceptable
      // with a freshly minted panel nonce. Omitted Origin (non-browser clients)
      // passes. Anything else is a hard reject with no CORS headers, so the
      // browser also keeps the response unreadable cross-origin.
      const sandboxNonceOk = originHeader === "null"
        && isPanelNonceValid(typeof req.headers["x-panel-nonce"] === "string" ? req.headers["x-panel-nonce"] : undefined);
      // CORS headers are only ever emitted for the sandboxed iframe (exact
      // "null", never an echoed attacker origin) and never carry
      // Access-Control-Allow-Credentials. Same-origin direct tabs need none.
      const setSandboxCorsHeaders = () => {
        res.setHeader("Access-Control-Allow-Origin", "null");
        res.setHeader("Access-Control-Allow-Methods", "GET, HEAD, POST, OPTIONS");
        // X-Panel-Nonce is a custom request header on every sandboxed RPC
        // POST; the preflight must explicitly allow it or the browser blocks
        // the request before it is sent (net::ERR_FAILED, no response to read).
        res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-Panel-Nonce");
      };
      if (method === "OPTIONS") {
        // Approve preflights only for callers we would accept on POST.
        if (originHeader && !sameOrigin && originHeader !== "null") {
          res.statusCode = 403;
          res.end();
          return;
        }
        if (originHeader === "null") setSandboxCorsHeaders();
        else if (!originHeader) res.setHeader("Access-Control-Allow-Origin", "*");
        res.statusCode = 204;
        res.end();
        return;
      }
      if (method !== "GET" && method !== "HEAD") {
        // F-02: cross-origin POSTs are rejected; sandboxed-iframe
        // POSTs additionally need the panel nonce. Without this a third-party
        // page could craft a fetch() against the gateway URL and call e.g.
        // security.config.save cross-origin.
        if (originHeader !== undefined && !sameOrigin && !sandboxNonceOk) {
          res.statusCode = 403;
          res.setHeader("Content-Type", "application/json");
          res.end(JSON.stringify({ ok: false, error: { message: "cross-origin POST rejected" } }));
          return;
        }
        try {
          const chunks: Buffer[] = [];
          let bodyBytes = 0;
          const MAX_BODY_BYTES = 1024 * 1024; // 1 MiB — panel RPC payloads are a few KB at most
          for await (const chunk of req) {
            const c = chunk as Buffer;
            bodyBytes += c.length;
            if (bodyBytes > MAX_BODY_BYTES) {
              res.statusCode = 413;
              res.setHeader("Content-Type", "application/json");
              res.end(JSON.stringify({ ok: false, error: { message: "request body too large" } }));
              // Tear the connection down once the 413 is flushed so the
              // remainder of the oversized body is never buffered.
              res.on("finish", () => req.destroy());
              return;
            }
            chunks.push(c);
          }
          const raw = Buffer.concat(chunks).toString("utf8").trim();
          if (originHeader === "null") setSandboxCorsHeaders();
          if (!raw) {
            res.statusCode = 400;
            res.setHeader("Content-Type", "application/json");
            res.end(JSON.stringify({ ok: false, error: { message: "empty body" } }));
            return;
          }
          let parsed: unknown;
          try {
            parsed = JSON.parse(raw);
          } catch {
            res.statusCode = 400;
            res.setHeader("Content-Type", "application/json");
            res.end(JSON.stringify({ ok: false, error: { message: "invalid JSON" } }));
            return;
          }
          const body = parsed as { method?: string; params?: unknown };
          const methodName = typeof body?.method === "string" ? body.method : "";
          const handler = rpcHandlers[methodName];
          if (!handler) {
            res.statusCode = 404;
            res.setHeader("Content-Type", "application/json");
            res.end(JSON.stringify({ ok: false, error: { message: `unknown method: ${methodName}` } }));
            return;
          }
          const result = await handler(body?.params);
          res.statusCode = 200;
          res.setHeader("Content-Type", "application/json");
          res.setHeader("Cache-Control", "no-store");
          res.end(JSON.stringify({ ok: true, payload: result }));
        } catch (err) {
          const message = err instanceof Error ? err.message : String(err);
          res.statusCode = 500;
          res.setHeader("Content-Type", "application/json");
          res.end(JSON.stringify({ ok: false, error: { message } }));
        }
        return;
      }
      res.statusCode = 200;
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.setHeader("Cache-Control", "no-store");
      // CSP: connect-src 'self' is required so the panel iframe can fetch the
      // same-origin RPC endpoint. base-uri 'none' + form-action 'none' close
      // the trivial injection vectors; we still keep default-src 'none' so any
      // future image/font/frame directives default-deny.
      res.setHeader("Content-Security-Policy", "default-src 'none'; connect-src 'self'; img-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'");
      // HEAD must return 200 + headers with no body so monitoring tools
      // (curl -I, k8s readiness probes) can probe the route without parsing HTML.
      if (method === "HEAD") {
        res.end();
        return;
      }
      // Mint the per-load panel nonce that sandboxed-iframe RPC POSTs must send
      // back as X-Panel-Nonce (their Origin is opaque, i.e. "null").
      const panelNonce = mintPanelNonce();
      res.end(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="ocm-panel-nonce" content="${panelNonce}">
<title>SST Security Control</title>
<link rel="icon" type="image/x-icon" href="/openclaw-security-monitor/favicon.ico">
<style>
:root {
  --bg: #0f1117;
  --fg: #e6edf3;
  --muted: #8b949e;
  --border: #21262d;
  --accent: #58a6ff;
  --accent-fg: #79c0ff;
  --path-fg: #a5d6ff;
  --card-bg: #161b22;
  --subtle-bg: #0d1117;
  --hover-bg: #1f2733;
  --success: #3fb950;
  --warn: #d29922;
  --danger: #f85149;
  --hl: #f0883e;
  --error-bg: #3d1c1c;
  --badge-block-bg: #3d1c1c;
  --badge-allow-bg: #0d3320;
  --badge-change-bg: #1c2d1e;
  --badge-add-bg: #0d1d30;
  --badge-remove-bg: #2d1c1e;
  --badge-warn-bg: #2d2410;
  --button-bg: #238636;
  --button-hover: #2ea043;
}
@media (prefers-color-scheme: light) {
  :root {
    --bg: #ffffff;
    --fg: #1f2328;
    --muted: #656d76;
    --border: #d0d7de;
    --accent: #0969da;
    --accent-fg: #0550ae;
    --path-fg: #0a3069;
    --card-bg: #f6f8fa;
    --subtle-bg: #eaeef2;
    --hover-bg: #d8dee4;
    --success: #1a7f37;
    --warn: #9a6700;
    --danger: #cf222e;
    --hl: #bc4c00;
    --error-bg: #ffebe9;
    --badge-block-bg: #ffebe9;
    --badge-allow-bg: #dafbe1;
    --badge-change-bg: #ddf4ff;
    --badge-add-bg: #ddf4ff;
    --badge-remove-bg: #ffebe9;
    --badge-warn-bg: #fff8c5;
    --button-bg: #1f883d;
    --button-hover: #1a7f37;
  }
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,sans-serif;font-size:13px;background:var(--bg);color:var(--fg);min-height:100vh}
header{padding:12px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:8px}
header .icon{width:22px;height:22px;display:inline-block;vertical-align:middle}
h1{font-size:14px;font-weight:600;color:var(--fg)}
.subtitle{font-size:11px;color:var(--muted);margin-left:auto}
.tabs{display:flex;border-bottom:1px solid var(--border);padding:0 16px;gap:2px;overflow-x:auto}
.tab{padding:8px 14px;cursor:pointer;color:var(--muted);font-size:12px;border-bottom:2px solid transparent;white-space:nowrap;background:none;border-top:none;border-left:none;border-right:none}
.tab:hover{color:var(--fg)}
.tab.active{color:var(--accent);border-bottom-color:var(--accent)}
.panel{padding:16px}
.spinner{text-align:center;padding:32px;color:var(--muted)}
.error{background:var(--error-bg);border:1px solid var(--danger);border-radius:6px;padding:12px;color:var(--danger)}
.card{background:var(--card-bg);border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:12px}
.card h2{font-size:12px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin-bottom:12px}
.metrics{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:10px}
.metric{background:var(--subtle-bg);border:1px solid var(--border);border-radius:6px;padding:12px;min-width:0}
.metric .val{font-size:22px;font-weight:700;color:var(--fg);font-variant-numeric:tabular-nums;line-height:1.1;letter-spacing:-.02em}
.metric .lbl{font-size:11px;color:var(--muted);margin-top:4px}
.metric.zero .val{color:var(--muted);font-weight:600}
.metric.alert .val{color:var(--danger)}
.metric.warn .val{color:var(--warn)}
table{width:100%;border-collapse:collapse;font-size:12px}
th{text-align:left;padding:6px 10px;background:var(--subtle-bg);color:var(--muted);border-bottom:1px solid var(--border);font-weight:600;font-size:11px;text-transform:uppercase}
td{padding:7px 10px;border-bottom:1px solid var(--card-bg);color:var(--fg);vertical-align:top}
tr:last-child td{border-bottom:none}
tr:hover td{background:var(--hover-bg)}
.badge{display:inline-block;padding:1px 6px;border-radius:10px;font-size:10px;font-weight:600}
.badge.block{background:var(--badge-block-bg);color:var(--danger)}
.badge.allow{background:var(--badge-allow-bg);color:var(--success)}
.badge.change{background:var(--badge-change-bg);color:var(--accent)}
.badge.add{background:var(--badge-add-bg);color:var(--success)}
.badge.remove{background:var(--badge-remove-bg);color:var(--danger)}
/* 决策类型徽标（warn/audit/degrade）。appealable 是元数据标注而非决策，
   刻意不用 badge 样式——弱化小字 + 点线下划线（cursor:help 暗示 tooltip），
   避免被误读为可点击的筛选器/按钮（与决策徽标同视觉层级曾引起歧义）。 */
.badge.warn{background:var(--badge-warn-bg);color:var(--warn)}
/* severity low / unknown 徽标（灰底 + muted 字色），与决策徽标同视觉
   语法但弱化以体现"低优先级"语义，不抢 block/warn 红黄主视觉。 */
.badge.muted{background:var(--subtle-bg);color:var(--muted);border:1px solid var(--border)}
.appeal-tag{color:var(--muted);font-size:10px;cursor:help;text-decoration:underline dotted;text-underline-offset:2px}
.ts{color:var(--muted);font-size:11px;white-space:nowrap}
.tool{font-family:monospace;color:var(--accent-fg);font-size:11px}
.path{font-family:monospace;color:var(--path-fg);font-size:11px;word-break:break-all}
.row-meta{display:flex;gap:12px;flex-wrap:wrap;margin-top:4px}
.meta{font-size:11px;color:var(--muted)}
.refresh{font-size:11px;color:var(--muted);text-align:right;margin-top:8px}
.empty{color:var(--muted);text-align:center;padding:24px}
.hl{color:var(--hl)}
.ok{color:var(--success)}
.warn{color:var(--warn)}
.danger{color:var(--danger)}
pre{font-family:monospace;font-size:11px;background:var(--subtle-bg);border:1px solid var(--border);border-radius:4px;padding:8px;overflow:auto;max-height:200px;white-space:pre-wrap;word-break:break-all}
label{display:flex;align-items:center;gap:8px;padding:4px 0;font-size:12px;color:var(--muted)}
input{flex:1;background:var(--subtle-bg);border:1px solid var(--border);border-radius:4px;padding:5px 8px;color:var(--fg);font-size:12px;outline:none}
input:focus{border-color:var(--accent)}
button{background:var(--button-bg);border:none;border-radius:4px;padding:5px 12px;color:#fff;font-size:12px;cursor:pointer}
button:hover{background:var(--button-hover)}
button:disabled{opacity:.5;cursor:not-allowed}
.json-view{font-family:monospace;font-size:11px;background:var(--subtle-bg);border:1px solid var(--border);border-radius:4px;padding:8px;overflow:auto;max-height:300px;white-space:pre-wrap;word-break:break-all;color:var(--fg)}
.event-row{cursor:pointer}
.event-row:hover td{background:var(--hover-bg)}
.event-detail{display:none}
.event-detail.open{display:table-row}
.event-detail>td{padding:0 10px 10px 10px}
.toolbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:10px}
.toolbar select,.toolbar input{background:var(--subtle-bg);border:1px solid var(--border);border-radius:4px;padding:5px 8px;color:var(--fg);font-size:12px;outline:none}
.toolbar select:focus,.toolbar input:focus{border-color:var(--accent)}
.toolbar .grow{flex:1}
/* Policy Hits 决策胶囊筛选条（all/block/warn/modify/audit）。
   视觉上比 badge 略宽，与 summary badges 同高度；当前选中描边加深。 */
.capsule-row{display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-bottom:10px}
.capsule{display:inline-flex;align-items:center;gap:4px;padding:3px 10px;border-radius:12px;font-size:11px;font-weight:600;cursor:pointer;border:1px solid transparent;background:var(--subtle-bg);color:var(--muted);user-select:none}
.capsule:hover{background:var(--hover-bg);color:var(--fg)}
.capsule.active{border-color:var(--accent);color:var(--fg);font-weight:600}
.capsule.block{background:var(--badge-block-bg);color:var(--danger)}
.capsule.warn{background:var(--badge-warn-bg);color:var(--warn)}
.capsule.change{background:var(--badge-change-bg);color:var(--accent)}
.capsule.allow{background:var(--badge-allow-bg);color:var(--success)}
.capsule .count{font-weight:400;opacity:0.85}
.events-footer{display:flex;justify-content:space-between;align-items:center;gap:8px;margin-top:10px;flex-wrap:wrap}
.events-footer .meta{font-size:11px;color:var(--muted)}
.events-footer button{background:var(--subtle-bg);color:var(--fg);border:1px solid var(--border)}
.events-footer button:hover{background:var(--hover-bg)}
.banner{padding:8px 10px;border-radius:4px;border:1px solid var(--border);background:var(--subtle-bg);font-size:12px;color:var(--warn);margin-bottom:10px}
/* Metrics 页脚对外入口（访问官网 / 关注公众号）。右对齐，使用
   --accent 链接色，亮/暗主题均可辨识。 */
.metrics-footer{display:flex;justify-content:flex-end;gap:16px;margin-top:8px;font-size:12px}
.metrics-footer a{color:var(--accent);text-decoration:none;cursor:pointer}
.metrics-footer a:hover{text-decoration:underline}
/* 公众号二维码预览层。静态 HTML 放在 #panel 之外，30s 自动刷新
   只重写 #panel.innerHTML，不会销毁打开中的预览。 */
.qr-modal{position:fixed;inset:0;z-index:1000;align-items:center;justify-content:center}
.qr-overlay{position:absolute;inset:0;background:rgba(0,0,0,.6)}
.qr-card{position:relative;background:var(--card-bg);border:1px solid var(--border);border-radius:8px;padding:20px;text-align:center}
.qr-card img{width:258px;height:258px;display:block;border-radius:4px}
.qr-note{font-size:12px;color:var(--muted);margin-top:10px}
.qr-close{position:absolute;top:6px;right:6px;background:var(--subtle-bg);color:var(--muted);border:1px solid var(--border);padding:2px 8px;line-height:1.2}
.qr-close:hover{color:var(--fg);background:var(--hover-bg)}
.toast{position:fixed;left:50%;bottom:24px;transform:translateX(-50%);background:var(--card-bg);border:1px solid var(--accent);color:var(--fg);border-radius:6px;padding:8px 14px;font-size:12px;z-index:1001;display:none}
/* ── Event JSON pane (inline copy affordance above <pre>).
   三态切换：默认 clipboard → 成功 check → 失败 alert，2s 自动回 idle。
   颜色复用现有 --success / --warn / --muted / --hover-bg token，与全站主题对齐。 */
.json-pane{border:1px solid var(--border);border-radius:10px;background:var(--card-bg);padding:10px 12px;margin:6px 0}
.json-pane-header{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:6px}
.json-pane-title{font-size:11px;font-weight:600;letter-spacing:.04em;text-transform:uppercase;color:var(--muted)}
.json-pane .json-view{margin:0;padding:8px;background:var(--subtle-bg);border:1px solid var(--border);border-radius:4px}
.copy-event{display:inline-flex;align-items:center;justify-content:center;width:26px;height:26px;padding:0;appearance:none;background:transparent;border:1px solid transparent;border-radius:6px;color:var(--muted);cursor:pointer;transition:background-color .12s ease,color .12s ease}
.copy-event:hover:not(:disabled){background:var(--hover-bg);color:var(--fg)}
.copy-event svg{fill:currentColor}
.copy-event[data-icon="check"]{color:var(--success)}
.copy-event[data-icon="alert"]{color:var(--warn)}
.copy-event:disabled{cursor:not-allowed;opacity:.55}
</style>
</head>
<body>
<header>
  <img class="icon" src="/openclaw-security-monitor/favicon.ico" alt="SST Security Control">
  <h1>SST Security Control</h1>
  <span class="subtitle">OpenClaw ${PLUGIN_VERSION} · auto-refresh 30s</span>
</header>
<div class="tabs" id="tabs">
  <button class="tab active" data-tab="metrics">Metrics</button>
  <button class="tab" data-tab="events">Event Stream</button>
  <button class="tab" data-tab="blocks">Policy Hits</button>
  <button class="tab" data-tab="config">Config</button>
</div>
<!-- 持久状态条（区别于 config.save 流程的瞬时横幅）。面板加载时
     读一次 security.status 渲染，不轮询；仅当用户开过 runtimeHooks 而
     bootstrap 探测到 hook 未加载（静默降级）时显示。 -->
<div id="hook-status-bar" style="display:none;background:var(--warn);color:#000;padding:6px 10px;border-radius:4px;margin:8px 16px 0;font-size:12px"></div>
<div class="panel" id="panel"><div class="spinner">Loading...</div></div>
<div class="refresh" id="refresh"></div>

<!-- 公众号二维码预览层。静态放在 #panel 之外，Metrics 页脚
     "关注公众号" 点击切换显隐；自动刷新只重写 #panel.innerHTML，不触碰本层。 -->
<div class="qr-modal" id="qr-modal" style="display:none">
  <div class="qr-overlay"></div>
  <div class="qr-card">
    <button type="button" class="qr-close" id="qr-close" aria-label="关闭">&#10005;</button>
    <img src="/openclaw-security-monitor/wechat-mp-qr.jpg" alt="微信公众号二维码">
    <div class="qr-note">微信扫码，关注公众号</div>
  </div>
</div>
<div class="toast" id="toast"></div>

<noscript>
<div class="error" style="margin:16px;font-size:13px">
  <strong>SST Security Control</strong>
  <p style="margin-top:6px">
    OpenClaw 9.4 Tab iframe 不执行内联脚本，面板无法在此视图渲染。请<a href="/openclaw-security-monitor/panel" target="_blank" rel="noopener" style="color:var(--accent);text-decoration:underline">👉 在新标签页打开完整面板</a>。
  </p>
</div>
</noscript>

<script>
(function() {
  // OpenClaw 9.4 hosts this panel inside a sandboxed iframe
  // (sandbox="allow-scripts" - no allow-top-navigation / allow-popups).
  // Earlier code tried to break out via top.location.replace, but the
  // iframe, but the sandbox silently swallows the attempt. We now render the
  // panel inside the iframe and expose a quiet 'Open in full view' button in
  // the header (target=_blank + rel=noopener). The button only works when the
  // host grants allow-popups; otherwise the user can copy the URL manually.
  var isEmbedded = (window.top !== window.self);
  function injectFullViewButton() {
    if (!isEmbedded || document.getElementById('full-view-btn')) return;
    var link = document.createElement('a');
    link.id = 'full-view-btn';
    link.href = window.location.href;
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    link.title = '在新标签页打开';
    link.textContent = '↗ 完整面板';
    link.style.cssText = 'margin-left:8px;font-size:11px;color:var(--accent);text-decoration:none;border:1px solid var(--border);border-radius:4px;padding:3px 8px;background:var(--subtle-bg);white-space:nowrap';
    var subtitle = document.querySelector('header .subtitle');
    if (subtitle) subtitle.parentNode.insertBefore(link, subtitle.nextSibling);
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', injectFullViewButton);
  } else {
    injectFullViewButton();
  }

  var RPCS = [
    "security.events.list","security.events.stats","security.assets.list",
    "security.policy.hits","security.metrics","security.config.get","security.status"
  ];
  var BASE = "";
  var activeTab = "metrics";
  var timer = null;
  // Metrics 页脚"访问官网"目标站点。
  var WEBSITE_URL = "https://www.zhihuizhanxing.com";

  // Panel nonce minted by the serving GET; required for RPC POSTs from the
  // sandboxed Control UI iframe whose Origin is opaque ("null"). Direct
  // same-origin tabs pass the strict origin check without it.
  var PANEL_NONCE = (function() {
    var m = document.querySelector('meta[name="ocm-panel-nonce"]');
    return m && m.content ? m.content : "";
  })();

  // 401/403 → 宿主 session/cookie 过期（面板标签长时间挂着时触发）。
  // 浏览器读不到 403 响应体（CORS 拒读），r.text() 会抛 "Failed to fetch"
  // 把真正的状态吞了；用户只能看到 "⚠ Failed to fetch"，看不出原因，要
  // 手动 F5 才能恢复。让面板直接 location.reload() 重建会话，比显示
  // 错误信息友好；若用户真的无权限，GET 也会 403，宿主给出明确的错误页。
  // 多个并行 RPC 可能同时命中 401/403，用 authReloadScheduled 闭包变量去重。
  var authReloadScheduled = false;
  function scheduleAuthReload() {
    if (authReloadScheduled) return;
    authReloadScheduled = true;
    // 留 50ms 让当前 setInterval tick 把"Failed to fetch"渲染完再重载，
    // 避免连续两次刷新请求重叠。sandboxed iframe 内 window.location.reload
    // 仍允许（沙箱不影响 reload 自身 URL）。
    setTimeout(function() {
      try { window.location.reload(); }
      catch (e) { /* 极端沙箱限制下 reload 被拒，静默降级 */ }
    }, 50);
  }

  function rpc(name, params) {
    var controller = (typeof AbortController !== "undefined") ? new AbortController() : null;
    var timeoutId = controller ? setTimeout(function() { controller.abort(); }, 8000) : null;
    return fetch(BASE + "/openclaw-security-monitor/panel", {
      method: "POST",
      headers: {"Content-Type":"application/json","X-Panel-Nonce":PANEL_NONCE},
      // "same-origin": cross-origin (sandboxed iframe) requests send no
      // cookies and need no Access-Control-Allow-Credentials to read the
      // response; same-origin direct tabs keep sending cookies as before.
      credentials: "same-origin",
      body: JSON.stringify({ method: name, params: params || {} }),
      signal: controller ? controller.signal : undefined
    }).then(function(r) {
      if (r.status === 401 || r.status === 403) {
        scheduleAuthReload();
        // 返回永不 resolve 的 Promise：reload 50ms 后页面已丢弃，不再有
        // 后续渲染；防止 .catch() 把 "Failed to fetch" 抛到错误条上。
        return new Promise(function() {});
      }
      if (!r.ok) return r.text().then(function(t) { throw new Error("HTTP "+r.status+": "+(t||r.statusText)); });
      return r.json().then(function(j) {
        if (j && j.ok === false) throw new Error(j.error && j.error.message || "rpc failed");
        return j && "payload" in j ? j.payload : j;
      });
    }).catch(function(err) {
      if (err && err.name === "AbortError") throw new Error("timeout after 8s");
      throw err;
    }).finally(function() {
      if (timeoutId) clearTimeout(timeoutId);
    });
  } // _w3 = '616e7869'

  function esc(s) {
    if (s == null) return "";
    return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
  }

  // Attribute-context escaping: also neutralizes quotes so a value injected
  // into a double-quoted attribute cannot break out and add new attributes
  // (e.g. value='x" autofocus onfocus="…'). Use escAttr for every dynamic
  // value inside a tag; esc is for text nodes only.
  function escAttr(s) {
    if (s == null) return "";
    return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;");
  }

  // ── Inline copy affordance for event JSON panes ────────────────────
  // 三态 SVG：默认 clipboard / 成功 check / 失败 alert。视觉与文案
  // 通过 setCopyIcon() 切 data-icon 与 aria-label，保持 keyboard + 屏幕阅读器
  // 同步；2s 自动回 idle 由 scheduleCopyReset() 守护，重复点击不会卡在某态。
  var COPY_ICON_PATHS = {
    copy:  "M8 2a2 2 0 0 0-2 2v.5H4a2 2 0 0 0-2 2v6a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2v-6a2 2 0 0 0-2-2h-2V4a2 2 0 0 0-2-2Zm0 1.5a.5.5 0 0 1 .5.5v1.5h-1V4a.5.5 0 0 1 .5-.5Z",
    check: "M13.78 4.22a.75.75 0 0 1 0 1.06l-7.25 7.25a.75.75 0 0 1-1.06 0L2.22 9.28a.751.751 0 0 1 .018-1.042.751.751 0 0 1 1.042-.018L6 10.94l6.72-6.72a.75.75 0 0 1 1.06 0Z",
    alert: "M6.457 1.047c.659-1.234 2.427-1.234 3.086 0l6.082 11.378A1.75 1.75 0 0 1 14.082 15H1.918a1.75 1.75 0 0 1-1.543-2.575Zm1.076.827a.25.25 0 0 0-.353 0L1.468 12.857a.25.25 0 0 0 .176.393h12.712a.25.25 0 0 0 .176-.393L8.357 1.874ZM8 5a.75.75 0 0 1 .75.75v2.5a.75.75 0 0 1-1.5 0v-2.5A.75.75 0 0 1 8 5Zm0 6a1 1 0 1 1 0-2 1 1 0 0 1 0 2Z"
  };
  var COPY_ICON_LABELS = {
    copy:  "Copy JSON",
    check: "Copied to clipboard.",
    alert: "Copy failed."
  };
  function makeCopyButton() {
    var path = COPY_ICON_PATHS.copy, label = COPY_ICON_LABELS.copy;
    return '<button type="button" class="copy-event" data-icon="copy" '
      + 'aria-label="'+escAttr(label)+'" title="'+escAttr(label)+'">'
      + '<svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true" focusable="false">'
      + '<path d="'+path+'" fill="currentColor"/></svg></button>';
  }
  function setCopyIcon(btn, slot, label) {
    btn.setAttribute("data-icon", slot);
    btn.setAttribute("aria-label", label);
    btn.setAttribute("title", label);
    var p = btn.querySelector("path");
    if (p) p.setAttribute("d", COPY_ICON_PATHS[slot]);
  }
  function scheduleCopyReset(btn, prevSlot) {
    if (btn.__copyTimer) clearTimeout(btn.__copyTimer);
    btn.__copyTimer = setTimeout(function() {
      // 只有没被新点击覆盖时才回 idle，避免快速双击把新 ok 状态冲掉。
      if (btn.getAttribute("data-icon") === prevSlot) setCopyIcon(btn, "copy", COPY_ICON_LABELS.copy);
    }, 2000);
  }
  function handleCopyEventJson(btn) {
    var pane = btn.closest && btn.closest(".json-pane");
    var pre = pane && pane.querySelector("pre.json-view");
    if (!pre) return;
    copyText(pre.textContent || "").then(function(ok) {
      if (ok) {
        setCopyIcon(btn, "check", COPY_ICON_LABELS.check);
        scheduleCopyReset(btn, "check");
      } else {
        setCopyIcon(btn, "alert", COPY_ICON_LABELS.alert);
        scheduleCopyReset(btn, "alert");
      }
    });
  }

  function ts(ms) {
    if (!ms) return "—";
    var d = new Date(ms);
    var pad = function(n) { return n < 10 ? "0"+n : n; };
    return d.getFullYear()+"-"+pad(d.getMonth()+1)+"-"+pad(d.getDate())+" "+pad(d.getHours())+":"+pad(d.getMinutes())+":"+pad(d.getSeconds());
  }

  function badge(cls, txt) { return '<span class="badge '+esc(cls)+'">'+esc(txt)+'</span>'; }

  // 决策类型 → 徽标样式。block 红、warn/audit/degrade 黄、
  // modify/substitute/context_adjust 蓝、allow 绿，未知类型回落到 change。
  function decisionBadgeClass(decision) {
    if (decision === "block") return "block";
    if (decision === "allow") return "allow";
    if (decision === "warn" || decision === "audit" || decision === "degrade") return "warn";
    return "change";
  }

  // severity 五档 → 徽标样式。
  // critical/extreme 红、high 橙、medium 黄、low 灰、unknown muted。
  // 来源优先级与后端 resolveEventSeverity 同口径，避免面板 / 后端漂移。
  function severityBadgeClass(sev) {
    if (sev === "critical" || sev === "extreme") return "block";
    if (sev === "high") return "warn";
    if (sev === "medium") return "change";
    if (sev === "low") return "muted";
    return "muted";
  }

  // 从事件上解析最高 severity（与后端 ControlUiService.resolveEventSeverity 同口径）。
  // 前端只在 Event Stream severity 列使用；Metrics / Policy Hits bySeverity 直接读后端聚合。
  function resolveEventSeverityClient(ev) {
    if (!ev) return null;
    var intervention = ev.intervention || {};
    var matched = intervention.matched_rules;
    if (Array.isArray(matched) && matched.length) {
      var rank = { low: 1, medium: 2, high: 3, critical: 4, extreme: 5 };
      var best = null, bestRank = 0;
      for (var i = 0; i < matched.length; i++) {
        var rl = matched[i] && matched[i].risk_level;
        if (typeof rl !== "string") continue;
        var r = rank[rl] || 0;
        if (r > bestRank) { bestRank = r; best = rl; }
      }
      if (best) return best;
    }
    if (typeof intervention.risk_level === "string") return intervention.risk_level;
    if (typeof ev.risk_level === "string" && ["low","medium","high","critical","extreme"].indexOf(ev.risk_level) >= 0) return ev.risk_level;
    if (typeof ev.severity === "string" && ["low","medium","high","critical","extreme"].indexOf(ev.severity) >= 0) return ev.severity;
    return null;
  }

  // appealable 是纯展示字段（方案 B，无在线申诉链路）。block 条目渲染
  // 只读 appealable 标注（弱化小字，非徽标），tooltip 带 remediationHint
  // （含 policyId 的复核指引：联系管理员复核 / 调整策略）；无 hint 时给缺省说明。
  function appealBadge(intervention) {
    if (!intervention || intervention.appealable !== true) return "";
    var hint = intervention.remediation_hint || "该阻断可联系管理员复核并调整策略（见事件 intervention.remediation_hint）";
    return ' <span class="appeal-tag" title="'+escAttr(hint)+'">appealable</span>';
  }

  function error(e) {
    return '<div class="error">⚠ '+esc(e && e.message ? e.message : e)+'</div>';
  }

  // Clipboard helpers for the "访问官网" fallback. Sandboxed iframes
  // (no allow-same-origin) may reject navigator.clipboard, so fall back to a
  // transient textarea + execCommand.
  function legacyCopy(text) {
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    var ok = false;
    try { ok = document.execCommand("copy"); } catch (err) { ok = false; }
    document.body.removeChild(ta);
    return ok;
  }
  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text).then(function() { return true; }, function() { return legacyCopy(text); });
    }
    return Promise.resolve(legacyCopy(text));
  }

  // Transient toast near the bottom of the viewport; auto-hides.
  var toastTimer = null;
  function toast(msg) {
    var el = document.getElementById("toast");
    if (!el) return;
    el.textContent = msg;
    el.style.display = "block";
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(function() { el.style.display = "none"; }, 3000);
  }

  // ── Metrics ──────────────────────────────────────────────────────────
  // 页脚对外入口（访问官网 / 关注公众号）由 renderMetrics 输出，
  // 因此只在 Metrics 页签出现，切走页签自然消失；错误/空态分支同样输出。
  function renderMetrics(d) {
    var footer = '<div class="metrics-footer">'+
      '<a id="open-website" href="'+escAttr(WEBSITE_URL)+'" target="_blank" rel="noopener noreferrer">访问官网</a>'+
      '<a id="show-qr" href="#">关注公众号</a>'+
      '</div>';
    if (d == null) return '<div class="error">No data</div>'+footer;
    var m = d.metrics || d;
    var blocks = m.blocks || m.blockCount || 0;
    var threats = m.threats || 0;
    var total = m.total || m.eventCount || 0;
    var last24 = m.last24h || 0;
    var byLayer = m.byLayer || {};
    // 面板分级消费要求 severity × decision 双重维度。后端
    // MetricsResult 同时返回 bySeverity 与 byDecision（O(1) 聚合），此处
    // 仅做展示 + 排序（critical → low + unknown 兜底）。
    var bySeverity = m.bySeverity || {};
    var byDecision = m.byDecision || {};
    var layerRows = Object.keys(byLayer).map(function(k) {
      return '<div class="meta">'+esc(k)+': <span class="hl">'+esc(byLayer[k])+'</span></div>';
    }).join("");
    // severity 固定顺序，避免聚合键迭代顺序漂移。
    var severityOrder = ["critical", "extreme", "high", "medium", "low"];
    var severityRows = severityOrder
      .filter(function(k) { return (bySeverity[k] || 0) > 0; })
      .map(function(k) {
        return '<div class="meta">'+badge(severityBadgeClass(k), k)+' <span class="hl">'+esc(bySeverity[k])+'</span></div>';
      }).join("");
    if ((bySeverity.unknown || 0) > 0) {
      severityRows += '<div class="meta"><span class="muted">unknown</span> <span class="hl">'+esc(bySeverity.unknown)+'</span></div>';
    }
    // decision 排序按阈值降序（最严重在前），稳定顺序——后端 byDecision 已含全集。
    var decisionOrder = ["block", "warn", "modify", "audit", "substitute", "context_adjust", "degrade"];
    var decisionRows = decisionOrder
      .filter(function(k) { return (byDecision[k] || 0) > 0; })
      .map(function(k) {
        return '<div class="meta">'+badge(decisionBadgeClass(k), k)+' <span class="hl">'+esc(byDecision[k])+'</span></div>';
      }).join("");
    // cell(value, label, kind): emit a metric tile. value === 0 gets the muted
    // .zero modifier so an idle counter doesn't visually dominate. kind ("alert"/"warn")
    // only fires when value > 0, so 0-block / 0-modify tiles aren't red/yellow.
    function cell(value, label, kind) {
      var cls = "metric";
      if (value === 0) cls += " zero";
      else if (kind === "alert" || kind === "warn") cls += " " + kind;
      return '<div class="'+cls+'"><div class="val">'+esc(value)+'</div><div class="lbl">'+esc(label)+'</div></div>';
    }
    return '<div class="metrics">'+
      cell(total, "Total events")+
      cell(last24, "Last 24h")+
      cell(blocks, "Blocked", "alert")+
      cell(threats, "Threat Events", "warn")+
      (layerRows ? '<div class="card" style="grid-column:1/-1"><h2>By Layer</h2>'+layerRows+'</div>' : '')+
      '</div>'+footer;
  }

  // ── Events ─────────────────────────────────────────────────────────
  // 表格 6 列 → 7 列（Time/Type/Layer/Severity/Agent/Tool/Status）。
  // Severity 列与 Status 列互不替代：Severity 表达策略威胁等级（critical 红 → low 灰），
  // Status 表达最终决策（block/warn/audit 等）。两条都可独立读。
  // 拆为 renderEventsTable（仅骨架，含 #events-body 用于 append）与
  // renderEventsRows（rows + startIdx → 行片段）两段，让 Load More 走
  // append-only 路径与 Policy Hits 一致：避免重复 <thead>、data-event-idx
  // 撞 id 导致 click 委托 selector 命中错行。
  function renderEventsTable() {
    return '<table><thead><tr><th>Time</th><th>Type</th><th>Layer</th><th>Severity</th><th>Agent</th><th>Tool/Session</th><th>Status</th></tr></thead><tbody id="events-body"></tbody></table>';
  }

  function renderEventsRows(rows, startIdx) {
    if (!rows.length) return "";
    var html = "";
    rows.forEach(function(r, i) {
      var idx = startIdx + i;
      var intervention = r.intervention;
      var decision = intervention ? intervention.decision : null;
      // 全决策类型徽标（原实现只区分 block/allow，warn/modify 等
      // 一律显示 allow 绿色，语义误导）；block 且 appealable 时追加弱化标注。
      var decisionBadge = decision ? badge(decisionBadgeClass(decision), decision) : "";
      if (decision === "block") decisionBadge += appealBadge(intervention);
      var eventType = r.event_type || r.eventType || "";
      // 采集端 canonical 字段是 cmdline（command_line 已废弃），缺 tool_name 时
      // 以命令行摘要填充，否则 process_start 行整列只剩 "—"。
      var cmdline = r.cmdline || r.command_line;
      var toolName = esc(r.tool_name || r.toolName || (cmdline ? cmdline.slice(0,40) : "—"));
      var session = esc(r.session_id || r.sessionId || "—");
      // Severity 列。无 severity 的事件（罕见——cgroup_anomaly 已有，非干预类
      // 事件无 severity）显示 muted —，避免空单元格。
      var sev = resolveEventSeverityClient(r);
      var sevCell = sev ? badge(severityBadgeClass(sev), sev) : '<span class="muted">—</span>';
      var rawJson = esc(JSON.stringify(r, null, 2));
      html += '<tr class="event-row" data-event-idx="'+idx+'">'+
        '<td class="ts">'+ts(r.ts)+'</td>'+
        '<td><span class="tool">'+esc(eventType)+'</span></td>'+
        '<td>'+esc(r.layer || "")+'</td>'+
        '<td>'+sevCell+'</td>'+
        '<td>'+esc(r.agent_id || r.agentId || "—")+'</td>'+
        '<td><span class="tool">'+toolName+'</span><div class="meta">'+session+'</div></td>'+
        '<td>'+decisionBadge+'</td>'+
        '</tr>'+
        '<tr class="event-detail" data-detail-idx="'+idx+'"><td colspan="7">'+
          '<div class="json-pane">'+
            '<div class="json-pane-header">'+
              '<div class="json-pane-title">Event JSON</div>'+
              makeCopyButton()+
            '</div>'+
            '<pre class="json-view">'+rawJson+'</pre>'+
          '</div>'+
        '</td></tr>';
    });
    return html;
  }

  // ── Policy Hits state + paging ────────────────────────────────────
  function buildBlocksShell() {
    var pauseBanner = '<div id="detail-paused-banner" style="display:none;background:var(--warn);color:#000;padding:6px 10px;border-radius:4px;margin-bottom:8px;font-size:12px">⏸ 有展开的事件详情，自动刷新已暂停（收起详情行后恢复）</div>';
    return pauseBanner+
      '<div id="blocks-table"><div class="spinner">Loading...</div></div>'+
      '<div id="blocks-footer"></div>';
  }

  function loadBlocks(reset) {
    if (blocksState.busy) return;
    blocksState.busy = true;
    if (reset) {
      blocksState.offset = 0;
      blocksState.allHits = [];
    }
    var params = { limit: blocksState.limit, offset: blocksState.offset };
    rpc("security.policy.hits", params).then(function(d) {
      var rows = Array.isArray(d) ? d : (d && d.hits ? d.hits : []);
      var byDecision = (d && d.byDecision) ? d.byDecision : null;
      // 累加到 allHits，使 renderBlocksBody 可独立重渲（胶囊切换不重发 RPC）。
      for (var ri = 0; ri < rows.length; ri++) blocksState.allHits.push(rows[ri]);
      blocksState.total = (d && typeof d.total === "number") ? d.total : blocksState.allHits.length;
      var tableArea = document.getElementById("blocks-table");
      var footerArea = document.getElementById("blocks-footer");
      if (reset) {
        // 胶囊筛选条（all/block/warn/modify/audit），客户端过滤不发新 RPC。
        // 计数从 byDecision 读取：all = 全 decision 之和；其余取该 decision 计数（无则 0）。
        var totalCount = byDecision ? Object.values(byDecision).reduce(function(a, b) { return a + b; }, 0) : 0;
        var capsuleDefs = [
          { key: "all", label: "all", count: totalCount, cls: "allow" },
          { key: "block", label: "block", count: (byDecision && byDecision.block) || 0, cls: "block" },
          { key: "warn", label: "warn", count: (byDecision && byDecision.warn) || 0, cls: "warn" },
          { key: "modify", label: "modify", count: (byDecision && byDecision.modify) || 0, cls: "change" },
          { key: "audit", label: "audit", count: (byDecision && byDecision.audit) || 0, cls: "warn" },
        ];
        var capsuleHtml = capsuleDefs.map(function(c) {
          var active = blocksState.filter === c.key ? " active" : "";
          return '<span class="capsule '+esc(c.cls)+active+'" data-capsule="'+esc(c.key)+'">'+esc(c.label)+' <span class="count">'+esc(c.count)+'</span></span>';
        }).join("");
        tableArea.innerHTML = '<div class="capsule-row">'+capsuleHtml+'</div>'+
          '<table><thead><tr><th>Time</th><th>Tool</th><th>Decision</th><th>Policy</th><th>Reason</th></tr></thead><tbody id="blocks-body"></tbody></table>';
        // 胶囊点击事件委托：仅切本地 filter，重渲染当前已加载 hits，不发新 RPC。
        var capsuleEls = tableArea.querySelectorAll("[data-capsule]");
        for (var ci = 0; ci < capsuleEls.length; ci++) {
          capsuleEls[ci].onclick = function(e) {
            var key = e.currentTarget.getAttribute("data-capsule");
            if (!key || key === blocksState.filter) return;
            blocksState.filter = key;
            writePolicyHitsFilter(key);
            // 重渲：胶囊条状态切换 + 重过滤 tbody
            var newCapsuleEls = tableArea.querySelectorAll("[data-capsule]");
            for (var k = 0; k < newCapsuleEls.length; k++) {
              var isActive = newCapsuleEls[k].getAttribute("data-capsule") === key;
              if (isActive) newCapsuleEls[k].className += " active";
              else newCapsuleEls[k].className = newCapsuleEls[k].className.replace(/ active\b/g, "");
            }
            renderBlocksBody();
          };
        }
      }
      // 行渲染从工具函数执行：胶囊过滤改变时仅重渲 tbody，不重置 offset / total。
      renderBlocksBody();
      blocksState.offset += rows.length;
      var shown = blocksState.offset;
      var total = blocksState.total;
      var more = blocksState.offset < blocksState.total
        ? '<button id="blocks-more">Load more</button>'
        : '<span class="meta">end of results</span>';
      footerArea.innerHTML = '<span class="meta">Showing '+shown+' of '+total+' hits</span> '+more;
      var moreBtn = document.getElementById("blocks-more");
      if (moreBtn) moreBtn.onclick = function() { loadBlocks(false); };
    }).catch(function(err) {
      var tableArea = document.getElementById("blocks-table");
      if (tableArea) tableArea.innerHTML = error(err);
    }).then(function() { blocksState.busy = false; });
  }

  // 渲染 Policy Hits tbody 行（含客户端 filter 应用 + Reason fallback）。
  // 抽取为工具函数使胶囊切换时仅重渲 tbody，不重发 RPC。
  // Reason 列字段优先级：intervention.block_reason（block 用）→ intervention.reason（warn/audit/modify）
  //   → "—"——后端返回全决策，warn/audit/modify 不再显示 "—"，避免信息丢失。
  function renderBlocksBody() {
    var tbody = document.getElementById("blocks-body");
    if (!tbody) return;
    tbody.innerHTML = "";
    var filter = blocksState.filter;
    var matched = filter === "all" ? blocksState.allHits : (blocksState.allHits || []).filter(function(r) {
      var d = r.intervention && r.intervention.decision;
      return d === filter;
    });
    matched.forEach(function(r, idx) {
      var intervention = r.intervention;
      var decision = intervention && intervention.decision ? intervention.decision : (r.decision || "—");
      var policyId = intervention && intervention.policy_id ? intervention.policy_id : (r.policy_id || "—");
      // Reason 列双源 fallback。
      var reasonText = intervention && intervention.block_reason
        ? intervention.block_reason
        : (intervention && intervention.reason ? intervention.reason : "—");
      var decisionBadge = badge(decisionBadgeClass(decision), decision);
      if (decision === "block") decisionBadge += appealBadge(intervention);
      var rawJson = esc(JSON.stringify(r, null, 2));
      var tr = document.createElement("tr");
      tr.className = "event-row";
      tr.dataset.eventIdx = idx;
      tr.innerHTML =
        '<td class="ts">'+ts(r.ts)+'</td>'+
        '<td><span class="tool">'+esc(r.tool_name || r.toolName || "—")+'</span></td>'+
        '<td>'+decisionBadge+'</td>'+
        '<td><span class="tool">'+esc(policyId)+'</span></td>'+
        '<td style="max-width:300px;word-break:break-word">'+esc(reasonText)+'</td>';
      var detailTr = document.createElement("tr");
      detailTr.className = "event-detail";
      detailTr.dataset.detailIdx = idx;
      detailTr.innerHTML = '<td colspan="5">'+
        '<div class="json-pane">'+
          '<div class="json-pane-header">'+
            '<div class="json-pane-title">Event JSON</div>'+
            makeCopyButton()+
          '</div>'+
          '<pre class="json-view">'+rawJson+'</pre>'+
        '</div>'+
      '</td>';
      tbody.appendChild(tr);
      tbody.appendChild(detailTr);
    });
  }

  function renderBlocks(d) {
    var rows = Array.isArray(d) ? d : (d && d.hits ? d.hits : []);
    var byDecision = (d && d.byDecision) ? d.byDecision : null;
    if (!rows.length && (!byDecision || !Object.keys(byDecision).length)) return '<div class="empty">No policy hits yet</div>';
    var summary = "";
    if (byDecision && Object.keys(byDecision).length) {
      summary = '<div class="toolbar" style="margin-bottom:8px">'+
        Object.keys(byDecision).map(function(k) {
          return badge(decisionBadgeClass(k), k+" "+byDecision[k]);
        }).join(" ")+
        '</div>';
    }
    var html = summary+'<table><thead><tr><th>Time</th><th>Tool</th><th>Decision</th><th>Policy</th><th>Reason</th></tr></thead><tbody>';
    rows.forEach(function(r, idx) {
      var intervention = r.intervention;
      var decision = intervention && intervention.decision ? intervention.decision : (r.decision || "—");
      var policyId = intervention && intervention.policy_id ? intervention.policy_id : (r.policy_id || "—");
      // Reason 列双源 fallback，与 renderBlocksBody 保持一致。
      var reasonText = intervention && intervention.block_reason
        ? intervention.block_reason
        : (intervention && intervention.reason ? intervention.reason : "—");
      var decisionBadge = badge(decisionBadgeClass(decision), decision);
      if (decision === "block") decisionBadge += appealBadge(intervention);
      var rawJson = esc(JSON.stringify(r, null, 2));
      html += '<tr class="event-row" data-event-idx="'+idx+'">'+
        '<td class="ts">'+ts(r.ts)+'</td>'+
        '<td><span class="tool">'+esc(r.tool_name || r.toolName || "—")+'</span></td>'+
        '<td>'+decisionBadge+'</td>'+
        '<td><span class="tool">'+esc(policyId)+'</span></td>'+
        '<td style="max-width:300px;word-break:break-word">'+esc(reasonText)+'</td>'+
        '</tr>'+
        '<tr class="event-detail" data-detail-idx="'+idx+'"><td colspan="5">'+
          '<div class="json-pane">'+
            '<div class="json-pane-header">'+
              '<div class="json-pane-title">Event JSON</div>'+
              makeCopyButton()+
            '</div>'+
            '<pre class="json-view">'+rawJson+'</pre>'+
          '</div>'+
        '</td></tr>';
    });
    html += '</tbody></table>';
    return html;
  }

  // ── Config editor (form-based) ─────────────────────────────────────
  // Group keys by top-level namespace, render flat rows. The host owns the
  // config store; we surface the values bootstrap merged in so the operator
  // can verify defaults actually landed (esp. after ensureHostPluginEntryDefaults).
  // Q2 form-based Config editor. Reads d.config (full merged config) and
  // d.schema (CONFIG_SCHEMA echoed back from the server). Renders one
  // fieldset per section, one input per field. Save / Reset / Copy JSON
  // buttons live at the bottom. The danger confirmation modal lives in the
  // markup too — doSave() shows it when the server answers a danger save with
  // a one-time confirmToken (client-declared confirmDanger alone no longer
  // executes dangerous patches).
  function renderConfig(d) {
    if (d == null) return '<div class="error">No config</div>';
    var config = (d && d.config) || {};
    var schema = (d && d.schema) || [];

    // Group fields by section while preserving schema order. Hidden fields
    // stay in the schema (so security.config.save still validates hand-
    // edited values from openclaw.json) but are filtered out of the form.
    var grouped = {};
    var sectionOrder = [];
    schema.forEach(function(f) {
      if (f.hidden) return;
      if (!grouped[f.section]) { grouped[f.section] = []; sectionOrder.push(f.section); }
      grouped[f.section].push(f);
    });

    var sectionTitles = {
      collector: "Collector",
      application: "Application",
      network: "Network",
      system: "System",
      intervention: "Intervention",
      assetMonitor: "Asset Monitor",
      bootstrap: "Bootstrap",
    };

    function readNested(obj, dotKey) {
      var parts = dotKey.split(".");
      var cur = obj;
      for (var i = 0; i < parts.length; i++) {
        if (cur == null || typeof cur !== "object") return undefined;
        cur = cur[parts[i]];
      }
      return cur;
    }

    function inputHtml(f, sectionVal) {
      var v = readNested(sectionVal, f.key);
      var id = 'cfg-' + f.section + '-' + f.key.replace(/\./g, '-');

      // Resolve dependsOn: when the dependency is unmet, render the input
      // disabled (no user edits, no collectPatch) and show an inline hint
      // explaining what's missing. Avoids the "parent off but child reads on"
      // UX trap for sub-toggles like runtimeHooks.networkEnabled. dependsOn
      // may be a single object or an array (ALL deps must be satisfied — e.g.
      // procfs.pythonPath needs system.enabled AND procfs.enabled).
      var depHtml = '';
      var disabledAttr = '';
      if (f.dependsOn) {
        var deps = Array.isArray(f.dependsOn) ? f.dependsOn : [f.dependsOn];
        var unmetDeps = [];
        for (var di = 0; di < deps.length; di++) {
          var depVal = readNested(sectionVal, deps[di].key);
          var wantVal = deps[di].value !== undefined ? deps[di].value : true;
          if (depVal !== wantVal) unmetDeps.push(deps[di]);
        }
        if (unmetDeps.length > 0) {
          disabledAttr = ' disabled';
          depHtml = '<div class="meta" style="color:var(--muted);margin-top:2px">ⓘ 需先启用 '+
            unmetDeps.map(function(d) { return '<code>'+esc(d.section+'.'+d.key)+'</code>'; }).join(' 和 ')+
            '</div>';
        }
      }

      var dangerAttr = f.danger ? ' data-danger="1" data-danger-reason="'+escAttr(f.dangerReason || '')+'"' : '';
      var dangerMark = f.danger ? ' <span style="color:var(--danger);font-size:10px">⚠ danger</span>' : '';
      var helpHtml = f.danger && f.dangerReason
        ? '<div class="meta" style="color:var(--danger);margin-top:2px">⚠ '+esc(f.dangerReason)+'</div>'
        : '';
      var helpBlockHtml = f.help
        ? '<div class="meta" style="color:var(--warn);margin-top:6px;white-space:pre-wrap;font-size:11px;line-height:1.5">'+esc(f.help)+'</div>'
        : '';
      var input = '';
      if (f.type === "bool") {
        var checked = v === true ? ' checked' : '';
        input = '<label style="display:inline-flex;align-items:center;gap:6px;cursor:'+(disabledAttr ? 'not-allowed' : 'pointer')+';line-height:1.6;opacity:'+(disabledAttr ? '0.5' : '1')+'">'+
          '<input type="checkbox" id="'+id+'" data-section="'+escAttr(f.section)+'" data-key="'+escAttr(f.key)+'" data-type="bool"'+checked+disabledAttr+dangerAttr+' style="margin:0;flex:none"/>'+
          '<span class="'+(v?'ok':'warn')+'">'+(v?'on':'off')+'</span></label>';
      } else if (f.type === "number") {
        var numVal = (typeof v === "number") ? v : '';
        var minAttr = f.min !== undefined ? ' min="'+f.min+'"' : '';
        var maxAttr = f.max !== undefined ? ' max="'+f.max+'"' : '';
        input = '<input type="number" id="'+id+'" data-section="'+escAttr(f.section)+'" data-key="'+escAttr(f.key)+'" data-type="number" value="'+escAttr(String(numVal))+'"'+minAttr+maxAttr+disabledAttr+' step="1" style="width:160px'+ (disabledAttr ? ';opacity:0.5' : '') +'"'+dangerAttr+'/>';
      } else if (f.type === "enum") {
        var opts = (f.values || []).map(function(opt) {
          var sel = (v === opt) ? ' selected' : '';
          return '<option value="'+escAttr(opt)+'"'+sel+'>'+esc(opt)+'</option>';
        }).join("");
        input = '<select id="'+id+'" data-section="'+escAttr(f.section)+'" data-key="'+escAttr(f.key)+'" data-type="enum" style="width:160px'+ (disabledAttr ? ';opacity:0.5' : '') +'"'+disabledAttr+dangerAttr+'>'+opts+'</select>';
      } else {
        var sVal = (typeof v === "string") ? v : '';
        input = '<input type="text" id="'+id+'" data-section="'+escAttr(f.section)+'" data-key="'+escAttr(f.key)+'" data-type="string" value="'+escAttr(sVal)+'"'+disabledAttr+' style="width:280px;font-family:monospace'+ (disabledAttr ? ';opacity:0.5' : '') +'"'+dangerAttr+'/>';
      }
      return '<div style="display:flex;align-items:flex-start;gap:12px;padding:6px 0;border-bottom:1px solid var(--border)">'+
        '<div style="flex:0 0 200px"><span class="tool">'+esc(f.label)+dangerMark+'</span><div class="meta">'+esc(f.section+'.'+f.key)+'</div></div>'+
        '<div style="flex:1">'+input+helpHtml+helpBlockHtml+depHtml+'</div></div>';
    }

    var sectionsHtml = sectionOrder.map(function(sec) {
      var fields = grouped[sec];
      var sectionVal = config[sec] || {};
      // advanced 字段收进 section 内二级折叠区（默认折叠），普通字段直接列出。
      var visibleFields = fields.filter(function(f) { return !f.advanced; });
      var advancedFields = fields.filter(function(f) { return !!f.advanced; });
      var body = visibleFields.map(function(f) { return inputHtml(f, sectionVal); }).join("");
      if (advancedFields.length > 0) {
        body += '<details style="margin:8px 0 2px;border:1px dashed var(--border);border-radius:4px;padding:4px 10px 6px">'+
          '<summary style="cursor:pointer;font-size:12px" class="meta">高级（'+advancedFields.length+' 项调优参数，默认不必改动）▾</summary>'+
          advancedFields.map(function(f) { return inputHtml(f, sectionVal); }).join("")+
          '</details>';
      }
      return '<details class="card" open style="margin-bottom:8px"><summary style="cursor:pointer"><h2 style="display:inline">'+esc(sectionTitles[sec] || sec)+'</h2> <span class="meta">('+fields.length+' 项)</span></summary>'+
        '<form id="config-form" data-section="'+escAttr(sec)+'" autocomplete="off">'+
        body+
        '</form></details>';
    }).join("");

    var html =
      '<div id="config-dirty-bar" style="display:none;background:var(--warn);color:#000;padding:6px 10px;border-radius:4px;margin-bottom:8px;font-size:12px"></div>'+
      '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">'+
        '<span class="meta">编辑后点击保存，重启 gateway 后生效。源: plugins.entries[id].config (DEFAULT_CONFIG × 用户 openclaw.json)</span>'+
        '<div style="display:flex;gap:6px">'+
          '<button type="button" id="reset-config" title="丢弃本地编辑，重新从服务器加载当前配置（不会恢复默认值）">撤销更改</button>'+
          '<button type="button" id="copy-config">Copy JSON</button>'+
          '<button type="button" id="save-config" style="background:var(--accent)">保存</button>'+
        '</div>'+
      '</div>'+
      sectionsHtml+
      '<pre id="copy-source" style="display:none">'+esc(JSON.stringify(config, null, 2))+'</pre>'+

      // Danger confirmation modal (L3). Hidden by default; saveConfig() shows
      // it when any changed field has danger:true.
      '<div id="danger-modal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:1000;align-items:center;justify-content:center">'+
        '<div style="background:var(--card-bg);border:1px solid var(--danger);border-radius:8px;padding:20px;max-width:520px;width:90%">'+
          '<h3 style="color:var(--danger);margin-bottom:12px">⚠ 危险操作确认</h3>'+
          '<div id="danger-modal-body" style="margin-bottom:12px;font-size:12px"></div>'+
          '<label style="display:block;margin-bottom:12px;cursor:pointer;line-height:1.6">'+
            '<input type="checkbox" id="danger-confirm" style="margin:0 6px 0 0;vertical-align:middle"/>'+
            '<span style="font-size:12px;vertical-align:middle">我已确认上述变更的影响，仍要保存</span>'+
          '</label>'+
          '<div style="display:flex;gap:8px;justify-content:flex-end">'+
            '<button type="button" id="danger-cancel">取消</button>'+
            '<button type="button" id="danger-ok" disabled>确认保存</button>'+
          '</div>'+
        '</div>'+
      '</div>';

    return html;
  }

  // ── Config save flow ──────────────────────────────────────────────────
  // Snapshot of the config currently shown in the form; used by saveConfig()
  // to diff the form values against what came from the server. Updated every
  // time renderConfig() runs, and once more after a successful save so the
  // next diff compares against the on-disk state (otherwise render() would
  // re-fetch the pre-save in-memory snapshot and the form would visibly snap
  // back to the old values).
  var __lastConfig = {};

  function readNestedConfig(obj, dotKey) {
    var parts = dotKey.split(".");
    var cur = obj;
    for (var i = 0; i < parts.length; i++) {
      if (cur == null || typeof cur !== "object") return undefined;
      cur = cur[parts[i]];
    }
    return cur;
  }

  // In-place nested merge for the applied-patch echo from security.config.save.
  // Matches the server-side deep merge semantics in saveHostConfigPatch so the
  // local __lastConfig stays byte-equivalent to what is now on disk.
  function deepMergeInPlace(target, source) {
    for (var k in source) {
      if (!Object.prototype.hasOwnProperty.call(source, k)) continue;
      var sv = source[k];
      var tv = target[k];
      if (sv && typeof sv === "object" && !Array.isArray(sv) &&
          tv && typeof tv === "object" && !Array.isArray(tv)) {
        deepMergeInPlace(tv, sv);
      } else {
        target[k] = sv;
      }
    }
    return target;
  }

  function readInputValue(input) {
    var type = input.getAttribute("data-type");
    if (type === "bool") return !!input.checked;
    if (type === "number") {
      var n = parseFloat(input.value);
      return isNaN(n) ? null : n;
    }
    // enum (intervention.mode / intervention.failStrategy) and string both
    // surface via <select> / <input type=text>. Trim to defend against
    // devtools-injected whitespace or paste-trailing-space that would make
    // the value differ from the schema enum on save (validateConfigPatch
    // rejects values outside f.values). Coerce unknown enum candidates to
    // the closest match (preserves the previous "raw input.value" behaviour
    // for strings while making enums predictable).
    if (type === "enum") {
      var v = String(input.value || "").trim();
      return v === "" ? "" : v;
    }
    return input.value;
  }

  // ── Config dirty tracking ──────────────────────────────────────────
  // While the user is editing Config, the 30s auto-refresh must NOT clobber
  // their in-progress input. We compare each input against __lastConfig;
  // while any field differs, render() skips the Config tab and a banner
  // makes the pause visible. The flag is recomputed from DOM after every
  // render() so reset-config / save success / tab switch can't leave it
  // stale (which would either wedge the auto-refresh in paused state or
  // flash the dirty banner for one tick on a clean form).
  var __configDirty = false;
  // Event Stream / Policy Hits 详情展开时同样暂停自动刷新，避免 30s tick 把
  // 用户正在查看的 JSON 行冲掉。每个 render() 入口从 DOM 同步一次真值，
  // 防止 Apply / Load More 重建表格后标志停留在 true。
  var __detailOpen = false;

  function isConfigDirty() {
    var inputs = document.querySelectorAll("#panel [data-section][data-key]");
    for (var i = 0; i < inputs.length; i++) {
      var input = inputs[i];
      var section = input.getAttribute("data-section");
      var key = input.getAttribute("data-key");
      // Schema fields added in a newer plugin version may not yet exist in
      // __lastConfig (e.g. user updated plugin but hasn't saved). Treat
      // missing as 'undefined' so a populated input is correctly detected
      // as dirty instead of always-false.
      var orig = readNestedConfig((__lastConfig && __lastConfig[section]) || {}, key);
      // 清空的 number 输入框视为未修改（回退到当前生效值），
      // 不提交 null——服务端必填校验会拒绝 null，保留其语义不变。
      var cur = readInputValue(input);
      if (cur === null && input.getAttribute("data-type") === "number") cur = orig;
      // Normalise undefined / null so JSON.stringify compares apples to
      // apples (otherwise 'undefined' !== 'true' is always true and the
      // banner would flash on the very first render after a schema bump).
      if (cur === undefined) cur = null;
      if (orig === undefined) orig = null;
      if (JSON.stringify(cur) !== JSON.stringify(orig)) return true;
    }
    return false;
  }

  function updateConfigDirtyBar() {
    var bar = document.getElementById("config-dirty-bar");
    if (!bar) return;
    __configDirty = isConfigDirty();
    bar.style.display = __configDirty ? "block" : "none";
    if (__configDirty) bar.textContent = "● 有未保存改动，自动刷新已暂停（保存或撤销更改后恢复）";
  }

  function collectPatch() {
    var patch = {};
    var changed = [];
    var inputs = document.querySelectorAll("#panel [data-section][data-key]");
    for (var i = 0; i < inputs.length; i++) {
      var input = inputs[i];
      var section = input.getAttribute("data-section");
      var key = input.getAttribute("data-key");
      var orig = readNestedConfig((__lastConfig && __lastConfig[section]) || {}, key);
      // 清空的 number 输入框按未修改处理（回退到当前生效值），不提交 null。
      var cur = readInputValue(input);
      if (cur === null && input.getAttribute("data-type") === "number") cur = orig;
      // New schema fields: orig === undefined means the field didn't exist
      // in the last saved config (e.g. user upgraded plugin and the new
      // version exposes a knob). Treat undefined as null for the comparison
      // so a populated input always lands in the patch, and surface the
      // from-value as 'null' (not undefined) so JSON.stringify round-trips
      // cleanly for the danger modal preview.
      var cmpOrig = orig === undefined ? null : orig;
      var cmpCur = cur === undefined ? null : cur;
      if (JSON.stringify(cmpCur) !== JSON.stringify(cmpOrig)) {
        if (!patch[section]) patch[section] = {};
        patch[section][key] = cur;
        changed.push({
          section: section, key: key,
          from: cmpOrig, to: cur,
          danger: input.getAttribute("data-danger") === "1",
          dangerReason: input.getAttribute("data-danger-reason") || "",
        });
      }
    }
    return { patch: patch, changed: changed };
  }

  function showRestartNotice(res) {
    var n = document.createElement("div");
    n.style.cssText = "position:fixed;top:20px;right:20px;background:var(--card-bg);border:1px solid var(--success);border-radius:6px;padding:12px;max-width:420px;z-index:1001;font-size:12px;box-shadow:0 4px 12px rgba(0,0,0,.4)";
    n.innerHTML =
      '<strong style="color:var(--success)">✓ 配置已写入磁盘</strong><br>' +
      '<span class="meta">备份: '+esc(res.backup || "无")+'</span><br>' +
      '<span style="color:var(--warn)">⚠ 需重启 gateway 后生效</span>';
    document.body.appendChild(n);
    setTimeout(function() { if (n.parentNode) n.parentNode.removeChild(n); }, 8000);
  }

  // Surfaces fields the bootstrap pipeline will clamp to false after restart
  // (NODE_OPTIONS missing → runtime hooks off, psutil missing → system layer
  // off, ...). Without this banner users would only see the warning in
  // gateway logs and assume the toggle "didn't take".
  function showBootstrapReportBanner(forcedDisabled) {
    var n = document.createElement("div");
    n.style.cssText = "position:fixed;top:96px;right:20px;background:var(--card-bg);border:1px solid var(--warn);border-radius:6px;padding:12px;max-width:520px;z-index:1001;font-size:12px;box-shadow:0 4px 12px rgba(0,0,0,.4)";
    var items = forcedDisabled.map(function(d) {
      return '<li style="margin-bottom:6px"><code style="font-family:monospace;color:var(--warn)">'+esc(d.path)+'</code>: ' +
        esc(d.reason) + '</li>';
    }).join("");
    n.innerHTML =
      '<strong style="color:var(--warn)">⚠ 重启 gateway 后以下项会被自动关闭</strong><br>' +
      '<span class="meta">原因：宿主环境不满足前置条件（如 NODE_OPTIONS 未引用 runtime hook / Python 缺 psutil）</span>' +
      '<ul style="margin:8px 0 6px;padding-left:20px">'+items+'</ul>' +
      '<span class="meta">完整诊断：宿主 OpenClaw 日志中的 bootstrap complete 行（容器部署用 <code>docker logs &lt;容器名&gt;</code> 查看）</span>';
    document.body.appendChild(n);
    setTimeout(function() { if (n.parentNode) n.parentNode.removeChild(n); }, 15000);
  }

  // Save-response warnings (unknown keys accepted into openclaw.json, empty
  // system layer, ...). Distinct from the bootstrap banner below it so both
  // stay readable when they fire on the same save.
  function showSaveWarningsBanner(warnings) {
    var n = document.createElement("div");
    n.style.cssText = "position:fixed;top:172px;right:20px;background:var(--card-bg);border:1px solid var(--warn);border-radius:6px;padding:12px;max-width:520px;z-index:1001;font-size:12px;box-shadow:0 4px 12px rgba(0,0,0,.4)";
    var items = warnings.map(function(w) {
      return '<li style="margin-bottom:6px"><code style="font-family:monospace;color:var(--warn)">'+esc(w.path)+'</code>: ' +
        esc(w.message) + '</li>';
    }).join("");
    n.innerHTML =
      '<strong style="color:var(--warn)">⚠ 配置已保存，请注意以下提示</strong>' +
      '<ul style="margin:8px 0 6px;padding-left:20px">'+items+'</ul>';
    document.body.appendChild(n);
    setTimeout(function() { if (n.parentNode) n.parentNode.removeChild(n); }, 15000);
  }

  // Render the danger confirmation modal. dangerList is the client-side list
  // of changed danger fields (rich from/to rendering); serverFields is the
  // fallback when the server flagged fields the client schema doesn't know.
  // confirmToken is the server-issued one-time token that the retry after
  // "确认保存" must carry — the client can no longer self-declare confirmation.
  function openDangerModal(patch, dangerList, confirmToken, serverFields) {
    var body = document.getElementById("danger-modal-body");
    if (body) {
      var rows = (dangerList || []).map(function(d) {
        return '<li style="margin-bottom:8px">' +
          '<strong>' + esc(d.section + "." + d.key) + '</strong>: ' +
          '<span class="meta">' + esc(JSON.stringify(d.from)) + '</span> → ' +
          '<strong style="color:var(--accent)">' + esc(JSON.stringify(d.to)) + '</strong>' +
          (d.dangerReason ? '<br><span style="color:var(--danger);font-size:11px">⚠ '+esc(d.dangerReason)+'</span>' : '') +
          '</li>';
      });
      if (rows.length === 0 && serverFields && serverFields.length) {
        rows = serverFields.map(function(f) {
          return '<li style="margin-bottom:8px"><strong>' + esc(f) + '</strong></li>';
        });
      }
      body.innerHTML =
        '<p style="margin-bottom:8px">以下变更涉及关键参数，保存前请确认：</p>' +
        '<ul style="margin:0;padding-left:18px">' + rows.join("") + '</ul>';
    }
    var confirmBox = document.getElementById("danger-confirm");
    var okBtn = document.getElementById("danger-ok");
    if (confirmBox) confirmBox.checked = false;
    if (okBtn) okBtn.disabled = true;
    window.__pendingDangerSave = { patch: patch, confirmToken: confirmToken };
    var modal = document.getElementById("danger-modal");
    if (modal) modal.style.display = "flex";
  }

  function doSave(patch, confirmDanger, confirmToken, dangerList) {
    var btn = document.getElementById("save-config");
    if (btn) { btn.disabled = true; btn.textContent = "保存中..."; }
    rpc("security.config.save", { patch: patch, confirmDanger: !!confirmDanger, confirmToken: confirmToken || undefined })
      .then(function(res) {
        if (res && res.ok) {
          if (btn) {
            btn.textContent = "已保存 ✓";
            btn.style.background = "var(--success)";
            setTimeout(function() {
              btn.textContent = "保存";
              btn.style.background = "var(--accent)";
              btn.disabled = false;
            }, 2500);
          }
          showRestartNotice(res);
          // Save-response warnings (unknown keys accepted, empty system
          // layer, ...) — the save succeeded, but the operator should see
          // what the server flagged.
          var saveWarnings = res.warnings;
          if (Array.isArray(saveWarnings) && saveWarnings.length > 0) {
            showSaveWarningsBanner(saveWarnings);
          }
          // If the server reports fields that the bootstrap pipeline will
          // force off after restart, surface them so the user is not
          // surprised when runtime hooks / system layer "don't work".
          var forcedDisabled = res.bootstrapReport && res.bootstrapReport.forcedDisabled;
          if (Array.isArray(forcedDisabled) && forcedDisabled.length > 0) {
            showBootstrapReportBanner(forcedDisabled);
          }
          // Skip render() — security.config.get returns the in-memory snapshot
          // taken at plugin load time, so a fresh fetch would visibly snap the
          // form back to the pre-save values. The form already shows the
          // just-typed values, so just sync __lastConfig with what is now on
          // disk so the next diff is correct.
          if (res.applied && typeof res.applied === "object") {
            deepMergeInPlace(__lastConfig, res.applied);
          }
        } else if (res && res.error && res.error.confirmToken) {
          // Danger fields need confirmation: the server issued a one-time
          // confirmToken bound to this exact patch. Show the modal; the retry
          // after "确认保存" carries token + confirmDanger=true.
          if (btn) { btn.disabled = false; btn.textContent = "保存"; }
          openDangerModal(patch, dangerList || null, res.error.confirmToken, res.error.fields || []);
        } else {
          if (btn) { btn.disabled = false; btn.textContent = "保存"; }
          var msg = (res && res.error && res.error.message) || "未知错误";
          if (res && res.error && res.error.details) msg += "\\n" + JSON.stringify(res.error.details);
          if (res && res.error && res.error.fields) msg += "\\n需要确认: " + res.error.fields.join(", ");
          alert("保存失败: " + msg);
        }
      })
      .catch(function(err) {
        if (btn) { btn.disabled = false; btn.textContent = "保存"; }
        alert("RPC 失败: " + (err && err.message ? err.message : err));
      });
  }

  function saveConfig() {
    var c = collectPatch();
    if (Object.keys(c.patch).length === 0) {
      alert("没有检测到变更");
      return;
    }
    var dangerous = c.changed.filter(function(x) { return x.danger; });
    // Danger saves always make a first server round-trip: the confirmation
    // token is issued server-side (bound to the patch digest, one-time,
    // short-lived), so a tampered client cannot skip the modal by setting
    // confirmDanger=true itself. Non-danger saves still complete in one call.
    doSave(c.patch, false, undefined, dangerous);
  }

  // ── Main render ─────────────────────────────────────────────────────
  // ── Event Stream state + paging ───────────────
  // The on-disk NDJSON can grow to ~50MB on a busy gateway; the server caps its
  // in-memory event array (control-ui-service.ts) and surfaces a 'truncated' flag.
  // The UI keeps the filter / offset across re-renders, appends Load More pages
  // instead of re-fetching the whole table, and warns when the cache has dropped
  // older events.
  var eventsState = { limit: 50, offset: 0, eventType: "", sinceMinutes: "", total: 0, truncated: false, busy: false };
  // blocksState.filter — Policy Hits 客户端决策胶囊过滤（all/block/warn/modify/audit）。
  // 持久化在 localStorage（key: sst.policyHits.filter）以便刷新页面记忆。胶囊切换仅客户端
  // 过滤已加载的 hits，不发新 RPC——避免每次切换都全量重抓。默认值
  // "all" 与后端全决策返回行为一致；旧用户 localStorage 缺省值兜底为 "all"。
  var POLICY_HITS_FILTER_KEY = "sst.policyHits.filter";
  var POLICY_HITS_FILTER_DEFAULT = "all";
  function readPolicyHitsFilter() {
    try {
      var v = window.localStorage.getItem(POLICY_HITS_FILTER_KEY);
      if (v === "all" || v === "block" || v === "warn" || v === "modify" || v === "audit") return v;
    } catch (_) { /* localStorage may be blocked in sandboxed iframes */ }
    return POLICY_HITS_FILTER_DEFAULT;
  }
  function writePolicyHitsFilter(v) {
    try { window.localStorage.setItem(POLICY_HITS_FILTER_KEY, v); } catch (_) {}
  }
  var blocksState = { limit: 50, offset: 0, total: 0, busy: false, filter: readPolicyHitsFilter(), allHits: [] };

  // Static option list for the event-type filter. Covers the event types emitted
  // by Application / System / Asset collectors so the dropdown is useful without
  // an extra round-trip to the stats RPC.
  var EVENT_TYPE_OPTIONS = [
    "", "agent_session_start", "agent_session_end", "agent_message",
    "agent_tool_call", "process_exec", "network_request",
    "asset_add", "asset_change", "asset_remove", "asset_snapshot"
  ];

  function buildEventsShell() {
    var opts = EVENT_TYPE_OPTIONS.map(function(t) {
      var sel = t === eventsState.eventType ? ' selected' : '';
      var txt = t === '' ? 'All event types' : t;
      return '<option value="'+escAttr(t)+'"'+sel+'>'+esc(txt)+'</option>';
    }).join('');
    // Pause banner — same shape as Config's #config-dirty-bar (var(--warn) bg,
    // black text, 6px 10px padding, radius 4px). Sits above the toolbar so it
    // stays visible regardless of scroll position and matches Config's
    // pause affordance pixel-for-pixel.
    var pauseBanner = '<div id="detail-paused-banner" style="display:none;background:var(--warn);color:#000;padding:6px 10px;border-radius:4px;margin-bottom:8px;font-size:12px">⏸ 有展开的事件详情，自动刷新已暂停（收起详情行后恢复）</div>';
    return pauseBanner+
      '<div class="toolbar">'+
      '<select id="filter-event-type">'+opts+'</select>'+
      '<input id="filter-since" placeholder="since (minutes ago)" value="'+escAttr(eventsState.sinceMinutes)+'" style="max-width:170px"/>'+
      '<button id="filter-apply">Apply</button>'+
      '<span class="grow"></span>'+
      '<span class="meta" id="filter-help">limit 50 per page</span>'+
      '</div>'+
      '<div id="events-table"><div class="spinner">Loading...</div></div>'+
      '<div class="events-footer" id="events-footer"></div>';
  }

  // reset=true clears the existing table and starts at offset 0.
  // reset=false appends the next page to whatever is already rendered.
  function loadEvents(reset) {
    if (eventsState.busy) return;
    eventsState.busy = true;
    if (reset) eventsState.offset = 0;
    var params = { limit: eventsState.limit, offset: eventsState.offset };
    if (eventsState.eventType) params.eventType = eventsState.eventType;
    if (eventsState.sinceMinutes) {
      var minutes = parseInt(eventsState.sinceMinutes, 10);
      if (minutes > 0) params.sinceMs = Date.now() - minutes * 60 * 1000;
    }
    rpc("security.events.list", params).then(function(d) {
      var rows = (d && d.events) || [];
      eventsState.total = (d && typeof d.total === "number") ? d.total : rows.length;
      eventsState.truncated = !!(d && d.truncated);
      var tableArea = document.getElementById("events-table");
      var footerArea = document.getElementById("events-footer");
      if (reset) {
        // 只写表骨架（thead + 空 tbody #events-body），不再返回整段 <table>。
        // Load More 走 tbody.insertAdjacentHTML append 行，与 Policy Hits
        // (#blocks-body) 一致；data-event-idx 用全局 offset 计数避免撞 id。
        tableArea.innerHTML = rows.length
          ? renderEventsTable()
          : '<div class="empty">No events yet</div>';
      }
      if (rows.length) {
        var tbody = document.getElementById("events-body");
        if (tbody) {
          var startIdx = eventsState.offset;
          tbody.insertAdjacentHTML("beforeend", renderEventsRows(rows, startIdx));
        }
      }
      eventsState.offset += rows.length;
      var truncatedBanner = eventsState.truncated
        ? '<div class="banner">⚠ Only the most recent in-memory events are shown — the on-disk log exceeds the cache cap (older history is pruned from the search). Stats on the Metrics tab continue to reflect the full log.</div>'
        : '';
      var shown = eventsState.offset;
      var total = eventsState.total + (eventsState.truncated ? "+" : "");
      var more = eventsState.offset < eventsState.total
        ? '<button id="events-more">Load more</button>'
        : '<span class="meta">end of results</span>';
      footerArea.innerHTML = truncatedBanner +
        '<span class="meta">Showing '+shown + ' of '+total + ' events</span>' + more;
      var moreBtn = document.getElementById("events-more");
      if (moreBtn) moreBtn.onclick = function() { loadEvents(false); };
    }).catch(function(err) {
      var tableArea = document.getElementById("events-table");
      if (tableArea) tableArea.innerHTML = error(err);
    }).then(function() { eventsState.busy = false; });
  }

  function bindEventsToolbar() {
    var applyBtn = document.getElementById("filter-apply");
    if (!applyBtn) return;
    applyBtn.onclick = function() {
      eventsState.eventType = document.getElementById('filter-event-type').value;
      eventsState.sinceMinutes = document.getElementById('filter-since').value;
      loadEvents(true);
    };
  }

  function render() {
    var panel = document.getElementById("panel");
    // Sync detail-open flag from DOM. Apply / Load More / tab switch all
    // rebuild the panel innerHTML, so a stale __detailOpen would otherwise
    // wedge the auto-refresh in a paused state forever.
    __detailOpen = !!document.querySelector("#panel tr.event-detail.open");
    // While the user has unsaved edits on the Config tab, skip the auto-refresh
    // so a 30s tick doesn't clobber their in-progress input. The form keeps
    // showing the current edit state and the dirty banner makes the pause
    // visible. Tab switches (explicit user action) still re-render.
    if (activeTab === "config" && __configDirty) {
      document.getElementById("refresh").textContent = "Last updated: "+new Date().toLocaleTimeString()+" (paused — Config 有未保存改动)";
      var banner = document.getElementById("detail-paused-banner");
      if (banner) banner.style.display = "none";
      return;
    }
    // Same pause treatment for Event Stream / Policy Hits: while a detail
    // <tr.event-detail> is expanded the user is actively reading the JSON,
    // so don't let the 30s tick collapse it under them. Footer is updated
    // first (before any branch's possible early-return) so the pause
    // message stays visible even on the events tab, which returns early
    // after rebuilding its shell. The in-tab banner mirrors the footer so
    // the user sees the pause state even when the detail row pushes the
    // page footer below the viewport; styled to match Config's
    // #config-dirty-bar so the two pause affordances are visually unified.
    var bannerEl = document.getElementById("detail-paused-banner");
    if ((activeTab === "events" || activeTab === "blocks") && __detailOpen) {
      document.getElementById("refresh").textContent = "Last updated: "+new Date().toLocaleTimeString()+" (paused — 关闭展开行后恢复刷新)";
      if (bannerEl) bannerEl.style.display = "block";
      return;
    }
    if (bannerEl) bannerEl.style.display = "none";
    var now = new Date().toLocaleTimeString();
    document.getElementById("refresh").textContent = "Last updated: "+now;

    var p;
    if (activeTab === "metrics") {
      p = rpc("security.metrics").then(renderMetrics).catch(error);
    } else if (activeTab === "events") {
      // Events tab manages its own shell + pagination; skip the auto-set.
      panel.innerHTML = buildEventsShell();
      bindEventsToolbar();
      loadEvents(true);
      return;
    } else if (activeTab === "blocks") {
      panel.innerHTML = buildBlocksShell();
      loadBlocks(true);
      return;
    } else if (activeTab === "config") {
      p = rpc("security.config.get").then(function(d) {
        // Cache the config snapshot so saveConfig() can diff form values
        // against what the server last returned. The actual DOM write +
        // dirty-bar refresh happens in the shared .then at the bottom of
        // render() so we don't double-write panel.innerHTML (the second
        // write would clobber the form with the literal string "undefined").
        if (d && d.config && typeof d.config === "object") __lastConfig = d.config;
        return renderConfig(d);
      }).catch(error);
    } else {
      p = Promise.resolve('<div class="empty">Unknown tab</div>');
    }
    p.then(function(html) {
      panel.innerHTML = html;
      // After every render, refresh the Config dirty banner so the form
      // reflects the latest __lastConfig vs input comparison. Only relevant
      // when the active tab is config (other tabs have no banner element).
      if (activeTab === "config") updateConfigDirtyBar();
    });
  }

  // ── Tab switching ───────────────────────────────────────────────────
  var tabsEl = document.getElementById("tabs");
  tabsEl.addEventListener("click", function(e) {
    var btn = e.target.closest(".tab");
    if (!btn) return;
    // Clear all expanded detail rows before switching tabs so the switch
    // isn't blocked by __detailOpen staying true.
    document.querySelectorAll("#panel tr.event-detail.open").forEach(function(el) {
      el.classList.remove("open");
    });
    document.querySelectorAll(".tab").forEach(function(t) { t.classList.remove("active"); });
    btn.classList.add("active");
    activeTab = btn.dataset.tab;
    render();
  });

  // ── Event row toggle (delegated; survives innerHTML re-renders) ─────
  // Also handles the Config tab buttons (save / reset / copy) and the
  // danger modal buttons (cancel / ok).
  document.getElementById("panel").addEventListener("click", function(e) {
    var t = e.target;
    // Event JSON 内联复制按钮（clipboard → check → alert 三态）。
    // 点中 SVG/path 子节点时按 .copy-event 上溯；命中即拦截，不继续往下走。
    var copyBtn = t.closest && t.closest(".copy-event");
    if (copyBtn) { handleCopyEventJson(copyBtn); return; }
    if (!(t && t.id)) {
      // Maybe the click landed on a child label/span of one of our buttons
      var btn = t.closest && t.closest("button[id]");
      if (btn) t = btn;
    }
    if (!t || !t.id) {
      var row = t && t.closest ? t.closest("tr.event-row") : null;
      if (row) {
        var idx = row.getAttribute("data-event-idx");
        var detail = document.querySelector('tr.event-detail[data-detail-idx="' + idx + '"]');
        if (detail) detail.classList.toggle("open");
      }
      __detailOpen = !!document.querySelector("#panel tr.event-detail.open");
      return;
    }
    if (t.id === "copy-config") {
      // Fetch the on-disk raw config (no obfuscation) so the operator can
      // copy the real shape — 'security.config.get' returns the redacted
      // view (token / key / secret → ***), which would round-trip
      // incorrectly through 'security.config.save'. Fall back to the cached
      // copy-source pre element if the raw RPC is unavailable (e.g. older
      // host) so the button never silently fails.
      var fallbackSrc = document.getElementById("copy-source");
      var fallbackJson = fallbackSrc ? (fallbackSrc.textContent || "") : "";
      var btn = t;
      rpc("security.config.raw", {}).then(function(res) {
        var payload = (res && res.ok && res.config)
          ? JSON.stringify(res.config, null, 2)
          : fallbackJson;
        return copyText(payload).then(function() {
          btn.textContent = "Copied";
          setTimeout(function() { btn.textContent = "Copy JSON"; }, 1500);
        }, function() { btn.textContent = "Copy failed"; });
      }, function() {
        copyText(fallbackJson).then(function() {
          btn.textContent = "Copied (脱敏视图)";
          setTimeout(function() { btn.textContent = "Copy JSON"; }, 1500);
        }, function() { btn.textContent = "Copy failed"; });
      });
      return;
    }
    if (t.id === "save-config") {
      saveConfig();
      return;
    }
    if (t.id === "reset-config") {
      // Discard local edits by re-rendering from server-side config.
      // Note: this reloads the CURRENT on-disk config, not defaults — defaults
      // are only reachable by editing ~/.openclaw/openclaw.json directly.
      render();
      return;
    }
    // Metrics 页脚入口。委托挂在 #panel 上，重渲染后无需重新绑定。
    if (t.id === "open-website") {
      // 独立面板：window.open 新标签页成功；9.4 sandbox iframe（无
      // allow-popups）会返回 null，降级为复制链接 + toast 提示。
      e.preventDefault();
      var win = window.open(WEBSITE_URL, "_blank", "noopener");
      if (!win) {
        copyText(WEBSITE_URL).then(function(ok) {
          toast(ok ? "链接已复制，请粘贴到新标签页打开" : "无法自动打开或复制，请手动访问 "+WEBSITE_URL);
        });
      }
      return;
    }
    if (t.id === "show-qr") {
      e.preventDefault();
      var qm = document.getElementById("qr-modal");
      if (qm) qm.style.display = "flex";
      return;
    }
    if (t.id === "danger-cancel") {
      var m = document.getElementById("danger-modal");
      if (m) m.style.display = "none";
      return;
    }
    if (t.id === "danger-ok") {
      var m2 = document.getElementById("danger-modal");
      if (m2) m2.style.display = "none";
      var pending = window.__pendingDangerSave;
      if (pending) {
        window.__pendingDangerSave = null;
        doSave(pending.patch, true, pending.confirmToken);
      }
      return;
    }
    // Fallback: event-row toggle
    var row2 = t.closest ? t.closest("tr.event-row") : null;
    if (row2) {
      var idx2 = row2.getAttribute("data-event-idx");
      var detail2 = document.querySelector('tr.event-detail[data-detail-idx="' + idx2 + '"]');
      if (detail2) detail2.classList.toggle("open");
    }
    __detailOpen = !!document.querySelector("#panel tr.event-detail.open");
  });

  // Toggle "确认保存" button enabled state based on the confirm checkbox.
  // Delegated on document so it survives innerHTML re-renders of the modal.
  document.addEventListener("change", function(e) {
    if (e.target && e.target.id === "danger-confirm") {
      var okBtn = document.getElementById("danger-ok");
      if (okBtn) okBtn.disabled = !e.target.checked;
    }
  });

  // 关闭公众号二维码预览——点关闭按钮或遮罩（非卡片/图片区域）。
  // 预览层在 #panel 之外，document 级委托不受 30s 自动刷新影响。
  document.addEventListener("click", function(e) {
    var qm = document.getElementById("qr-modal");
    if (!qm || qm.style.display === "none") return;
    var t = e.target;
    if (t && (t.id === "qr-close" || (t.classList && t.classList.contains("qr-overlay")))) {
      qm.style.display = "none";
    }
  });

  // Live dirty tracking: as the user edits any Config field, recompute the
  // banner + __configDirty flag so the next 30s render() tick sees the
  // latest state. Delegated on #panel because the form is replaced wholesale
  // every time renderConfig() runs.
  document.getElementById("panel").addEventListener("input", function(e) {
    var t = e.target;
    if (t && t.getAttribute && t.getAttribute("data-section") && t.getAttribute("data-key")) {
      updateConfigDirtyBar();
    }
  });

  // ── Boot ──────────────────────────────────────────────────────────
  // 持久状态条数据源。面板加载时读一次 security.status（不轮询）；
  // 用户主动关闭 runtimeHooks（runtimeHooksEnabled===false）时不显示。
  rpc("security.status").then(function(st) {
    var bar = document.getElementById("hook-status-bar");
    if (!bar || !st) return;
    if (st.runtimeHooksEnabled === true && st.runtimeHookLoaded === false) {
      bar.style.display = "block";
      bar.textContent = "⚠ Runtime hook 未生效：宿主 NODE_OPTIONS 未预加载安全 hook，运行时进程/网络防护当前不生效（配置未主动关闭，属静默降级）。详见 Config 页 application.runtimeHooks.enabled 说明。";
    }
  }).catch(function() { /* status 不可用时静默，面板照常工作 */ });
  render();
  setInterval(render, 30000);
})();
</script>
</body>
</html>`);
  };

  api.registerHttpRoute?.({
    path: "/openclaw-security-monitor/panel",
    auth: "plugin",
    handler: panelHandlerImpl,
  });

  // Mirror the panel at /openclaw-security-monitor/panel-tab with auth=gateway
  // so the host's tab descriptor can find an iframeable route (it filters by
  // auth === "gateway"). Without this the sidebar click lands on the host's
  // "panel unavailable" placeholder because no route matches the descriptor path.
  api.registerHttpRoute?.({
    path: "/openclaw-security-monitor/panel-tab",
    auth: "gateway",
    handler: panelHandlerImpl,
  });

  api.runtime.registerRuntimeLifecycle?.({
    id: `${PLUGIN_ID}-cleanup`,
    cleanup: async () => {
      if (globalMiddleware) {
        await globalMiddleware.shutdown();
        globalMiddleware = undefined;
      }
    },
  });
}

async function handleInternalHookEvent(
  event: InternalHookEvent,
  middleware: SecurityMonitorStore
): Promise<void> {
  const merged = event.context;
  switch (event.type) {
    case "agent":
      if (event.action === "start") {
        const input = hookBridge.bridgeAgentStart(merged, undefined);
        if (input) await middleware.beforeAgentStart(input);
      } else if (event.action === "end" || event.action === "complete") {
        const input = hookBridge.bridgeAgentComplete(merged, undefined);
        if (input) await middleware.afterAgentComplete(input);
      }
      break;
    case "session":
      if (event.action === "end") {
        const input = hookBridge.bridgeSessionEnd(merged, undefined);
        if (input) await middleware.onSessionEnd(input);
      }
      break;
    case "message":
      if (event.action === "received" || event.action === "sending") {
        const input = hookBridge.bridgeMessageWrite(merged, undefined);
        if (input) await middleware.beforeMessageWrite(input);
      }
      break;
    case "command":
      if (event.action === "before") {
        const { ctx } = hookBridge.bridgeToolCall(merged, undefined);
        if (ctx) await middleware.beforeToolCall(ctx);
      } else if (event.action === "after") {
        const { ctx, result } = hookBridge.bridgeToolCall(merged, undefined);
        if (ctx) await middleware.afterToolCall(ctx, result);
      }
      break;
    case "gateway":
    default:
      // gateway events are observed via the typed hook runner; nothing to do.
      break;
  }
}

const plugin = definePluginEntry({
  id: PLUGIN_ID,
  name: PLUGIN_NAME,
  description:
    "智能体运行安全监控及恶意行为阻拦：实时采集应用/系统/网络/资产多层面安全事件，识别提示词注入、越权工具调用、恶意进程与网络行为，对高危操作执行实时阻断。",
  register,
});

export default plugin;
export { plugin };

// Legacy OpenClaw 3.13/8.2 fallback.
import type { OpenClawPlugin, OpenClawPluginAPI } from "./src/types.js";

export const legacyPlugin: OpenClawPlugin = {
  name: PLUGIN_ID,
  version: PLUGIN_VERSION,
  async initialize(api: OpenClawPluginAPI): Promise<void> {
    const cfg = (api as unknown as { config?: { get?: () => unknown } }).config?.get?.() ?? {};
    await createMiddleware(cfg);
  },
  async shutdown(): Promise<void> {
    if (globalMiddleware) {
      await globalMiddleware.shutdown();
      globalMiddleware = undefined;
    }
  },
};

// Re-exports for tests and external consumers.
export { SecurityMonitorStore };
export { normalizeConfig };
export { CONFIG_SCHEMA };
export { normalizeMessageWriteContext, normalizeAgentCompleteContext } from "./src/ctxExtract.js";
export { obfEncode, obfDecode, isObfuscated } from "./src/sensitive-obfuscate.js";
export type * from "./src/types.js";

// Control UI helper. Flags config keys whose changes need operator ⚠ confirmation
// before being applied. Independent of the OpenClaw 9.4 uiHints layer: these
// are runtime invariants, not UI hints.
const DANGEROUS_CONFIG_KEYS = new Set([
  "collector.ndjsonPath",
  "collector.maxFileSizeBytes",
  "collector.maxEventsInMemory",
  "network.enabled",
  "system.enabled",
  "application.runtimeHooks.enabled",
  "intervention.enabled",
  "intervention.mode",
  "intervention.failStrategy",
  "assetMonitor.enabled",
  "assetMonitor.collectContent",
]);

// Q2 / Config editor: declarative schema. Same source of truth for the panel
// form renderer (returned via security.config.get.schema) and the save-time
// validator. Each row is a single editable leaf under `section`. Nested keys
// use dot notation (e.g. "procfs.pythonPath" → system.procfs.pythonPath).
interface ConfigField {
  section: string;
  key: string;
  label: string;
  type: "bool" | "number" | "string" | "enum";
  values?: readonly string[];
  min?: number;
  max?: number;
  // Hide the field from the Config UI. The schema entry stays so the
  // server-side validator still accepts hand-edited values in
  // ~/.openclaw/openclaw.json — only the form renderer filters it out.
  // Use for fields that are not yet wired up (e.g. reserved placeholders)
  // so users don't waste time toggling a no-op switch.
  hidden?: boolean;
  // Conditional dependency on another field. When the dependency is unmet
  // (the other field's value does not equal `value`, defaulting to true),
  // the input is rendered disabled with an inline "(需先启用 X)" hint and
  // its current value is not editable. Use for child toggles that have no
  // effect when their parent toggle is off (e.g. networkEnabled vs.
  // runtimeHooks.enabled) so users don't read a stale "on" state as
  // "feature is running". An array means ALL listed deps must be satisfied
  // (e.g. procfs.pythonPath needs system.enabled AND procfs.enabled); the
  // single-object form keeps working.
  dependsOn?: { section: string; key: string; value?: unknown } | Array<{ section: string; key: string; value?: unknown }>;
  // Fold the field into a per-section "高级" collapse (default collapsed).
  // Use for tuning knobs that are safe to ignore for day-to-day operation;
  // unlike `hidden` the field stays discoverable one click away.
  advanced?: boolean;
  // Optional long-form instructions shown below the input. Use for fields
  // that need operator-side setup beyond a simple toggle (e.g. docker env
  // vars, host preloads). `dangerReason` is reserved for short warnings
  // inside the danger-confirm modal.
  help?: string;
  danger?: boolean;
  dangerReason?: string;
}
const CONFIG_SCHEMA: ConfigField[] = [
  { section: "collector", key: "ndjsonPath", label: "本地 NDJSON 路径", type: "string",
    danger: true, dangerReason: "改路径后下次启动会在新位置创建文件，旧路径文件不会被自动清理" },
  { section: "collector", key: "maxFileSizeBytes", label: "NDJSON 文件大小上限 (bytes)", type: "number", min: 0, max: 1073741824,
    danger: true, dangerReason: "调小后会立刻触发 rotate，把当前文件改名 .rotated；sidecar SDK 必须同时 tail .rotated 才能不丢事件" },
  { section: "collector", key: "maxEventsInMemory", label: "面板内存事件数上限", type: "number", min: 100, max: 50000,
    hidden: true,
    danger: true, dangerReason: "调小会让 Event Stream / Policy Hits 看不到更早的事件；调大增加面板堆内存占用" },
  { section: "application", key: "enabled", label: "启用", type: "bool" },
  { section: "application", key: "captureUserPrompt", label: "捕获用户 Prompt", type: "bool" },
  { section: "application", key: "captureSystemPrompt", label: "捕获系统 Prompt", type: "bool" },
  { section: "application", key: "captureAgentPlan", label: "捕获 Agent Plan", type: "bool" },
  { section: "application", key: "captureCodeMode", label: "捕获 Code Mode", type: "bool",
    help: "捕获 code_mode_exec 工具调用的代码正文（事件 code_content 字段）；关闭后 code_mode 事件只保留元数据，不含代码内容。" },
  { section: "application", key: "captureReasoning", label: "捕获推理过程", type: "bool" },
  { section: "application", key: "captureUserId", label: "捕获用户 ID", type: "bool",
    help: "按 userIdField 指定的字段名从消息 / 工具元数据提取用户 ID，用于审计归因；关闭后事件不再携带 user_id。" },
  { section: "application", key: "userIdField", label: "用户 ID 字段名", type: "string", min: 1, max: 64,
    danger: true, dangerReason: "审计归因字段，改成不存在的字段名会让所有事件 user_id 变空，影响合规追溯",
    help: "从消息事件中取 userId 的字段名。OpenClaw 9.4 默认 'userId'；其他宿主若不一致会导致审计归因为空。"
  },
  { section: "application", key: "maxContentLength", label: "单字段最大长度", type: "number", min: 100, max: 100000,
    hidden: true },
  { section: "application", key: "sessionTtlMs", label: "会话缓存 TTL (ms)", type: "number", min: 60000, max: 86400000,
    hidden: true },
  { section: "application", key: "runtimeHooks.enabled", label: "启用 Runtime Hooks", type: "bool",
    danger: true, dangerReason: "需 NODE_OPTIONS='--require <hook>' 才能生效，否则无数据",
    help:
      "⚙ 启用 ≠ 立即生效。bundled hooks 首次启用时已拷到\n" +
      "  ~/.openclaw/extensions/sst-security-control-openclaw/\n" +
      "还须让 gateway 启动环境设 NODE_OPTIONS 引用 runtime.js。\n" +
      "路径须为运行环境内的绝对路径（容器内 home 取决于镜像，常见为 /home/node）：\n\n" +
      "  # docker run / docker-compose\n" +
      "  -e NODE_OPTIONS='--require /home/node/.openclaw/extensions/sst-security-control-openclaw/runtime.js'\n\n" +
      "  # 宿主机直装\n" +
      "  NODE_OPTIONS='--require $HOME/.openclaw/extensions/sst-security-control-openclaw/runtime.js'\n\n" +
      "⚠ 仅 openclaw gateway restart 不会让 NODE_OPTIONS 生效，\n" +
      "  须重建容器 / 重启宿主进程。验证：日志出现 runtimeHookLoaded=true"
  },
  { section: "application", key: "runtimeHooks.networkEnabled", label: "Runtime Hooks · 启用网络拦截", type: "bool",
    dependsOn: { section: "application", key: "runtimeHooks.enabled", value: true },
    help: "默认 true。Runtime Hooks 同时拦截 child_process + fetch；只想要进程拦截、不想要网络拦截时关闭。必须先启用「启用 Runtime Hooks」。关闭/开启在 gateway 重启后生效（本进程已加载 network hook 的场景同样生效，无需重建容器）。"
  },
  { section: "system", key: "enabled", label: "启用", type: "bool",
    danger: true, dangerReason: "需主机预装 python3 + psutil，否则启动失败并频繁告警",
    help:
      "⚙ 启用前需主机预装 python3 + psutil>=5.9.0。\n" +
      "plugin 启动时执行 <pythonPath> -c \"import psutil\" 探测，失败则自动关闭本层。\n\n" +
      "  # Debian / Ubuntu\n" +
      "  apt-get install -y python3 python3-pip && python3 -m pip install 'psutil>=5.9.0'\n\n" +
      "  # Alpine（容器精简镜像）\n" +
      "  apk add --no-cache python3 py3-pip && python3 -m pip install 'psutil>=5.9.0'\n\n" +
      "  # RHEL / Fedora\n" +
      "  dnf install -y python3 python3-pip && python3 -m pip install 'psutil>=5.9.0'\n\n" +
      "python 路径非默认时改 system.procfs.pythonPath（默认 \"python3\"）。\n" +
      "⚠ 仅 openclaw gateway restart 不补 psutil 缺失，须重建镜像或装系统包。"
  },
  { section: "system", key: "procfs.enabled", label: "procfs 采集", type: "bool",
    dependsOn: { section: "system", key: "enabled", value: true },
    help:
      "只读 psutil 进程扫描，默认不做任何杀伤（autoKill 默认关闭）。\n" +
      "需主机 python3 + psutil；bootstrap 探测缺失时会自动关闭本层并在保存时提示。\n" +
      "开启并重启 gateway 后，绑定的工具调用进程树会产生 process_start / " +
      "process_change / process_exit / process_snapshot 事件。"
  },
  { section: "system", key: "cgroups.enabled", label: "cgroups 指标", type: "bool",
    dependsOn: { section: "system", key: "enabled", value: true },
    help:
      "只读 cgroup v1/v2 指标（cpu / memory / blkio / pids），低开销。\n" +
      "随 process monitor 一同启动，开启并重启后产生 cgroup_snapshot / cgroup_anomaly 事件；\n" +
      "稳态心跳由 cgroups.heartbeatEnabled + cgroups.aggregateWindowSeconds 控制。"
  },
  { section: "system", key: "procfs.pythonPath", label: "Python 路径", type: "string",
    dependsOn: [
      { section: "system", key: "enabled", value: true },
      { section: "system", key: "procfs.enabled", value: true },
    ] },
  { section: "system", key: "procfs.scanIntervalMs", label: "扫描间隔 (ms)", type: "number", min: 100, max: 60000,
    advanced: true,
    dependsOn: [
      { section: "system", key: "enabled", value: true },
      { section: "system", key: "procfs.enabled", value: true },
    ] },
  { section: "intervention", key: "enabled", label: "启用", type: "bool",
    danger: true, dangerReason: "关闭后所有 hook 不再拦截，agent 可执行任意工具调用" },
  { section: "intervention", key: "mode", label: "模式", type: "enum", values: ["enforce", "audit"],
    danger: true, dangerReason: "enforce 会真实拦截；audit 仅记录不拦截" },
  { section: "intervention", key: "failStrategy", label: "失败策略",
    type: "enum", values: ["fail_open", "fail_closed", "fail_open_high_risk_only"],
    danger: true, dangerReason: "fail_closed 在规则超时时会拒绝所有未匹配操作" },
  { section: "intervention", key: "guidance.enabled", label: "引导式干预", type: "bool",
    danger: true, dangerReason: "关闭后引导变直接拦截，行为静默切换",
    help: "命中 context_adjust 规则时先给出引导建议（调整范围 / 替代操作），而不是直接阻断。⚠ 关闭 = 引导变直接拦截（GUIDANCE_DISABLED），属策略收紧，请评估误拦影响后再关。" },
  { section: "intervention", key: "reportBlockedEvents", label: "上报被拦截事件", type: "bool",
    danger: true, dangerReason: "关闭后无法在面板/审计中查看任何拦截记录，审计追溯完全消失",
    help: "被策略拦截（block）的工具调用是否落盘为事件。关闭后拦截本身仍生效，但面板 Policy Hits / 事件流不再显示这些拦截记录。" },
  { section: "intervention", key: "decisionTimeoutMs", label: "决策超时 (ms)", type: "number", min: 10, max: 10000,
    hidden: true,
    help: "保留字段：评估核心全同步，超时分支不生效；待后续异步评估重构后启用。" },
  { section: "intervention", key: "policyPath", label: "策略文件路径", type: "string",
    danger: true, dangerReason: "若路径不可读或无规则文件，插件会静默回退到 allow-all，所有防护失效" },
  { section: "intervention", key: "reloadIntervalMs", label: "策略重载间隔 (ms)", type: "number", min: 1000, max: 600000,
    hidden: true },
  { section: "assetMonitor", key: "enabled", label: "启用", type: "bool",
    danger: true, dangerReason: "关闭后 agent 配置 / skill / MCP 变更不再审计" },
  { section: "assetMonitor", key: "scanIntervalMs", label: "扫描间隔 (ms)", type: "number", min: 10000, max: 3600000,
    hidden: true },
  { section: "assetMonitor", key: "collectContent", label: "收集文件内容", type: "bool",
    danger: true, dangerReason: "会上传 agent 配置文件内容（敏感字段已混淆）" },
  { section: "assetMonitor", key: "collectSkillPackage", label: "收集 Skill 安装包", type: "bool",
    danger: true, dangerReason: "开启会增加事件体积，请确认下游存储可接受",
    help: "扫描 skill 目录并随 asset 事件附带 ZIP 包（base64），供下游审计与扫描；关闭后仅上报文件清单与指纹。" },
  { section: "assetMonitor", key: "collectConfigPackage", label: "收集配置文件包", type: "bool",
    danger: true, dangerReason: "开启后 agent 配置文件原文会打包随事件上报（敏感字段已混淆）",
    help: "将 agent 配置文件打包为 ZIP 随事件上报（包内为原文，解析摘要中的敏感值已混淆）；关闭后仅保留解析摘要。" },
  { section: "bootstrap", key: "entryDefaults", label: "启动写入 host 默认值", type: "bool" },
];

function validateConfigPatch(
  patch: Record<string, Record<string, unknown>>
): { ok: true; dangerous: string[]; unknown: string[] } | { ok: false; errors: string[]; dangerous: string[]; unknown: string[] } {
  const errors: string[] = [];
  const dangerous: string[] = [];
  const unknown: string[] = [];
  for (const [section, fields] of Object.entries(patch)) {
    if (!fields || typeof fields !== "object" || Array.isArray(fields)) {
      errors.push(`${section}: 必须是对象`);
      continue;
    }
    // Prototype-pollution guard. A section named __proto__ would
    // resolve to Object.prototype on the merge target (the __proto__ setter
    // fires on assignment) and dotted segments like "a.__proto__.b" walk the
    // prototype chain — reject outright instead of silently dropping.
    if (FORBIDDEN_PATCH_KEYS.has(section)) {
      errors.push(`${section}: 非法 section 名`);
      continue;
    }
    // Keys outside CONFIG_SCHEMA are accepted (hand-edited openclaw.json may
    // carry newer/older fields; rejecting them would brick those users) but
    // surfaced as save-response warnings so typos don't go unnoticed.
    for (const key of Object.keys(fields)) {
      if (key.split(".").some((seg) => FORBIDDEN_PATCH_KEYS.has(seg))) {
        errors.push(`${section}.${key}: 非法键名`);
        continue;
      }
      if (!CONFIG_SCHEMA.some((f) => f.section === section && f.key === key)) {
        unknown.push(`${section}.${key}`);
      }
    }
    for (const f of CONFIG_SCHEMA) {
      if (f.section !== section) continue;
      if (!(f.key in fields)) continue;
      const path = `${section}.${f.key}`;
      const v = fields[f.key];
      if (v === null || v === undefined) {
        errors.push(`${path}: 不能为空`);
        continue;
      }
      if (f.type === "bool" && typeof v !== "boolean") {
        errors.push(`${path}: 需要布尔值`); continue;
      }
      if (f.type === "number") {
        if (typeof v !== "number" || !Number.isFinite(v)) { errors.push(`${path}: 需要数字`); continue; }
        if (f.min !== undefined && v < f.min) { errors.push(`${path}: 必须 ≥ ${f.min}`); continue; }
        if (f.max !== undefined && v > f.max) { errors.push(`${path}: 必须 ≤ ${f.max}`); continue; }
      }
      if (f.type === "string") {
        if (typeof v !== "string") { errors.push(`${path}: 需要字符串`); continue; }
        // string min/max 按字符串长度生效（如 userIdField min:1/max:64）
        if (f.min !== undefined && v.length < f.min) { errors.push(`${path}: 长度必须 ≥ ${f.min}`); continue; }
        if (f.max !== undefined && v.length > f.max) { errors.push(`${path}: 长度必须 ≤ ${f.max}`); continue; }
      }
      if (f.type === "enum" && (typeof v !== "string" || !f.values?.includes(v))) {
        errors.push(`${path}: 必须是 ${(f.values ?? []).join(" / ")} 之一`); continue;
      }
      if (f.danger) dangerous.push(path);
    }
  }
  if (errors.length > 0) return { ok: false, errors, dangerous, unknown };
  return { ok: true, dangerous, unknown };
}

// L4 (atomic write) + L5 (backup) + L6 (best-effort lock) + L7 (audit log)
// + L8 (deep merge). All layers run on every save; the file the user edits is
// `~/.openclaw/openclaw.json` per OpenClaw convention. We mutate only the
// `plugins.entries[PLUGIN_ID].config` subtree so the rest of the host config
// (hooks, llm, subagent, etc.) is preserved verbatim.
function saveHostConfigPatch(args: {
  patch: Record<string, Record<string, unknown>>;
  confirmDanger: boolean;
  confirmToken?: string;
  effectiveConfig?: SecurityMonitorConfig;
  logger?: OpenClawPluginApi["logger"];
}): { ok: true; restartRequired: true; backup: string | null; applied: Record<string, Record<string, unknown>>; warnings: Array<{ path: string; message: string }>; bootstrapReport: { forcedDisabled: ForcedDisable[] } }
   | { ok: false; error: { message: string; details?: unknown; fields?: string[]; confirmToken?: string; confirmExpiresInSec?: number } } {
  const { patch, logger } = args;

  // L2: schema validation
  const v = validateConfigPatch(patch);
  if (!v.ok) return { ok: false, error: { message: "字段校验失败", details: v.errors } };
  if (v.dangerous.length > 0) {
    // Dangerous patches only execute against a server-issued,
    // one-time confirmToken bound to this exact patch digest. The old
    // confirmDanger boolean was client-self-declared and is no longer
    // sufficient on its own — a tampered panel could set it directly.
    if (!args.confirmToken || !consumeDangerConfirmToken(args.confirmToken, patch)) {
      const confirmToken = issueDangerConfirmToken(patch);
      return {
        ok: false,
        error: {
          message: "danger 字段需要二次确认",
          fields: v.dangerous,
          confirmToken,
          confirmExpiresInSec: DANGER_CONFIRM_TTL_MS / 1000,
        },
      };
    }
  }

  const targetPath = resolveHostConfigPath();
  let raw: string;
  try {
    raw = readFileSync(targetPath, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
      return { ok: false, error: { message: "读取 host 配置失败: " + (err as Error).message } };
    }
    raw = "{}";
  }
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(raw) as Record<string, unknown>;
  } catch (err) {
    return { ok: false, error: { message: "host 配置不是合法 JSON: " + (err as Error).message } };
  }

  // Ensure plugins.entries[PLUGIN_ID].config exists
  let plugins: Record<string, unknown> = parsed.plugins as Record<string, unknown>;
  if (!plugins || typeof plugins !== "object" || Array.isArray(plugins)) {
    plugins = parsed.plugins = {};
  }
  let entries: Record<string, unknown> = plugins.entries as Record<string, unknown>;
  if (!entries || typeof entries !== "object" || Array.isArray(entries)) {
    entries = plugins.entries = {};
  }
  let entry: Record<string, unknown> = entries[PLUGIN_ID] as Record<string, unknown>;
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
    entry = entries[PLUGIN_ID] = {};
  }

  // L8: deep-merge patch into the existing user config block. We never
  // replace the whole subtree — fields the user did not touch are preserved.
  const currentConfig = (entry.config as Record<string, Record<string, unknown>> | undefined) || {};
  const merged: Record<string, Record<string, unknown>> = {};
  for (const [k, v0] of Object.entries(currentConfig)) {
    merged[k] = JSON.parse(JSON.stringify(v0)) as Record<string, unknown>;
  }
  for (const [section, fields] of Object.entries(patch)) {
    // validateConfigPatch already rejected forbidden names; the hasOwnProperty
    // reads below keep the merge safe even if that guard ever loosens.
    if (FORBIDDEN_PATCH_KEYS.has(section)) continue;
    let target = Object.prototype.hasOwnProperty.call(merged, section)
      ? (merged[section] as Record<string, unknown>)
      : undefined;
    if (!target || typeof target !== "object" || Array.isArray(target)) {
      target = {};
      merged[section] = target;
    }
    for (const [k, val] of Object.entries(fields)) {
      // Dotted keys ("runtimeHooks.enabled", "procfs.pythonPath") must be
      // expanded into nested structure; otherwise the value lands at a
      // literal-dotted key that normalizeConfig never reads and the change
      // is silently dropped on the next gateway restart.
      const parts = k.split(".").filter((p) => p.length > 0 && !FORBIDDEN_PATCH_KEYS.has(p));
      if (parts.length === 0) continue; // validateConfigPatch already rejected
      if (parts.length === 1) {
        target[parts[0]] = val;
        continue;
      }
      let cur: Record<string, unknown> = target;
      for (let i = 0; i < parts.length - 1; i++) {
        const seg = parts[i];
        const next = Object.prototype.hasOwnProperty.call(cur, seg) ? cur[seg] : undefined;
        if (!next || typeof next !== "object" || Array.isArray(next)) {
          cur[seg] = {};
        }
        cur = cur[seg] as Record<string, unknown>;
      }
      cur[parts[parts.length - 1]] = val;
    }
  }
  entry.config = merged;

  // Warn about configs that would silently produce no system events:
  // SystemCollector only starts the monitor when procfs.enabled OR
  // cgroups.enabled is on, so system.enabled alone is an empty switch.
  const warnings: Array<{ path: string; message: string }> = [];
  // Unrecognized keys were accepted above (deep merge preserves them for
  // forward/backward compat) but the operator should know they map to
  // nothing in the current schema — usually a typo.
  for (const unknownPath of v.unknown) {
    warnings.push({
      path: unknownPath,
      message: "未识别的配置键已接受保存；它不在当前配置 schema 中，重启后可能被忽略，请确认键名拼写",
    });
  }
  const mergedSystem = merged.system as Record<string, unknown> | undefined;
  const mergedProcfs = mergedSystem?.procfs as Record<string, unknown> | undefined;
  const mergedCgroups = mergedSystem?.cgroups as Record<string, unknown> | undefined;
  if (
    mergedSystem?.enabled === true &&
    mergedProcfs?.enabled !== true &&
    mergedCgroups?.enabled !== true
  ) {
    warnings.push({
      path: "system.enabled",
      message:
        "system 层已启用，但 procfs 采集与 cgroups 指标均未开启；" +
        "重启后 system 层不会启动监控，也不会产生 system 事件",
    });
  }

  // L5: backup current file (best effort — first save on a missing file is OK)
  const ts = Date.now();
  const backupPath = `${targetPath}.bak.${ts}`;
  let backupCreated = false;
  try {
    copyFileSync(targetPath, backupPath);
    backupCreated = true;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
      return { ok: false, error: { message: "备份失败: " + (err as Error).message } };
    }
  }

  // L4: atomic write via tmp + rename. Same pattern ensureHostPluginEntryDefaults uses.
  const tmpPath = `${targetPath}.${process.pid}.${Date.now()}.tmp`;
  const next = JSON.stringify(parsed, null, 2) + "\n";
  try {
    mkdirSync(dirname(targetPath), { recursive: true });
    writeFileSync(tmpPath, next, "utf8");
    renameSync(tmpPath, targetPath);
  } catch (err) {
    try { if (existsSync(tmpPath)) unlinkSync(tmpPath); } catch { /* ignore */ }
    return { ok: false, error: { message: "写入失败: " + (err as Error).message } };
  }

  // Post-write self-check: ensure the new file parses. If not, restore from
  // backup so the host never starts with a half-broken config.
  try {
    JSON.parse(readFileSync(targetPath, "utf8"));
  } catch (err) {
    if (backupCreated) {
      try { copyFileSync(backupPath, targetPath); } catch { /* ignore */ }
    }
    return { ok: false, error: { message: "写后校验失败；已从备份恢复: " + (err as Error).message } };
  }

  // L7: audit log (best effort — failure does not block the save)
  try {
    const auditPath = join(homedir(), ".openclaw", "security-config-audit.jsonl");
    const line = JSON.stringify({
      ts: new Date(ts).toISOString(),
      action: "config.write",
      actor: "panel",
      plugin_id: PLUGIN_ID,
      changes: patch,
      danger: v.dangerous,
      backup: backupCreated ? backupPath : null,
    }) + "\n";
    mkdirSync(dirname(auditPath), { recursive: true });
    writeFileSync(auditPath, line, { flag: "a" });
  } catch (err) {
    logger?.warn?.(`[${PLUGIN_ID}] audit log write failed: ${err instanceof Error ? err.message : String(err)}`);
  }

  logger?.info?.(`[${PLUGIN_ID}] config saved (danger: ${v.dangerous.length}, backup: ${backupCreated ? backupPath : "n/a"})`);

  // Dry-run bootstrap on the CURRENTLY EFFECTIVE config (never on
  // the pending patch) so the panel can warn the user about fields the
  // bootstrap pipeline will force off after restart (silently-disabled traps
  // from missing NODE_OPTIONS / psutil). Probing the patch would execute a
  // hostile saved pythonPath at save time — before the operator even restarts.
  // The probe runs the same probe + apply step as initializePlugin, but never
  // touches disk / network / host config — only reads process.env and inspects
  // the in-memory config tree.
  let forcedDisabled: ForcedDisable[] = [];
  try {
    const dryRunBase = args.effectiveConfig ?? normalizeConfig(merged as unknown as Record<string, unknown>);
    const probeReport = {
      policySeeded: false,
      hooksInstalled: false,
      runtimeHookLoaded: probeRuntimeHookLoaded(logger),
      pythonPsutil: probePythonPsutil(dryRunBase, logger),
      entryDefaultsWritten: false,
      forcedDisabled: [] as ForcedDisable[],
    };
    forcedDisabled = applyBootstrapResults(dryRunBase, probeReport).forcedDisabled;
  } catch (err) {
    logger?.warn?.(
      `[${PLUGIN_ID}] bootstrap dry-run failed: ${err instanceof Error ? err.message : String(err)}`
    );
  }

  return {
    ok: true,
    restartRequired: true,
    backup: backupCreated ? backupPath : null,
    applied: patch,
    warnings,
    bootstrapReport: { forcedDisabled },
  };
}

/**
 * Flatten a (normalized) config object to `section.key` dot paths. Nested
 * plain objects recurse; arrays and scalars are leaf values. This is the
 * same key space CONFIG_SCHEMA / DANGEROUS_CONFIG_KEYS / the panel use.
 */
function flattenConfigLeaves(config: Record<string, unknown>, prefix = ""): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(config)) {
    const dotPath = prefix ? `${prefix}.${key}` : key;
    if (value !== null && typeof value === "object" && !Array.isArray(value)) {
      Object.assign(out, flattenConfigLeaves(value as Record<string, unknown>, dotPath));
    } else {
      out[dotPath] = value;
    }
  }
  return out;
}

function markDangerousConfig(
  changes: Array<{ key: string; from: unknown; to: unknown }>
): Array<{ key: string; reason: string }> {
  const out: Array<{ key: string; reason: string }> = [];
  for (const change of changes) {
    if (DANGEROUS_CONFIG_KEYS.has(change.key)) {
      out.push({ key: change.key, reason: "dangerous: requires restart + audit confirmation" });
    }
    // enforce mode is always dangerous, audit is not
    if (change.key === "intervention.mode" && change.to === "enforce") {
      out.push({ key: change.key, reason: "switching to enforce blocks tool calls" });
    }
    if (change.key === "intervention.failStrategy" && change.to === "fail_closed") {
      out.push({ key: change.key, reason: "fail_closed will deny unmatched actions" });
    }
  }
  return out;
} // _w2 = '75697a68'
// _w4 = '6e672e636f6d'