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
// depend on the host's @openclaw/plugin-sdk being installed.
//
// Host integration surface:
//   - definePluginEntry + register(api) skeleton, with legacy
//     OpenClawPlugin fallback.
//   - Typed hook subscriptions via api.on(...) wired through
//     src/hook-bridge.ts into SecurityMonitorStore. InternalHookEvent
//     subscriptions (api.registerHook) for the 5 family actions
//     (command/session/agent/gateway/message) remain opt-in for legacy hosts.
//   - registerGatewayMethod / registerHttpRoute inside `register`.

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
import { HTML_LANG, PANEL_LOCALE_PREFERENCES, RAW_FALLBACK_PREFIXES, normalizePanelLocalePreference, parseLocale, serializeDictionary, translate, type PanelLocalePreference } from "./src/panel-i18n.js";
import { PLUGIN_ID, resolvePreloadTarget } from "./src/hook-locations.js";

export { PLUGIN_ID };
export const PLUGIN_NAME = "SST Security Control 安全监控插件";

/**
 * npm 包名可以带 scope。本插件仓库根的 package.json 是
 * `@zhanxing/sst-security-control-openclaw`（带 scope），而 build.js 生成的
 * 安装包会剥掉 scope 写成 `openclaw.plugin.json#name`。两边都应解析成功，
 * 所以比较时统一去掉 scope 前缀 —— 否则开发树（含 dist/index.js）静默返回
 * "0.0.0-unknown"，面板副标题和启动日志显示的是一个看起来正常的假版本号。
 *
 * 放宽后的匹配面：任意 scope 下的同名包都能命中。实际风险可忽略（剥完 scope
 * 仍是与 PLUGIN_ID 的精确相等；真能往目录树里塞 package.json 的人，做点别的
 * 危害大得多），换来的是换 scope / 改包名时不必回来改这里。
 */
function unscopedPackageName(name: unknown): string {
  return typeof name === "string" ? name.replace(/^@[^/]+\//, "") : "";
}

/**
 * package.json is the single source of truth for the version. Walk up from
 * this module looking for a package.json that names this plugin — the same
 * compiled file lands at repo-root (index.ts), dist/index.js and
 * install/application/index.js, each one level deeper. The only copy that
 * has to be kept in sync by hand is openclaw.plugin.json#version (the host
 * manifest contract); scripts/build.js fails the build when it drifts.
 * The zero-dependency CJS hooks carry no version at all — they are
 * fingerprinted by content hash for upgrade detection (see readHookFingerprint
 * in src/initialize.ts), so nothing there tracks the package version.
 *
 * @param fromUrl 起点模块 URL，默认本模块；测试用临时目录伪造各种安装布局。
 */
export function resolvePluginVersion(fromUrl: string = import.meta.url): string {
  let dir = dirname(fileURLToPath(fromUrl));
  // 4 层足够覆盖已知的三个落点：仓库根第 1 层命中；安装后最深的
  // package/application/index.js 在第 2 层命中（application/ 下无
  // package.json）。再多留一层余量给未来的目录嵌套。
  for (let i = 0; i < 4; i++) {
    const candidate = join(dir, "package.json");
    if (existsSync(candidate)) {
      try {
        const pkg = JSON.parse(readFileSync(candidate, "utf8")) as { name?: string; version?: string };
        if (unscopedPackageName(pkg.name) === PLUGIN_ID && typeof pkg.version === "string") {
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
      schema: withRuntimeHelpVars(CONFIG_SCHEMA),
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

  // Read side of the switcher. Both halves are reported, not just the
  // effective one: "面板是中文" 要能分辨是开关按过、配置键钉死、还是浏览器
  // 协商出来的 —— 只回一个解析结果的话，排查时看不出该去改哪一处。
  rpcHandlers["security.panel.locale.get"] = () => ({
    saved: readPanelStateLocale(),
    configDefault: readPanelLocalePreference(),
    effective: readSavedPanelLocale(),
  });

  // Header language switcher: persist the choice in the plugin's own state
  // file rather than the host config (see writePanelStateLocale for why), and
  // hand the panel back the value it actually stored so it can tell "saved"
  // from "silently coerced to auto".
  rpcHandlers["security.panel.locale.set"] = (params) => {
    const requested = ((params ?? {}) as { locale?: unknown }).locale;
    if (
      typeof requested !== "string" ||
      !(PANEL_LOCALE_PREFERENCES as readonly string[]).includes(requested)
    ) {
      return {
        ok: false,
        error: { message: `locale 必须是 ${PANEL_LOCALE_PREFERENCES.join(" / ")} 之一` },
      };
    }
    return writePanelStateLocale(requested as PanelLocalePreference);
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
    "security.panel.locale.get": "operator.read",
    "security.panel.locale.set": "operator.write",
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

  // Expose NDJSON event log as an HTTP route so the SDK sidecar (or any
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
          // 沙箱 iframe 的 Origin 恒为 "null"。这个 403 若不带
          // Access-Control-Allow-Origin，浏览器的 CORS 检查会让 fetch 直接
          // reject 成 "Failed to fetch"，面板里 rpc() 的 r.status===401/403
          // 分支（scheduleAuthReload → 自动重载重建会话）永远走不到——用户
          // 只看到一个点不动、也不报错的控件。给 "null" 补上 CORS 头让面板能
          // 读到自己的拒绝理由，恢复路径才存在。
          // 不放宽任何东西：POST 照旧 403，不带 Access-Control-Allow-Credentials
          // （opaque origin 本来也拿不到 cookie），响应体只有一句固定拒绝文案，
          // 不含任何请求方的信息。
          if (originHeader === "null") setSandboxCorsHeaders();
          // 客户端读不到 body、服务端此前也不记一笔：这个拒绝在两边都无痕，
          // 线上只能靠猜。留下 origin 与 nonce 状态，下一次复现就有据可查。
          api.logger.warn(
            `[panel] cross-origin POST rejected origin=${originHeader} nonce=${
              typeof req.headers["x-panel-nonce"] === "string"
                ? isPanelNonceValid(req.headers["x-panel-nonce"] as string)
                  ? "valid-but-untrusted-origin"
                  : "invalid"
                : "missing"
            } host=${req.headers.host ?? "-"}`,
          );
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
      // Locale is resolved here, on the server, and the dictionary travels with
      // the HTML. The panel runs in a sandbox="allow-scripts" iframe where
      // client-side detection is unreliable (navigator.language is not even
      // present in the vm sandbox tests/panel-auth-rce.test.ts runs this script
      // in), and the locale has to be frozen at render time anyway: dangerReason
      // round-trips through an HTML attribute, so switching language mid-session
      // could not re-render it.
      const locale = parseLocale(
        req.url,
        typeof req.headers["accept-language"] === "string" ? req.headers["accept-language"] : undefined,
        readSavedPanelLocale()
      );
      // Server-side half of the panel's i18n: resolves the strings baked into the
      // static HTML below (tabs, spinner, QR modal, noscript). The dynamic half
      // is the `T()` defined at the top of the inlined <script>.
      const T = (key: string, vars?: Record<string, unknown>) => translate(locale, key, vars);
      res.end(`<!doctype html>
<html lang="${HTML_LANG[locale]}">
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
/* 语言切换控件。语言名用 endonym（EN / 中文），两种界面下形状完全一致。
   写在 header 里 subtitle 之后，使 injectFullViewButton 的
   insertBefore(link, subtitle.nextSibling) 恰好把"完整面板"落在它前面，
   切换控件恒为最右——嵌入与否位置一致，且不必改动那段宿主适配代码。 */
.langswitch{display:inline-flex;align-items:stretch;border:1px solid var(--border);border-radius:4px;overflow:hidden;font-size:11px;line-height:1.4;margin-left:8px;flex:none}
.langswitch button{padding:3px 8px;background:var(--subtle-bg);color:var(--muted);border:none;border-left:1px solid var(--border);cursor:pointer;font:inherit;white-space:nowrap}
.langswitch button:first-child{border-left:none}
.langswitch button:hover{color:var(--fg)}
.langswitch button[aria-pressed="true"]{background:var(--card-bg);color:var(--fg);font-weight:600}
.langswitch button:focus-visible{outline:2px solid var(--accent);outline-offset:-2px}
/* 窄屏优先牺牲装饰性的副标题，保住标题与两个控件 */
@media (max-width:640px){.subtitle{display:none}}
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
  <span class="subtitle">${T("header.subtitle", { version: PLUGIN_VERSION })}</span>
  <div class="langswitch" id="langswitch" data-current="${locale}" role="group" aria-label="${T("lang.group")}">
    <button type="button" data-lang="en"${locale === "en" ? ' aria-pressed="true"' : ' aria-pressed="false"'}>EN</button>
    <button type="button" data-lang="zh"${locale === "zh" ? ' aria-pressed="true"' : ' aria-pressed="false"'}>中文</button>
  </div>
</header>
<div class="tabs" id="tabs">
  <button class="tab active" data-tab="metrics">${T("tab.metrics")}</button>
  <button class="tab" data-tab="events">${T("tab.events")}</button>
  <button class="tab" data-tab="blocks">${T("tab.blocks")}</button>
  <button class="tab" data-tab="config">${T("tab.config")}</button>
</div>
<!-- 持久状态条（区别于 config.save 流程的瞬时横幅）。面板加载时
     读一次 security.status 渲染，不轮询；仅当用户开过 runtimeHooks 而
     bootstrap 探测到 hook 未加载（静默降级）时显示。 -->
<div id="hook-status-bar" style="display:none;background:var(--warn);color:#000;padding:6px 10px;border-radius:4px;margin:8px 16px 0;font-size:12px;white-space:pre-wrap"></div>
<div class="panel" id="panel"><div class="spinner">${T("spinner.loading")}</div></div>
<div class="refresh" id="refresh"></div>

<!-- 公众号二维码预览层。静态放在 #panel 之外，Metrics 页脚
     "关注公众号" 点击切换显隐；自动刷新只重写 #panel.innerHTML，不触碰本层。 -->
<div class="qr-modal" id="qr-modal" style="display:none">
  <div class="qr-overlay"></div>
  <div class="qr-card">
    <button type="button" class="qr-close" id="qr-close" aria-label="${T("qr.close")}">&#10005;</button>
    <img src="/openclaw-security-monitor/wechat-mp-qr.jpg" alt="${T("qr.alt")}">
    <div class="qr-note">${T("qr.note")}</div>
  </div>
</div>
<div class="toast" id="toast"></div>

<noscript>
<div class="error" style="margin:16px;font-size:13px">
  <strong>SST Security Control</strong>
  <p style="margin-top:6px">
    ${T("noscript.lead")}<a href="/openclaw-security-monitor/panel" target="_blank" rel="noopener" style="color:var(--accent);text-decoration:underline">${T("noscript.link")}</a>${T("noscript.tail")}
  </p>
</div>
</noscript>

<script>
(function() {
  // ── i18n ──────────────────────────────────────────────────────────
  // Dictionary for the locale resolved server-side (parseLocale) and inlined
  // with the HTML. It MUST stay in this same script block: tests/panel-auth-rce
  // .test.ts pulls the panel out with a non-greedy regex that only ever matches
  // the first opening script tag, so a second inline dictionary block would be
  // the one picked up and the panel would never execute under the vm harness.
  // (Three traps for editors, all paid for already: spelling that regex's
  // closing tag here emits a real one and truncates the block, because the
  // backslash-escaped form is itself an escape inside this template literal;
  // and naming the opening tag in a comment makes tests that count script tags
  // see a phantom. Describe them, do not spell them.)
  //
  // Third trap, and the quietest: a backslash inside a regex literal is an
  // escape in *this* template too, so what ships is not what you wrote. Two
  // live examples used to ride it: a word-boundary class strip that shipped as
  // a plain substring strip, and an escaped-dot key mangle that shipped as
  // "replace every character". Write split/join / charAt / slice instead — no
  // regex, no escape, nothing to lose.)
  var I18N = ${serializeDictionary(locale)};
  // Mirrors RAW_FALLBACK_PREFIXES in src/panel-i18n.ts; kept in sync by
  // tests/panel-i18n.test.ts so the two copies cannot drift.
  var RAW_PREFIXES = ${JSON.stringify(RAW_FALLBACK_PREFIXES)};
  function T(key, vars) {
    var s = I18N[key];
    if (typeof s !== "string" || s === "") {
      // Unknown enum value (a decision / severity / layer the backend grew
      // after this build): fall back to the raw identifier so the badge reads
      // "degrade", never "decision.degrade" and never blank.
      for (var i = 0; i < RAW_PREFIXES.length; i++) {
        if (key.indexOf(RAW_PREFIXES[i]) === 0) return key.slice(RAW_PREFIXES[i].length);
      }
      return key;
    }
    if (vars) {
      for (var k in vars) s = s.split("{" + k + "}").join(String(vars[k]));
    }
    return s;
  }

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
    link.title = T("fullView.title");
    link.textContent = T("fullView.label");
    link.style.cssText = 'margin-left:8px;font-size:11px;color:var(--accent);text-decoration:none;border:1px solid var(--border);border-radius:4px;padding:3px 8px;background:var(--subtle-bg);white-space:nowrap';
    var subtitle = document.querySelector('header .subtitle');
    if (subtitle) subtitle.parentNode.insertBefore(link, subtitle.nextSibling);
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', injectFullViewButton);
  } else {
    injectFullViewButton();
  }

  // 语言切换控件：把选择写进插件自己的状态文件（panel-state.json）再整页重载。
  // locale 在服务端渲染时固化（dangerReason 经 HTML 属性往返，中途切语言
  // 无法重渲染），所以没有前端热切，只能 reload。
  //
  // 为什么不是 security.config.save + application.panelLocale：写宿主
  // openclaw.json 会让 gateway 重载全部插件，实测有 1.7~4.8s 所有插件路由 500，
  // 加上等路由缓过来的时间，一次语言切换要 8.4 秒才看得到效果。语言是一个
  // UI 偏好，不值得为它把整个插件栈换一遍血。
  function wireLangSwitch() {
    var box = document.getElementById('langswitch');
    if (!box) return;
    var current = box.getAttribute('data-current');
    var buttons = box.querySelectorAll('button');
    for (var i = 0; i < buttons.length; i++) wireLangButton(buttons[i], current);
  }

  // 单独一个具名函数、btn 用参数传进来，不用循环变量直接进闭包：var 是函数
  // 作用域的，直接在循环里 var btn = buttons[i] 会被后一轮覆盖，两个按钮都
  // 变成只对最后一个生效。
  //
  // 另：事件对象的 currentTarget 只在派发期间有效，一进 promise 回调就是 null。
  // 在 catch 里写 ev.currentTarget.disabled = false 会抛
  // "Cannot set properties of null"，异常本身又把"按钮恢复可点"这一步吃掉，
  // 控件就此永久变灰——所以这里全程只认参数传进来的 btn。
  function wireLangButton(btn, current) {
    btn.addEventListener('click', function () {
      var target = btn.getAttribute('data-lang');
      if (!target || target === current) return;
      btn.disabled = true;
      // 立刻说"切换中"，而不是等写入成功才说"已保存"：这次写入不碰宿主配置，
      // 正常情况下几百毫秒就刷新过去了，文案必须对得上这段时间里页面仍然是
      // 旧语言这件事——按钮写着"已保存"却半天不换语言，正是被当成坏掉的原因。
      btn.textContent = T('lang.switching');
      rpc('security.panel.locale.set', { locale: target })
        .then(function (res) {
          // rpc() 把 payload 原样交回来，服务端拒绝是 {ok:false,error} 而不是
          // 抛异常。不看 ok 的话，一次"字段校验失败"也会被当成保存成功，
          // 按钮卡在切换中、页面永远不变——又是一个看起来像坏了的失败。
          if (res && res.ok === false) {
            throw new Error(String((res.error && res.error.message) || 'panel locale save failed'));
          }
          // ?lang= 在 parseLocale 里独占决定权。不从地址栏摘掉它的话，
          // 偏好虽然写成功了，刷新后仍被 URL 盖回原语言——看起来像按钮坏了。
          if (window.location.search.indexOf('lang=') !== -1) {
            // 用 slice 而非 replace(/^\?/)：这段 JS 位于面板 HTML 的
            // template literal 内，反斜杠会被模板字面量吃掉（\? 会变成 ?，
            // 发出 /^\?/ 这种非法正则）。同理此处不写任何正则。
            var search = window.location.search;
            var rest = (search.charAt(0) === '?' ? search.slice(1) : search)
              .split('&')
              .filter(function (kv) { return kv.split('=')[0] !== 'lang'; })
              .join('&');
            window.history.replaceState(
              null, '',
              window.location.pathname + (rest ? '?' + rest : '') + window.location.hash
            );
          }
          // 偏好已经落盘。minWaitMs 传 0：这次写入没有触碰宿主配置，正常情况
          // 下路由一直可读，两次探询就导航（~0.5s）。万一宿主连插件自己的状态
          // 文件也 watch（今天的证据是不会），窗口会在写入 1.7s 后才打开，而
          // 我们在这之前就已经刷新到新语言了；nonce 随窗口失效时 rpc() 的
          // 401/403 分支会把面板自己重载一次，一两秒后自愈。
          reloadAfterGatewaySettles({ minWaitMs: 0 });
        })
        .catch(function (err) {
          // 无论失败成什么样，控件必须回到可点状态：卡成灰色是最糟的失败方式，
          // 用户既看不到原因也换不回另一种语言。页面整体卡死时 toast 未必
          // 存在，typeof 兜住，不让恢复动作再抛一次。
          btn.disabled = false;
          btn.textContent = target === 'en' ? 'EN' : '中文';
          if (typeof toast === 'function') toast(String((err && err.message) || err));
        });
    });
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', wireLangSwitch);
  } else {
    wireLangSwitch();
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
  // 本页是否成功过一次 RPC。区分"用着用着过期"与"一开始就过不了"，只有前者
  // 才值得自动重载（见下面 rpc() 的 TypeError 分支）。
  var rpcEverOk = false;

  // ── 写宿主配置 → 宿主重载窗口 ──────────────────────────────────────
  //
  // security.config.save 写的是**宿主**的 openclaw.json。宿主随后重载插件
  // 配置，那个窗口里所有插件路由都由宿主自己回 500（text/plain、**不带**
  // CORS 头）——本插件的 handler 根本没被调用，所以拿不到 ACAO。浏览器把
  // 读不到响应的失败一律报成 TypeError("Failed to fetch")，而正落在这个窗口
  // 里的 window.location.reload() 会把操作者直接甩到一张裸 500 页上：用户点
  // 语言开关 → 控制台一串 CORS 报错 → GET panel-tab 500，面板从此是死的。
  //
  // 实测（2026-10-23，本机 tunnel 到远端 gateway，真实 Chrome 点一遍）：
  //   · 不写配置：连续 44 次预检全部 204 + ACAO null，零异常；
  //   · 写一次配置：保存 200 后约 2s 起所有路由 500（无 ACAO，读不到），约 4.5s
  //     结束；窗口过后插件被重新实例化，本次加载铸的 panel nonce 失效，此后
  //     每个 RPC 都拿到**可读**的 403 —— 本次加载只能靠重新渲染（reload）复活。
  // 也就是说"能读到响应" = 宿主已经缓过来，"读不到" = 还在窗口里。
  //
  // 判据因此是"**连续可读**"，不是"过了多久"：窗口是在写入之后才打开的，一
  // 上来就连探到 200 是"还没坏"的假信号。可读连续 RELOAD_SETTLE_READABLE_STREAK
  // 次即视为缓过来；minWaitMs 只用来在"一直没坏"的情况下替假信号兜底——写宿主
  // 配置时留 3s（窗口在 1.7~2.5s 后才打开），不写宿主配置时留 0（见
  // wireLangButton：语言偏好写的是插件自己的状态文件，宿主不必重载）。
  //
  // 这三个值曾经是 STREAK 3.5s / MAX 8s，而窗口本身就要 1.7~4.5s：streak 永远
  // 攒不满，实测每次切换都走 8s 上限的兜底分支，按钮灰着、文案"已保存"卡满
  // 8.4 秒才刷新——用户看到的就是"点了没反应"。
  var RELOAD_SETTLE_READABLE_STREAK = 2;
  var RELOAD_SETTLE_POLL_MS = 250;
  var RELOAD_SETTLE_MAX_MS = 12000;
  // 单次探询自带超时。fetch 不返回（隧道挂住、宿主收下连接不吐响应）时，
  // 上限判断在 .then 里，永远轮不到 —— 页面就此钉在"切换中"再也不会导航。
  var RELOAD_SETTLE_PROBE_TIMEOUT_MS = 3000;

  function reloadNow() {
    try { window.location.reload(); }
    catch (e) { /* 极端沙箱限制下 reload 被拒，静默降级 */ }
  }

  // 探一次路由：resolve = 宿主给出了可读响应（200，或 nonce 失效的可读 403），
  // reject = 还在 500 窗口里 / 网络不通。刻意不走 rpc()：它把可读的 401/403
  // 转成永不 resolve 的 promise 并自己再排一次 reload，这里要的是状态本身。
  function probeRouteReadable() {
    var controller = (typeof AbortController !== "undefined") ? new AbortController() : null;
    var timer = controller ? setTimeout(function () { controller.abort(); }, RELOAD_SETTLE_PROBE_TIMEOUT_MS) : null;
    return fetch(BASE + "/openclaw-security-monitor/panel", {
      method: "POST",
      headers: {"Content-Type":"application/json","X-Panel-Nonce":PANEL_NONCE},
      credentials: "same-origin",
      body: JSON.stringify({ method: "security.status", params: {} }),
      signal: controller ? controller.signal : undefined
    }).then(function () { return true; }, function () { return false; })
      .then(function (readable) { if (timer) clearTimeout(timer); return readable; });
  }

  // 等宿主缓过来再导航。opts.minWaitMs = 在路由一直可读时至少先观察多久；
  // opts.beforeReload 返回 false 时放弃导航（Config 页有未保存改动时用）。
  // 上限 RELOAD_SETTLE_MAX_MS 后无条件导航：宁可让用户看到宿主的错误页，也
  // 不要把面板永远钉在坏状态里。
  function reloadAfterGatewaySettles(opts) {
    var beforeReload = opts && opts.beforeReload;
    var minWaitMs = (opts && opts.minWaitMs) || 0;
    var started = Date.now();
    var readableStreak = 0;
    (function attempt() {
      probeRouteReadable().then(function (readable) {
        var now = Date.now();
        readableStreak = readable ? readableStreak + 1 : 0;
        var settled = readableStreak >= RELOAD_SETTLE_READABLE_STREAK && (now - started) >= minWaitMs;
        if (!settled && (now - started) < RELOAD_SETTLE_MAX_MS) {
          setTimeout(attempt, RELOAD_SETTLE_POLL_MS);
          return;
        }
        if (beforeReload && beforeReload() === false) return;
        reloadNow();
      });
    })();
  }

  function scheduleAuthReload() {
    if (authReloadScheduled) return;
    authReloadScheduled = true;
    // 留 50ms 让当前 setInterval tick 把"Failed to fetch"渲染完再重载，
    // 避免连续两次刷新请求重叠。sandboxed iframe 内 window.location.reload
    // 仍允许（沙箱不影响 reload 自身 URL）。
    setTimeout(function() {
      // Config 页有未保存改动时不重载：刷新会把用户正在填的表单冲掉，而
      // "⚠ Failed to fetch" 已经留在页面上说明了原因，用户自己决定何时刷。
      if (__configDirty) {
        authReloadScheduled = false;
        return;
      }
      reloadNow();
    }, 50);
  }

  // 读不到响应的失败（宿主 500 窗口 / 隧道抖动）走"缓过来再重载"：可读的
  // 401/403 说明路由在应答，直接重载即可；读不到的恰恰是宿主在换血，此刻
  // 重载正好撞上去。
  function scheduleAuthReloadWhenSettled() {
    if (authReloadScheduled) return;
    authReloadScheduled = true;
    reloadAfterGatewaySettles({
      // 这条路径的触发源是读不到响应（宿主正在换血），不是我们刚写完配置，
      // 没有"窗口还没打开"的假信号要躲，探到可读就走。
      minWaitMs: 0,
      beforeReload: function () {
        if (__configDirty) {
          authReloadScheduled = false;
          return false;
        }
        return true;
      }
    });
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
      if (r.status === 200) rpcEverOk = true;
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
      // sandboxed iframe 里 Origin 恒为 "null"，宿主/本插件的 401/403 都是
      // 不带 Access-Control-Allow-Origin 发出的，浏览器的 CORS 检查会让 fetch
      // 直接 reject 成 TypeError —— r 从来没出现过，上面那个 status 分支在这条
      // 路径上**根本走不到**。所以"认证过期 → 自动重载"在这里曾经是死代码，
      // 表现就是每次自动刷新都把面板内容换成 "⚠ Failed to fetch" 且永不恢复，
      // 只能手动 F5。按 TypeError（而非状态码）识别，才能真正自愈。
      if (err && err.name === "TypeError" && rpcEverOk) {
        // rpcEverOk 是关键判据：它区分了"会话从能用变成不能用"（长挂后宿主
        // session 过期，重载能换到新 grant，值得自愈）和"这次加载就没能过"
        // （授权本来就发不下来 / 网断了，重载一万次也还是不通）。后者若也
        // 重载，就是"每 30s 刷新一次、永远停在加载中"的死循环——而本页里
        // authReloadScheduled 去重只能管住本页，管不住新的一页。
        // 注意这个标志**不能**做成跨页计数：sandboxed iframe 里 localStorage
        // 和 sessionStorage 都读不了（宿主自己的 bundle 就栽在这上面）。
        //
        // 只补"要重载"的信号，错误继续抛出去。**不能**像上面 401/403 分支那样
        // 返回一个永不 resolve 的 Promise：那会让所有下游 .catch 全部失效，
        // 语言切换按钮就停在 disabled 上再也点不动——恰好在重载没发生
        // （Config 有未保存改动）时最致命。抛出后页面很快就会被换掉。
        //
        // 读不到响应 = 宿主 500 窗口（写宿主配置之后）或隧道抖动。此刻立刻
        // reload 会正好落进窗口、把用户甩到裸 500 页，所以改成"缓过来再重载"。
        scheduleAuthReloadWhenSettled();
      }
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
    copy:  T("copy.idle"),
    check: T("copy.ok"),
    alert: T("copy.fail")
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
    var hint = intervention.remediation_hint || T("appeal.defaultHint");
    return ' <span class="appeal-tag" title="'+escAttr(hint)+'">appealable</span>';
  }

  function error(e) {
    return '<div class="error">⚠ '+esc(e && e.message ? e.message : e)+'</div>';
  }

  // ── 两视图共用 chrome ──────────────────────────────────────────────
  // 分页页脚 / 事件详情 JSON 面板 / 展开行暂停横幅，这三段在 Policy Hits 与
  // Event Stream 各有一份字面相同的实现（连 id 后缀都只差 events-/blocks-）。
  // 文案改版时两处不同步就会漂移，故集中到此处，各视图只传差异参数。

  /**
   * 分页页脚：计数 + Load more / end of results。
   * total 是判定"还有下一页"的数字，不能传带符号的展示值——
   * "200+" 转成 NaN 会让 shown < total 恒假，永远显示 end of results。
   * overflowMark 追加到计数文案
   * （events 用 "+" 表示日志已被内存上限截断，见 truncatedBanner）；
   * prefixHtml 为前置横幅。
   */
  function pagerFooter(btnId, shown, total, unit, prefixHtml, overflowMark) {
    var more = shown < total
      ? '<button id="'+escAttr(btnId)+'">'+esc(T("pager.loadMore"))+'</button>'
      : '<span class="meta">'+esc(T("pager.endOfResults"))+'</span>';
    // unit arrives as a wire identifier ("events" / "hits"); resolve it so
    // the count reads "20 events" / "20 条" rather than an untranslated noun.
    return (prefixHtml || '') +
      '<span class="meta">'+esc(T("pager.showing", { shown: shown, total: total, mark: overflowMark || "", unit: T("pager.unit."+unit) }))+'</span> '+more;
  }

  /** 事件详情行的 JSON 面板：标题 + 复制按钮 + 预格式化正文。 */
  function jsonPaneHtml(rawJson) {
    return '<div class="json-pane">'+
      '<div class="json-pane-header">'+
        '<div class="json-pane-title">'+esc(T("jsonPane.title"))+'</div>'+
        makeCopyButton()+
      '</div>'+
      '<pre class="json-view">'+rawJson+'</pre>'+
    '</div>';
  }

  /** 详情行展开时的自动刷新暂停横幅。样式与 Config 的 #config-dirty-bar 逐像素一致。 */
  function detailPausedBanner() {
    return '<div id="detail-paused-banner" style="display:none;background:var(--warn);color:#000;padding:6px 10px;border-radius:4px;margin-bottom:8px;font-size:12px">'+esc(T("detail.paused"))+'</div>';
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
      '<a id="open-website" href="'+escAttr(WEBSITE_URL)+'" target="_blank" rel="noopener noreferrer">'+esc(T("footer.visitSite"))+'</a>'+
      '<a id="show-qr" href="#">'+esc(T("footer.followWeChat"))+'</a>'+
      '</div>';
    if (d == null) return '<div class="error">'+esc(T("metric.noData"))+'</div>'+footer;
    var m = d.metrics || d;
    var blocks = m.blocks || m.blockCount || 0;
    var threats = m.threats || 0;
    var total = m.total || m.eventCount || 0;
    var last24 = m.last24h || 0;
    var byLayer = m.byLayer || {};
    // bySeverity / byDecision 后端一直在传（O(1) 聚合），但本视图只渲染
    // 指标卡 + By Layer：分级卡片此前算了却从未拼进返回值。已确认不恢复，
    // 以后要加请直接重建卡片，不要重新引入"算了不画"的死变量。
    var layerRows = Object.keys(byLayer).map(function(k) {
      return '<div class="meta">'+esc(T("layer."+k))+': <span class="hl">'+esc(byLayer[k])+'</span></div>';
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
      cell(total, T("metric.totalEvents"))+
      cell(last24, T("metric.last24h"))+
      cell(blocks, T("metric.blocked"), "alert")+
      cell(threats, T("metric.threatEvents"), "warn")+
      (layerRows ? '<div class="card" style="grid-column:1/-1"><h2>'+esc(T("metric.byLayer"))+'</h2>'+layerRows+'</div>' : '')+
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
    return '<table><thead><tr><th>'+esc(T("th.time"))+'</th><th>'+esc(T("th.type"))+'</th><th>'+esc(T("th.layer"))+
      '</th><th>'+esc(T("th.severity"))+'</th><th>'+esc(T("th.agent"))+'</th><th>'+esc(T("th.toolSession"))+
      '</th><th>'+esc(T("th.status"))+'</th></tr></thead><tbody id="events-body"></tbody></table>';
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
      var decisionBadge = decision ? badge(decisionBadgeClass(decision), T("decision."+decision)) : "";
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
      var sevCell = sev ? badge(severityBadgeClass(sev), T("sev."+sev)) : '<span class="muted">—</span>';
      var rawJson = esc(JSON.stringify(r, null, 2));
      html += '<tr class="event-row" data-event-idx="'+idx+'">'+
        '<td class="ts">'+ts(r.ts)+'</td>'+
        '<td><span class="tool">'+esc(eventType)+'</span></td>'+
        '<td>'+esc(r.layer ? T("layer."+r.layer) : "")+'</td>'+
        '<td>'+sevCell+'</td>'+
        '<td>'+esc(r.agent_id || r.agentId || "—")+'</td>'+
        '<td><span class="tool">'+toolName+'</span><div class="meta">'+session+'</div></td>'+
        '<td>'+decisionBadge+'</td>'+
        '</tr>'+
        '<tr class="event-detail" data-detail-idx="'+idx+'"><td colspan="7">'+
          jsonPaneHtml(rawJson)+
        '</td></tr>';
    });
    return html;
  }

  // ── Policy Hits state + paging ────────────────────────────────────
  function buildBlocksShell() {
    return detailPausedBanner()+
      '<div id="blocks-table"><div class="spinner">'+esc(T("spinner.loading"))+'</div></div>'+
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
          { key: "all", label: T("capsule.all"), count: totalCount, cls: "allow" },
          { key: "block", label: T("capsule.block"), count: (byDecision && byDecision.block) || 0, cls: "block" },
          { key: "warn", label: T("capsule.warn"), count: (byDecision && byDecision.warn) || 0, cls: "warn" },
          { key: "modify", label: T("capsule.modify"), count: (byDecision && byDecision.modify) || 0, cls: "change" },
          { key: "audit", label: T("capsule.audit"), count: (byDecision && byDecision.audit) || 0, cls: "warn" },
        ];
        var capsuleHtml = capsuleDefs.map(function(c) {
          var active = blocksState.filter === c.key ? " active" : "";
          return '<span class="capsule '+esc(c.cls)+active+'" data-capsule="'+esc(c.key)+'">'+esc(c.label)+' <span class="count">'+esc(c.count)+'</span></span>';
        }).join("");
        tableArea.innerHTML = '<div class="capsule-row">'+capsuleHtml+'</div>'+
          '<table><thead><tr><th>'+esc(T("th.time"))+'</th><th>'+esc(T("th.tool"))+'</th><th>'+esc(T("th.decision"))+
          '</th><th>'+esc(T("th.policy"))+'</th><th>'+esc(T("th.reason"))+'</th></tr></thead><tbody id="blocks-body"></tbody></table>';
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
      footerArea.innerHTML = pagerFooter("blocks-more", shown, blocksState.total, "hits");
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
      var decisionBadge = badge(decisionBadgeClass(decision), T("decision."+decision));
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
      detailTr.innerHTML = '<td colspan="5">'+jsonPaneHtml(rawJson)+'</td>';
      tbody.appendChild(tr);
      tbody.appendChild(detailTr);
    });
  }

  // renderBlocks() 曾与 renderBlocksBody() 并存：整表重渲版本已无调用方
  // （Policy Hits 走「骨架 + tbody append」路径，见 loadBlocks）。它重复了
  // 表头与详情行 JSON 面板两处字面量，并独自持有一份分页页脚文案——三份
  // 副本在改版时会各自漂移。已删除；需要重渲 tbody 请用 renderBlocksBody()。

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
    if (d == null) return '<div class="error">'+esc(T("config.noConfig"))+'</div>';
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

    // CONFIG_SCHEMA carries dictionary KEYS (cfg.label.* / cfg.help.* / cfg.danger.*),
    // not prose, so a locale switch can never leave a stale Chinese string behind
    // in the schema itself. Absent key → empty string (optional fields).
    // vars fills in per-field runtime values (the NODE_OPTIONS preload paths),
    // so help prose never hard-codes a path that only holds on some machines.
    function cfgText(key, vars) { return key ? T(key, vars) : ""; }

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
      // 用 split/join 而不是 replace(/\./g, '-')：这段 JS 在面板 HTML 的
      // template literal 里，正则里的反斜杠会被模板字面量吃掉，产出的其实是
      // /./g ——把键名里**每一个字符**都换成短横。长度相同的两个配置键
      // （"procfs.pythonPath" 与任何同长度的键）因此会拿到同一个 id。
      var id = 'cfg-' + f.section + '-' + f.key.split('.').join('-');

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
          depHtml = '<div class="meta" style="color:var(--muted);margin-top:2px">'+esc(T("config.depHint", {
            deps: unmetDeps.map(function(d) { return '<code>'+esc(d.section+'.'+d.key)+'</code>'; }).join(esc(T("config.depJoiner")))
          }))+'</div>';
        }
      }

      var dangerText = cfgText(f.dangerReason);
      var dangerAttr = f.danger ? ' data-danger="1" data-danger-reason="'+escAttr(dangerText)+'"' : '';
      var dangerMark = f.danger ? ' <span style="color:var(--danger);font-size:10px">'+esc(T("config.dangerMark"))+'</span>' : '';
      var helpHtml = f.danger && dangerText
        ? '<div class="meta" style="color:var(--danger);margin-top:2px">⚠ '+esc(dangerText)+'</div>'
        : '';
      var helpBlockHtml = f.help
        ? '<div class="meta" style="color:var(--warn);margin-top:6px;white-space:pre-wrap;font-size:11px;line-height:1.5">'+esc(cfgText(f.help, f.helpVars))+'</div>'
        : '';
      var input = '';
      if (f.type === "bool") {
        var checked = v === true ? ' checked' : '';
        input = '<label style="display:inline-flex;align-items:center;gap:6px;cursor:'+(disabledAttr ? 'not-allowed' : 'pointer')+';line-height:1.6;opacity:'+(disabledAttr ? '0.5' : '1')+'">'+
          '<input type="checkbox" id="'+id+'" data-section="'+escAttr(f.section)+'" data-key="'+escAttr(f.key)+'" data-type="bool"'+checked+disabledAttr+dangerAttr+' style="margin:0;flex:none"/>'+
          '<span class="'+(v?'ok':'warn')+'">'+(v?esc(T("config.on")):esc(T("config.off")))+'</span></label>';
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
        '<div style="flex:0 0 200px"><span class="tool">'+esc(cfgText(f.label))+dangerMark+'</span><div class="meta">'+esc(f.section+'.'+f.key)+'</div></div>'+
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
          '<summary style="cursor:pointer;font-size:12px" class="meta">'+esc(T("config.advanced", { n: advancedFields.length }))+'</summary>'+
          advancedFields.map(function(f) { return inputHtml(f, sectionVal); }).join("")+
          '</details>';
      }
      return '<details class="card" open style="margin-bottom:8px"><summary style="cursor:pointer"><h2 style="display:inline">'+esc(T("sec."+sec))+'</h2> <span class="meta">'+esc(T("config.itemCount", { n: fields.length }))+'</span></summary>'+
        '<form id="config-form" data-section="'+escAttr(sec)+'" autocomplete="off">'+
        body+
        '</form></details>';
    }).join("");

    var html =
      '<div id="config-dirty-bar" style="display:none;background:var(--warn);color:#000;padding:6px 10px;border-radius:4px;margin-bottom:8px;font-size:12px"></div>'+
      '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">'+
        '<span class="meta">'+esc(T("config.sourceHint"))+'</span>'+
        '<div style="display:flex;gap:6px">'+
          '<button type="button" id="reset-config" title="'+escAttr(T("config.resetTitle"))+'">'+esc(T("config.reset"))+'</button>'+
          '<button type="button" id="copy-config">'+esc(T("copy.idle"))+'</button>'+
          '<button type="button" id="save-config" style="background:var(--accent)">'+esc(T("config.save"))+'</button>'+
        '</div>'+
      '</div>'+
      sectionsHtml+
      '<pre id="copy-source" style="display:none">'+esc(JSON.stringify(config, null, 2))+'</pre>'+

      // Danger confirmation modal (L3). Hidden by default; saveConfig() shows
      // it when any changed field has danger:true.
      '<div id="danger-modal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:1000;align-items:center;justify-content:center">'+
        '<div style="background:var(--card-bg);border:1px solid var(--danger);border-radius:8px;padding:20px;max-width:520px;width:90%">'+
          '<h3 style="color:var(--danger);margin-bottom:12px">'+esc(T("danger.title"))+'</h3>'+
          '<div id="danger-modal-body" style="margin-bottom:12px;font-size:12px"></div>'+
          '<label style="display:block;margin-bottom:12px;cursor:pointer;line-height:1.6">'+
            '<input type="checkbox" id="danger-confirm" style="margin:0 6px 0 0;vertical-align:middle"/>'+
            '<span style="font-size:12px;vertical-align:middle">'+esc(T("danger.confirmLabel"))+'</span>'+
          '</label>'+
          '<div style="display:flex;gap:8px;justify-content:flex-end">'+
            '<button type="button" id="danger-cancel">'+esc(T("danger.cancel"))+'</button>'+
            '<button type="button" id="danger-ok" disabled>'+esc(T("danger.ok"))+'</button>'+
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
    if (__configDirty) bar.textContent = T("config.dirty");
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
      '<strong style="color:var(--success)">'+esc(T("banner.savedTitle"))+'</strong><br>' +
      '<span class="meta">'+esc(T("banner.backup", { path: res.backup || T("banner.none") }))+'</span><br>' +
      '<span style="color:var(--warn)">'+esc(T("banner.restart"))+'</span>';
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
      '<strong style="color:var(--warn)">'+esc(T("banner.bootstrapTitle"))+'</strong><br>' +
      '<span class="meta">'+esc(T("banner.bootstrapReason"))+'</span>' +
      '<ul style="margin:8px 0 6px;padding-left:20px">'+items+'</ul>' +
      '<span class="meta">'+esc(T("banner.bootstrapDiagLead"))+'<code>docker logs</code>'+T("banner.bootstrapDiagTail")+'</span>';
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
      '<strong style="color:var(--warn)">'+esc(T("banner.warningsTitle"))+'</strong>' +
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
        '<p style="margin-bottom:8px">'+esc(T("danger.intro"))+'</p>' +
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
    if (btn) { btn.disabled = true; btn.textContent = T("save.saving"); }
    rpc("security.config.save", { patch: patch, confirmDanger: !!confirmDanger, confirmToken: confirmToken || undefined })
      .then(function(res) {
        if (res && res.ok) {
          if (btn) {
            btn.textContent = T("save.saved");
            btn.style.background = "var(--success)";
            setTimeout(function() {
              btn.textContent = T("config.save");
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
          if (btn) { btn.disabled = false; btn.textContent = T("config.save"); }
          openDangerModal(patch, dangerList || null, res.error.confirmToken, res.error.fields || []);
        } else {
          if (btn) { btn.disabled = false; btn.textContent = T("config.save"); }
          var msg = (res && res.error && res.error.message) || T("save.unknownError");
          if (res && res.error && res.error.details) msg += "\\n" + JSON.stringify(res.error.details);
          if (res && res.error && res.error.fields) msg += "\\n" + T("save.needsConfirm") + res.error.fields.join(", ");
          alert(T("save.failed") + msg);
        }
      })
      .catch(function(err) {
        if (btn) { btn.disabled = false; btn.textContent = T("config.save"); }
        alert(T("save.rpcFailed") + (err && err.message ? err.message : err));
      });
  }

  function saveConfig() {
    var c = collectPatch();
    if (Object.keys(c.patch).length === 0) {
      alert(T("save.noChanges"));
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
      var txt = t === '' ? T("events.allTypes") : t;
      return '<option value="'+escAttr(t)+'"'+sel+'>'+esc(txt)+'</option>';
    }).join('');
    // Pause banner — same shape as Config's #config-dirty-bar (var(--warn) bg,
    // black text, 6px 10px padding, radius 4px). Sits above the toolbar so it
    // stays visible regardless of scroll position and matches Config's
    // pause affordance pixel-for-pixel. Shared with Policy Hits — see
    // detailPausedBanner().
    return detailPausedBanner()+
      '<div class="toolbar">'+
      '<select id="filter-event-type">'+opts+'</select>'+
      '<input id="filter-since" placeholder="'+escAttr(T("events.since"))+'" value="'+escAttr(eventsState.sinceMinutes)+'" style="max-width:170px"/>'+
      '<button id="filter-apply">'+esc(T("events.apply"))+'</button>'+
      '<span class="grow"></span>'+
      '<span class="meta" id="filter-help">'+esc(T("events.limit"))+'</span>'+
      '</div>'+
      '<div id="events-table"><div class="spinner">'+esc(T("spinner.loading"))+'</div></div>'+
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
          : '<div class="empty">'+esc(T("events.empty"))+'</div>';
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
        ? '<div class="banner">'+esc(T("events.truncated"))+'</div>'
        : '';
      var shown = eventsState.offset;
      footerArea.innerHTML = pagerFooter("events-more", shown, eventsState.total, "events",
        truncatedBanner, eventsState.truncated ? "+" : "");
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
      document.getElementById("refresh").textContent = T("refresh.updated", { time: new Date().toLocaleTimeString() })+" "+T("refresh.pausedConfig");
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
      document.getElementById("refresh").textContent = T("refresh.updated", { time: new Date().toLocaleTimeString() })+" "+T("refresh.pausedDetail");
      if (bannerEl) bannerEl.style.display = "block";
      return;
    }
    if (bannerEl) bannerEl.style.display = "none";
    var now = new Date().toLocaleTimeString();
    document.getElementById("refresh").textContent = T("refresh.updated", { time: now });

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
      p = Promise.resolve('<div class="empty">'+esc(T("misc.unknownTab"))+'</div>');
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
          btn.textContent = T("copy.configCopied");
          setTimeout(function() { btn.textContent = T("copy.idle"); }, 1500);
        }, function() { btn.textContent = T("copy.configFailed"); });
      }, function() {
        copyText(fallbackJson).then(function() {
          btn.textContent = T("copy.configCopiedFallback");
          setTimeout(function() { btn.textContent = T("copy.idle"); }, 1500);
        }, function() { btn.textContent = T("copy.configFailed"); });
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
          toast(ok ? T("toast.copied") : T("toast.cannotOpen", { url: WEBSITE_URL }));
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
      // 有解析出的预加载路径就用带路径的文案直接把它印出来：这段警告最常见的
      // 成因就是 NODE_OPTIONS 指了一条当前机器上并不存在的路径，而路径必须
      // 现读现算（容器里的 home 与宿主机的 home 不是同一个）。
      // 注意换行只能来自词典 —— 面板 JS 位于 index.ts 的模板字面量内，那里的
      // 转义序列会在编译期被吃掉，产出无法解析的字符串字面量。
      var hookPath = (st && typeof st.runtimeHookPath === "string") ? st.runtimeHookPath : "";
      bar.textContent = hookPath
        ? T("status.hookNotLoadedWithPath", { hookPath: hookPath })
        : T("status.hookNotLoaded");
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
//
// `label` / `help` / `dangerReason` hold **dictionary keys**, not prose:
// `cfg.label.<section>.<key>`, `cfg.help.<section>.<key>`,
// `cfg.danger.<section>.<key>`, resolved by the panel through
// src/panel-i18n.ts. Storing keys rather than one language's text is what
// keeps a single source of truth — the prose lives in exactly one place and a
// language switch cannot leave a stale Chinese string behind in the schema.
// tests/panel-i18n.test.ts fails if a field here has no matching dictionary
// entry, so adding a row without its copy is a red test, not a silent gap.
interface ConfigField {
  section: string;
  key: string;
  /** Dictionary key: cfg.label.<section>.<key> */
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
  // the input is rendered disabled with an inline "enable X first" hint and
  // its current value is not editable. Use for child toggles that have no
  // effect when their parent toggle is off (e.g. networkEnabled vs.
  // runtimeHooks.enabled) so users don't read a stale "on" state as
  // "feature is running". An array means ALL listed deps must be satisfied
  // (e.g. procfs.pythonPath needs system.enabled AND procfs.enabled); the
  // single-object form keeps working.
  dependsOn?: { section: string; key: string; value?: unknown } | Array<{ section: string; key: string; value?: unknown }>;
  // Fold the field into a per-section "advanced" collapse (default collapsed).
  // Use for tuning knobs that are safe to ignore for day-to-day operation;
  // unlike `hidden` the field stays discoverable one click away.
  advanced?: boolean;
  // Optional long-form instructions shown below the input. Dictionary key:
  // cfg.help.<section>.<key>. Use for fields that need operator-side setup
  // beyond a simple toggle (e.g. docker env vars, host preloads).
  // `dangerReason` (cfg.danger.<section>.<key>) is reserved for short
  // warnings inside the danger-confirm modal.
  help?: string;
  /** Values substituted into the `help` prose's {placeholders}. Injected per
   *  request by withRuntimeHelpVars rather than baked into the module-level
   *  schema: the paths depend on the runtime environment (a container's home
   *  is not the operator's home), and CONFIG_SCHEMA is also exported for
   *  tests that would then pin whatever machine happened to build them. */
  helpVars?: Record<string, string>;
  danger?: boolean;
  dangerReason?: string;
}
/**
 * 把运行期才能确定的值（NODE_OPTIONS 预加载路径）填进帮助文案的占位符。
 *
 * 此前这段路径是硬编码在词典里的字面量（`.../extensions/<id>/runtime.js`），
 * 于是两件事同时错：它指向的文件根本不在安装包里（是插件每次启动现拷进去
 * 的），而文案里的 `/home/node` 对宿主机直装用户又是错的。现在路径一律由
 * src/hook-locations.ts 在请求时解析，词典只留 `{preloadTarget}` 占位符 ——
 * 面板从此不可能印出一条在当前机器上不成立的命令。
 */
function withRuntimeHelpVars(schema: ConfigField[]): ConfigField[] {
  const preloadTarget = resolvePreloadTarget();
  // 只给数据目录这一条路径。安装目录（extensions/<id>/）曾经也印给过用户，
  // 但它由宿主安装器拥有、随装卸来去：预加载目标放在那里一旦消失就是启动
  // 失败，且无从重建。现在它在文案里只作为**反例**出现。
  return schema.map((f) =>
    f.section === "application" && f.key === "runtimeHooks.enabled"
      ? { ...f, helpVars: { preloadTarget } }
      : f
  );
}

const CONFIG_SCHEMA: ConfigField[] = [
  { section: "collector", key: "ndjsonPath", label: "cfg.label.collector.ndjsonPath", type: "string",
    danger: true, dangerReason: "cfg.danger.collector.ndjsonPath" },
  { section: "collector", key: "maxFileSizeBytes", label: "cfg.label.collector.maxFileSizeBytes", type: "number", min: 0, max: 1073741824,
    danger: true, dangerReason: "cfg.danger.collector.maxFileSizeBytes" },
  { section: "collector", key: "maxEventsInMemory", label: "cfg.label.collector.maxEventsInMemory", type: "number", min: 100, max: 50000,
    hidden: true,
    danger: true, dangerReason: "cfg.danger.collector.maxEventsInMemory" },
  { section: "application", key: "enabled", label: "cfg.label.application.enabled", type: "bool" },
  { section: "application", key: "captureUserPrompt", label: "cfg.label.application.captureUserPrompt", type: "bool" },
  { section: "application", key: "captureSystemPrompt", label: "cfg.label.application.captureSystemPrompt", type: "bool" },
  { section: "application", key: "captureAgentPlan", label: "cfg.label.application.captureAgentPlan", type: "bool" },
  { section: "application", key: "captureCodeMode", label: "cfg.label.application.captureCodeMode", type: "bool",
    help: "cfg.help.application.captureCodeMode" },
  { section: "application", key: "captureReasoning", label: "cfg.label.application.captureReasoning", type: "bool" },
  { section: "application", key: "captureUserId", label: "cfg.label.application.captureUserId", type: "bool",
    help: "cfg.help.application.captureUserId" },
  { section: "application", key: "userIdField", label: "cfg.label.application.userIdField", type: "string", min: 1, max: 64,
    danger: true, dangerReason: "cfg.danger.application.userIdField",
    help: "cfg.help.application.userIdField"
  },
  { section: "application", key: "maxContentLength", label: "cfg.label.application.maxContentLength", type: "number", min: 100, max: 100000,
    hidden: true },
  { section: "application", key: "sessionTtlMs", label: "cfg.label.application.sessionTtlMs", type: "number", min: 60000, max: 86400000,
    hidden: true },
  { section: "application", key: "runtimeHooks.enabled", label: "cfg.label.application.runtimeHooks.enabled", type: "bool",
    danger: true, dangerReason: "cfg.danger.application.runtimeHooks.enabled",
    help: "cfg.help.application.runtimeHooks.enabled"
  },
  { section: "application", key: "runtimeHooks.networkEnabled", label: "cfg.label.application.runtimeHooks.networkEnabled", type: "bool",
    dependsOn: { section: "application", key: "runtimeHooks.enabled", value: true },
    help: "cfg.help.application.runtimeHooks.networkEnabled"
  },
  // 面板语言。非 danger 字段：切语言不需要二次确认，也不需要重启 gateway
  // ——面板 GET 每次现读 host 配置（readPanelLocalePreference）。
  { section: "application", key: "panelLocale", label: "cfg.label.application.panelLocale", type: "enum", values: ["auto", "en", "zh"],
    help: "cfg.help.application.panelLocale" },
  { section: "system", key: "enabled", label: "cfg.label.system.enabled", type: "bool",
    danger: true, dangerReason: "cfg.danger.system.enabled",
    help: "cfg.help.system.enabled"
  },
  { section: "system", key: "procfs.enabled", label: "cfg.label.system.procfs.enabled", type: "bool",
    dependsOn: { section: "system", key: "enabled", value: true },
    help: "cfg.help.system.procfs.enabled"
  },
  { section: "system", key: "cgroups.enabled", label: "cfg.label.system.cgroups.enabled", type: "bool",
    dependsOn: { section: "system", key: "enabled", value: true },
    help: "cfg.help.system.cgroups.enabled"
  },
  { section: "system", key: "procfs.pythonPath", label: "cfg.label.system.procfs.pythonPath", type: "string",
    dependsOn: [
      { section: "system", key: "enabled", value: true },
      { section: "system", key: "procfs.enabled", value: true },
    ] },
  { section: "system", key: "procfs.scanIntervalMs", label: "cfg.label.system.procfs.scanIntervalMs", type: "number", min: 100, max: 60000,
    advanced: true,
    dependsOn: [
      { section: "system", key: "enabled", value: true },
      { section: "system", key: "procfs.enabled", value: true },
    ] },
  { section: "intervention", key: "enabled", label: "cfg.label.intervention.enabled", type: "bool",
    danger: true, dangerReason: "cfg.danger.intervention.enabled" },
  { section: "intervention", key: "mode", label: "cfg.label.intervention.mode", type: "enum", values: ["enforce", "audit"],
    danger: true, dangerReason: "cfg.danger.intervention.mode" },
  { section: "intervention", key: "failStrategy", label: "cfg.label.intervention.failStrategy",
    type: "enum", values: ["fail_open", "fail_closed", "fail_open_high_risk_only"],
    danger: true, dangerReason: "cfg.danger.intervention.failStrategy" },
  { section: "intervention", key: "guidance.enabled", label: "cfg.label.intervention.guidance.enabled", type: "bool",
    danger: true, dangerReason: "cfg.danger.intervention.guidance.enabled",
    help: "cfg.help.intervention.guidance.enabled" },
  { section: "intervention", key: "reportBlockedEvents", label: "cfg.label.intervention.reportBlockedEvents", type: "bool",
    danger: true, dangerReason: "cfg.danger.intervention.reportBlockedEvents",
    help: "cfg.help.intervention.reportBlockedEvents" },
  { section: "intervention", key: "decisionTimeoutMs", label: "cfg.label.intervention.decisionTimeoutMs", type: "number", min: 10, max: 10000,
    hidden: true,
    help: "cfg.help.intervention.decisionTimeoutMs" },
  { section: "intervention", key: "policyPath", label: "cfg.label.intervention.policyPath", type: "string",
    danger: true, dangerReason: "cfg.danger.intervention.policyPath" },
  { section: "intervention", key: "reloadIntervalMs", label: "cfg.label.intervention.reloadIntervalMs", type: "number", min: 1000, max: 600000,
    hidden: true },
  { section: "assetMonitor", key: "enabled", label: "cfg.label.assetMonitor.enabled", type: "bool",
    danger: true, dangerReason: "cfg.danger.assetMonitor.enabled" },
  { section: "assetMonitor", key: "scanIntervalMs", label: "cfg.label.assetMonitor.scanIntervalMs", type: "number", min: 10000, max: 3600000,
    hidden: true },
  { section: "assetMonitor", key: "collectContent", label: "cfg.label.assetMonitor.collectContent", type: "bool",
    danger: true, dangerReason: "cfg.danger.assetMonitor.collectContent" },
  { section: "assetMonitor", key: "collectSkillPackage", label: "cfg.label.assetMonitor.collectSkillPackage", type: "bool",
    danger: true, dangerReason: "cfg.danger.assetMonitor.collectSkillPackage",
    help: "cfg.help.assetMonitor.collectSkillPackage" },
  { section: "assetMonitor", key: "collectConfigPackage", label: "cfg.label.assetMonitor.collectConfigPackage", type: "bool",
    danger: true, dangerReason: "cfg.danger.assetMonitor.collectConfigPackage",
    help: "cfg.help.assetMonitor.collectConfigPackage" },
  { section: "bootstrap", key: "entryDefaults", label: "cfg.label.bootstrap.entryDefaults", type: "bool" },
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

/**
 * Read `application.panelLocale` from the host config file on every panel GET.
 *
 * Deliberately NOT via middleware.getConfig(): that is the activation-time
 * snapshot, so a language chosen in the header switcher would need a gateway
 * restart before the panel honoured it — the toggle would look broken. Reading
 * the file per request mirrors what security.config.raw already does, and one
 * small JSON read per page load is not worth optimising away.
 *
 * Any failure (missing file, unparseable JSON, missing subtree) degrades to
 * "auto", which is exactly the pre-existing negotiation behaviour.
 */
function readPanelLocalePreference(): PanelLocalePreference {
  try {
    const parsed = JSON.parse(readFileSync(resolveHostConfigPath(), "utf8")) as {
      plugins?: { entries?: Record<string, { config?: unknown }> };
    };
    const block = parsed?.plugins?.entries?.[PLUGIN_ID]?.config as
      | { application?: { panelLocale?: unknown } }
      | undefined;
    return normalizePanelLocalePreference(block?.application?.panelLocale);
  } catch {
    return "auto";
  }
}

/**
 * 面板语言偏好的落盘位置：`openclaw.json` 旁边的 `panel-state.json`。
 *
 * 挨着宿主配置文件放（而不是硬编码 `~/.openclaw`）是为了跟着
 * OPENCLAW_HOME / OPENCLAW_CONFIG_PATH 走，测试也因此只要指一个临时目录。
 */
function resolvePanelStatePath(): string {
  const override = process.env.OPENCLAW_PANEL_STATE_PATH;
  if (override) return override;
  return join(dirname(resolveHostConfigPath()), "panel-state.json");
}

/**
 * 读 header 开关上一次的选择，读不到/损坏都折成 auto（= 未设置）。
 *
 * 与 readPanelLocalePreference 一样每次 GET 现读：走 getConfig() 那份启动
 * 快照的话，用户刚点的语言要等 gateway 重启才生效，开关看起来就是坏的。
 */
function readPanelStateLocale(): PanelLocalePreference {
  try {
    const parsed = JSON.parse(readFileSync(resolvePanelStatePath(), "utf8")) as { panelLocale?: unknown };
    return normalizePanelLocalePreference(parsed?.panelLocale);
  } catch {
    return "auto";
  }
}

/**
 * 面板语言偏好的最终生效值：开关写下的 `panel-state.json` 优先于配置键
 * `application.panelLocale`。
 *
 * 两处并存是有意的，不是历史遗留：
 *   · header 开关写 panel-state.json —— 写宿主 openclaw.json 会让 gateway
 *     重载全部插件，实测有 1.7~4.8s 的窗口期所有插件路由 500，语言切换要等
 *     8s 以上才看得见效果（见面板脚本里 RELOAD_SETTLE_* 那段注释）；
 *   · `application.panelLocale` 保留为"钉死的默认值"：想给一台机器固定语言
 *     的运维仍然可以在 Config 页或手改文件里定，优先级低于开关。
 * 两者都是"已保存的偏好"，由 parseLocale 当作一层处理。
 */
function readSavedPanelLocale(): PanelLocalePreference {
  const fromSwitch = readPanelStateLocale();
  return fromSwitch !== "auto" ? fromSwitch : readPanelLocalePreference();
}

/**
 * 写 header 开关的选择。只碰插件自己的状态文件，**不**写宿主 openclaw.json
 * —— 面板上的每一个其它保存动作都要 gateway 重载插件，8 秒的等待就是从那里
 * 来的（交付后的现场实测），语言切换不值得付这个代价。
 *
 * 写入走 tmp + rename（L4），读方永远看不到半个文件；失败时返回错误而不
 * 抛，调用方（面板）据此把按钮还给用户并说明原因。
 */
function writePanelStateLocale(locale: PanelLocalePreference): { ok: true; locale: PanelLocalePreference } | { ok: false; error: { message: string } } {
  const target = resolvePanelStatePath();
  const tmp = `${target}.${process.pid}.${Date.now()}.tmp`;
  try {
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(tmp, JSON.stringify({ panelLocale: locale }, null, 2) + "\n", "utf8");
    renameSync(tmp, target);
  } catch (err) {
    try { if (existsSync(tmp)) unlinkSync(tmp); } catch { /* ignore */ }
    return { ok: false, error: { message: "写入面板语言偏好失败: " + (err as Error).message } };
  }
  try {
    JSON.parse(readFileSync(target, "utf8"));
  } catch (err) {
    return { ok: false, error: { message: "写后校验失败: " + (err as Error).message } };
  }
  return { ok: true, locale };
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
}//_w1 = '7a686968'

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