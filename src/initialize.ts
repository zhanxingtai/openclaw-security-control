// Plugin bootstrap. Centralizes everything the old `install.sh` /
// `setup-openclaw.js` scripts used to do, so the plugin is strictly
// self-contained per the OpenClaw 9.4 plugin spec — no external install
// helpers required.
//
// What lives here:
//   1. seedDefaultPolicy            — copy bundled policy template to
//                                     ~/.openclaw/security-policy.{yaml,json}
//                                     when the file is missing.
//   2. ensureBundledHooks           — copy the bundled runtime hooks into
//                                     the OpenClaw extensions dir when the
//                                     user opted in to runtime hooks. This
//                                     is purely a deployment convenience so
//                                     NODE_OPTIONS can reference a stable
//                                     path; the plugin loads the hooks from
//                                     the tarball when the dir is not writable.
//   3. probeRuntimeHookLoaded        — detect whether NODE_OPTIONS actually
//                                     preloaded the Node hook. If not, turn
//                                     `application.runtimeHooks.enabled` off
//                                     so the plugin does not pretend to have
//                                     coverage it does not.
//   4. probePythonPsutil            — detect whether the Python monitor can
//                                     actually import psutil. If not, turn
//                                     `system.enabled` off (system layer
//                                     requires psutil to do anything useful).
//   5. initializePlugin             — orchestrator called from register().
//                                     Runs probes, logs a short summary, and
//                                     returns a copy of the config with
//                                     feature flags adjusted so the store
//                                     picks up the post-bootstrap state.
//
// Each step is best-effort: failure is logged, never thrown. The plugin must
// always boot even when the host is missing prereqs.

import { existsSync, copyFileSync, mkdirSync, readFileSync, writeFileSync, renameSync, openSync, closeSync, readSync, unlinkSync } from "fs";
import { spawnSync } from "node:child_process";
import { dirname, resolve, join, basename, isAbsolute } from "path";
import { fileURLToPath } from "url";
import { homedir } from "os";
import type { SecurityMonitorConfig } from "./types.js";
import type { OpenClawPluginApi } from "./openclaw-sdk/plugin-entry.js";

export const PLUGIN_ID = "sst-security-control-openclaw";

export interface BootstrapLogger {
  info?: (message: string) => void;
  warn?: (message: string) => void;
  error?: (message: string) => void;
}

export interface BootstrapReport {
  policySeeded: boolean;
  hooksInstalled: boolean;
  runtimeHookLoaded: boolean;
  pythonPsutil: boolean;
  /** True iff this run wrote any new host-side plugin-entry defaults. */
  entryDefaultsWritten: boolean;
  /** Fields the bootstrap pipeline forced to `false` because the host
   *  environment can't support them (NODE_OPTIONS missing, psutil not
   *  importable, etc). Populated by applyBootstrapResults — empty /
   *  undefined before that runs. Surfaced back to the Config UI so users
   *  are not surprised when a toggled-on feature silently stops producing
   *  events after a save + restart. */
  forcedDisabled?: ForcedDisable[];
}

/** A single field that bootstrap will clamp to false. `path` is a dotted
 *  name compatible with the CONFIG_SCHEMA dot notation used by the Config
 *  UI (e.g. "application.runtimeHooks.enabled"). */
export interface ForcedDisable {
  path: string;
  reason: string;
}

/** Resolve a bundled assets subdirectory regardless of how the plugin is loaded. */
function findBundledDir(subdir: string): string | undefined {
  try {
    const entryDir = dirname(fileURLToPath(import.meta.url));
    for (const offset of ["", "..", "../.."]) {
      const root = offset ? resolve(entryDir, offset) : entryDir;
      const candidate = resolve(root, subdir);
      if (existsSync(candidate)) return candidate;
    }
  } catch {
    /* import.meta.url may not be available under legacy loaders; tolerate. */
  }
  return undefined;
}

/**
 * Seed ~/.openclaw/security-policy.{yaml,json} from the bundled template when
 * the user has not supplied a custom path and the file does not yet exist.
 * Runs before collectors initialize so the InterventionEngine starts with
 * rules instead of falling back to the implicit allow-all.
 */
export function seedDefaultPolicy(
  targetPath: string,
  logger?: BootstrapLogger
): boolean {
  if (!targetPath || existsSync(targetPath)) return false;
  // 直接按文件定位 bundled 模板，不能只找第一个名为 policies 的目录：
  // 安装包内 application/policies 只含 risk-flags.json，完整策略在包根的
  // policies/，目录存在≠模板存在（曾因此静默 seed 失败，引擎 0 规则启动）。
  let entryDir: string;
  try {
    entryDir = dirname(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
  let sourcePath: string | undefined;
  for (const offset of ["", "..", "../.."]) {
    for (const name of ["security-policy.yaml", "security-policy.json"]) {
      const candidate = resolve(entryDir, offset, "policies", name);
      if (existsSync(candidate)) {
        sourcePath = candidate;
        break;
      }
    }
    if (sourcePath) break;
  }
  if (!sourcePath) return false;
  try {
    mkdirSync(dirname(targetPath), { recursive: true });
    copyFileSync(sourcePath, targetPath);
    logger?.info?.(`[${PLUGIN_ID}] seeded default policy from bundled template: ${targetPath}`);
    return true;
  } catch (err) {
    logger?.warn?.(
      `[${PLUGIN_ID}] failed to seed default policy: ${err instanceof Error ? err.message : String(err)}`
    );
    return false;
  }
}

/**
 * Copy the bundled runtime hooks into the OpenClaw extensions directory when
 * the user opted in to `application.runtimeHooks.enabled`. The plugin does
 * NOT auto-mutate `NODE_OPTIONS` (that requires patching the host entrypoint,
 * which is out of scope for a strictly spec-compliant plugin). If the
 * extensions dir is not writable we skip silently — the host must set
 * `NODE_OPTIONS` itself, or live with the hooks running from the tarball
 * cache dir if NODE_OPTIONS was already configured.
 */
export function ensureBundledHooks(
  config: SecurityMonitorConfig,
  logger?: BootstrapLogger
): boolean {
  if (!config.application?.runtimeHooks?.enabled) return false;
  const hooksDir = findBundledDir("hooks");
  if (!hooksDir) return false;

  // OpenClaw extensions dir is conventionally $OPENCLAW_HOME/extensions;
  // when OPENCLAW_HOME is unset, fall back to ~/.openclaw/extensions so
  // the host can find hooks from its loader path. Both are best-effort —
  // if we cannot write, we do not throw.
  const home = process.env.OPENCLAW_HOME
    ? resolve(process.env.OPENCLAW_HOME)
    : resolve(homedir(), ".openclaw");
  const extensionsDir = process.env.OPENCLAW_EXTENSIONS_DIR
    ? resolve(process.env.OPENCLAW_EXTENSIONS_DIR)
    : resolve(home, "extensions", PLUGIN_ID);
  // Restrict to paths under the OpenClaw data home or /usr/lib/openclaw
  // to prevent env injection from writing hooks to arbitrary system locations.
  const resolvedExt = resolve(extensionsDir);
  const allowedBase = [home, '/usr/lib/openclaw'];
  if (!allowedBase.some((base) => resolvedExt.startsWith(base))) {
    logger?.warn?.(`[${PLUGIN_ID}] extensionsDir ${extensionsDir} is outside allowed base paths; skipping hook installation`);
    return false;
  }
  try {
    mkdirSync(extensionsDir, { recursive: true });
    let installed = false;
    // hook-mounter.js is the recommended preload entry point (gracefully
    // degrades when sibling hook files are missing). It is always copied —
    // even on first install — so older deployments that still point
    // NODE_OPTIONS at runtime.js / network.js directly still work.
    const HOOK_FILES = ["runtime.js", "network.js", "hook-mounter.js"];
    for (const hookName of HOOK_FILES) {
      const source = resolve(hooksDir, hookName);
      if (!existsSync(source)) continue;
      const target = resolve(extensionsDir, hookName);
      // Upgrade when the target is missing OR when its embedded version
      // tag (// openclaw-hook: vX.Y.Z) does not match the bundled source.
      // Without this check, ensureBundledHooks would silently keep stale
      // hook files after plugin upgrades — leading to the same bug we saw
      // when the OPENCLAW_MONITOR_LOG_PATH fallback fix never reached the
      // container despite multiple plugin reinstalls.
      if (existsSync(target) && readHookVersion(target) === readHookVersion(source)) {
        continue;
      }
      copyFileSync(source, target);
      installed = true;
      if (hookName === "hook-mounter.js") {
        logger?.info?.(
          `[${PLUGIN_ID}] installed hook-mounter to ${target} — recommend NODE_OPTIONS=--require ${target}`
        );
      }
    }
    if (installed) {
      logger?.info?.(
        `[${PLUGIN_ID}] installed bundled runtime hooks to ${extensionsDir}`
      );
    }
    return installed;
  } catch (err) {
    logger?.warn?.(
      `[${PLUGIN_ID}] failed to install bundled hooks: ${err instanceof Error ? err.message : String(err)}`
    );
    return false;
  }
}

/**
 * Read the `// openclaw-hook: vX.Y.Z` version tag from the first 200 bytes
 * of a hook file. Returns undefined if the tag is absent or unreadable so
 * callers can decide whether to upgrade (tag mismatch → upgrade, no tag →
 * upgrade because the source always carries the tag).
 */
function readHookVersion(filePath: string): string | undefined {
  try {
    const fd = openSync(filePath, "r");
    try {
      const buffer = Buffer.alloc(200);
      const bytesRead = readSync(fd, buffer, 0, 200, 0);
      const head = buffer.toString("utf8", 0, bytesRead);
      const match = head.match(/\/\/ openclaw-hook:\s*(\S+)/);
      return match ? match[1] : undefined;
    } finally {
      closeSync(fd);
    }
  } catch {
    return undefined;
  }
}

/**
 * Detect whether the runtime hook was actually preloaded into the Node.js
 * runtime. We use the `NODE_OPTIONS` env var as a proxy: if it points at a
 * script we recognize, we trust it; otherwise the runtime hook collector
 * would never see anything and we should disable the feature instead of
 * silently misreporting.
 */
export function probeRuntimeHookLoaded(logger?: BootstrapLogger): boolean {
  const nodeOptions = process.env.NODE_OPTIONS || "";
  if (!nodeOptions) {
    logger?.warn?.(
      `[${PLUGIN_ID}] NODE_OPTIONS not set — runtime hook coverage disabled ` +
        `(set NODE_OPTIONS='--require /path/to/runtime.js' to enable)`
    );
    return false;
  }
  // Best-effort: NODE_OPTIONS may list multiple --require flags separated by
  // spaces. Look for any entry that looks like our hook.
  const requires = nodeOptions.match(/--require\s+(\S+)/g) || [];
  const matches = requires.some((entry) => /sst-security-control-openclaw.*runtime|openclaw-security-monitor.*runtime|hooks\/runtime/i.test(entry));
  if (!matches) {
    logger?.warn?.(
      `[${PLUGIN_ID}] NODE_OPTIONS does not reference the bundled runtime hook — coverage disabled`
    );
    return false;
  }
  return true;
}

/**
 * pythonPath is an RCE sink — probePythonPsutil spawns it at save
 * time (dry-run) and SystemCollector spawns it as the long-running monitor.
 * Only accept a bare "python3"/"python3.x" (PATH-resolved, the default) or an
 * ABSOLUTE path whose basename is python3/python3.x. Anything else (relative
 * paths with slashes, other basenames, embedded whitespace/flags) is skipped
 * and treated as "psutil missing" — never executed.
 */
export function isSafePythonPath(pythonPath: string): boolean {
  if (typeof pythonPath !== "string" || pythonPath.length === 0) return false;
  const hasSeparator = pythonPath.includes("/") || pythonPath.includes("\\");
  if (hasSeparator && !isAbsolute(pythonPath)) return false;
  return /^python3(\.\d+)?$/.test(basename(pythonPath));
}

/**
 * Probe whether `python3 -c "import psutil"` succeeds. The system collector's
 * process monitor requires psutil; when it's absent the entire system layer
 * would silently produce no events, so we disable the layer in that case.
 */
export function probePythonPsutil(
  config: SecurityMonitorConfig,
  logger?: BootstrapLogger
): boolean {
  if (!config.system?.procfs?.enabled && !config.system?.cgroups?.enabled) return true;
  const pythonPath = config.system.procfs?.pythonPath || "python3";
  if (!isSafePythonPath(pythonPath)) {
    logger?.warn?.(
      `[${PLUGIN_ID}] 非法 pythonPath "${pythonPath}"（须为 python3/python3.x 或绝对路径且 basename 匹配 python3(\\.\\d+)?）— 跳过 psutil 探测，system 层按缺失处理`
    );
    return false;
  }
  try {
    const result = spawnSync(pythonPath, ["-c", "import psutil"], {
      stdio: ["ignore", "ignore", "ignore"],
      timeout: 5000,
    });
    if (result.error || result.status !== 0) {
      logger?.warn?.(
        `[${PLUGIN_ID}] ${pythonPath} cannot import psutil — system layer disabled ` +
          `(install with: ${pythonPath} -m pip install psutil>=5.9)`
      );
      return false;
    }
    return true;
  } catch (err) {
    logger?.warn?.(
      `[${PLUGIN_ID}] psutil probe failed: ${err instanceof Error ? err.message : String(err)} — system layer disabled`
    );
    return false;
  }
}

/**
 * Adjust the normalized config based on the bootstrap probes. Each probe
 * that comes back negative turns the corresponding feature off so downstream
 * collectors don't churn on a layer that cannot actually run.
 */
export function applyBootstrapResults(
  config: SecurityMonitorConfig,
  report: BootstrapReport
): { config: SecurityMonitorConfig; forcedDisabled: ForcedDisable[] } {
  const next: SecurityMonitorConfig = JSON.parse(JSON.stringify(config));
  const forcedDisabled: ForcedDisable[] = [];

  if (!report.runtimeHookLoaded) {
    if (next.application?.runtimeHooks?.enabled) {
      next.application.runtimeHooks.enabled = false;
      forcedDisabled.push({
        path: "application.runtimeHooks.enabled",
        reason: "宿主 NODE_OPTIONS 未引用 bundled runtime hook；需在启动环境加 NODE_OPTIONS='--require ~/.openclaw/extensions/sst-security-control-openclaw/runtime.js'（绝对路径写法见该字段帮助）",
      });
    }
  }
  if (!report.pythonPsutil) {
    if (next.system?.procfs?.enabled) {
      next.system.procfs.enabled = false;
      forcedDisabled.push({
        path: "system.procfs.enabled",
        reason: `${config.system?.procfs?.pythonPath || "python3"} 缺 psutil>=5.9.0；详见 Config 页面「启用 System」下方说明`,
      });
    }
    if (next.system?.cgroups?.enabled) {
      next.system.cgroups.enabled = false;
      forcedDisabled.push({
        path: "system.cgroups.enabled",
        reason: "python 缺 psutil，cgroups 层无法采集",
      });
    }
    if (next.system?.enabled) {
      next.system.enabled = false;
      forcedDisabled.push({
        path: "system.enabled",
        reason: "python 缺 psutil，system 层整体关闭",
      });
    }
  }

  return { config: next, forcedDisabled };
}

/**
 * Resolve the host OpenClaw config file path. Honours explicit env overrides
 * first, then `OPENCLAW_HOME`, and finally falls back to `~/.openclaw/`.
 * Mirrors the loader behaviour on the host side so the bootstrap pipeline
 * writes to the same file the host reads from.
 */
export function resolveHostConfigPath(): string {
  if (process.env.OPENCLAW_EXTERNAL_CONFIG_PATH) return process.env.OPENCLAW_EXTERNAL_CONFIG_PATH;
  if (process.env.OPENCLAW_CONFIG_PATH) return process.env.OPENCLAW_CONFIG_PATH;
  const home = process.env.OPENCLAW_HOME || join(homedir(), ".openclaw");
  return join(home, "openclaw.json");
}

/**
 * Write the four host-side plugin-entry defaults this plugin relies on into
 * `~/.openclaw/openclaw.json` when they are missing:
 *   - plugins.entries[PLUGIN_ID].hooks.allowConversationAccess  = true
 *   - plugins.entries[PLUGIN_ID].hooks.allowPromptInjection     = true
 *   - plugins.entries[PLUGIN_ID].llm.allowModelOverride         = true
 *   - plugins.entries[PLUGIN_ID].subagent.allowModelOverride    = true
 *
 * These mirror the default policy values that ship with this plugin: without
 * them the host UI shows "blocked" while the runtime hook policy is actually
 * permissive (or vice versa), and the plugin ends up either seeing no
 * session content or falsely advertising coverage it cannot deliver.
 *
 * The write is idempotent and only touches the four target paths — every
 * other key in the JSON is preserved verbatim. The file is rewritten via
 * temp + rename so a concurrent host reader never sees a half-written file.
 *
 * Failures are logged and swallowed: this is a best-effort convenience, the
 * plugin must boot even when the file is unparseable or unwritable.
 *
 * @returns true iff this invocation added at least one missing default.
 */
export function ensureHostPluginEntryDefaults(
  targetPath: string,
  logger?: BootstrapLogger
): boolean {
  const DEFAULTS: Array<{ path: string[]; value: boolean }> = [
    { path: ["plugins", "entries", PLUGIN_ID, "hooks", "allowConversationAccess"], value: true },
    { path: ["plugins", "entries", PLUGIN_ID, "hooks", "allowPromptInjection"], value: true },
    { path: ["plugins", "entries", PLUGIN_ID, "llm", "allowModelOverride"], value: true },
    { path: ["plugins", "entries", PLUGIN_ID, "subagent", "allowModelOverride"], value: true },
  ];

  let raw: string;
  try {
    raw = readFileSync(targetPath, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      // File does not yet exist — bootstrap an empty object and write all
      // defaults in one shot. Common on a brand-new install where the host
      // has not been launched yet.
      raw = "{}";
    } else {
      logger?.warn?.(
        `[${PLUGIN_ID}] cannot read host config ${targetPath}: ${err instanceof Error ? err.message : String(err)}`
      );
      return false;
    }
  }

  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(raw) as Record<string, unknown>;
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("host config is not a JSON object");
    }
  } catch (err) {
    logger?.warn?.(
      `[${PLUGIN_ID}] host config ${targetPath} is not valid JSON — skipping entry-default write: ${err instanceof Error ? err.message : String(err)}`
    );
    return false;
  }

  const written: string[] = [];
  for (const { path: pathSegments, value } of DEFAULTS) {
    let cursor: Record<string, unknown> = parsed;
    let blocked = false;
    for (let i = 0; i < pathSegments.length - 1; i++) {
      const seg = pathSegments[i];
      const next = cursor[seg];
      if (next === undefined) {
        // Brand-new install only has `enabled: true` under
        // plugins.entries[PLUGIN_ID]; the `hooks` / `llm` / `subagent`
        // sub-objects the bootstrap needs to seed do not exist yet.
        // Create them on the fly so the leaf default can land.
        cursor[seg] = {};
        cursor = cursor[seg] as Record<string, unknown>;
        continue;
      }
      if (next === null || typeof next !== "object" || Array.isArray(next)) {
        // Existing scalar/array in the path slot blocks the default — leave
        // it alone and skip. The user has intentionally shaped their config.
        blocked = true;
        break;
      }
      cursor = next as Record<string, unknown>;
    }
    if (blocked) continue;
    const leaf = pathSegments[pathSegments.length - 1];
    if (cursor[leaf] === undefined) {
      cursor[leaf] = value;
      written.push(pathSegments.join("."));
    }
  }

  if (written.length === 0) return false;

  const next = JSON.stringify(parsed, null, 2) + "\n";
  const tmpPath = `${targetPath}.${process.pid}.${Date.now()}.tmp`;
  try {
    mkdirSync(dirname(targetPath), { recursive: true });
    writeFileSync(tmpPath, next, "utf8");
    renameSync(tmpPath, targetPath);
    logger?.info?.(
      `[${PLUGIN_ID}] wrote host plugin-entry defaults to ${targetPath}: ${written.join(", ")}`
    );
    return true;
  } catch (err) {
    logger?.warn?.(
      `[${PLUGIN_ID}] failed to persist host plugin-entry defaults: ${err instanceof Error ? err.message : String(err)}`
    );
    try {
      // best-effort cleanup of the temp file on rename failure
      if (existsSync(tmpPath)) {
        unlinkSync(tmpPath);
      }
    } catch {
      /* ignore */
    }
    return false;
  }
}

/**
 * One-shot bootstrap. Called from `register()` in index.ts. Returns the
 * post-bootstrap config so the caller can pass it to the store. Never throws.
 */
export function initializePlugin(
  api: Pick<OpenClawPluginApi, "logger">,
  config: SecurityMonitorConfig
): { config: SecurityMonitorConfig; report: BootstrapReport } {
  const logger: BootstrapLogger = api.logger;
  const report: BootstrapReport = {
    policySeeded: false,
    hooksInstalled: false,
    runtimeHookLoaded: true,
    pythonPsutil: true,
    entryDefaultsWritten: false,
  };

  try {
    if (config.intervention?.policyPath) {
      report.policySeeded = seedDefaultPolicy(config.intervention.policyPath, logger);
    }
  } catch (err) {
    logger?.warn?.(
      `[${PLUGIN_ID}] policy seed failed: ${err instanceof Error ? err.message : String(err)}`
    );
  }

  try {
    if (config.bootstrap?.entryDefaults !== false) {
      const hostConfigPath = resolveHostConfigPath();
      report.entryDefaultsWritten = ensureHostPluginEntryDefaults(hostConfigPath, logger);
    }
  } catch (err) {
    logger?.warn?.(
      `[${PLUGIN_ID}] host entry-default write failed: ${err instanceof Error ? err.message : String(err)}`
    );
  }

  try {
    report.hooksInstalled = ensureBundledHooks(config, logger);
  } catch (err) {
    logger?.warn?.(
      `[${PLUGIN_ID}] hook install failed: ${err instanceof Error ? err.message : String(err)}`
    );
  }

  try {
    report.runtimeHookLoaded = probeRuntimeHookLoaded(logger);
  } catch (err) {
    logger?.warn?.(
      `[${PLUGIN_ID}] runtime hook probe failed: ${err instanceof Error ? err.message : String(err)}`
    );
    report.runtimeHookLoaded = false;
  }

  try {
    report.pythonPsutil = probePythonPsutil(config, logger);
  } catch (err) {
    logger?.warn?.(
      `[${PLUGIN_ID}] psutil probe failed: ${err instanceof Error ? err.message : String(err)}`
    );
    report.pythonPsutil = false;
  }

  const adjusted = applyBootstrapResults(config, report);
  const adjustedConfig = adjusted.config;
  report.forcedDisabled = adjusted.forcedDisabled;

  logger?.info?.(
    `[${PLUGIN_ID}] bootstrap complete: ` +
      `policy=${report.policySeeded ? "seeded" : "kept"} ` +
      `hooks=${report.hooksInstalled ? "installed" : "skipped"} ` +
      `runtimeHookLoaded=${report.runtimeHookLoaded} ` +
      `psutil=${report.pythonPsutil} ` +
      `entryDefaults=${report.entryDefaultsWritten ? "written" : "skipped"}`
  );

  return { config: adjustedConfig, report };
}