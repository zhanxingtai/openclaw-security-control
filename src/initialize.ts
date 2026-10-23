// Plugin bootstrap. Centralizes everything the old `install.sh` /
// `setup-openclaw.js` scripts used to do, so the plugin is strictly
// self-contained per the OpenClaw 9.4 plugin spec — no external install
// helpers required.
//
// What lives here:
//   1. seedDefaultPolicy            — copy bundled policy template to
//                                     ~/.openclaw/security-policy.{yaml,json}
//                                     when the file is missing.
//   2. ensureBundledHooks           — copy the bundled runtime hooks into the
//                                     plugin's own data dir
//                                     ($OPENCLAW_HOME/<id>/hooks/) unconditionally,
//                                     so NODE_OPTIONS can reference a path that
//                                     always exists and that the host installer
//                                     never touches. Unconditional on purpose:
//                                     gating the copy on runtimeHooks.enabled
//                                     made "set NODE_OPTIONS first" a boot
//                                     deadlock. Path facts live in
//                                     src/hook-locations.ts (single authority).
//   3. probeRuntimeHookLoaded        — detect whether NODE_OPTIONS actually
//                                     preloaded one of our hooks. If not, turn
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

import { existsSync, copyFileSync, mkdirSync, readFileSync, writeFileSync, renameSync, unlinkSync } from "fs";
import { createHash } from "node:crypto";
import { Script } from "node:vm";
import { spawnSync } from "node:child_process";
import { dirname, resolve, join, basename, isAbsolute } from "path";
import { fileURLToPath } from "url";
import type { SecurityMonitorConfig } from "./types.js";
import type { OpenClawPluginApi } from "./openclaw-sdk/plugin-entry.js";
import {
  HOOK_BASENAMES,
  PREFERRED_PRELOAD_BASENAME,
  PLUGIN_ID,
  findBundledDir,
  isInside,
  matchHookRequires,
  resolveOpenClawHome,
  resolveLegacyDir,
  resolvePluginDataDir,
  resolvePreloadDir,
  resolvePreloadTarget,
} from "./hook-locations.js";

// 再导出以保持既有 import 路径可用（index.ts / 测试都从这里取）。
export { PLUGIN_ID };

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
  /** 预加载目标绝对路径（面板直接印给用户，不再手写死字符串）。 */
  preloadTarget?: string;
  /** NODE_OPTIONS 仍指向的遗留安装目录副本路径；已提示迁移则仍在用。 */
  legacyPreloadTargetInUse?: string;
}

/** A single field that bootstrap will clamp to false. `path` is a dotted
 *  name compatible with the CONFIG_SCHEMA dot notation used by the Config
 *  UI (e.g. "application.runtimeHooks.enabled"). */
export interface ForcedDisable {
  path: string;
  reason: string;
}

/** Resolve a bundled assets subdirectory regardless of how the plugin is loaded. */
export { findBundledDir };

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
 * Copy the bundled runtime hooks into the plugin's own data directory. The
 * plugin does NOT auto-mutate `NODE_OPTIONS` (that requires patching the host
 * entrypoint, which is out of scope for a strictly spec-compliant plugin).
 *
 * 目标目录是 `$OPENCLAW_HOME/<id>/hooks/`，**不是**安装目录
 * `$OPENCLAW_HOME/extensions/<id>/`。这不是审美选择：
 *
 *   extensions/<id>/ 由宿主安装器拥有。它按"目录实有内容 vs 包清单"对账，
 *   而 hook 副本不在包清单里（包内只有 hooks/），于是每次装/升级都被判成
 *   无法解释的外来文件并提示清理；反过来，用户照提示删掉它，NODE_OPTIONS
 *   的 --require 就指向不存在的文件，gateway 起不来，插件也没机会把副本
 *   拷回来 —— 自举死锁。
 *
 * 数据目录不属于安装器：升级、覆盖式安装、卸载都不动它，删除插件目录因此
 * 不再能杀死进程。
 *
 * **不看 runtimeHooks.enabled，无条件 seed。** 这一条是被自举死锁反向逼出来
 * 的：如果只在开关打开时写副本，那么"先配 NODE_OPTIONS 再开开关"这条路
 * 必然起不来 —— 目标文件要等一次成功的启动才会出现，而启动要 `--require`
 * 成功才行。于是从另一扇门把同一个死锁请了回来：默认状态（开关 false）
 * 的用户照文档把 NODE_OPTIONS 指到数据目录，gateway 当场死，他们连进去
 * 把开关打开的机会都没有。
 * 代价只是没启用的人也多出三个文件（几十 KB，写在非宿主目录，不产生安装
 * 器告警）；换来的是 NODE_OPTIONS 的设置顺序彻底不再重要。
 *
 * 遗留的 extensions/<id>/*.js：**仍被 NODE_OPTIONS 引用时才继续刷新**，引用
 * 一改走就立刻停手。理由是安全修复必须送达 —— 早先"修复随多次重装仍送不到
 * 容器"那次事故正是靠这个指纹比对解决的，存量部署若在迁移前就停止刷新，
 * 等于把同一个问题重新引入。（不再被引用时它们对用户已经无害，删不删由宿主
 * 提示和用户决定：**绝不能由插件代删** —— 主动删一个还被 NODE_OPTIONS 引用
 * 的文件，等于当场把服务打死。）
 *
 * 目录不可写时静默跳过 —— 宿主可以自己设 NODE_OPTIONS 指向安装包内的
 * hooks/，零残留写法同样被 probeRuntimeHookLoaded 认可。
 */
export function ensureBundledHooks(
  config: SecurityMonitorConfig,
  logger?: BootstrapLogger
): boolean {
  const hooksDir = findBundledDir("hooks");
  if (!hooksDir) return false;
  const optedIn = config.application?.runtimeHooks?.enabled === true;

  const preloadDir = resolvePreloadDir();
  const installed = installHooksInto(hooksDir, preloadDir, logger, optedIn);
  // 模块类型锚点只播到数据目录：插件完全拥有这个目录，播错了不会碰到任何
  // 别人的文件。遗留目录是宿主安装器拥有的，只刷新那三个 .js。
  installHooksPackageJson(hooksDir, preloadDir, logger);
  const legacy = probeLegacyHookPathInUse();
  if (legacy) {
    // 存量部署：NODE_OPTIONS 仍指着安装目录里的副本，那份必须跟得上版本，
    // 否则升级后的安全修复到不了用户的进程。
    installHooksInto(hooksDir, resolveLegacyDir(), logger, optedIn);
  }
  return installed;
}

/**
 * 归一化 hook 源码，让被 `--require` 的文件不再对"首字节"敏感。
 *
 * `#!` 是 JavaScript 里唯一必须出现在文件最开头的语法，而 Node 只认字节 0
 * 处的 shebang。实测（Node v24）：
 *   - 首行是 `#!`                        → 正常加载；
 *   - 首行是空行/注释、`#!` 落到第 2 行   → SyntaxError: Invalid or
 *     unexpected token，**报错行号正是 2**（本次线上故障的原始形态）；
 *   - 首字节是 UTF-8 BOM                 → SyntaxError（Node 在剥 BOM
 *     之前就判 shebang，BOM 在前同样致命）。
 *
 * 而这三个文件是 NODE_OPTIONS 的预加载目标：语法错 = 宿主进程在加载任何
 * 插件之前就退出，插件连"把副本修回去"的机会都没有（自举死锁的又一种
 * 形态）。归一化做两件事，把这一整类失败消掉：
 *   1. 去掉 UTF-8 BOM；
 *   2. 删掉所有以 `#!` 开头的行 —— CJS 里行首 `#` 只能开私有字段名，
 *      `#!` 必然是语法错误；删掉之后，文件无论被谁在前面插过内容都合法。
 *
 * 顺带把 CRLF 归一成 LF：预加载副本要跑在容器里，LF 是那边的事实标准；
 * 而且行尾差异会让"源与副本是不是同一份"的指纹比对在跨平台时反复不一致。
 *
 * 幂等：normalize(normalize(x)) === normalize(x)，落盘与指纹两边同口径，
 * 不会每次启动都判定"需要重写"。
 */
export function normalizeHookContent(source: string): string {
  const withoutBom = source.charCodeAt(0) === 0xfeff ? source.slice(1) : source;
  return withoutBom
    .split(/\r?\n/)
    .filter((line) => !/^\s*#!/.test(line))
    .join("\n");
}

/**
 * 原子落盘：写同目录临时文件再 rename。
 *
 * 预加载目标是被**别的进程**在启动期读的（`NODE_OPTIONS=--require`），而
 * 写入发生在 gateway 的 register() 里 —— 那时 CLI 及其 worker 随时可能正
 * 在并发拉起进程。裸 `writeFileSync` 会先把目标截断再逐块写出去，读到
 * 中间态的进程看到的就是一份"语法坏掉的 hook"，恰好复现本次要根治的启动
 * 崩溃。同目录保证 rename 不跨文件系统（跨了会退化成 copy，原子性就没了）。
 */
function writeFileAtomic(target: string, content: string): void {
  const tmp = `${target}.tmp-${process.pid}-${Date.now()}`;
  try {
    writeFileSync(tmp, content, "utf8");
    renameSync(tmp, target);
  } catch (err) {
    try {
      unlinkSync(tmp);
    } catch {
      /* 临时文件删不掉不该盖掉真正的错误 */
    }
    throw err;
  }
}

/**
 * 读一个 hook 文件并归一化。读不到返回 undefined（调用方按"需要重装"处理）。
 */
function readHookContent(filePath: string): string | undefined {
  try {
    return normalizeHookContent(readFileSync(filePath, "utf8"));
  } catch {
    return undefined;
  }
}

/**
 * 按 Node 的 CommonJS 形态编译一次，验"这份文件能不能被 --require"。
 *
 * 用 CJS 包装形态而不是裸 Script：顶层 `return` 在真模块里合法、在裸 Script
 * 里非法，包一层才不会误判（Node 自己就是这么包 CJS 模块的）。
 */
function isParsableAsCommonJs(content: string, filename: string): boolean {
  try {
    new Script(
      `(function (exports, require, module, __filename, __dirname) {${content}\n});`,
      { filename }
    );
    return true;
  } catch {
    return false;
  }
}

/**
 * 随包 hook 解析失败时的占位入口。
 *
 * 预加载入口语法错 = 宿主进程在启动期直接退出（SyntaxError），插件连运行
 * 机会都没有 → 用户看到的是"服务起不来 + 一个看不懂的报错"，而真正的
 * 原因（随包文件坏了）藏在没人会去看的地方。与其留一份 SyntaxError 的
 * 文件把整个服务打死，不如留一个"能加载、但什么都不做"的入口：覆盖从
 * "整个宿主挂掉"降级为"这一层没有覆盖"，服务还能起来、面板还能打开。
 *
 * 只有**入口**（hook-mounter.js）坏掉时整层才算失效，才留全局标记让探针
 * 判成未生效；兄弟文件（runtime.js / network.js）坏掉只影响那一层，入口
 * 仍然在工作，不该因此把整层判死。
 */
function degradedHookStub(hookName: string): string {
  const marker =
    hookName === PREFERRED_PRELOAD_BASENAME
      ? "globalThis.__openclaw_security_hook_degraded = true;"
      : "";
  return `// openclaw-security-monitor: degraded placeholder (${hookName})
//
// 随包 runtime hook 解析失败，这里是占位文件：能被 --require 加载，但不做
// 任何事情。真正的错误见宿主日志里同一时刻的 hook install 告警。
${marker}
console.warn('[openclaw-security-monitor] runtime hook degraded: bundled ${hookName} is not parsable');
`;
}

/**
 * 把随包 hook 拷进 targetDir，逐个按内容指纹决定是否覆盖。
 * 返回"本次是否真的写了文件"。
 *
 * `recommendPreload` 只控制那行 "recommend NODE_OPTIONS=..." 日志：开关
 * 没打开时照样落盘（见 ensureBundledHooks 的注释），但不该怂恿用户去改
 * 一个他们没要求启用的功能的环境变量。
 *
 * 落盘是**原子的**：写临时文件 + rename。预加载目标是被别的进程
 * （`NODE_OPTIONS=--require`）在启动期读的，而本函数跑在 gateway 的
 * register() 里 —— 此时 CLI 及其 worker 可能正在并发拉起进程。裸
 * `writeFileSync` 不是原子的，它们正好读到写了一半的文件时，就会看到
 * 一份"语法坏掉的 hook"，也就是本次要根治的那个启动崩溃本身。
 *
 * 落盘的是**归一化后的内容**，不是逐字节拷贝。逐字节拷贝会把随包源里的
 * 任何污染原样带进预加载目录（shebang 不在首字节 / BOM），而预加载目录
 * 里的文件一旦语法错，宿主进程就在加载任何插件之前退出。
 */
export function installHooksInto(
  hooksDir: string,
  targetDir: string,
  logger?: BootstrapLogger,
  recommendPreload = true
): boolean {
  // 防止环境变量注入把 hook 写到任意系统位置。旧实现用字符串 startsWith
  // 判包含，`/home/node/.openclaw-evil` 能蒙混过关；现按 isInside 判。
  const home = resolveOpenClawHome();
  const allowedBase = [home, '/usr/lib/openclaw'];
  if (!allowedBase.some((base) => isInside(targetDir, base))) {
    logger?.warn?.(`[${PLUGIN_ID}] hook target dir ${targetDir} is outside allowed base paths; skipping`);
    return false;
  }
  try {
    mkdirSync(targetDir, { recursive: true });
    let installed = false;
    for (const hookName of HOOK_BASENAMES) {
      const source = resolve(hooksDir, hookName);
      if (!existsSync(source)) continue;
      const target = resolve(targetDir, hookName);
      // 源与目标同路径（布局退化时的自指）：拷贝自己等于把源清空，跳过。
      if (source === target) continue;
      // Upgrade when the target is missing OR when its content fingerprint
      // differs from the bundled source. Without this check, ensureBundledHooks
      // would silently keep stale hook files after plugin upgrades — leading
      // to the same bug we saw when the OPENCLAW_MONITOR_LOG_PATH fallback
      // fix never reached the container despite multiple plugin reinstalls.
      const sourceFingerprint = readHookFingerprint(source);
      if (sourceFingerprint === undefined) {
        logger?.warn?.(`[${PLUGIN_ID}] bundled hook ${source} is unreadable; skipping`);
        continue;
      }
      if (existsSync(target) && readHookFingerprint(target) === sourceFingerprint) {
        continue;
      }
      const content = readHookContent(source);
      if (content === undefined) continue;
      if (!isParsableAsCommonJs(content, target)) {
        // 不落那份坏文件：预加载入口语法错 = 宿主在加载任何插件之前就退出。
        // 落一份"能加载但什么都不做"的占位入口，把"整个服务挂掉"降级成
        // "这一层没有覆盖"，并在日志里点名随包文件。
        //
        // 但**绝不拿占位文件去顶掉一份还能用的旧副本**：存量部署（尤其还在
        // 遗留路径上的）手上那份是被 Node 正常加载过的，拿它换掉等于用
        // "有覆盖"换"零覆盖"，是纯粹的倒退。留着旧副本 + 告警，让它继续跑。
        const existing = existsSync(target) ? readHookContent(target) : undefined;
        if (existing !== undefined && isParsableAsCommonJs(existing, target)) {
          logger?.warn?.(
            `[${PLUGIN_ID}] bundled hook ${source} is not parsable as CommonJS — ` +
              `kept the existing working copy at ${target} (coverage stays on). ` +
              `Reinstall the plugin package to restore the bundled fix.`
          );
          continue;
        }
        writeFileAtomic(target, degradedHookStub(hookName));
        installed = true;
        logger?.warn?.(
          `[${PLUGIN_ID}] bundled hook ${source} is not parsable as CommonJS — ` +
            `wrote a degraded placeholder to ${target} instead. Putting the real file in ` +
            `NODE_OPTIONS would kill the host process at startup (SyntaxError).`
        );
        continue;
      }
      writeFileAtomic(target, content);
      installed = true;
      if (hookName === PREFERRED_PRELOAD_BASENAME && recommendPreload) {
        logger?.info?.(
          `[${PLUGIN_ID}] installed ${hookName} to ${target} — recommend NODE_OPTIONS=--require ${target}`
        );
      }
    }
    if (installed) {
      logger?.info?.(
        `[${PLUGIN_ID}] installed bundled runtime hooks to ${targetDir}`
      );
    }
    return installed;
  } catch (err) {
    logger?.warn?.(
      `[${PLUGIN_ID}] failed to install bundled hooks into ${targetDir}: ${err instanceof Error ? err.message : String(err)}`
    );
    return false;
  }
}

/**
 * 把随包的 hooks/package.json 播种到**插件数据目录**（模块类型锚点）。
 *
 * 数据目录里没有 package.json 时，模块类型由**最近的祖先** package.json
 * 决定：宿主若在 ~/.openclaw/package.json 里写了 "type": "module"，三件套
 * 就会被当成 ESM —— ESM 里 `require` 未定义，预加载一进去就抛
 * "require is not defined in ES module scope"，同样让宿主进程在启动期退出。
 * 随包的 hooks/package.json 声明了 "type": "commonjs"，必须一起带走
 * （tests/hook-preload-deployment.test.ts 早就按这个前提手工拷过它，
 * 但生产播种路径一直没带 —— 这次一并补上）。
 *
 * **只对数据目录调用，且绝不覆盖已存在的 package.json。** 两条都来自同一
 * 个坑：1.0.x 布局下插件**就装在** `extensions/<id>/`，于是
 * `findBundledDir("hooks")` 解析到的 hooksDir 恰好是 `extensions/<id>/hooks`，
 * 而遗留目录就是 `extensions/<id>/` —— 播种目标落在插件**自己的清单**上。
 * 覆盖它等于把宿主要读的 manifest（main: index.js / type: module）换成
 * hooks 的（main: runtime.js / type: commonjs），插件直接加载不起来；
 * 而"文件不存在时就新建"同样致命：那会把整个 `extensions/<id>/` 的模块
 * 类型钉成 commonjs，连插件自己的 index.js 一起废掉。
 * 遗留目录是兼容期的**只读维护对象**，只刷新那三个 .js，不新增任何文件。
 */
function installHooksPackageJson(
  hooksDir: string,
  targetDir: string,
  logger?: BootstrapLogger
): boolean {
  const source = resolve(hooksDir, "package.json");
  const target = resolve(targetDir, "package.json");
  if (!existsSync(source)) return false;
  try {
    const content = readFileSync(source, "utf8");
    // 已存在就是别人的（宿主 / 插件自己的 manifest），一律不碰。
    if (existsSync(target)) return false;
    writeFileAtomic(target, content);
    logger?.info?.(`[${PLUGIN_ID}] pinned ${targetDir} as CommonJS (hooks/package.json)`);
    return true;
  } catch (err) {
    logger?.warn?.(
      `[${PLUGIN_ID}] failed to install hooks package.json into ${targetDir}: ${err instanceof Error ? err.message : String(err)}`
    );
    return false;
  }
}

/**
 * Fingerprint a hook file: SHA-256 over its FULL contents with the
 * `// openclaw-hook: vX.Y.Z` header line normalized to a constant.
 *
 * 为什么用内容哈希而不是手写版本号：
 *   - 这里的判定语义是"已装副本与随包副本是不是同一份内容"。哈希天然覆盖
 *     全文，改任何一行都会让已装副本被判过期并覆盖。旧的手写 tag 有 7 次
 *     内容改动没 bump（fix(issue-57)、fix(issue-60)、fix(issue-67) 等），
 *     那些修复是攒到下一个版本 bump 才一起送到用户手上的 —— tag 实际扮演
 *     的是"随哪个版本发货"，不是"第几次改动"。
 *   - tag 行保留为人读注释，但归一化后不再影响哈希，也就不再需要人工维护。
 *     顺手解决"发版要改两个 hook 文件头"这件事。
 *   - hook-mounter.js 从来没有 tag。旧实现下两边都读到 undefined、判定相等
 *     而跳过，该文件自 tag 机制引入（0cee1fc）以来对老用户从未更新过。哈希
 *     对三个文件一视同仁，这个洞自动消失。
 *
 * 必须哈希整个文件而不是头部若干字节：只读前 N 字节会漏掉文件尾部的修复，
 * 正是当初"修复送不到容器"事故的成因。
 *
 * 哈希前先走 normalizeHookContent：源与副本同口径（都归一化过），否则
 * 归一化前后的差异会被算成"内容变了"，导致每次启动都重写一遍。
 *
 * Returns undefined if the file is unreadable so the caller upgrades.
 */
function readHookFingerprint(filePath: string): string | undefined {
  const content = readHookContent(filePath);
  if (content === undefined) return undefined;
  // 归一化而非删除：带 tag 与不带 tag 的文件在同一位置留下同样的占位，
  // 这样"只 bump 了 tag"不会改变指纹（tag 已不承载语义）。
  const normalized = content.replace(/^\/\/ openclaw-hook:.*$/m, "// openclaw-hook");
  return createHash("sha256").update(normalized, "utf8").digest("hex").slice(0, 16);
}

/**
 * 预加载入口是否处于降级状态（随包文件解析失败 → 落盘的是占位入口）。
 *
 * 占位入口能被 --require 加载，所以 NODE_OPTIONS 探针会认为"hook 已在"，
 * 但那一层其实什么也没干。这个全局标记把真相透出来：探针据此判成未生效，
 * 面板如实显示"hook 未生效"，而不是谎报已生效。
 */
export function isRuntimeHookDegraded(): boolean {
  return (globalThis as Record<string, unknown>).__openclaw_security_hook_degraded === true;
}

/**
 * Detect whether one of our hooks was actually preloaded into the Node.js
 * runtime. We use the `NODE_OPTIONS` env var as a proxy: if it references a
 * hook file we own, we trust it; otherwise the runtime hook collector would
 * never see anything and we should disable the feature instead of silently
 * misreporting.
 *
 * 判定走"文件名 + 路径归属"（matchHookRequires），不再用正则猜路径形状。旧
 * 正则只认路径里带 `runtime` 的写法，于是三个文件里唯一被推荐给 NODE_OPTIONS
 * 的 hook-mounter.js 反而被判成"不是我们的 hook" → 误杀 → 强制关停
 * runtimeHooks.enabled → 下次启动连副本都不再刷新。详见 hook-locations.ts。
 */
export function probeRuntimeHookLoaded(logger?: BootstrapLogger): boolean {
  // 降级占位入口会在全局留标记：它能被 --require 加载，所以 NODE_OPTIONS
  // 探针会认为"hook 已在" —— 但那一层其实什么也没干。判成未生效，面板
  // 才会如实显示"hook 未生效"，而不是谎报已生效。
  if (isRuntimeHookDegraded()) {
    logger?.warn?.(
      `[${PLUGIN_ID}] runtime hook is running in DEGRADED mode (the bundled hook was not ` +
        `parsable) — coverage disabled until the plugin package is reinstalled`
    );
    return false;
  }
  const nodeOptions = process.env.NODE_OPTIONS || "";
  if (!nodeOptions.trim()) {
    logger?.warn?.(
      `[${PLUGIN_ID}] NODE_OPTIONS not set — runtime hook coverage disabled ` +
        `(set NODE_OPTIONS='--require ${resolvePreloadTarget()}' to enable)`
    );
    return false;
  }
  if (matchHookRequires(nodeOptions).length === 0) {
    logger?.warn?.(
      `[${PLUGIN_ID}] NODE_OPTIONS does not reference any of our hooks (${HOOK_BASENAMES.join(" / ")}) — coverage disabled`
    );
    return false;
  }
  return true;
}

/**
 * NODE_OPTIONS 是否仍指向遗留安装目录里的 hook 副本。
 *
 * 存量部署（照 1.0.x 面板文案配的）指向 `$OPENCLAW_HOME/extensions/<id>/*.js`。
 * 那份副本不在包清单里，安装器每次装/升级都会提示它"未删除"，而删掉它会让
 * gateway 起不来 —— 正是要根治的故障。这里只**识别**并提示迁移，绝不代替
 * 用户去删：删一个还被 NODE_OPTIONS 引着的文件，等于当场把服务打死。
 */
export function probeLegacyHookPathInUse(): string | undefined {
  return matchHookRequires(process.env.NODE_OPTIONS || "").find((m) => m.inLegacyDir)?.resolved;
}

/**
 * 迁移提示只打一次：用户可能有意留在遗留路径（探针仍然认它，功能不受影响），
 * 每次启动都刷一遍只会把面板警告变成噪音。marker 记录上次提示过的路径，换了
 * 路径才再提示一次；写不动 marker（只读数据目录）就退化成每次都提示。
 */
function warnLegacyHookPathOnce(legacyTarget: string, logger?: BootstrapLogger): void {
  const dataDir = resolvePluginDataDir();
  const markerPath = resolve(dataDir, "hook-path-migrated.txt");
  try {
    if (existsSync(markerPath) && readFileSync(markerPath, "utf8").trim() === legacyTarget) return;
  } catch {
    /* marker 读不到就当没打过，提示一次不算错 */
  }
  logger?.warn?.(
    `[${PLUGIN_ID}] NODE_OPTIONS 仍指向遗留安装目录的 hook 副本 ${legacyTarget}。` +
      `该副本不在安装包清单内，宿主每次装/升级都会提示删除它，而删除会让 gateway` +
      `因 --require 找不到文件而无法启动（插件也无从重建）。请把启动环境的 NODE_OPTIONS` +
      `改指向插件数据目录（改完即可安全删除那 3 个遗留文件）：` +
      `NODE_OPTIONS='--require ${resolvePreloadTarget()}'`
  );
  try {
    mkdirSync(dataDir, { recursive: true });
    writeFileSync(markerPath, legacyTarget, "utf8");
  } catch {
    /* marker 只是去重，写不成就下次再提示一次 */
  }
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
      // 两种成因共用一句文案：宿主没引用我们的 hook，或者引用到的副本处于
      // 降级状态（随包文件解析失败 → 预加载入口被换成占位文件）。后者在
      // 宿主日志里有专门的告警行，这里只负责让面板别谎报"已生效"。
      const reason = isRuntimeHookDegraded()
        ? `预加载 hook 处于降级状态（随包文件解析失败，副本已被替换为占位入口）；请重新安装插件包后再启用`
        : `宿主 NODE_OPTIONS 未引用 bundled runtime hook；需在启动环境加 NODE_OPTIONS='--require ${resolvePreloadTarget()}'（绝对路径写法见该字段帮助）`;
      forcedDisabled.push({
        path: "application.runtimeHooks.enabled",
        reason,
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
  const home = resolveOpenClawHome();
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
    preloadTarget: resolvePreloadTarget(),
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
    const legacyTarget = probeLegacyHookPathInUse();
    if (legacyTarget) {
      report.legacyPreloadTargetInUse = legacyTarget;
      warnLegacyHookPathOnce(legacyTarget, logger);
    }
  } catch (err) {
    logger?.warn?.(
      `[${PLUGIN_ID}] legacy hook path probe failed: ${err instanceof Error ? err.message : String(err)}`
    );
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