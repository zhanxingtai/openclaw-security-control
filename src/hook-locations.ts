/**
 * 运行时 hook 预加载路径的**唯一权威**。
 *
 * 为什么要有这个模块：hook 文件的"家"这件事此前被三处各自独立地编码过——
 *   1. 打包清单（scripts/build.js 的 `files` + tgz 实际内容），
 *   2. bootstrap 运行期写入（src/initialize.ts 的 ensureBundledHooks），
 *   3. 用户可见文案（src/panel-i18n.ts 的 NODE_OPTIONS 帮助、README）。
 * 三层各自演进，2026-10 终于对不齐：安装包把 hook 放在 `hooks/` 下，面板却
 * 让用户把 NODE_OPTIONS 指向**包根**的 runtime.js —— 那个文件不在包清单里，
 * 它是插件每次启动现拷进去的。于是：
 *   - 装/升级时，安装器按"目录实有内容 vs 包清单"对账，认出 3 个无法解释的
 *     外来文件（runtime.js / network.js / hook-mounter.js），提示"未删除"；
 *   - 而删掉它 = NODE_OPTIONS --require 指向不存在的文件 = Node 启动期直接
 *     Cannot find module = gateway 起不来；gateway 起不来，插件就没机会把
 *     副本拷回来 = 自举死锁。装一次提示一次，删了又会回来。
 *
 * 修复的方向不是"再加一层前置条件"，而是让预加载目标**只存在于插件自己的
 * 数据目录**（`$OPENCLAW_HOME/sst-security-control-openclaw/hooks/`）：
 * 该目录不属于安装器，升级/卸载/覆盖式安装都不会动它，删除插件目录因此
 * 不再能杀死进程；插件每次启动照旧把随包副本刷新到那里（指纹比对）。
 *
 * 遗留路径（`$OPENCLAW_HOME/extensions/<id>/*.js`）只作为**兼容期识别与
 * 维护**对象：NODE_OPTIONS 仍引用它时 bootstrap 继续刷新那里的副本（否则
 * 升级后的安全修复到不了存量用户），引用一改走就立刻停手。
 * 但插件**绝不代替用户删除**它们 —— 主动删一个还被 NODE_OPTIONS 引用着的
 * 文件，等于当场把服务打死，正是本次要根治的故障。
 */
import { existsSync } from "fs";
import { homedir } from "os";
import { basename, dirname, isAbsolute, join, relative, resolve } from "path";
import { fileURLToPath } from "url";

/** 插件 id。index.ts / initialize.ts 均从此处再导出，避免三份字面量漂移。 */
export const PLUGIN_ID = "sst-security-control-openclaw";

/**
 * 三个预加载文件的文件名。顺序即"复制到数据目录"的顺序，首选预加载入口排第一。
 *
 * hook-mounter.js 是**推荐**的 NODE_OPTIONS 目标：它在同目录现 require
 * runtime.js / network.js，缺文件只打 WARN 并继续，gateway 不会因为一个
 * 缺失的 hook 而起不来（直接 --require runtime.js 则会）。
 */
export const HOOK_BASENAMES = ["hook-mounter.js", "runtime.js", "network.js"] as const;

export type HookBasename = (typeof HOOK_BASENAMES)[number];

/** 首选预加载入口。面板文案与迁移提示都用它。 */
export const PREFERRED_PRELOAD_BASENAME: HookBasename = "hook-mounter.js";

export function isHookBasename(name: string): name is HookBasename {
  return (HOOK_BASENAMES as readonly string[]).includes(name);
}

/** OpenClaw 数据根：`$OPENCLAW_HOME`，未设时回落 `~/.openclaw`。 */
export function resolveOpenClawHome(): string {
  return process.env.OPENCLAW_HOME
    ? resolve(process.env.OPENCLAW_HOME)
    : resolve(homedir(), ".openclaw");
}

/**
 * 插件自有数据目录。`~/.openclaw/` 根下已有本插件的其它产物
 * （security-events.jsonl / asset-state.json 等），这里只是把 hook 也归到
 * 同一个命名空间下。
 */
export function resolvePluginDataDir(): string {
  return join(resolveOpenClawHome(), PLUGIN_ID);
}

/** 预加载文件目录（安装器不拥有）。 */
export function resolvePreloadDir(): string {
  return join(resolvePluginDataDir(), "hooks");
}

/** 预加载目标绝对路径，默认首选入口。面板直接把它印给用户，不允许手写死。 */
export function resolvePreloadTarget(basename: HookBasename = PREFERRED_PRELOAD_BASENAME): string {
  return join(resolvePreloadDir(), basename);
}

/**
 * 遗留安装目录：`$OPENCLAW_EXTENSIONS_DIR`，未设时为
 * `$OPENCLAW_HOME/extensions/<id>`。新装不再写入这里；只有当 NODE_OPTIONS
 * 仍然引用它时，bootstrap 才继续刷新那里的副本（安全修复必须送达），引用
 * 一改走就立刻停手。
 */
export function resolveLegacyDir(): string {
  return process.env.OPENCLAW_EXTENSIONS_DIR
    ? resolve(process.env.OPENCLAW_EXTENSIONS_DIR)
    : join(resolveOpenClawHome(), "extensions", PLUGIN_ID);
}

/** 遗留预加载目标路径（识别用）。 */
export function resolveLegacyTarget(basename: string = PREFERRED_PRELOAD_BASENAME): string {
  return join(resolveLegacyDir(), basename);
}

/**
 * 随包 hook 源目录（`hooks/`，类型由 hooks/package.json 固定为 commonjs，
 * 因此其中的 .js 可以直接被 `--require`）。无论插件从源码树还是 tgz 加载
 * 都要能找到，故沿 import.meta.url 向上试三层。
 *
 * 返回 undefined 表示随包目录缺失（源码树未构建 / 裁剪过安装包），调用方
 * 必须优雅降级而不是抛错。
 */
export function findBundledDir(subdir: string): string | undefined {
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
 * 路径包含判定（比字符串 startsWith 严）。`relative` 返回 "" 表示两者相同，
 * 以 `..` 开头或绝对路径表示已跳出 parent —— 后者正是旧实现用前缀匹配时
 * 会被 `/home/node/.openclaw-evil` 蒙混过关的那一类。
 */
export function isInside(child: string, parent: string): boolean {
  const rel = relative(resolve(parent), resolve(child));
  return rel !== "" && !rel.startsWith("..") && !isAbsolute(rel);
}

/**
 * 解析 NODE_OPTIONS 里的 `--require` 目标。
 *
 * Node 自己按空格切分 NODE_OPTIONS 且不支持引号（hooks/runtime.js 里有同样
 * 的告诫），所以这里只能照抄这个规则。认 `--require x` / `-r x` /
 * `--require=x` 三种形态。
 */
export function parseRequireTargets(nodeOptions: string | undefined): string[] {
  const out: string[] = [];
  const tokens = (nodeOptions ?? "").trim().split(/\s+/);
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    if (token === "--require" || token === "-r") {
      const value = tokens[++i];
      if (value) out.push(value);
    } else if (token.startsWith("--require=")) {
      const value = token.slice("--require=".length);
      if (value) out.push(value);
    } else if (token.startsWith("-r=")) {
      const value = token.slice("-r=".length);
      if (value) out.push(value);
    }
  }
  return out;
}

export interface HookRequireMatch {
  /** NODE_OPTIONS 里写下的原始 target（未做绝对化）。 */
  raw: string;
  /** 解析成绝对路径后的 target；`--require` 相对路径由 Node 按 cwd 解析。 */
  resolved: string;
  /** 命中的 hook 文件名。 */
  basename: HookBasename;
  /** 落在插件自有数据目录（期望布局）。 */
  inPreloadDir: boolean;
  /** 落在遗留安装目录（旧部署写法，需迁移）。 */
  inLegacyDir: boolean;
  /** 落在安装包自带的 hooks/ 下（零残留写法，不需要 seed 副本）。 */
  inBundledDir: boolean;
}

/**
 * 列出 NODE_OPTIONS 中属于本插件的 hook 预加载目标。
 *
 * 判定方式是"文件名 + 路径归属"，不再靠猜路径形状。旧实现用一条正则
 * `sst-security-control-openclaw.*runtime|...|hooks\/runtime` 去匹配，于是：
 *   - `.../extensions/<id>/hook-mounter.js`     → no-match（被误判成外人的 hook）
 *   - `.../extensions/<id>/hooks/hook-mounter.js` → 同样 no-match
 * 而 hook-mounter.js 恰恰是三个文件里唯一推荐给 NODE_OPTIONS 的那个。误判的
 * 代价不是一行日志：`probeRuntimeHookLoaded` 返回 false →
 * `applyBootstrapResults` 把 `application.runtimeHooks.enabled` 强制改成 false
 * → 下次启动 `ensureBundledHooks` 首行就 return false，连副本都不再维护。
 */
export function matchHookRequires(nodeOptions: string | undefined): HookRequireMatch[] {
  const preloadDir = resolvePreloadDir();
  const legacyDir = resolveLegacyDir();
  const bundledDir = findBundledDir("hooks");
  const matches: HookRequireMatch[] = [];
  for (const raw of parseRequireTargets(nodeOptions)) {
    const resolved = isAbsolute(raw) ? resolve(raw) : resolve(process.cwd(), raw);
    const name = basename(resolved);
    if (!isHookBasename(name)) continue;
    const inPreloadDir = isInside(resolved, preloadDir);
    const inBundledDir = bundledDir ? isInside(resolved, bundledDir) : false;
    // 遗留布局除了默认路径，还可能是 OPENCLAW_EXTENSIONS_DIR 指到的别处，
    // 那种路径不一定含插件 id，因此"落在 legacyDir 内"与"路径带插件 id"并判。
    const inLegacyDir =
      isInside(resolved, legacyDir) ||
      (!inPreloadDir && !inBundledDir && resolved.includes(PLUGIN_ID));
    if (!inPreloadDir && !inBundledDir && !inLegacyDir) continue;
    matches.push({ raw, resolved, basename: name, inPreloadDir, inLegacyDir, inBundledDir });
  }
  return matches;
}