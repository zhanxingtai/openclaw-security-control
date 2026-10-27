/**
 * OpenClaw Security Monitor - Self-Protection Engine
 *
 * Hard-coded last line of defense: prevents the agent from disabling or
 * uninstalling the security monitor plugin itself, tampering with its
 * configuration, or destroying its policy / event data.
 *
 * This layer intentionally runs *before* the policy-based intervention engine
 * so that protection cannot be bypassed by deleting or editing the policy file.
 */

import { readFileSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import type { InterventionContext, SecurityDecision } from './types.js';
import { DEFAULT_DESTRUCTIVE_WRITE_TOOLS } from './destructive-tools.js';

export interface SelfProtectionResult {
  /** True if the action would harm the plugin and must be blocked. */
  blocked: boolean;
  /** Decision to return when blocked. */
  decision?: SecurityDecision;
}

/** Canonical plugin identifiers. The plugin id is locked lowercase by the
 * OpenClaw 9.4 host (validateRegistryNpmSpec regex) and `plugin-registry-id-
 * normalizer.toLowerCase()` lookup. Historical ids (`...-v0.9.1` and the
 * legacy `openclaw-security-monitor`) are still matched via
 * PLUGIN_ID_RE_SRC so previously installed copies cannot evade
 * self-protection by quoting an old name. */
const PLUGIN_ID = 'sst-security-control-openclaw';
/** Regex alternation that matches the current and any historical plugin id,
 * used in the self-harm patterns below so every historical id stays protected. */
const PLUGIN_ID_RE_SRC = '(?:sst-security-control-openclaw|sst-security-control-openclaw-v0\\.9\\.1|openclaw[-_]?security[-_]?monitor)';

/** File paths that the plugin owns and that must not be deleted/modified.
 *
 * IMPORTANT: keep these patterns scoped to the plugin's own install/config
 * locations.  Broad patterns like `(^|/)openclaw-security-monitor` would also
 * match the current development workspace or any user directory that happens
 * to contain the plugin id, causing false positives on normal file operations.
 */
const PROTECTED_PATH_PATTERNS = [
  // Plugin configuration and data home.
  // 2026-10-27 误报收敛：agent 工作区（.openclaw/workspace）不是插件资产，
  // 承载 agent 自己的 memory/笔记；把它拖进受保护路径会让「把排查笔记写进
  // memory」因正文出现工作区路径而被当成篡改拦下。插件自有资产（openclaw.json
  // / 策略文件 / 审计日志 / 扩展目录 / 安装目录）由下方逐条精确模式覆盖。
  String.raw`(^|/)\.openclaw[/\\](?!workspace\b)`,
  String.raw`(^|/)\.openclaw[/\\]openclaw\.json$`,
  String.raw`(^|/)\.openclaw[/\\]security-policy\.ya?ml$`,
  String.raw`(^|/)\.openclaw[/\\]security-events\.jsonl$`,
  String.raw`(^|/)\.openclaw[/\\]security-events-runtime\.jsonl$`,
  String.raw`(^|/)\.openclaw[/\\]guidance-templates[/\\]`,
  String.raw`(^|/)\.openclaw[/\\]extensions[/\\]${escapeRegex(PLUGIN_ID)}`,
  // Common plugin install directories (npm / openclaw)
  String.raw`(^|/)node_modules[/\\]${escapeRegex(PLUGIN_ID)}`,
  String.raw`(^|/)node_modules[/\\]@zhanxing[/\\]${escapeRegex(PLUGIN_ID)}`,
  // Backup install location the setup script also recognizes (is_plugin_installed)
  String.raw`(^|/)\.openclaw[/\\]npm[/\\]projects[/\\]${escapeRegex(PLUGIN_ID)}`,
  // Source / build artifacts of this repository, scoped under the plugin
  // directory to avoid blocking normal user workspaces.
  String.raw`(^|/)${escapeRegex(PLUGIN_ID)}[/\\]src[/\\]store\.(ts|js)$`,
  String.raw`(^|/)${escapeRegex(PLUGIN_ID)}[/\\]src[/\\]intervention[/\\]`,
  String.raw`(^|/)${escapeRegex(PLUGIN_ID)}[/\\]dist[/\\]index\.(ts|js)$`,
];

/** Gateway / plugin-manager config operations that can disable or remove the plugin. */
const GATEWAY_CONFIG_SELF_HARM_PATTERNS = [
  // plugin id + enabled:false / enabled = false / enabled: false
  String.raw`${PLUGIN_ID_RE_SRC}.*\benabled\b\s*[:=]\s*false`,
  // plugin id + disabled / disable
  String.raw`${PLUGIN_ID_RE_SRC}.*\bdisabl`,
  // plugin entries set to null/undefined/removed
  String.raw`${PLUGIN_ID_RE_SRC}\s*[:=]\s*(null|undefined)`,
  // any mention of openclaw.json together with the plugin id (full-config replacement)
  String.raw`openclaw\.json.*${PLUGIN_ID_RE_SRC}`,
  String.raw`${PLUGIN_ID_RE_SRC}.*openclaw\.json`,
  // path that explicitly targets the plugin entry
  String.raw`plugins?\.entries\.${PLUGIN_ID_RE_SRC}`,
];

/** Commands that uninstall, disable, or tamper with the plugin. */
const SELF_HARM_COMMAND_PATTERNS = [
  // Setup script cleanup / uninstall (catches any extension: js/mjs/cjs)
  String.raw`\bsetup-openclaw\.(js|mjs|cjs).*--(cleanup|uninstall)\b`,
  // npm / yarn / pnpm uninstall of the plugin package
  String.raw`\b(npm|yarn|pnpm)\s+(uninstall|remove|rm)\b.*(openclaw-security-monitor|sst-security-control-openclaw|sst-security-control-openclaw-v0\.9\.1|@zhanxing/openclaw-security-monitor|@zhanxing/sst-security-control-openclaw|@zhanxing/sst-security-control-openclaw-v0\.9\.1)`,
  // openclaw plugin/extension CLI (singular/plural, uninstall/remove/disable/delete)
  String.raw`\bopenclaw\s+(plugins?|extensions?)\s+(uninstall|remove|disable|delete)\b.*(openclaw-security-monitor|sst-security-control-openclaw|sst-security-control-openclaw-v0\.9\.1|security-monitor)`,
  String.raw`\bopenclaw\s+(plugins?|extensions?)\s+(uninstall|remove|disable|delete)\b.*${PLUGIN_ID_RE_SRC}`,
  // 8.2 CLI 变体：set-enabled / rm
  String.raw`\bopenclaw\s+plugins?\s+set-?enabled\b.*\b${PLUGIN_ID_RE_SRC}\b`,
  String.raw`\bopenclaw\s+plugins?\s+\brm\b.*\b${PLUGIN_ID_RE_SRC}\b`,
  // plugins.deny 塞入插件 id（deny 在平台层封死，阻断再启用）
  String.raw`plugins?\.deny\s*.*\b${PLUGIN_ID_RE_SRC}\b`,
  String.raw`\b${PLUGIN_ID_RE_SRC}\b.*plugins?\.deny`,
  // Destructive file operations against the plugin data / install directory.
  // We intentionally do NOT block generic `rm .../node_modules` because that
  // is a normal workspace cleanup operation; the plugin is protected by the
  // .openclaw/ and openclaw-security-monitor-specific rules above.
  String.raw`\brm\s+(-[a-zA-Z]*\s+)?\S*\.openclaw(\s|$)`,
  String.raw`\brm\s+(-[a-zA-Z]*\s+)?\S*(openclaw-security-monitor|sst-security-control-openclaw|sst-security-control-openclaw-v0\.9\.1)(\s|$)`,
  String.raw`\brmdir\s+\S*(openclaw-security-monitor|sst-security-control-openclaw|sst-security-control-openclaw-v0\.9\.1)`,
  String.raw`\b(mv|chmod|chown)\s+.*(openclaw-security-monitor|sst-security-control-openclaw|sst-security-control-openclaw-v0\.9\.1)`,
  // Editing the plugin config to disable itself
  String.raw`openclaw\.json.*"enabled"\s*:\s*false`,
  String.raw`plugins\.entries\s*\[\s*['"]${escapeRegex(PLUGIN_ID)}['"]\s*\]\s*=\s*(null|undefined)`,
  String.raw`plugins\.allow\s*=\s*plugins\.allow\.filter\s*\(\s*id\s*=>\s*id\s*!==\s*['"]${escapeRegex(PLUGIN_ID)}['"]`,
];

/** User message patterns that attempt to socially-engineer disabling the plugin. */
const SELF_HARM_MESSAGE_PATTERNS = [
  // Chinese (simplified / traditional variants)
  String.raw`卸载\s*${PLUGIN_ID_RE_SRC}`,
  String.raw`卸载\s*安全\s*监[控告]`,
  String.raw`关闭\s*${PLUGIN_ID_RE_SRC}`,
  String.raw`关闭\s*安全\s*监[控告]`,
  String.raw`禁用\s*${PLUGIN_ID_RE_SRC}`,
  String.raw`禁用\s*安全\s*监[控告]`,
  String.raw`移除\s*${PLUGIN_ID_RE_SRC}`,
  String.raw`删除\s*${PLUGIN_ID_RE_SRC}`,
  // English
  String.raw`\b(uninstall|remove|disable|turn off|shut down|delete)\s+(the\s+)?${PLUGIN_ID_RE_SRC}\s+(plugin\s+)?`,
  String.raw`\b(uninstall|remove|disable|turn off|shut down|delete)\s+(the\s+)?security\s+monitor\s+(plugin\s+)?`,
  String.raw`\bstop\s+(the\s+)?${PLUGIN_ID_RE_SRC}\b`,
  String.raw`\bstop\s+(the\s+)?security\s+monitor\b`,
  // Mixed / code references
  String.raw`\bsetup-openclaw\.(js|mjs|cjs).*--(cleanup|uninstall)\b`,
  String.raw`\bnpm\s+(uninstall|remove|rm)\s+.*${PLUGIN_ID_RE_SRC}`,
  String.raw`\bopenclaw\s+plugins?\s+(uninstall|remove|disable)\s+.*${PLUGIN_ID_RE_SRC}`,
  // plugins.deny 塞入插件 id
  String.raw`plugins?\.deny.*\b${PLUGIN_ID_RE_SRC}\b`,
];

/**
 * 构建期生成的 SelfProtection 模式产物。
 * 唯一数据源是 policies/security-policy.spl.yaml 的顶层
 * `x-openclaw-selfProtection` 区（项目扩展走 x- 前缀）；
 * 构建把它结构化到
 * policies/generated/self-protection-patterns.generated.json 并随 dist
 * 放到本模块旁边。加载失败/文件缺失时回退上方内置常量 + WARN，绝不抛错
 * （自防护层必须永远可用）。
 */
interface SelfProtectionPatternSpec {
  flags?: string;
  groups: {
    protected_paths?: string[];
    gateway_config_self_harm?: string[];
    self_harm_commands?: string[];
    self_harm_messages?: string[];
  };
  structural: {
    inline_interpreter?: string;
    indirect_deletion?: string;
    protected_file_basenames?: string;
    shell_overwrite_verbs?: string;
  };
}

function isNonEmptyStringList(v: unknown): v is string[] {
  return Array.isArray(v) && v.length > 0 && v.every((p) => typeof p === 'string' && p.length > 0);
}

/** 校验并返回产物 spec；任一关键组缺失视为损坏（返回 null 走兜底）。 */
function validateSelfProtectionSpec(raw: unknown): SelfProtectionPatternSpec | null {
  if (!raw || typeof raw !== 'object') return null;
  const spec = raw as SelfProtectionPatternSpec;
  const g = spec.groups;
  const s = spec.structural;
  if (!g || typeof g !== 'object' || !s || typeof s !== 'object') return null;
  if (
    !isNonEmptyStringList(g.protected_paths) ||
    !isNonEmptyStringList(g.gateway_config_self_harm) ||
    !isNonEmptyStringList(g.self_harm_commands) ||
    !isNonEmptyStringList(g.self_harm_messages)
  ) {
    return null;
  }
  if (
    typeof s.inline_interpreter !== 'string' ||
    typeof s.indirect_deletion !== 'string' ||
    typeof s.protected_file_basenames !== 'string' ||
    typeof s.shell_overwrite_verbs !== 'string'
  ) {
    return null;
  }
  if (spec.flags !== undefined && !/^[ims]*$/.test(spec.flags)) return null;
  return spec;
}

/** 加载构建期产物；不可用返回 null（调用方回退内置常量）。 */
function loadSelfProtectionSpec(): SelfProtectionPatternSpec | null {
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [
    // 部署/构建布局：与编译产物同目录（dist/src/intervention/，install 包内 application/src/intervention/）。
    join(here, 'self-protection-patterns.generated.json'),
    // 仓库开发布局：src/intervention → <repo>/policies/generated/。
    join(here, '..', '..', 'policies', 'generated', 'self-protection-patterns.generated.json'),
  ];
  for (const file of candidates) {
    let raw: unknown;
    try {
      raw = JSON.parse(readFileSync(file, 'utf8'));
    } catch {
      continue; // 缺失/不可读：试下一个候选路径
    }
    const spec = validateSelfProtectionSpec(raw);
    if (spec) return spec;
    console.warn(`[SelfProtection] ${file} 结构不完整（缺关键模式组），忽略该产物`);
  }
  console.warn(
    '[SelfProtection] self-protection-patterns.generated.json 不可用，回退内置模式常量' +
    '（构建期产物缺失；请重新执行 npm run build:prod 生成）'
  );
  return null;
}

const SELF_PROTECTION_SPEC = loadSelfProtectionSpec();
const SELF_PROTECTION_FLAGS = SELF_PROTECTION_SPEC?.flags ?? 'i';
const PROTECTED_PATH_REX = (SELF_PROTECTION_SPEC?.groups.protected_paths ?? PROTECTED_PATH_PATTERNS).map((p) => new RegExp(p, SELF_PROTECTION_FLAGS));
const SELF_HARM_COMMAND_REX = (SELF_PROTECTION_SPEC?.groups.self_harm_commands ?? SELF_HARM_COMMAND_PATTERNS).map((p) => new RegExp(p, SELF_PROTECTION_FLAGS));
const SELF_HARM_MESSAGE_REX = (SELF_PROTECTION_SPEC?.groups.self_harm_messages ?? SELF_HARM_MESSAGE_PATTERNS).map((p) => new RegExp(p, SELF_PROTECTION_FLAGS));
const GATEWAY_CONFIG_SELF_HARM_REX = (SELF_PROTECTION_SPEC?.groups.gateway_config_self_harm ?? GATEWAY_CONFIG_SELF_HARM_PATTERNS).map((p) => new RegExp(p, SELF_PROTECTION_FLAGS));

// 内联解释器绕过点：python3 -c "os.remove(...)" / node -e "fs.rmSync(...)" 等
// 内联解释器执行文件删除，直接绕开原生 rm 命令模式。检测需要同时满足：
//   ① 解释器前缀（python/node/… -c/-e） ② 破坏性 API ③ 命中受保护路径或自有文件基名，
// 保证普通读取脚本（如 print(open(...).read())）不受影响。
const INLINE_INTERPRETER_RE = SELF_PROTECTION_SPEC
  ? new RegExp(SELF_PROTECTION_SPEC.structural.inline_interpreter!, SELF_PROTECTION_FLAGS)
  : /\b(python|python3|python2|node|nodejs|deno|bun|ruby|perl|php|lua|jruby)\s+(?:-[ce]|--[a-z]+)\b/;
const INDIRECT_DELETION_RE = SELF_PROTECTION_SPEC
  ? new RegExp(SELF_PROTECTION_SPEC.structural.indirect_deletion!, SELF_PROTECTION_FLAGS)
  : /\bos\.(remove|unlink|rmdir|system|rmtree)\b|\bshutil\.(rmtree|rm)\b|\bfs\.(rm|rmSync|unlink|unlinkSync|rmdir|rmdirSync)\b|\b(?:Path\.)?unlink\s*\(|\b(?:remove|unlink|rmtree|rmdir|truncate)\s*\(|\b(?:rmSync|unlinkSync|rmdirSync)\s*\(|require\s*\(\s*['"](?:node:)?fs['"]\s*\)\s*\.\s*(?:rm|rmSync|unlink|unlinkSync|rmdir|rmdirSync|rmtree)\b|\b(?:Remove-Item|ri|rm|del)\s+/i;
const PROTECTED_FILE_BASENAMES = SELF_PROTECTION_SPEC
  ? new RegExp(SELF_PROTECTION_SPEC.structural.protected_file_basenames!, SELF_PROTECTION_FLAGS)
  : /\bsecurity-(?:events|events-runtime|events-debug)\.jsonl\b|\bsecurity-policy\.(?:ya?ml|json)\b|\bsecurity-monitor-shim\b/;

// 壳层组合改写(非 rm 形态):重定向覆盖 >/>>、truncate、tee、cp /dev/null、find -delete、
// sed -i、dd of=,以及解释器 open(...,'w').write / os.rename / shutil.copy 覆盖。
// 仅在与受保护路径同一命令段时判定,避免误拦普通文件操作。
const SHELL_OVERWRITE_VERBS_RE = SELF_PROTECTION_SPEC
  ? new RegExp(SELF_PROTECTION_SPEC.structural.shell_overwrite_verbs!, SELF_PROTECTION_FLAGS)
  : /\b(?:truncate|tee)\b|\b(?:cp|install)\s+\/?dev\/null\b|\bfind\b[^\n]*-delete\b|\bdd\b[^\n]*\bof=|\bsed\b[^\n]*-i\b|\bos\.(?:rename|replace)\b|\bshutil\.(?:copy2?|copyfile|move)\b|\bPath\.write_text\b|\b\.write\s*\(|\bopen\s*\(\s*["'][^"']*["']\s*,\s*["']w/i;

const BLOCK_REASON = '该操作会禁用或卸载安全监控插件，已被系统自我保护机制阻断';
const BLOCK_CODE = 'SELF_PROTECTION_001';

/**
 * 网关主配置 openclaw.json 的改写动词。
 *
 * 旧实现把 isDestructive 里的 /openclaw\.json/i 全文匹配当作「正在写网关
 * 配置」——只要命令里出现 openclaw.json 就算破坏性，于是
 * `cat ~/.openclaw/openclaw.json` 这类纯读取也被当成篡改拦下。
 * 改为按命令段判定：段内同时出现 openclaw.json 与写类动词/重定向才算改写。
 */
const GATEWAY_CONFIG_WRITE_VERB_RE =
  /\b(?:cp|mv|install|rsync|rm|rmdir|unlink|truncate|tee)\b|\bsed\b[^\n]*-i\b|\b(?:writefile|writefilesync|appendfile|appendfilesync|copyfile|rename)\s*\(/i;

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// 与 RuleMatcher.collectMatchStrings 同款的深度/节点预算：host 传入的
// params 是 live 对象，可能循环引用或超深嵌套，无界递归会爆栈抛
// RangeError 并打断整条 tool-call 链路。超限时只跳过越界
// 子树并告警留痕，绝不上抛。
const COLLECT_STRINGS_MAX_DEPTH = 32;
const COLLECT_STRINGS_MAX_NODES = 2000;
let collectStringsTruncatedWarned = false;

function collectStrings(value: unknown): string[] {
  const out: string[] = [];
  let nodes = 0;
  let truncated = false;
  // ancestors 只记录当前路径上的容器：既能断环，又不会因兄弟节点
  // 共享同一子树而漏收字符串。
  const ancestors = new Set<object>();
  const walk = (v: unknown, depth: number): void => {
    if (truncated) return;
    if (nodes >= COLLECT_STRINGS_MAX_NODES) {
      truncated = true;
      return;
    }
    nodes++;
    if (typeof v === 'string') out.push(v);
    else if (typeof v === 'number' || typeof v === 'boolean') out.push(String(v));
    else if (Array.isArray(v)) {
      if (depth >= COLLECT_STRINGS_MAX_DEPTH || ancestors.has(v)) {
        truncated = true;
        return;
      }
      ancestors.add(v);
      for (const item of v) walk(item, depth + 1);
      ancestors.delete(v);
    } else if (v && typeof v === 'object') {
      if (depth >= COLLECT_STRINGS_MAX_DEPTH || ancestors.has(v)) {
        truncated = true;
        return;
      }
      ancestors.add(v);
      for (const item of Object.values(v)) walk(item, depth + 1);
      ancestors.delete(v);
    }
  };
  walk(value, 0);
  if (truncated && !collectStringsTruncatedWarned) {
    collectStringsTruncatedWarned = true;
    console.warn(
      `[SelfProtection] params 嵌套超出提取上限（深度 ${COLLECT_STRINGS_MAX_DEPTH} / 节点 ${COLLECT_STRINGS_MAX_NODES}）或存在循环引用，`
        + '已跳过越界子树并继续评估；被跳过子树内的字符串不参与匹配'
    );
  }
  return out;
}

function anyMatch(text: string, patterns: RegExp[]): boolean {
  return patterns.some((re) => re.test(text));
}

function isProtectedPath(value: string): boolean {
  return anyMatch(value, PROTECTED_PATH_REX);
}

function isSelfHarmCommand(text: string): boolean {
  return anyMatch(text, SELF_HARM_COMMAND_REX);
}

function isSelfHarmMessage(text: string): boolean {
  return anyMatch(text, SELF_HARM_MESSAGE_REX);
}

function isGatewayConfigSelfHarm(text: string): boolean {
  return anyMatch(text, GATEWAY_CONFIG_SELF_HARM_REX);
}

/**
 * 检测"内联解释器直删受保护文件"（绕开 rm 命令模式的直删形态）：
 *   python3 -c "os.remove('.../security-events.jsonl')"
 *   node -e "require('fs').rmSync('.../security-policy.yaml')"
 *   python3 -c "shutil.rmtree('.../.openclaw/extensions/...')"
 * 三者（解释器前缀 + 破坏性 API + 受保护路径/自有文件基名）同时命中才判定。
 */
function isIndirectDeletionOfProtectedData(text: string): boolean {
  const lower = text.toLowerCase();
  if (!INLINE_INTERPRETER_RE.test(lower)) return false;
  if (!INDIRECT_DELETION_RE.test(lower)) return false;
  if (isProtectedPath(text)) return true;
  // 兜底：路径不含 .openclaw 时，只要点名了插件自有文件基名也算。
  return PROTECTED_FILE_BASENAMES.test(lower);
}

/**
 * 检测"壳层组合改写/截断受保护文件"（非 rm 形态的既有缺口）：
 *   echo "#" > ~/.openclaw/security-policy.yaml        （重定向覆盖）
 *   truncate -s 0 ~/.openclaw/security-events.jsonl    （截断清零）
 *   cp /dev/null <受保护文件> / find <受保护目录> -delete / dd of=<受保护文件>
 *   sed -i '...' <受保护文件>
 *   python3 -c "open(path,'w').write(...)" / os.rename / shutil.copy 覆盖
 * 判定按命令段切分（; & | 换行）：段内同时出现"写类动词或重定向"与受保护路径/自有文件基名才命中，
 * 使 `cp -r ~/.openclaw /tmp/backup > log` 这类只读备份不受影响。
 */
function isShellOverwriteOfProtectedData(text: string): boolean {
  const lower = text.toLowerCase();
  const segments = lower.split(/[;&|]\s*|\n+/);
  for (const seg of segments) {
    const hasProtectedTarget = isProtectedPath(seg) || PROTECTED_FILE_BASENAMES.test(seg);
    if (!hasProtectedTarget) continue;

    // 直接改写/截断/清空命令（段内同时点到受保护文件）
    if (SHELL_OVERWRITE_VERBS_RE.test(seg)) {
      return true;
    }

    // 重定向覆盖：受保护文件紧跟 > / >> 之后
    const redir = /(?:^|[\s;|&])>+\s*([^\s;|&]+)/g;
    let m: RegExpExecArray | null;
    while ((m = redir.exec(seg)) !== null) {
      const target = m[1];
      if (isProtectedPath(target) || PROTECTED_FILE_BASENAMES.test(target)) {
        return true;
      }
    }
  }
  return false;
}

/**
 * 判定「改写网关主配置 openclaw.json」。
 *
 * 纯读取（cat / sed -n / jq / grep / less / head）不是破坏性操作；只有
 * 写类动词、重定向覆盖、脚本写 API 落到 openclaw.json 上才算改写。
 * 按命令段切分（; & | 换行），读命令与写命令在同一段里也不会互相污染。
 */
function isGatewayConfigOverwrite(text: string): boolean {
  const lower = text.toLowerCase();
  const segments = lower.split(/[;&|]\s*|\n+/);
  for (const seg of segments) {
    if (!seg.includes('openclaw.json')) continue;
    // 壳层改写/截断类动词与脚本写 API（truncate/tee/sed -i/open(...,'w')…）
    if (SHELL_OVERWRITE_VERBS_RE.test(seg)) return true;
    // 复制/移动/删除/改名等直接改写主配置的动词
    if (GATEWAY_CONFIG_WRITE_VERB_RE.test(seg)) return true;
    // 重定向覆盖：openclaw.json 紧跟 > / >> 之后
    const redir = /(?:^|[\s;|&])>+\s*([^\s;|&]+)/g;
    let m: RegExpExecArray | null;
    while ((m = redir.exec(seg)) !== null) {
      if (m[1].includes('openclaw.json')) return true;
    }
  }
  return false;
}

/**
 * General catch-all: a gateway/config_manager write that touches the plugin
 * configuration (plugins, allow lists, openclaw.json) is self-harm unless it
 * clearly keeps the plugin enabled/allowed. We err on the side of blocking
 * because these config tools are powerful and rare.
 */
function isGatewayModifyingPluginConfig(allParamText: string): boolean {
  const lower = allParamText.toLowerCase();
  const mentionsPluginId =
    lower.includes(PLUGIN_ID) ||
    lower.includes('@zhanxing/openclaw-security-monitor') ||
    lower.includes('@zhanxing/sst-security-control-openclaw') ||
    lower.includes('@zhanxing/sst-security-control-openclaw-v0.9.1');
  const mentionsPluginConfig = /\bplugins?\b|openclaw\.json|\.openclaw\b/i.test(allParamText);
  const mentionsDisableOrRemove =
    /\benabled\b\s*[:=]\s*false|\bdisabled\b|\bdisable\b|\buninstall\b|\bremove\b|\bdelete\b|\bnull\b|\bundefined\b/i.test(allParamText);

  // Plugin id + disabling/removal indicator in plugin config context.
  if (mentionsPluginId && mentionsPluginConfig && mentionsDisableOrRemove) {
    return true;
  }

  // Any modification that rewrites the global openclaw.json and also touches
  // plugin configuration is self-harm (we cannot easily tell if it keeps the
  // plugin enabled, so we block and require admin action).
  if (/openclaw\.json/i.test(allParamText) && /\bplugins?\b/i.test(allParamText)) {
    return true;
  }

  return false;
}

function isGatewayConfigTool(toolName: string): boolean {
  return /^(gateway|config_manager|plugin_manager|extension_manager|openclaw_gateway|core\.gateway|plugin_uninstall|extension_uninstall|manage_plugin)$/i.test(toolName);
}

/**
 * Detect when a gateway/plugin-manager tool directly targets the security monitor
 * plugin with an uninstall, remove, disable, or delete action.
 *
 * This covers explicit calls such as `gateway { action: 'plugin.uninstall',
 * plugin: 'openclaw-security-monitor' }` or a dedicated `plugin_uninstall` tool.
 */
function isGatewayDisablingPlugin(
  toolName: string,
  params: Record<string, unknown>,
  allParamText: string
): boolean {
  const action = String(params.action || params.command || params.method || '').toLowerCase();
  const targetPlugin = String(
    params.plugin ||
      params.extension ||
      params.pluginId ||
      params.extensionId ||
      params.id ||
      params.target ||
      ''
  );
  const toolNameImpliesHarm = /(uninstall|remove|disable|delete)/i.test(toolName);
  const actionImpliesHarm = /\b(uninstall|remove|delete|disable|turn[_-]?off|shut[_-]?down)\b/.test(
    action
  );
  if (!toolNameImpliesHarm && !actionImpliesHarm) return false;

  const targetMentionsPlugin =
    targetPlugin.toLowerCase().includes(PLUGIN_ID) ||
    targetPlugin.toLowerCase().includes('security-monitor') ||
    targetPlugin.toLowerCase().includes('@zhanxing/openclaw-security-monitor') ||
    targetPlugin.toLowerCase().includes('@zhanxing/sst-security-control-openclaw') ||
    targetPlugin.toLowerCase().includes('@zhanxing/sst-security-control-openclaw-v0.9.1');
  if (targetMentionsPlugin) return true;

  // Fallback: the whole parameter text names the plugin in a harmful context.
  return isSelfHarmMessage(allParamText) || isGatewayConfigSelfHarm(allParamText);
}

function isConfigModifyingAction(params: Record<string, unknown>): boolean {
  const action = String(params.action || params.command || params.method || '').toLowerCase();
  // Direct config CRUD actions.
  if (/^(config\.)?(patch|set|update|put|write|delete|remove|unset|replace|merge|edit)$/.test(action)) {
    return true;
  }
  // Plugin / extension management actions that disable or remove.
  if (/\b(uninstall|remove|disable|delete|unset|turn[_-]?off|shut[_-]?down)\b/.test(action)) {
    return true;
  }
  return false;
}

/**
 * gateway restart/reload is normally benign, but if the agent explicitly uses it
 * to drop the security monitor hooks after an uninstall, it becomes self-harm.
 */
function isGatewayRestartWithUninstallIntent(params: Record<string, unknown>, allParamText: string): boolean {
  const action = String(params.action || '').toLowerCase();
  if (action !== 'restart' && action !== 'reload' && action !== 'reboot') {
    return false;
  }
  if (isSelfHarmMessage(allParamText) || isGatewayConfigSelfHarm(allParamText)) {
    return true;
  }
  const lower = allParamText.toLowerCase();
  const mentionsMonitor =
    lower.includes(PLUGIN_ID) ||
    lower.includes('security-monitor') ||
    lower.includes('@zhanxing/openclaw-security-monitor') ||
    lower.includes('@zhanxing/sst-security-control-openclaw') ||
    lower.includes('@zhanxing/sst-security-control-openclaw-v0.9.1');
  const mentionsUninstall = /\b(uninstall|remove|delete|drop)\b/i.test(allParamText);
  const mentionsHooks = /\bhooks?\b/i.test(allParamText);
  return mentionsMonitor && (mentionsUninstall || mentionsHooks);
}

/**
 * Recursively scan a value for a plugin allow-list that does not contain the
 * security monitor plugin. Handles nested JSON objects and arrays, including
 * JSON-serialized strings.
 */
function containsAllowListWithoutPlugin(value: unknown): boolean {
  if (value === null || value === undefined) return false;
  if (typeof value === 'string') {
    try {
      const parsed = JSON.parse(value);
      if (Array.isArray(parsed) || typeof parsed === 'object') {
        return containsAllowListWithoutPlugin(parsed);
      }
    } catch {
      // Not JSON: plain strings cannot be an allow-list.
    }
    return false;
  }
  if (Array.isArray(value)) {
    const stringItems = value.filter((item): item is string => typeof item === 'string');
    if (stringItems.length > 0) {
      const hasPlugin = stringItems.some(
        (item) =>
          item.toLowerCase().includes(PLUGIN_ID) ||
          item.toLowerCase().includes('openclaw-security-monitor')
      );
      if (!hasPlugin) return true;
    }
    return value.some(containsAllowListWithoutPlugin);
  }
  if (typeof value === 'object') {
    for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
      // Recognise common allow-list key synonyms: allow / whitelist / permit /
      // enabled-list / permitted. PLUGIN_ID must be present in the list or the
      // attacker is removing us from the policy surface.
      if (/allow|whitelist|permit|permitted|enabled[-_]?list/i.test(String(key)) && Array.isArray(val)) {
        const stringItems = val.filter((item): item is string => typeof item === 'string');
        if (stringItems.length > 0 && !stringItems.some((item) => item.toLowerCase().includes(PLUGIN_ID))) {
          return true;
        }
      }
      if (containsAllowListWithoutPlugin(val)) return true;
    }
  }
  return false;
}

/**
 * Detect when the agent sets plugins.allow (or the whole plugins object / full
 * config) to a list/object that omits the security monitor plugin.
 */
function isPluginAllowListRemoval(params: Record<string, unknown>): boolean {
  const path = String(params.path || '');
  const raw = params.raw ?? params.value ?? params.content ?? params.data ?? params.config;
  if (!raw) return false;
  const context = `${path} ${JSON.stringify(raw)}`;
  if (!/plugins?(\.allow|\b)|\ballow\b|openclaw\.json/i.test(context)) {
    return false;
  }
  return containsAllowListWithoutPlugin(raw) || containsAllowListWithoutPlugin(params);
}

function blockDecision(): SecurityDecision {
  return {
    decision: 'block',
    blockReason: BLOCK_REASON,
    blockCode: BLOCK_CODE,
    appealable: false,
    policyId: 'self-protection',
    policyName: 'Self-Protection',
    reason: BLOCK_REASON,
  };
}

/**
 * Evaluate a tool_call intervention context for self-harm.
 */
function evaluateToolCall(ctx: InterventionContext): SelfProtectionResult {
  const params = ctx.params || {};
  const allParamText = collectStrings(params).join('\n');

  // 1. Destructive commands (exec, bash, shell, run_command, etc.)
  if (isSelfHarmCommand(allParamText)) {
    return { blocked: true, decision: blockDecision() };
  }

  // 2. Gateway / plugin-manager config operations that disable or remove the plugin.
  //    This covers the real bypass where the agent used `gateway` with
  //    action=config.patch to drop the plugin from plugins.allow and set
  //    enabled:false. It also covers variants such as config.set on
  //    plugins.entries.<plugin>.enabled, full openclaw.json rewrite, and
  //    plugin_manager disable/remove actions.
  if (isGatewayConfigTool(ctx.toolName || '')) {
    if (isGatewayRestartWithUninstallIntent(params, allParamText)) {
      return { blocked: true, decision: blockDecision() };
    }
    if (
      isGatewayDisablingPlugin(ctx.toolName || '', params, allParamText) ||
      isGatewayConfigSelfHarm(allParamText) ||
      isSelfHarmMessage(allParamText) ||
      isPluginAllowListRemoval(params) ||
      (isConfigModifyingAction(params) && isGatewayModifyingPluginConfig(allParamText))
    ) {
      return { blocked: true, decision: blockDecision() };
    }
  }

  // 3. Any tool parameter text that explicitly asks to uninstall/disable the
  //    plugin (e.g. the "note" field of a gateway call) is also self-harm.
  if (isSelfHarmMessage(allParamText)) {
    return { blocked: true, decision: blockDecision() };
  }

  // 3.5 Inline-interpreter deletion of protected data (python3 -c / node -e /
  //     shutil.rmtree). Bypasses native rm command patterns.
  if (isIndirectDeletionOfProtectedData(allParamText)) {
    return { blocked: true, decision: blockDecision() };
  }

  // 4. File operations targeting protected paths (read/write/delete/edit)
  if (isProtectedPath(allParamText)) {
    // Only block destructive or config-modifying operations; allow reads of the
    // policy / events for legitimate inspection unless the content is a command.
    // 默认字典见 src/intervention/destructive-tools.ts —— 单源、保守默认；
    // 超出默认的工具由插件 manifest 声明 capabilities.destructive_write_tools
    // 后再纳入，不在 SelfProtection 层硬编码扩字典。
    const toolName = ctx.toolName || '';
    const isDestructive =
      DEFAULT_DESTRUCTIVE_WRITE_TOOLS.has(toolName) ||
      isSelfHarmCommand(allParamText) ||
      // Shell-composed overwrite/truncate of a protected file (echo > / truncate / find -delete ...)
      isShellOverwriteOfProtectedData(allParamText) ||
      // Writing to openclaw.json is always suspect, even for benign-looking tools.
      // 只读（cat / sed -n / jq / grep）不算改写——旧实现按「文本里出现
      // openclaw.json」判定，把纯读取也当成篡改拦下。
      isGatewayConfigOverwrite(allParamText);

    if (isDestructive) {
      return { blocked: true, decision: blockDecision() };
    }
  }

  return { blocked: false };
}

/**
 * Evaluate a message_write intervention context for self-harm.
 */
export function evaluateMessageWrite(ctx: InterventionContext): SelfProtectionResult {
  const text = ctx.body || ctx.userPrompt || '';
  if (isSelfHarmMessage(text)) {
    return { blocked: true, decision: blockDecision() };
  }
  return { blocked: false };
}

/**
 * Evaluate a generic intervention context for self-harm.
 */
export function evaluate(ctx: InterventionContext): SelfProtectionResult {
  // SPL canonical actionType for native tool calls is 'agent_tool_call';
  // legacy 'tool_call' and 'message_write' aliases are still recognized.
  if (ctx.actionType === 'agent_tool_call' || ctx.actionType === 'tool_call') {
    return evaluateToolCall(ctx);
  }
  if (ctx.actionType === 'agent_message' || ctx.actionType === 'message_write') {
    return evaluateMessageWrite(ctx);
  }
  return { blocked: false };
}
