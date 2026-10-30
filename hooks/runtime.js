// openclaw-hook: v1.0.2 (信息性注释；升级判定用全文内容哈希，勿依赖此值)
// ⚠ 本文件只被 --require 加载，不要加 shebang —— `#!` 一旦不在文件最开头
// 就是语法错，而这个文件正是 NODE_OPTIONS 的预加载目标，语法错 = 整个宿主
// 进程在启动期退出。详见 hooks/hook-mounter.js 顶部同款说明。
/**
 * OpenClaw Security Monitor - Node.js Runtime Hook
 *
 * Preload this module via NODE_OPTIONS to intercept child_process executions
 * inside the OpenClaw gateway / agent process:
 *
 *   NODE_OPTIONS="-r /path/to/openclaw-security-monitor/hooks/node/runtime.js"
 *
 * Captured APIs:
 *   - child_process.exec / execSync
 *   - child_process.execFile / execFileSync
 *   - child_process.spawn / spawnSync
 *   - child_process.fork
 *
 * Events are appended to the file pointed at by OPENCLAW_MONITOR_LOG_PATH
 * (JSON Lines). If the file path is not configured, events are silently dropped
 * after stderr logging in debug mode.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');

const MODULE_NAME = 'openclaw-security-monitor-runtime-hook';
// 诊断开关。OPENCLAW_HOOK_DEBUG 是总开关（network.js / hook-mounter.js 也认），
// 单 hook 的 OPENCLAW_RUNTIME_HOOK_DEBUG 保留，两者任一为真即开。
const DEBUG =
  process.env.OPENCLAW_RUNTIME_HOOK_DEBUG === 'true' ||
  process.env.OPENCLAW_RUNTIME_HOOK_DEBUG === '1' ||
  process.env.OPENCLAW_HOOK_DEBUG === 'true' ||
  process.env.OPENCLAW_HOOK_DEBUG === '1';
const MAX_COMMAND_LINE_LENGTH = parseInt(process.env.OPENCLAW_RUNTIME_HOOK_MAX_CMD_LENGTH || '4096', 10);
const MAX_ARGUMENTS_TOTAL_LENGTH = parseInt(process.env.OPENCLAW_RUNTIME_HOOK_MAX_ARGS_LENGTH || '4096', 10);

// 纯正则 cmdline flag 的检测模式与默认阻断名单的唯一数据源是
// policies/security-policy.spl.yaml（hookPatterns / metadata.flagRegistry），
// 构建期生成同目录 generated-patterns.json。本文件内的 FALLBACK_* 常量只在
// 产物缺失/损坏（部分部署包）时兜底，并打 WARN；正常构建不再双写漂移。
// 产物缺失/损坏时兜底表必须严格镜像 spl.yaml；一致性由 hooks/runtime.test.ts
// 的「兜底 vs 产物」用例守住（改了一边必须改另一边）。
const FALLBACK_BLOCKED_FLAGS = [
  'reverse_shell',
  'download_execute',
  'mass_deletion',
  'privilege_escalation',
  'token_in_command',
  'skill_binary_execution',
];

// 运行时 hook 的同步阻断模式集（不占 flag 名），与 spl.yaml 的 hookBlockPatterns
// 段一一对应：模式级 Tier-1 阻断给出具体原因（读口令库 / 读私钥…），flag 级只给 flag 名。
//
// ⚠️ 与 hooks/generated-patterns.json 的 blockPatterns 逐条一致
//    （pattern 原文 + reason + input）——一致性由 hooks/runtime.test.ts 断言。
const FALLBACK_BLOCK_PATTERNS = [
  {
    pattern: '(?:^|\\s|["\'<>])(?:/etc/shadow|/etc/gshadow|/etc/sudoers(?:/|\\b))\\b',
    input: 'raw',
    reason: '读取 Tier-1 口令库/提权配置（/etc/shadow、/etc/gshadow、/etc/sudoers）',
  },
  {
    pattern: '(?:^|\\s|["\'<>])/etc/ssh/ssh_host_\\S+',
    input: 'raw',
    reason: '读取 SSH 主机私钥（/etc/ssh/ssh_host_*）',
  },
  {
    pattern: '(?:^|\\s|["\'<>])/proc/self/environ\\b',
    input: 'raw',
    reason: '读取进程环境变量（/proc/self/environ，常含明文 API Key）',
  },
  {
    pattern: '(?:^|\\s|["\'<>])(?:[^\\s"\'<>]*/)?\\.ssh/(?:id_rsa|id_ed25519|id_ecdsa|id_dsa)\\b',
    input: 'raw',
    reason: '读取 SSH 用户私钥（~/.ssh/id_*）',
  },
  {
    pattern: '(?:^|\\s|["\'<>])(?:[^\\s"\'<>]*/)?\\.aws/credentials\\b',
    input: 'raw',
    reason: '读取云厂商凭据文件（~/.aws/credentials）',
  },
  {
    pattern: '(?:^|\\s|["\'<>])(?:[^\\s"\'<>]*/)?\\.(?:git-credentials|netrc)\\b',
    input: 'raw',
    reason: '读取 git / netrc 明文凭据文件',
  },
  {
    pattern: '\\bgetent\\s+(?:shadow|gshadow)\\b',
    input: 'raw',
    reason: '通过 getent 读取 shadow 口令库',
  },
];

// 内置兜底模式表：与 spl.yaml hookPatterns 一一对应（含 input 语义：
// raw = 匹配原始大小写 redacted，缺省 = 匹配小写化 redacted）。
// 无 /g 标志：共享正则的 stateful lastIndex 会让重复 .test() 交替命中。
const FALLBACK_HOOK_PATTERNS = {
  network_tool: [{ re: /\bcurl\b|\bwget\b|\bnc\b|\bnetcat\b|\bnmap\b/ }],
  pipe_to_shell: [{ re: /\|[^|]*\bsh\b|\|[^|]*\bbash\b|\beval\b|\bbase64\b/ }],
  // mass_deletion: any recursive + force rm, or --no-preserve-root, is treated as high-risk.
  mass_deletion: [
    { re: /\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|--recursive)\b/ },
    { re: /\brm\s+-[a-zA-Z]*\s+--no-preserve-root/ },
  ],
  file_deletion: [{ re: /\brm\b/ }],
  // sensitive_file_access: any reference to common sensitive system files or
  // SSH keys, anywhere in the command line (including shell redirect input
  // like `while read ... < /etc/passwd`); getent 等价于读 /etc/passwd 等。
  sensitive_file_access: [
    { re: /(?:^|\s|["'<>])(?:\/etc\/(?:passwd|shadow|gshadow|sudoers|hosts|ssh\/\S*)|\/root\/\S*|\/proc\/self\/environ|(?:.*\/)?\.ssh\/(?:id_rsa|id_ed25519|id_ecdsa|id_dsa|authorized_keys|known_hosts|config))\b/ },
    { re: /\bgetent\s+(passwd|shadow|group)\b/ },
  ],
  privilege_escalation: [{ re: /\bsudo\b|\bsu\b|\bchmod\b.*\+s|\bsetuid\s*\(/ }],
  // Authorization / Bearer / 标准凭据字段名（不论是否已被 redact）。
  token_in_command: [
    { re: /Authorization\s*[:=]|Bearer\s+[A-Za-z0-9_\-\.~+\/=]{8,}|api[_-]?key\s*[:=]\s*\S+|access[_-]?token\s*[:=]\s*\S+|secret\s*[:=]\s*\S+|password\s*[:=]\s*\S+/i, raw: true },
  ],
  background_execution: [{ re: /nohup\b|&\s*$|\bdetach\b/ }],
  // Reverse shell patterns: bash -i >& /dev/tcp/..., nc -e /bin/sh, python socket.
  reverse_shell: [
    { re: /\/dev\/tcp\/|\/dev\/udp\/|bash\s+-i\s+>&|sh\s+-i\s+>&|nc\s+.*-e\s+\/(?:bin|usr)\/(?:sh|bash|zsh)|python.*socket.*connect/ },
  ],
  // Download and execute: curl ... | sh, wget -O - | bash
  download_execute: [{ re: /(?:curl|wget|fetch).*\|.*\b(?:sh|bash|zsh)\b/ }],
  chmod_executable: [{ re: /\bchmod\b.*\+x/ }],
  suspicious_encoding: [{ re: /\bbase64\b.*\|.*\b(?:sh|bash|zsh)\b|\becho\b.*\|.*\bbase64\b/ }],
  // Data exfiltration tools.
  // 仅覆盖上传/传输形态：纯下载的 curl/wget 不打标。
  data_exfiltration: [
    { re: /\bscp\b|\brsync\b|\bsftp\b|\btar\b.*\b-c\b|\bzip\b.*\b-r\b/ },
    { re: /\bcurl\b[^|;&]*(?:-t\b|--upload-file\b)/ },
    { re: /\bcurl\b[^|;&]*(?:-d\b|--data(?:-raw|-binary|-ascii|-urlencode)?\b)[^|;&]*https?:\/\// },
    { re: /\bwget\b[^|;&]*--post-(?:file|data)\b/ },
    { re: /\brclone\b[^|;&]*\b(?:copy|move|sync)\b/ },
    { re: /\bgit\b[^|;&]*\bpush\b/ },
    { re: /\b(?:nc|ncat|socat)\b[^|;&]*</ },
  ],
  // 数据库/日志脱库工具与导出语句（L3.1）。
  db_dump: [
    { re: /\b(?:mysqldump|pg_dump|pg_dumpall|mongoexport|mongodump|bcp)\b/ },
    { re: /\bredis-cli\b[^|;&]*--rdb\b/ },
    { re: /\bsqlite3\b[^|;&]*\.dump\b/ },
    { re: /\bselect\b[^|;&]*\binto\s+outfile\b/i, raw: true },
  ],
  // 内容命中 D1 凭据模式：AWS AKIA / PEM 私钥块 / JWT。
  // 原始大小写 redacted 匹配（AKIA/JWT 大小写敏感）。flag 名自 1.0 起按字典
  // deprecation 链为 credential_exposure（旧名 secret_in_content 已废弃）。
  credential_exposure: [
    { re: /AKIA[0-9A-Z]{16}/, raw: true },
    { re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/, raw: true },
    { re: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/, raw: true },
  ],
};

function compileGeneratedHookPatterns(spec) {
  const out = {};
  const flags = spec && typeof spec === 'object' ? spec.flags : undefined;
  if (!flags || typeof flags !== 'object') throw new Error('missing "flags" map');
  for (const flag of Object.keys(flags)) {
    const list = flags[flag];
    if (!Array.isArray(list)) throw new Error(`flags.${flag} is not an array`);
    const entries = list.map((item) => {
      if (!item || typeof item.pattern !== 'string') throw new Error(`flags.${flag}: entry missing pattern`);
      return { re: new RegExp(item.pattern, item.flags || ''), raw: item.input === 'raw' };
    });
    if (entries.length > 0) out[flag] = entries;
  }
  return out;
}

/**
 * 把 blockPatterns 条目编译成可测正则。input 语义同 compileGeneratedHookPatterns；
 * 无 `g` 标志（共享正则的 stateful lastIndex 会让重复 .test() 交替命中）。
 */
function compileBlockPatterns(entries) {
  const out = [];
  for (const entry of entries || []) {
    if (!entry || typeof entry.pattern !== 'string' || entry.pattern.length === 0) continue;
    out.push({
      re: new RegExp(entry.pattern),
      raw: entry.input === 'raw',
      reason: typeof entry.reason === 'string' ? entry.reason : '',
    });
  }
  return out;
}

function loadHookPatternSpec() {
  const file = path.join(__dirname, 'generated-patterns.json');
  try {
    const spec = JSON.parse(fs.readFileSync(file, 'utf8'));
    const patterns = compileGeneratedHookPatterns(spec);
    const blockedFlags =
      Array.isArray(spec.blockedFlags) && spec.blockedFlags.length > 0
        ? spec.blockedFlags.map((f) => String(f))
        : FALLBACK_BLOCKED_FLAGS;
    const blockPatterns = compileBlockPatterns(
      Array.isArray(spec.blockPatterns) && spec.blockPatterns.length > 0
        ? spec.blockPatterns
        : FALLBACK_BLOCK_PATTERNS
    );
    return { patterns, blockedFlags, blockPatterns };
  } catch (err) {
    log('warn', `generated-patterns.json unavailable (${err && err.message ? err.message : String(err)}); using built-in fallback patterns`);
    return {
      patterns: FALLBACK_HOOK_PATTERNS,
      blockedFlags: FALLBACK_BLOCKED_FLAGS,
      blockPatterns: compileBlockPatterns(FALLBACK_BLOCK_PATTERNS),
    };
  }
}

const HOOK_PATTERN_SPEC = loadHookPatternSpec();
const DEFAULT_BLOCKED_FLAGS = HOOK_PATTERN_SPEC.blockedFlags;
const DEFAULT_BLOCK_PATTERNS = HOOK_PATTERN_SPEC.blockPatterns;

// Enforce mode is read lazily on every check, not captured at preload time:
// the plugin sets OPENCLAW_RUNTIME_ENFORCE during its own initialize(), which
// runs AFTER this hook was preloaded. Top-level capture would freeze the flag
// for the gateway process and only apply to children forked later. Reads stay
// on the hot path but are cheap (one env lookup).
//
// The plugin pins the authoritative values on globalThis with a
// non-configurable descriptor once it initializes. Node's process.env only
// accepts writable+configurable+enumerable descriptors, so the env slot
// itself cannot be frozen; the pin is what makes in-process tampering
// ineffective — after it exists, mutating process.env no longer changes the
// enforcement decision.
const HOOK_ENV_PIN = '__OPENCLAW_SECURITY_HOOK_ENV__';

// Child-process hook propagation: a spawned Node child whose env
// does NOT carry this hook's --require flag runs unhooked — silent coverage
// loss (the "strip NODE_OPTIONS to bypass the preload" bypass). We therefore
// force-inject this hook into the child env (idempotent append, never
// overwriting the caller's own NODE_OPTIONS) unless the caller explicitly
// opts out via the __skipHookPropagation sentinel. The opt-out path raises a
// self_protection_bypass flag on the emitted process event (the child really
// runs unhooked); the strip-and-reinject path is repaired by the hook and is
// recorded as hook_env_reinjected instead.
//
// HOOK_MARKER_ENV doubles as the marker the Python process monitor reads to
// tell hooked node processes from unhooked ones (install() sets it on the
// current process; children either inherit it wholesale together with
// NODE_OPTIONS, or get it re-injected here).
const HOOK_MARKER_ENV = 'OPENCLAW_RUNTIME_HOOK_ACTIVE';
const SKIP_HOOK_PROPAGATION = '__skipHookPropagation';
// Caveat: NODE_OPTIONS is space-split by Node with no quoting, so a hook
// path containing spaces would not parse. The bundled extensions path is
// space-free by construction ($OPENCLAW_HOME/extensions/<id>/runtime.js).
const HOOK_REQUIRE_FLAG = '--require ' + __filename;

function readHookEnv(key) {
  const pin = globalThis[HOOK_ENV_PIN];
  if (typeof pin === 'function') {
    try {
      const pinned = pin();
      if (pinned && Object.prototype.hasOwnProperty.call(pinned, key)) {
        return pinned[key];
      }
    } catch {
      // A hostile pin would mean the host is already compromised; fall back
      // to the environment rather than crash the gateway.
    }
  }
  return process.env[key];
}

function isRuntimeEnforceEnabled() {
  const v = readHookEnv('OPENCLAW_RUNTIME_ENFORCE');
  return v === 'true' || v === '1';
}

// Same laziness for the block list: the plugin writes
// OPENCLAW_RUNTIME_BLOCKED_FLAGS at initialize time, so a preload-time parse
// would see a stale (empty) value in the gateway process.
function getBlockedFlags() {
  const flags = (readHookEnv('OPENCLAW_RUNTIME_BLOCKED_FLAGS') || '')
    .split(',')
    .map((f) => f.trim())
    .filter(Boolean);
  return flags.length > 0 ? flags : DEFAULT_BLOCKED_FLAGS;
}

function getLogPath() {
  let raw = process.env.OPENCLAW_MONITOR_LOG_PATH || '';
  if (!raw) {
    // Fall back to the plugin's default sink so the hook stays aligned with
    // `application.runtimeHooks.logPath` even when the operator forgot to
    // export OPENCLAW_MONITOR_LOG_PATH into the host (typical for ad-hoc
    // docker-compose setups where NODE_OPTIONS was set but this var wasn't).
    raw = path.join(os.homedir(), '.openclaw', 'security-events-runtime.jsonl');
  }
  if (raw === '~') return os.homedir();
  if (raw.startsWith('~/') || raw.startsWith('~\\')) {
    return path.join(os.homedir(), raw.slice(2));
  }
  return raw;
}

/**
 * @typedef {Object} CommandExecutionEvent
 * @property {string} type
 * @property {string} id
 * @property {string} ts
 * @property {string} runtime
 * @property {string} api
 * @property {string} command_line
 * @property {string} [command_line_raw]
 * @property {string} executable
 * @property {string[]} [arguments]
 * @property {boolean} shell_involved
 * @property {string} [shell]
 * @property {string} cwd
 * @property {number} pid
 * @property {number} ppid
 * @property {number} [target_pid]
 * @property {Object} [caller]
 * @property {string} [session_id]
 * @property {string} [run_id]
 * @property {string} [agent_id]
 * @property {string} [tool_call_id]
 * @property {string} [tool_name]
 * @property {string[]} [risk_flags]
 * @property {boolean} [blocked]
 * @property {string} [block_reason]
 */

/**
 * 全部级别一律走 stderr。NODE_OPTIONS=--require 会扩散到宿主里每一个 node
 * 进程，其中包含把 stdout 当数据通道解析的机器进程（例如 OpenClaw CLI 的
 * SQLite 只读 worker 要从 stdout 读 JSON）。预加载在别人进程最早期抢到的
 * stdout 等于替别人改协议 —— 一行非 JSON 日志就能让下游解析失败
 * （2026-10-23 实测：`SQLite read-only worker returned invalid JSON`）。
 */
function log(level, message) {
  if (!DEBUG && level !== 'error') return;
  console.error(`[${MODULE_NAME}] ${level}: ${message}`);
}

function generateId() {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

function getTimestamp() {
  return new Date().toISOString();
}

/**
 * 同一进程里可能加载了不止一份 hook：插件被装了两份（扩展目录与
 * npm/projects 各有一份）、或者旧实例没退场又起了一个新实例。
 * 后加载的那份会跳过 install()（全局标记），可它的模块帧仍可能出现在
 * 栈上——此时"调用方"会被算成 hook 自己，审计轨迹就成了监控在看自己。
 *
 * 把加载过的 hook 文件登记到全局表，任何一份都能认出其他份的帧。
 */
const HOOK_FILE_REGISTRY = '__OPENCLAW_SECURITY_HOOK_FILES__';

/** hook 自己的内部函数名。用于"文件名相同 + 函数名是内部函数"这条兜底判据。 */
const HOOK_INTERNAL_FUNCTIONS = new Set([
  'getCallerLocation',
  'buildEvent',
  'emit',
  'emitEvent',
  'computeRiskFlags',
  'shouldBlock',
  'isRecentDuplicate',
  'commandEventDedupKey',
  'wrapSpawn',
  'wrapExec',
  'wrapExecFile',
  'wrapFork',
  'safeApplyHookPropagation',
  'applyHookPropagation',
  'detectShellInvocation',
  'resolveShell',
  'truncateCommandLine',
  'getGlobalContext',
]);

function registerHookFile(filePath) {
  try {
    const registry = globalThis[HOOK_FILE_REGISTRY] || (globalThis[HOOK_FILE_REGISTRY] = new Set());
    registry.add(String(filePath).replace(/\\/g, '/'));
  } catch {
    /* 冻结的 globalThis：登记不了也不影响主流程 */
  }
}

function isRegisteredHookFile(normalized) {
  try {
    const registry = globalThis[HOOK_FILE_REGISTRY];
    return registry instanceof Set && registry.has(normalized);
  } catch {
    return false;
  }
}

/**
 * Extract the first non-library caller from the current stack.
 * @returns {{function: string, file: string, line: number, column: number} | null}
 */
function getCallerLocation() {
  const stack = new Error().stack?.split('\n') || [];
  // Skip Error, getCallerLocation, and the wrapper function frames.
  for (let i = 3; i < stack.length; i++) {
    const line = stack[i];
    // Match: "    at functionName (file:line:column)"
    const matchWithName = line.match(/^\s+at\s+(.*?)\s+\((.*?):(\d+):(\d+)\)$/);
    if (matchWithName) {
      const [, fnName, filePath, lineNo, colNo] = matchWithName;
      if (isInterestingCaller(filePath, fnName)) {
        return {
          function: fnName || '<anonymous>',
          file: filePath,
          line: parseInt(lineNo, 10),
          column: parseInt(colNo, 10),
        };
      }
    }
    // Match: "    at file:line:column"
    const matchWithoutName = line.match(/^\s+at\s+(.*?):(\d+):(\d+)$/);
    if (matchWithoutName) {
      const [, filePath, lineNo, colNo] = matchWithoutName;
      if (isInterestingCaller(filePath)) {
        return {
          function: '<anonymous>',
          file: filePath,
          line: parseInt(lineNo, 10),
          column: parseInt(colNo, 10),
        };
      }
    }
  }

  // Fallback: return the first non-runtime-hook, non-core frame even if it
  // lives in node_modules. This is common when OpenClaw wraps child_process
  // internally before calling it.
  for (let i = 3; i < stack.length; i++) {
    const line = stack[i];
    const matchWithName = line.match(/^\s+at\s+(.*?)\s+\((.*?):(\d+):(\d+)\)$/);
    if (matchWithName) {
      const [, fnName, filePath, lineNo, colNo] = matchWithName;
      if (filePath && !isOwnHookFile(filePath, fnName) && !filePath.startsWith('node:')) {
        return {
          function: fnName || '<anonymous>',
          file: filePath,
          line: parseInt(lineNo, 10),
          column: parseInt(colNo, 10),
        };
      }
    }
    const matchWithoutName = line.match(/^\s+at\s+(.*?):(\d+):(\d+)$/);
    if (matchWithoutName) {
      const [, filePath, lineNo, colNo] = matchWithoutName;
      if (filePath && !isOwnHookFile(filePath) && !filePath.startsWith('node:')) {
        return {
          function: '<anonymous>',
          file: filePath,
          line: parseInt(lineNo, 10),
          column: parseInt(colNo, 10),
        };
      }
    }
  }

  return null;
}

/**
 * Is this stack frame part of the hook itself?
 *
 * The old check compared against a hard-coded `/hooks/node/runtime.js` path
 * left over from an earlier install layout. The file now ships as
 * `hooks/runtime.js`, so the filter never matched and `caller` always
 * resolved to the hook's own `emit` frame — the audit trail recorded the
 * monitor looking at itself instead of the code that spawned the process.
 * Compare against this module's own path instead.
 *
 * 但"本模块的路径"这一条在实测部署里也不够用：
 *   - 插件被装了两份（扩展目录 + npm/projects 各一份）时，同一个进程会
 *     先后加载两份 hook。后加载的那份会跳过 install()（全局标记），可它
 *     的模块帧仍可能出现在栈上——此时"调用方"就被算成了 hook 自己。
 *   - 部署布局把 hook 放在扩展根目录（不在 hooks/ 下），"文件名相同且在
 *     hooks/ 下"这条兜底匹配不上。
 *
 * 所以再叠两层判据：全局登记表（任何一份 hook 都能认出其他份的帧），
 * 以及"文件名相同 + 帧函数名是 hook 内部函数"这条强信号。
 */
function isOwnHookFile(filePath, fnName) {
  if (!filePath) return false;
  const normalized = filePath.replace(/\\/g, '/');
  if (isRegisteredHookFile(normalized)) return true;
  const own = __filename.replace(/\\/g, '/');
  if (normalized === own) return true;
  const ownBase = own.split('/').pop();
  if (normalized.endsWith('/' + ownBase)) {
    // 同一份 hook 换了个路径形式（符号链接、副本）：路径里有 hooks/ 就认。
    if (normalized.includes('/hooks/')) return true;
    // 否则用帧函数名兜底：应用代码几乎不可能既叫 runtime.js，函数名又
    // 正好是 wrappedSpawn / emit 这类 hook 内部函数名。
    if (fnName && HOOK_INTERNAL_FUNCTIONS.has(fnName)) return true;
  }
  return false;
}

function isInterestingCaller(filePath, fnName) {
  if (!filePath) return false;
  const normalized = filePath.replace(/\\/g, '/');
  if (isOwnHookFile(normalized, fnName)) return false;
  // Node.js core modules do not provide useful user-code location.
  if (normalized.startsWith('node:')) return false;
  if (normalized.includes('internal/')) return false;
  if (fnName && fnName.includes('wrapped')) return false;
  return true;
}

/**
 * Redact likely sensitive tokens from a command line string.
 * @param {string} cmdline
 * @returns {string}
 */
function redactCommandLine(cmdline) {
  if (typeof cmdline !== 'string') return String(cmdline);

  return cmdline
    // -H "Authorization: Bearer secret-token" or Authorization: Bearer ...
    .replace(
      /(\bAuthorization\s*[:=]\s*(?:Bearer\s+)?)\S+/gi,
      '$1***'
    )
    // token=..., api_key=..., password=...
    .replace(
      /\b(password|passwd|pwd|token|secret|api[_-]?key|access[_-]?key|auth)\s*[:=]\s*\S+/gi,
      '$1=***'
    )
    // URL credentials: strip userinfo password.
    .replace(
      /(https?:\/\/[^\s:@]+):([^\s@]+)@/g,
      '$1:***@'
    );
}

function getGlobalContext() {
  // Missing context must be null, not '': an empty string reads downstream as
  // "present but empty", which is a third meaning next to "null" and
  // "field absent".
  const pick = (...values) => {
    for (const value of values) {
      if (value) return value;
    }
    return null;
  };
  return {
    session_id: pick(global.__OPENCLAW_SESSION_ID__, process.env.OPENCLAW_SESSION_ID),
    run_id: pick(global.__OPENCLAW_RUN_ID__, process.env.OPENCLAW_RUN_ID),
    agent_id: pick(global.__OPENCLAW_AGENT_ID__, process.env.OPENCLAW_AGENT_ID),
    tool_call_id: pick(global.__OPENCLAW_TOOL_CALL_ID__, process.env.OPENCLAW_TOOL_CALL_ID),
    tool_name: pick(global.__OPENCLAW_TOOL_NAME__, process.env.OPENCLAW_TOOL_NAME),
  };
}

/**
 * 取用于阻断判定的命令行文本。
 *
 * ⚠️ 优先 options.command_line（原始、未截断、未脱敏）：事件里的 command_line
 *    已脱敏且截断到 4096 字符，长命令的敏感路径可能落在截断外 ⇒ 漏判。
 *    判定用原文只用于匹配，从不回写到事件或日志。
 */
function pickBlockingCommandLine(event, options) {
  if (options && typeof options.command_line === 'string' && options.command_line.length > 0) {
    return options.command_line;
  }
  if (event && typeof event.command_line === 'string' && event.command_line.length > 0) {
    return event.command_line;
  }
  return '';
}

/**
 * 模式级 Tier-1 阻断的逃生阀：误报时操作员可一键关闭，不必改包升级。
 * 默认启用；关闭：OPENCLAW_RUNTIME_BLOCK_PATTERNS=0（或 off / false）。
 */
function isBlockPatternTierEnabled() {
  const raw = (readHookEnv('OPENCLAW_RUNTIME_BLOCK_PATTERNS') || '').trim().toLowerCase();
  if (!raw) return true;
  return !(raw === '0' || raw === 'off' || raw === 'false' || raw === 'no');
}

/**
 * Determine whether a runtime event should be blocked based on configured
 * risk flags. Returns a human-readable block reason, or undefined if the
 * event should be allowed.
 *
 * 两档判定，互相独立：
 *   ① flag 级：risk_flags ∩ hookBlockedFlags（可被 OPENCLAW_RUNTIME_BLOCKED_FLAGS 覆盖）。
 *   ② 模式级（Tier-1）：命令行命中 hookBlockPatterns。
 *
 * ⚠️ 两档不能合并成 early-return：flag 名单为空 ≠ 命令安全
 *    （例：cat ~/.aws/credentials 一个 flag 都不打，但仍是 Tier-1 凭据文件）。
 */
function shouldBlock(event, options) {
  if (!isRuntimeEnforceEnabled()) return undefined;

  // ① flag 级阻断名单
  const flags = (event && event.risk_flags) || [];
  if (flags.length > 0) {
    const blockedFlags = getBlockedFlags();
    const matched = flags.find((f) => blockedFlags.includes(f));
    if (matched) {
      return `命令被 OpenClaw runtime hook 拦截（risk flag: ${matched}）`;
    }
  }

  // ② 模式级 Tier-1 阻断（不占 flag 名）
  if (!isBlockPatternTierEnabled()) return undefined;
  const cmdline = pickBlockingCommandLine(event, options);
  if (!cmdline) return undefined;
  for (const entry of DEFAULT_BLOCK_PATTERNS) {
    const text = entry.raw ? cmdline : cmdline.toLowerCase();
    if (entry.re.test(text)) {
      const why = entry.reason ? entry.reason : '命中 Tier-1 阻断模式';
      return `命令被 OpenClaw runtime hook 拦截（Tier-1 敏感文件：${why}）`;
    }
  }

  return undefined;
}

/**
 * Build a command execution event.
 * @param {Object} options
 * @param {string} options.api
 * @param {string} options.command_line
 * @param {string} options.executable
 * @param {string[]} [options.args]
 * @param {boolean} [options.shell_involved]
 * @param {string} [options.shell]
 * @returns {CommandExecutionEvent}
 */
function truncateCommandLine(cmd) {
  if (typeof cmd !== 'string') return String(cmd);
  return cmd.length > MAX_COMMAND_LINE_LENGTH ? cmd.slice(0, MAX_COMMAND_LINE_LENGTH) + '...' : cmd;
}

function truncateArguments(args) {
  if (!Array.isArray(args)) return args;
  let total = 0;
  const result = [];
  for (const arg of args) {
    const s = typeof arg === 'string' ? arg : String(arg);
    total += s.length;
    if (total > MAX_ARGUMENTS_TOTAL_LENGTH) {
      result.push('...');
      break;
    }
    result.push(s);
  }
  return result;
}

function buildEvent(options) {
  const ctx = getGlobalContext();
  const raw = truncateCommandLine(options.command_line);
  const redacted = truncateCommandLine(redactCommandLine(raw));

  /** @type {CommandExecutionEvent} */
  const eventId = generateId();
  const event = {
    // Renamed to process_start to match the platform data standard (进程类事件).
    event_type: 'process_start',
    type: 'application.process_start',
    id: eventId,
    // Same value under the standard field name: the collector uses it as the
    // event identity, so a replayed sidecar line can be de-duplicated instead
    // of landing in the audit trail once per replay.
    event_id: eventId,
    ts: getTimestamp(),
    comm: options.executable ? path.basename(options.executable) : 'node',
    runtime: 'node',
    api: options.api,
    command_line: redacted,
    executable: options.executable,
    process_name: options.executable ? path.basename(options.executable) : redacted.split(/\s+/, 1)[0],
    layer: 'system',
    collection_method: 'runtime',
    source: 'openclaw.runtime-hooks.v1',
    collector: {
      hook_name: 'process_start',
      middleware_name: 'openclaw-security-monitor',
      collector_name: 'security-runtime-middleware',
    },
    shell_involved: options.shell_involved ?? false,
    cwd: process.cwd(),
    pid: process.pid,
    // 发起方 pid：调用 spawn 的那个进程。子进程 pid 只有 spawn 返回后才知道，
    // 由 attachChildLifecycle 回填到 child_pid。
    spawner_pid: process.pid,
    ppid: process.ppid,
    caller: getCallerLocation(),
    risk_flags: computeRiskFlags(options, redacted),
  };

  if (options.shell) {
    event.shell = options.shell;
  }
  if (options.bypass_reason) {
    event.bypass_reason = options.bypass_reason;
  }
  event.session_id = ctx.session_id ?? null;
  event.run_id = ctx.run_id ?? null;
  event.agent_id = ctx.agent_id ?? null;
  event.tool_call_id = ctx.tool_call_id ?? null;
  event.tool_name = ctx.tool_name ?? null;

  // Note: `command_line_raw` (deprecated in process.json) and
  // `arguments` argv-array are intentionally NOT emitted. The redacted
  // `command_line` above is the canonical signal; raw forms must travel
  // through an out-of-band audit channel.

  return event;
}

/**
 * Detect whether the executable is a skill-shipped binary. OpenClaw skills are
 * normally JavaScript/TypeScript/Python packages; a compiled or shell binary
 * hidden under <skill>/bin/ is a common bypass vector used by malicious skills
 * to hide the real command lines (e.g. `runner 01` executes `cat /etc/passwd`
 * in a child process that the Node.js runtime hook cannot see).
 */
function isSkillBinaryExecution(executable) {
  if (typeof executable !== 'string' || !executable) return false;
  const normalized = executable.replace(/\\/g, '/');
  // Match paths like .../skills/<skill-name>/bin/<binary>.
  return /\/skills\/[^/]+\/bin\/[^/]+$/i.test(normalized);
}

function computeRiskFlags(options, redacted) {
  const flags = [];
  const cmd = redacted.toLowerCase();

  // hook 传播是否被绕过，要看子进程**最终有没有带上 hook**：
  //
  //   - 'explicit_skip'：调用方显式要求跳过传播 → 子进程真的会裸跑 →
  //     覆盖真的丢了 → 这才是 self_protection_bypass。
  //   - 'env_stripped'：调用方给了显式 env 但没带 NODE_OPTIONS → hook 已经
  //     **把它补回去了**（子进程照样带 hook 跑），覆盖没丢。两种情形都判
  //     self_protection_bypass 会把宿主自己的探活命令（execa 之类总是显式
  //     传 env）打成「绕过自保护」，噪声淹没真正的绕过信号。
  //
  // 补回去的情形改用 hook_env_reinjected 留痕——信号还在，但不再冒充
  // 高危绕过。
  if (options.bypass_reason === 'explicit_skip') {
    flags.push('self_protection_bypass');
  } else if (options.bypass_reason) {
    flags.push('hook_env_reinjected');
  }

  // 代码驱动 flag（非纯正则 cmdline 匹配）：保持代码判定，不进 pattern 表。
  if (options.shell_involved) flags.push('shell_involved');
  if (isSkillBinaryExecution(options.executable)) flags.push('skill_binary_execution');

  // 纯正则 flag 一律走构建期产物（缺失时内置兜底表）。input 语义：
  // raw → 匹配原始大小写 redacted（AKIA/JWT 等大小写敏感模式）；缺省 → 匹配
  // 小写化 redacted。flags 由条目自带（编译期已合并规则级默认）。
  for (const flag of Object.keys(HOOK_PATTERN_SPEC.patterns)) {
    const entries = HOOK_PATTERN_SPEC.patterns[flag];
    for (const entry of entries) {
      if (entry.re.test(entry.raw ? redacted : cmd)) {
        flags.push(flag);
        break;
      }
    }
  }

  return flags.length > 0 ? flags : undefined;
}

let writeErrorLogged = false;

// Best-effort deduplication for child_process events. Node's exec() sometimes
// surfaces both an exec and an execFile event for the same underlying call
// (e.g. @homebridge/ciao's periodic "ip neigh show"). We drop the near-
// duplicate to reduce noise while preserving security-relevant events.
const recentCommandEvents = [];
// Cover back-to-back calls like exec -> execFile for the same command, plus
// startup/version checks that legitimate callers may issue ~200ms apart.
const DEDUP_WINDOW_MS = 300;
const MAX_DEDUP_CACHE_SIZE = 100;

function commandEventDedupKey(event) {
  const caller = event.caller || {};
  // process_exit 按子进程 pid 区分：同一条命令可能被连续 spawn 多次，每个
  // 子进程都有自己的退出事件，不能互相去重。process_start 仍然只按
  // 「命令 + 发起方 + 调用点」去重——同一个调用点上的同一条命令是重复。
  const scope = event.event_type === 'process_exit' ? String(event.child_pid ?? '') : '';
  return `${event.event_type}|${event.command_line}|${event.pid}|${event.ppid}|${scope}|${caller.file || ''}:${caller.line || ''}:${caller.column || ''}`;
}

function isRecentDuplicate(event) {
  const now = Date.now();
  const key = commandEventDedupKey(event);

  // Evict stale entries.
  while (recentCommandEvents.length > 0 && now - recentCommandEvents[0].time > DEDUP_WINDOW_MS) {
    recentCommandEvents.shift();
  }

  for (const entry of recentCommandEvents) {
    if (entry.key === key) {
      return true;
    }
  }

  recentCommandEvents.push({ key, time: now });
  if (recentCommandEvents.length > MAX_DEDUP_CACHE_SIZE) {
    recentCommandEvents.shift();
  }
  return false;
}

function emitEvent(event) {
  if (isRecentDuplicate(event)) {
    return;
  }

  const logPath = getLogPath();
  if (!logPath) {
    log('debug', `event dropped (no OPENCLAW_MONITOR_LOG_PATH): ${event.command_line}`);
    return;
  }

  const line = JSON.stringify(event) + '\n';
  try {
    const fd = fs.openSync(logPath, 'a');
    fs.writeSync(fd, line, 'utf8');
    fs.closeSync(fd);
  } catch (err) {
    if (!writeErrorLogged) {
      log('error', `failed to write event to ${logPath}: ${err.message}`);
      writeErrorLogged = true;
    }
  }
}

/**
 * Error codes carried by the errors this hook throws at the caller.
 *
 *   RUNTIME_HOOK_BLOCK    — the policy decided to deny the command.
 *   RUNTIME_HOOK_INTERNAL — the hook itself failed (event could not be
 *                           assembled or evaluated).
 *
 * Both deny the command (fail-closed), but only the first is a policy
 * decision — the caller and the operator must be able to tell them apart.
 */
const HOOK_BLOCK_ERROR_CODE = 'RUNTIME_HOOK_BLOCK';
const HOOK_INTERNAL_ERROR_CODE = 'RUNTIME_HOOK_INTERNAL';

function createHookError(code, message) {
  const err = new Error(message);
  err.code = code;
  err.name = 'OpenClawRuntimeHookError';
  return err;
}

function hookErrorMessage(err) {
  if (!err) return 'unknown error';
  if (err.message) return err.message;
  return String(err);
}

function isInternalHookError(err) {
  return !!err && err.code === HOOK_INTERNAL_ERROR_CODE;
}

/**
 * 构造命令事件并做拦截判定。
 *
 * 判定与写盘必须拆开：拦截判定要在 spawn **之前**做（否则拦不住），而子
 * 进程 pid 只有 spawn 返回之后才知道（要回填到 child_pid）。所以这里只
 * 返回"事件 + 是否该拦"，写盘由调用方在合适的时机做。
 */
function prepareCommandEvent(options) {
  let event;
  let blockReason;
  try {
    event = buildEvent(options);
    // options 一起传：模式级判定要用原始未截断的命令行。
    blockReason = shouldBlock(event, options);
    if (blockReason) {
      event.blocked = true;
      event.block_reason = blockReason;
    }
    // spawn 前证明事件可序列化：失败以 RUNTIME_HOOK_INTERNAL 在 spawn 前拒绝
    // （fail-closed）；挪到 spawn 后验证会退化成「命令跑完才抛错」。
    if (typeof JSON.stringify(event) !== 'string') {
      throw new Error('event is not JSON-serializable');
    }
  } catch (err) {
    // Hook 组装/判定失败不是策略决策 — 以内部故障上报，与真实拒绝区分。
    throw createHookError(
      HOOK_INTERNAL_ERROR_CODE,
      `runtime hook internal failure while handling ${options.api}: ${hookErrorMessage(err)}`
    );
  }
  return { event, blockReason };
}

/**
 * 记录子进程的生命周期尾巴：回填子进程 pid，并挂上退出监听。
 *
 * 运行时层此前只记录 process_start，子进程的**结束**从来没有出现在事件
 * 流里（采样里 process_exit 为 0 条）——审计链上只有"发起了"，没有
 * "跑完了、结果如何"。这里在子进程退出时补一条 process_exit。
 */
function attachChildLifecycle(event, child) {
  if (!child || typeof child !== 'object') return () => {};
  if (typeof child.pid === 'number' && child.pid > 0) {
    event.child_pid = child.pid;
  }
  if (typeof child.on !== 'function') {
    // 同步 API（execSync / spawnSync）：子进程在返回时已经结束，结果对象
    // 里带着退出码与信号。退出事件必须排在 process_start 之后落盘，所以
    // 这里只把补写动作交给调用方（它在写完 process_start 之后调用）。
    const status = typeof child.status === 'number' ? child.status : undefined;
    const signal = child.signal;
    return () => {
      if (status === undefined) return;
      try {
        emitProcessExit(event, status, signal);
      } catch (err) {
        log('debug', `failed to emit process_exit: ${err && err.message}`);
      }
    };
  }
  try {
    child.on('exit', (code, signal) => {
      try {
        emitProcessExit(event, code, signal);
      } catch (err) {
        log('debug', `failed to emit process_exit: ${err && err.message}`);
      }
    });
  } catch (err) {
    log('debug', `failed to attach exit listener: ${err && err.message}`);
  }
  return () => {};
}

/**
 * 子进程退出事件。继承 process_start 的归属信息（会话 / 工具调用），
 * 这样"哪个 agent 起的进程、它是怎么结束的"能对上。
 */
function emitProcessExit(startEvent, code, signal) {
  const ctx = getGlobalContext();
  const eventId = generateId();
  const event = {
    event_type: 'process_exit',
    type: 'application.process_exit',
    id: eventId,
    event_id: eventId,
    ts: getTimestamp(),
    comm: startEvent.comm,
    runtime: 'node',
    api: startEvent.api,
    command_line: startEvent.command_line,
    executable: startEvent.executable,
    process_name: startEvent.process_name,
    layer: 'system',
    collection_method: 'runtime',
    source: 'openclaw.runtime-hooks.v1',
    collector: {
      hook_name: 'process_exit',
      middleware_name: 'openclaw-security-monitor',
      collector_name: 'security-runtime-middleware',
    },
    shell_involved: startEvent.shell_involved ?? false,
    cwd: startEvent.cwd,
    // pid 仍是发起方（兼容旧语义），spawner_pid 显式表达同一件事。
    pid: startEvent.pid,
    spawner_pid: startEvent.spawner_pid ?? startEvent.pid,
    child_pid: startEvent.child_pid,
    ppid: startEvent.ppid,
    exit_code: typeof code === 'number' ? code : null,
    exit_signal: signal || null,
    caller: startEvent.caller,
  };
  event.session_id = ctx.session_id ?? null;
  event.run_id = ctx.run_id ?? null;
  event.agent_id = ctx.agent_id ?? null;
  event.tool_call_id = ctx.tool_call_id ?? null;
  event.tool_name = ctx.tool_name ?? null;
  emitEvent(event);
}

// child_process wrappers

function isOptionsObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value);
}

/**
 * Force-propagate this hook into a child process env.
 *
 * Returns the bypass reason when the call attempted to dodge propagation
 * ('explicit_skip' | 'env_stripped'), undefined otherwise. Mutates `options`
 * in place: deletes the skip sentinel (it must never reach the real
 * child_process implementation) and injects/appends NODE_OPTIONS +
 * HOOK_MARKER_ENV when the caller supplied an explicit env.
 *
 * Cases:
 *   - no options / no explicit env: natural inheritance — the parent env
 *     already carries NODE_OPTIONS + the marker, nothing to do.
 *   - explicit env WITHOUT any NODE_OPTIONS key: the hook would be silently
 *     dropped in the child — re-inject and flag 'env_stripped'.
 *   - explicit env WITH NODE_OPTIONS: idempotent append (skip when our hook
 *     path is already present; never overwrite the caller's value). Windows
 *     env keys are case-insensitive, so NODE_OPTIONS / node_options /
 *     Node_Options are all matched.
 *   - options.__skipHookPropagation === true: explicit opt-out — no
 *     injection, flag 'explicit_skip', delete the sentinel.
 */
function applyHookPropagation(options) {
  if (!isOptionsObject(options)) return undefined;

  if (options[SKIP_HOOK_PROPAGATION] === true) {
    delete options[SKIP_HOOK_PROPAGATION];
    return 'explicit_skip';
  }

  const env = options.env;
  if (!isOptionsObject(env)) return undefined;

  let nodeOptionsKey;
  let existing;
  for (const key of Object.keys(env)) {
    if (key.toUpperCase() === 'NODE_OPTIONS') {
      nodeOptionsKey = key;
      existing = typeof env[key] === 'string' ? env[key] : '';
      break;
    }
  }

  if (nodeOptionsKey === undefined) {
    env.NODE_OPTIONS = HOOK_REQUIRE_FLAG;
    env[HOOK_MARKER_ENV] = '1';
    return 'env_stripped';
  }

  if (existing.indexOf(__filename) === -1) {
    env[nodeOptionsKey] = existing ? existing + ' ' + HOOK_REQUIRE_FLAG : HOOK_REQUIRE_FLAG;
  }
  env[HOOK_MARKER_ENV] = '1';
  return undefined;
}

/** Hot-path guard: propagation must never break the underlying spawn. */
function safeApplyHookPropagation(options) {
  try {
    return applyHookPropagation(options);
  } catch (err) {
    log('error', `hook propagation failed: ${err && err.message ? err.message : String(err)}`);
    return undefined;
  }
}

function resolveShell(options) {
  if (!isOptionsObject(options)) return undefined;
  if (options.shell === true) return '/bin/sh';
  if (typeof options.shell === 'string') return options.shell;
  return undefined;
}

const SHELL_NAMES = new Set([
  'sh', 'bash', 'zsh', 'ash', 'dash', 'ksh', 'csh', 'tcsh', 'fish',
  'cmd', 'cmd.exe', 'powershell', 'powershell.exe', 'pwsh', 'pwsh.exe',
]);

/**
 * Detect whether a spawn/execFile invocation effectively involves a shell.
 * This handles the common case where callers spawn('sh', ['-c', 'cmd'])
 * without setting options.shell.
 */
function detectShellInvocation(command, args, options) {
  const shell = resolveShell(options);
  if (shell) {
    return { shell_involved: true, shell };
  }

  if (typeof command !== 'string') {
    return { shell_involved: false, shell: undefined };
  }

  const base = path.basename(command).toLowerCase();
  if (SHELL_NAMES.has(base)) {
    return { shell_involved: true, shell: command };
  }

  // Arguments like -c or /c strongly indicate a shell interpreting a command.
  if (Array.isArray(args) && args.some((arg) => typeof arg === 'string' && /^[-/]c$/i.test(arg))) {
    return { shell_involved: true, shell: command };
  }

  return { shell_involved: false, shell: undefined };
}

/**
 * 把"拦截/执行失败"的错误交给调用方：优先走回调槽，没有回调就抛出去。
 * spawn / fork 没有回调语义，只能同步抛出。
 */
function routeSpawnError(err, ...callbackSlots) {
  for (const slot of callbackSlots) {
    if (typeof slot === 'function') {
      slot(err);
      return true;
    }
  }
  return false;
}

function wrapExec(original, apiName) {
  return function wrappedExec(command, options, callback) {
    const opts = isOptionsObject(options) ? options : undefined;
    const bypassReason = safeApplyHookPropagation(opts);
    const shell = (opts && opts.shell) || '/bin/sh';
    const prepared = prepareCommandEvent({
      api: apiName,
      command_line: command,
      executable: command.trim().split(/\s+/)[0],
      shell_involved: true,
      shell,
      bypass_reason: bypassReason,
    });
    if (prepared.blockReason) {
      // Runtime enforcement blocked the command. Route the error to the
      // callback when one is available; otherwise rethrow so the caller
      // observes a synchronous denial.
      emitEvent(prepared.event);
      const err = new Error(prepared.blockReason);
      if (routeSpawnError(err, options, callback)) return undefined;
      throw err;
    }
    let result;
    try {
      result = original.apply(this, arguments);
    } catch (err) {
      // The command itself failed (ENOENT and friends). The attempt still
      // belongs in the audit trail.
      emitEvent(prepared.event);
      throw err;
    }
    const flushExit = attachChildLifecycle(prepared.event, result);
    emitEvent(prepared.event);
    // 同步 API 的子进程在返回时已经退出：补写的 process_exit 必须排在
    // process_start 之后落盘。
    flushExit();
    return result;
  };
}

function wrapExecFile(original, apiName) {
  return function wrappedExecFile(file, args, options, callback) {
    // execFile(file[, args][, options][, callback]): like spawn, args may
    // carry the options object. Same env-strip bypass surface as spawn, so
    // propagation applies here too.
    const opts = isOptionsObject(options) ? options : isOptionsObject(args) ? args : undefined;
    const bypassReason = safeApplyHookPropagation(opts);
    const normalizedArgs = Array.isArray(args) ? args : [];
    const cmdline = [file, ...normalizedArgs].join(' ');
    const detection = detectShellInvocation(file, normalizedArgs, opts);
    const prepared = prepareCommandEvent({
      api: apiName,
      command_line: cmdline,
      executable: file,
      args: normalizedArgs,
      shell_involved: detection.shell_involved,
      shell: detection.shell,
      bypass_reason: bypassReason,
    });
    if (prepared.blockReason) {
      // Runtime enforcement blocked the command. Prefer the callback argument.
      emitEvent(prepared.event);
      const err = new Error(prepared.blockReason);
      if (routeSpawnError(err, args, options, callback)) return undefined;
      throw err;
    }
    let result;
    try {
      result = original.apply(this, arguments);
    } catch (err) {
      emitEvent(prepared.event);
      throw err;
    }
    const flushExit = attachChildLifecycle(prepared.event, result);
    emitEvent(prepared.event);
    // 同步 API 的子进程在返回时已经退出：补写的 process_exit 必须排在
    // process_start 之后落盘。
    flushExit();
    return result;
  };
}

function wrapSpawn(original, apiName) {
  return function wrappedSpawn(command, args, options) {
    // spawn(command[, args][, options]): when args is omitted it carries the
    // options object. Resolve the real options slot for propagation.
    const opts = isOptionsObject(options) ? options : isOptionsObject(args) ? args : undefined;
    const bypassReason = safeApplyHookPropagation(opts);
    const normalizedArgs = Array.isArray(args) ? args : [];
    const cmdline = [command, ...normalizedArgs].join(' ');
    const detection = detectShellInvocation(command, normalizedArgs, opts);
    const prepared = prepareCommandEvent({
      api: apiName,
      command_line: cmdline,
      executable: command,
      args: normalizedArgs,
      shell_involved: detection.shell_involved,
      shell: detection.shell,
      bypass_reason: bypassReason,
    });
    if (prepared.blockReason) {
      // Runtime enforcement blocked the command. spawn has no callback, so
      // throw synchronously to deny execution.
      emitEvent(prepared.event);
      throw new Error(prepared.blockReason);
    }
    let result;
    try {
      result = original.apply(this, arguments);
    } catch (err) {
      emitEvent(prepared.event);
      throw err;
    }
    const flushExit = attachChildLifecycle(prepared.event, result);
    emitEvent(prepared.event);
    // 同步 API 的子进程在返回时已经退出：补写的 process_exit 必须排在
    // process_start 之后落盘。
    flushExit();
    return result;
  };
}

function wrapFork(original) {
  return function wrappedFork(modulePath, args, options) {
    const opts = isOptionsObject(options) ? options : isOptionsObject(args) ? args : undefined;
    const bypassReason = safeApplyHookPropagation(opts);
    const normalizedArgs = Array.isArray(args) ? args : [];
    const cmdline = [modulePath, ...normalizedArgs].join(' ');
    const prepared = prepareCommandEvent({
      api: 'child_process.fork',
      command_line: cmdline,
      executable: 'node',
      args: [modulePath, ...normalizedArgs],
      shell_involved: false,
      bypass_reason: bypassReason,
    });
    if (prepared.blockReason) {
      // Runtime enforcement blocked the fork. Deny execution synchronously.
      emitEvent(prepared.event);
      throw new Error(prepared.blockReason);
    }
    let result;
    try {
      result = original.apply(this, arguments);
    } catch (err) {
      emitEvent(prepared.event);
      throw err;
    }
    const flushExit = attachChildLifecycle(prepared.event, result);
    emitEvent(prepared.event);
    // 同步 API 的子进程在返回时已经退出：补写的 process_exit 必须排在
    // process_start 之后落盘。
    flushExit();
    return result;
  };
}

// The unwrapped originals must NOT be cached under a well-known
// symbol (Symbol.for lands in the global registry, so any in-process code
// can look it up and restore the pristine implementations). Originals are
// kept only in module closures (originalChildProcessMethods WeakMap below)
// so uninstall can still restore without exposing a bypass handle.

function lockMethod(target, name, wrapped) {
  try {
    Object.defineProperty(target, name, {
      value: wrapped,
      writable: false,
      configurable: false,
      enumerable: true,
    });
  } catch (err) {
    // Some embedded hosts freeze child_process module exports. Fall back
    // to plain assignment; the install log line above will warn on first
    // install only if this fallback is hit.
    log('warn', `failed to lock child_process.${String(name)} via defineProperty: ${err.message}`);
    try { target[name] = wrapped; } catch { /* truly frozen; nothing we can do */ }
  }
}

function installChildProcessHooks(cp) {
  if (!cp || cp.__openclaw_hooked) return cp;
  cp.__openclaw_hooked = true;

  // Originals live only in this closure (and in the module-level WeakMap
  // used by uninstall) — never on the module object under a discoverable key.
  const originals = {
    exec: cp.exec,
    execSync: cp.execSync,
    execFile: cp.execFile,
    execFileSync: cp.execFileSync,
    spawn: cp.spawn,
    spawnSync: cp.spawnSync,
    fork: cp.fork,
  };

  lockMethod(cp, 'exec', wrapExec(originals.exec, 'child_process.exec'));
  lockMethod(cp, 'execSync', wrapExec(originals.execSync, 'child_process.execSync'));
  lockMethod(cp, 'execFile', wrapExecFile(originals.execFile, 'child_process.execFile'));
  lockMethod(cp, 'execFileSync', wrapExecFile(originals.execFileSync, 'child_process.execFileSync'));
  lockMethod(cp, 'spawn', wrapSpawn(originals.spawn, 'child_process.spawn'));
  lockMethod(cp, 'spawnSync', wrapSpawn(originals.spawnSync, 'child_process.spawnSync'));
  lockMethod(cp, 'fork', wrapFork(originals.fork));

  log('info', 'child_process hooks installed (defineProperty locked)');
  return cp;
}

// Keep original references so uninstall/restore is possible if needed.
const originalChildProcessMethods = new WeakMap();

function uninstallChildProcessHooks(cp) {
  if (!cp || !cp.__openclaw_hooked) return;
  const originals = originalChildProcessMethods.get(cp);
  if (originals) {
    cp.exec = originals.exec;
    cp.execSync = originals.execSync;
    cp.execFile = originals.execFile;
    cp.execFileSync = originals.execFileSync;
    cp.spawn = originals.spawn;
    cp.spawnSync = originals.spawnSync;
    cp.fork = originals.fork;
  }
  delete cp.__openclaw_hooked;
}

function installModuleLoadHook() {
  if (global.__openclaw_module_hook_installed) return;
  global.__openclaw_module_hook_installed = true;

  try {
    const Module = require('module');
    const originalLoad = Module._load;

    const hookedLoad = function hookedLoad(request, parent, isMain) {
      const result = originalLoad.apply(this, arguments);
      if (request === 'child_process' && result && !result.__openclaw_hooked) {
        return installChildProcessHooks(result);
      }
      return result;
    };

    // 标记：network.js 安装前会检查它。两个 hook 抢同一个 Module._load，而
    // hook-mounter 的加载顺序是 runtime.js 在前 —— 先装的把它锁成不可写，
    // 后装的裸赋值必然抛 "Cannot assign to read only property '_load'"，
    // 每次启动刷一条 error 还顺带 dump 整个 Module 源码。标记让后装的
    // 体面退出，而不是靠捕获异常。
    hookedLoad.__openclaw_hookModuleLoad = true;

    // F-01: lock Module._load so injected code cannot `delete Module._load`
    // and re-export the unwrapped original. Fall back to plain assignment
    // if the host freezes Module exports (rare; logging only).
    try {
      Object.defineProperty(Module, '_load', {
        value: hookedLoad,
        writable: false,
        configurable: false,
        enumerable: false,
      });
    } catch (err) {
      log('warn', `failed to lock Module._load via defineProperty: ${err.message}`);
      Module._load = hookedLoad;
    }

    log('info', 'Module._load hook installed (defineProperty locked)');
  } catch (err) {
    log('error', `failed to install Module._load hook: ${err.message}`);
  }
}

function uninstallModuleLoadHook() {
  // Restoring Module._load is complex because other modules may have wrapped it.
  // We provide a no-op for symmetry.
  global.__openclaw_module_hook_installed = false;
}

function install() {
  if (global.__openclaw_runtime_hook_installed) {
    log('debug', 'runtime hook already installed, skipping');
    return;
  }
  global.__openclaw_runtime_hook_installed = true;

  // Mark this process as hooked so the Python process monitor can
  // tell hooked node processes from unhooked ones (unpatched_engine flag).
  // Children either inherit the marker together with NODE_OPTIONS or get it
  // re-injected by applyHookPropagation().
  try {
    process.env[HOOK_MARKER_ENV] = '1';
  } catch {
    /* readonly env (exotic hosts) — marker is best-effort */
  }

  try {
    const cp = require('child_process');
    // Save originals before wrapping.
    if (!originalChildProcessMethods.has(cp)) {
      originalChildProcessMethods.set(cp, {
        exec: cp.exec,
        execSync: cp.execSync,
        execFile: cp.execFile,
        execFileSync: cp.execFileSync,
        spawn: cp.spawn,
        spawnSync: cp.spawnSync,
        fork: cp.fork,
      });
    }
    installChildProcessHooks(cp);
    installModuleLoadHook();
    log('info', 'Node.js runtime hooks installed');
  } catch (err) {
    log('error', `install failed: ${err.message}`);
  }
}

function uninstall() {
  global.__openclaw_runtime_hook_installed = false;
  try {
    const cp = require('child_process');
    uninstallChildProcessHooks(cp);
    uninstallModuleLoadHook();
    log('info', 'Node.js runtime hooks uninstalled');
  } catch (err) {
    log('error', `uninstall failed: ${err.message}`);
  }
}

// Auto-install when this module is required via -r.
registerHookFile(__filename);
install();

module.exports = {
  install,
  uninstall,
  buildEvent,
  redactCommandLine,
  getCallerLocation,
  computeRiskFlags,
  shouldBlock,
  // Exported for unit tests: pure env-mutation helper, no I/O.
  applyHookPropagation,
  HOOK_MARKER_ENV,
  SKIP_HOOK_PROPAGATION,
  HOOK_BLOCK_ERROR_CODE,
  HOOK_INTERNAL_ERROR_CODE,
  // Exported for the "fallback == generated" parity gate: the built-in fallback
  // tables must stay identical to policies/security-policy.spl.yaml (via
  // hooks/generated-patterns.json) so a deployment without the artifact
  // behaves identically to one that has it.
  FALLBACK_BLOCKED_FLAGS,
  FALLBACK_BLOCK_PATTERNS,
};
