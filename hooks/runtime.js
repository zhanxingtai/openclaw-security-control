// openclaw-hook: v1.0.1 (信息性注释；升级判定用全文内容哈希，勿依赖此值)
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
const DEBUG = process.env.OPENCLAW_RUNTIME_HOOK_DEBUG === 'true' || process.env.OPENCLAW_RUNTIME_HOOK_DEBUG === '1';
const MAX_COMMAND_LINE_LENGTH = parseInt(process.env.OPENCLAW_RUNTIME_HOOK_MAX_CMD_LENGTH || '4096', 10);
const MAX_ARGUMENTS_TOTAL_LENGTH = parseInt(process.env.OPENCLAW_RUNTIME_HOOK_MAX_ARGS_LENGTH || '4096', 10);

// 纯正则 cmdline flag 的检测模式与默认阻断名单的唯一数据源是
// policies/security-policy.spl.yaml（hookPatterns / metadata.flagRegistry），
// 构建期生成同目录 generated-patterns.json。本文件内的 FALLBACK_* 常量只在
// 产物缺失/损坏（部分部署包）时兜底，并打 WARN；正常构建不再双写漂移。
const FALLBACK_BLOCKED_FLAGS = [
  'reverse_shell',
  'download_execute',
  'mass_deletion',
  'privilege_escalation',
  'data_exfiltration',
  'token_in_command',
  'sensitive_file_access',
  'skill_binary_execution',
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

function loadHookPatternSpec() {
  const file = path.join(__dirname, 'generated-patterns.json');
  try {
    const spec = JSON.parse(fs.readFileSync(file, 'utf8'));
    const patterns = compileGeneratedHookPatterns(spec);
    const blockedFlags =
      Array.isArray(spec.blockedFlags) && spec.blockedFlags.length > 0
        ? spec.blockedFlags.map((f) => String(f))
        : FALLBACK_BLOCKED_FLAGS;
    return { patterns, blockedFlags };
  } catch (err) {
    log('warn', `generated-patterns.json unavailable (${err && err.message ? err.message : String(err)}); using built-in fallback patterns`);
    return { patterns: FALLBACK_HOOK_PATTERNS, blockedFlags: FALLBACK_BLOCKED_FLAGS };
  }
}

const HOOK_PATTERN_SPEC = loadHookPatternSpec();
const DEFAULT_BLOCKED_FLAGS = HOOK_PATTERN_SPEC.blockedFlags;

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
// opts out via the __skipHookPropagation sentinel. Both the opt-out and the
// strip-and-reinject paths raise a self_protection_bypass flag on the
// emitted process event.
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
      if (filePath && !filePath.includes('/hooks/node/runtime.js') && !filePath.startsWith('node:')) {
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
      if (filePath && !filePath.includes('/hooks/node/runtime.js') && !filePath.startsWith('node:')) {
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

function isInterestingCaller(filePath, fnName) {
  if (!filePath) return false;
  const normalized = filePath.replace(/\\/g, '/');
  if (normalized.includes('/hooks/node/runtime.js')) return false;
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
  return {
    session_id: global.__OPENCLAW_SESSION_ID__ || process.env.OPENCLAW_SESSION_ID || '',
    run_id: global.__OPENCLAW_RUN_ID__ || process.env.OPENCLAW_RUN_ID || '',
    agent_id: global.__OPENCLAW_AGENT_ID__ || process.env.OPENCLAW_AGENT_ID || '',
    tool_call_id: global.__OPENCLAW_TOOL_CALL_ID__ || process.env.OPENCLAW_TOOL_CALL_ID || '',
    tool_name: global.__OPENCLAW_TOOL_NAME__ || process.env.OPENCLAW_TOOL_NAME || '',
  };
}

/**
 * Determine whether a runtime event should be blocked based on configured
 * risk flags. Returns a human-readable block reason, or undefined if the
 * event should be allowed.
 */
function shouldBlock(event) {
  if (!isRuntimeEnforceEnabled()) return undefined;
  const flags = event.risk_flags || [];
  if (flags.length === 0) return undefined;

  const blockedFlags = getBlockedFlags();
  const matched = flags.find((f) => blockedFlags.includes(f));
  if (!matched) return undefined;

  return `命令被 OpenClaw runtime hook 拦截（risk flag: ${matched}）`;
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
  const event = {
    // Renamed to process_start to match the platform data standard (进程类事件).
    event_type: 'process_start',
    type: 'application.process_start',
    id: generateId(),
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

  // The caller explicitly skipped hook propagation or supplied a
  // NODE_OPTIONS-free env (hook would have been dropped) — flag the bypass.
  if (options.bypass_reason) flags.push('self_protection_bypass');

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
  return `${event.command_line}|${event.pid}|${event.ppid}|${caller.file || ''}:${caller.line || ''}:${caller.column || ''}`;
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

function emit(api, command_line, executable, args, shell_involved, shell, bypass_reason) {
  const event = buildEvent({
    api,
    command_line,
    executable,
    args,
    shell_involved,
    shell,
    bypass_reason,
  });
  const blockReason = shouldBlock(event);
  if (blockReason) {
    event.blocked = true;
    event.block_reason = blockReason;
    emitEvent(event);
    throw new Error(blockReason);
  }
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

function wrapExec(original, apiName) {
  return function wrappedExec(command, options, callback) {
    const opts = isOptionsObject(options) ? options : undefined;
    const bypassReason = safeApplyHookPropagation(opts);
    try {
      const shell = (opts && opts.shell) || '/bin/sh';
      emit(apiName, command, command.trim().split(/\s+/)[0], undefined, true, shell, bypassReason);
    } catch (err) {
      // Runtime enforcement blocked the command. Route the error to the
      // callback when one is available; otherwise rethrow so the caller
      // observes a synchronous denial.
      if (typeof options === 'function') {
        options(err);
        return undefined;
      }
      if (typeof callback === 'function') {
        callback(err);
        return undefined;
      }
      throw err;
    }
    return original.apply(this, arguments);
  };
}

function wrapExecFile(original, apiName) {
  return function wrappedExecFile(file, args, options, callback) {
    // execFile(file[, args][, options][, callback]): like spawn, args may
    // carry the options object. Same env-strip bypass surface as spawn, so
    // propagation applies here too.
    const opts = isOptionsObject(options) ? options : isOptionsObject(args) ? args : undefined;
    const bypassReason = safeApplyHookPropagation(opts);
    try {
      const normalizedArgs = Array.isArray(args) ? args : [];
      const cmdline = [file, ...normalizedArgs].join(' ');
      const detection = detectShellInvocation(file, normalizedArgs, opts);
      emit(apiName, cmdline, file, normalizedArgs, detection.shell_involved, detection.shell, bypassReason);
    } catch (err) {
      // Runtime enforcement blocked the command. Prefer the callback argument.
      if (typeof args === 'function') {
        args(err);
        return undefined;
      }
      if (typeof options === 'function') {
        options(err);
        return undefined;
      }
      if (typeof callback === 'function') {
        callback(err);
        return undefined;
      }
      throw err;
    }
    return original.apply(this, arguments);
  };
}

function wrapSpawn(original, apiName) {
  return function wrappedSpawn(command, args, options) {
    // spawn(command[, args][, options]): when args is omitted it carries the
    // options object. Resolve the real options slot for propagation.
    const opts = isOptionsObject(options) ? options : isOptionsObject(args) ? args : undefined;
    const bypassReason = safeApplyHookPropagation(opts);
    try {
      const normalizedArgs = Array.isArray(args) ? args : [];
      const cmdline = [command, ...normalizedArgs].join(' ');
      const detection = detectShellInvocation(command, normalizedArgs, opts);
      emit(apiName, cmdline, command, normalizedArgs, detection.shell_involved, detection.shell, bypassReason);
    } catch (err) {
      // Runtime enforcement blocked the command. spawn has no callback, so
      // throw synchronously to deny execution.
      throw err;
    }
    return original.apply(this, arguments);
  };
}

function wrapFork(original) {
  return function wrappedFork(modulePath, args, options) {
    const opts = isOptionsObject(options) ? options : isOptionsObject(args) ? args : undefined;
    const bypassReason = safeApplyHookPropagation(opts);
    try {
      const normalizedArgs = Array.isArray(args) ? args : [];
      const cmdline = [modulePath, ...normalizedArgs].join(' ');
      emit('child_process.fork', cmdline, 'node', [modulePath, ...normalizedArgs], false, undefined, bypassReason);
    } catch (err) {
      // Runtime enforcement blocked the fork. Deny execution synchronously.
      throw err;
    }
    return original.apply(this, arguments);
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
};
