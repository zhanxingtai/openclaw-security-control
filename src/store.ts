import type {
  OpenClawMiddleware,
  MiddlewareContext,
  MiddlewareResult,
  AgentStartContext,
  AgentStartResult,
  AgentCompleteContext,
  MessageWriteContext,
  MessageWriteResult,
  SessionEndContext,
  SubagentContext,
  CronEventContext,
  SecurityMonitorConfig,
  SecurityEvent,
} from './types.js';
import { appendFile, chmod, stat } from 'fs/promises';
import { renameSync, statSync } from 'fs';
import { dirname } from 'path';
import { generateUUID } from './uuid.js';
import { ControlUiService } from './control-ui-service.js';
import { ApplicationCollector } from './application-collector.js';
import { NetworkCollector } from './network-collector.js';
import { SystemCollector } from './system-collector.js';
import { RuntimeHookCollector } from './runtime-hook-collector.js';
import { AssetCollector } from './asset-collector.js';
import { redactEventForEmit } from './redact.js';
import { normalizeConfig } from './config.js';
import { InterventionEngineImpl } from './intervention/InterventionEngine.js';
import { ActionHistory } from './intervention/ActionHistory.js';
import { GENERATED_HOOK_BLOCKED_FLAGS } from './intervention/generated-flag-defaults.js';
import type { InterventionContext, SecurityDecision, PolicyAuditEvent } from './intervention/types.js';
import * as SelfProtection from './intervention/SelfProtection.js';

/**
 * Local NDJSON event sink. Writes events to the configured path so the SDK
 * sidecar can poll and upload them. The plugin only appends locally.
 *
 * Two pre-write guards protect the sink from a hostile or misconfigured host:
 *   1. A 64 KiB per-line cap drops oversized payloads that would otherwise
 *      break NDJSON framing for downstream readers.
 *   2. A parent-directory ownership / mode check refuses to write when the
 *      NDJSON directory is owned by another user or is world-writable, which
 *      stops an attacker who pre-created the directory from injecting a
 *      forged log file under our path.
 */
const MAX_NDJSON_LINE_BYTES = 64 * 1024;

// Tracks ndjson files whose permissions have already been tightened to 0o600.
// chmod runs once per path (first successful append) instead of after every
// event — the per-event syscall was pure hot-path overhead.
// The parent-dir ownership check in report() still guards the unlink-and-
// swap tamper window at write time.
const CHMOD_DONE_PATHS = new Set<string>();

class EventBridgeCollector {
  constructor(private readonly cfg: SecurityMonitorConfig['collector']) {}

  /**
   * In-flight appends. Hook handlers call report() fire-and-forget, so a
   * shutdown/reset must drain these before the caller tears down the
   * surrounding directory — otherwise a late append recreates files mid-cleanup
   * (observed on Windows CI as rmSync ENOTEMPTY).
   */
  private readonly pendingWrites = new Set<Promise<void>>();

  async report(event: SecurityEvent): Promise<void> {
    const path = this.cfg?.ndjsonPath;
    if (!path) return;
    // Unified redaction exit: every event that reaches the
    // NDJSON sink passes through redactEventForEmit here, so no collector can
    // bypass it by calling collector.report() directly. Only well-known PII /
    // credential fields are touched; obf:v1 obfuscated values and the event
    // schema are unaffected, and the call is idempotent for events that were
    // already redacted upstream (e.g. ApplicationCollector's emit helper).
    const line = JSON.stringify(redactEventForEmit(event as unknown as Record<string, unknown>)) + '\n';
    const lineBytes = Buffer.byteLength(line, 'utf8');
    const maxSize = this.cfg?.maxFileSizeBytes ?? 0;

    // Hard per-line cap. Anything larger would invalidate NDJSON framing
    // and silently truncate downstream consumers. Drop the event and warn
    // instead of writing a broken line.
    if (lineBytes > MAX_NDJSON_LINE_BYTES) {
      console.warn(
        `[EventBridgeCollector] dropping event ${event.event_id ?? '(no id)'} (${lineBytes} bytes > ${MAX_NDJSON_LINE_BYTES} NDJSON line cap)`
      );
      return;
    }

    // Parent-directory ownership / mode check. If the directory is owned by
    // a different user, or is world-writable WITHOUT the sticky bit, refuse
    // to write: an attacker could unlink the file between append and chmod
    // and drop a forged one under our path. mkdirSync at install-time runs
    // as the host user so this check is consistent on first-write and
    // steady-state. The sticky bit is what makes /tmp safe (1777) — any
    // world-writable dir WITHOUT the sticky bit is treated as hostile.
    try {
      const dir = dirname(path);
      const st = statSync(dir);
      // POSIX-only check: uid/mode semantics do not exist on Windows
      // (statSync there always reports uid=0 / mode derived from the DOS
      // readonly flag, so every write would trip "unsafe"). Where getuid is
      // unavailable we cannot attribute ownership at all — skip the check.
      if (typeof process.getuid === 'function') {
        const worldWritable = (st.mode & 0o002) !== 0;
        const sticky = (st.mode & 0o1000) !== 0;
        const unsafe = st.uid !== process.getuid() || (worldWritable && !sticky);
        if (unsafe) {
          console.warn(
            `[EventBridgeCollector] refusing to write ${path}: parent dir uid=${st.uid} mode=${(st.mode & 0o1777).toString(8)} (expected uid=${process.getuid?.()}, no world-write without sticky bit)`
          );
          this.emitTamperEvent(event, 'parent_dir_insecure', {
            uid: st.uid,
            mode: st.mode & 0o777,
          });
          return;
        }
      }
    } catch {
      // Directory not present yet — mkdirSync will be handled by caller / host.
    }

    // Size-bounded rollover. When the current file plus the incoming line
    // would exceed maxFileSizeBytes, rename the existing file aside and let
    // appendFile create a fresh one. Sidecar SDK should also tail
    // `<path>.rotated` so it does not lose the rollover window.
    if (maxSize > 0) {
      try {
        let currentSize = 0;
        try { currentSize = statSync(path).size; } catch { /* file may not exist yet */ }
        if (currentSize + lineBytes > maxSize) {
          try {
            renameSync(path, `${path}.rotated`);
          } catch (err) {
            console.warn(
              `[EventBridgeCollector] failed to rotate ${path}: ${err instanceof Error ? err.message : String(err)}`
            );
          }
        }
      } catch {
        // statSync / renameSync threw unexpectedly; fall through to append.
      }
    }

    const write = (async () => {
      try {
        await appendFile(path, line, 'utf8');
        // NDJSON may carry credential plaintext / prompts. Default umask (022)
        // leaves the file world-readable; tighten to owner-only once per path —
        // the first append creates the file under the current umask, after which
        // the mode persists across appends.
        if (!CHMOD_DONE_PATHS.has(path)) {
          try {
            await chmod(path, 0o600);
            CHMOD_DONE_PATHS.add(path);
          } catch (err) {
            // permission tightening best-effort, but keep visibility
            this.logWriteIssue(`chmod ${path} 0o600 failed: ${err instanceof Error ? err.message : String(err)}`);
          }
        }
      } catch (err) {
        // best-effort: do not break hook handlers — but count and surface the
        // failure instead of swallowing it silently.
        this.writeErrorCount += 1;
        this.logWriteIssue(`append ${path} failed: ${err instanceof Error ? err.message : String(err)}`);
      }
    })();
    this.pendingWrites.add(write);
    try {
      await write;
    } finally {
      this.pendingWrites.delete(write);
    }
  }

  private writeErrorCount = 0;
  private writeIssueLogged = false;
  /** Throttled warning: first issue logs immediately, repeats every 10th. */
  private logWriteIssue(message: string): void {
    if (!this.writeIssueLogged || this.writeErrorCount % 10 === 0) {
      console.warn(`[EventBridgeCollector] ${message} (total write errors: ${this.writeErrorCount + 1})`);
      this.writeIssueLogged = true;
    }
  }

  private emitTamperEvent(_event: SecurityEvent, kind: string, detail: Record<string, unknown>): void {
    // Best-effort: surface a tamper_detected event so the audit panel can
    // alert. We intentionally do not block the host — operator decides.
    console.warn(`[EventBridgeCollector] tamper_detected kind=${kind} detail=${JSON.stringify(detail)}`);
  }

  async initialize(): Promise<void> { /* no-op */ }
  async shutdown(): Promise<void> {
    // Drain fire-and-forget appends so plugin unload / store reset does not
    // orphan in-flight writes (Windows CI: late append recreated files while
    // the test's rmSync was deleting the temp dir → ENOTEMPTY).
    await Promise.allSettled([...this.pendingWrites]);
  }
  /** Polling/ack handled by SDK sidecar; this stub is a no-op. */
  async flush(): Promise<void> { /* no-op */ }
  /** Stats exposed via bridge route; this stub returns zeros. */
  getStats(): { queueSize: number; totalFailed: number; totalReported: number } {
    return { queueSize: 0, totalFailed: 0, totalReported: 0 };
  }
}

interface HostAdapterContext {
  framework: string;
  agentId?: string;
  sessionId?: string;
  runId?: string;
  phase: string;
  auditMode: boolean;
}

/**
 * Translates a SecurityDecision (intervention engine output) into the host's
 * MiddlewareResult shape. Critical: in enforce mode, a `block` decision must
 * surface as `{ block: true, reason }` so OpenClaw's before_tool_call policy
 * skips the actual tool execution. The previous stub returned
 * `{ block: false }` for everything, which let tool calls run even when the
 * policy said block — agents received /etc/passwd contents despite the block.
 */
const OpenClawAdapter = class {
  constructor(_opts: { strictContextAdjust: boolean }) {}

  /**
   * build a real agent_start InterventionContext from the
   * AgentStartContext. The previous stub returned {} so agent_start rules
   * (e.g. agent-start-path-boundary-hint) evaluated an empty context and
   * could never match.
   */
  toInterventionContext(ctx: unknown, host: HostAdapterContext): InterventionContext {
    const c = (ctx ?? {}) as Record<string, unknown>;
    const prompt = typeof c.prompt === 'string' ? c.prompt : undefined;
    const agentId = typeof c.agentId === 'string' ? c.agentId : host.agentId;
    return {
      actionType: 'agent_start',
      toolName: agentId,
      body: prompt,
      userPrompt: prompt,
      params: {
        ...(typeof c.systemPrompt === 'string' ? { systemPrompt: c.systemPrompt } : {}),
        ...(Array.isArray(c.skills) ? { skills: c.skills } : {}),
        ...(Array.isArray(c.tools) ? { tools: c.tools } : {}),
      },
      sessionId: typeof c.sessionKey === 'string' ? c.sessionKey : host.sessionId,
      agentId,
    };
  }

  /**
   * translate an agent_start decision into the 9.4 before_agent_run
   * InputGateDecision. The 9.4 gate supports only pass/block
   * (hook-decision-types.ts: no systemPromptAddition), so block decisions are
   * returned as { outcome: 'block', reason } and every other decision type
   * returns undefined — the caller records why it cannot be delivered.
   */
  adaptAgentStart(
    d: SecurityDecision | undefined,
    _c: InterventionContext,
    _p: HostAdapterContext
  ): AgentStartResult | undefined {
    if (!d || d.decision !== 'block') {
      return undefined;
    }
    const reason = d.blockReason || d.reason || `policy ${d.policyId || 'block'}`;
    return { outcome: 'block', reason };
  }

  /**
   * translate a message_write decision into MessageWriteResult.
   * block → { content } (the SelfProtection form), which the hook entry
   * converts to the host shape { block: true, message: { role, content } }.
   * Guidance / audit decisions cannot be delivered through
   * before_message_write (sync hook, block/message-replace only) and return
   * undefined — the caller records why.
   */
  adaptMessageWrite(
    d: SecurityDecision | undefined,
    _c: InterventionContext,
    _p: HostAdapterContext
  ): MessageWriteResult | void {
    if (!d || d.decision !== 'block') {
      return undefined;
    }
    return { content: d.blockReason || d.reason || `policy ${d.policyId || 'block'}` };
  }
  adapt(decision: SecurityDecision, _ctx: InterventionContext, _host: HostAdapterContext): { native: MiddlewareResult } {
    const reason = decision.blockReason || decision.reason || `policy ${decision.policyId || 'block'}`;
    switch (decision.decision) {
      case 'block':
        return { native: { block: true, reason, modifiedParams: decision.modifiedParams } };
      case 'modify':
        return { native: { block: false, modifiedParams: decision.modifiedParams, reason } };
      case 'substitute':
        return { native: { block: false, reason } };
      case 'audit':
        // audit 是"放行 + 审计留痕"，不改变宿主放行语义。
        return { native: { block: false, reason } };
      case 'allow':
      default:
        return { native: { block: false } };
    }
  }
};

// ---------------------------------------------------------------------------
// runtime hook enforce env 防进程内篡改。
//
// 背景：runtime/network hook 每次拦截时惰性读 OPENCLAW_RUNTIME_ENFORCE 等
// 开关（插件 initialize 晚于 hook preload，本进程内必须动态生效）。但
// process.env 槽位本身谁都能改，同进程代码（如 prompt 注入后在 gateway
// 进程内执行的工具代码）一行 `process.env.OPENCLAW_RUNTIME_ENFORCE =
// 'false'` 即可关闭强制拦截。
//
// 原设想用 Object.defineProperty(process.env, KEY, {writable:false,
// configurable:false}) 冻结槽位，但 Node 的 process.env 只接受
// {writable:true, configurable:true, enumerable:true} 数据描述符，其余
// 形态一律抛 ERR_INVALID_OBJECT_DEFINE_PROPERTY（Node >=16 起，含本项目
// 支持的 >=18）。因此改为：插件把权威值保存在本模块私有绑定里，并在
// globalThis 上钉一个 configurable:false 的只读 getter；hook 侧每次拦截
// 先查钉住值（存在即权威），未钉住时回落 process.env 惰性读取；钉住后
// 进程内改 env 对判定不再生效（严格模式下改写 globalThis 钉会直接抛错）。
// ---------------------------------------------------------------------------
const HOOK_ENV_PIN_KEY = '__OPENCLAW_SECURITY_HOOK_ENV__';
// 模块私有绑定：同 isolate 内的其他代码拿不到它，只能调用 globalThis 上
// 那只读 getter；每次 pin 都换一个新的冻结快照，getter 返回副本，调用方
// 即使拿到返回值也无法回写权威状态。
let pinnedHookEnv: Record<string, string | undefined> = {};
let hookEnvPinInstalled = false;

function pinHookEnv(values: Record<string, string | undefined>): void {
  pinnedHookEnv = Object.freeze({ ...values });
  if (hookEnvPinInstalled) return;
  try {
    Object.defineProperty(globalThis, HOOK_ENV_PIN_KEY, {
      value: () => ({ ...pinnedHookEnv }),
      writable: false,
      configurable: false,
      enumerable: false,
    });
    hookEnvPinInstalled = true;
  } catch {
    // 宿主冻结 globalThis 等极端场景：退化为纯 env 传播。
  }
}

export class SecurityMonitorStore implements OpenClawMiddleware {
  readonly name = 'sst-security-control-openclaw';

  private config: SecurityMonitorConfig;
  /** Expose the merged config so the panel can render the full editable surface. */
  getConfig(): SecurityMonitorConfig { return this.config; }
  private collector: EventBridgeCollector;
  private applicationCollector: ApplicationCollector;
  private networkCollector: NetworkCollector;
  private systemCollector: SystemCollector;
  private runtimeHookCollector: RuntimeHookCollector;
  private assetCollector: AssetCollector;
  private interventionEngine?: InterventionEngineImpl;
  private openClawAdapter: InstanceType<typeof OpenClawAdapter>;
  private enabled = true;
  // 自保护自检：周期检测干预引擎规则空载与关键文件被删/截断，产生留痕事件。
  private selfCheckTimer?: ReturnType<typeof setInterval>;
  private fileBaselines = new Map<string, number>();
  // chain 规则的 previousActions 数据源，跨评估入口共享。
  private actionHistory = new ActionHistory();
  // runtime hook 事件按会话沉淀的最近风险标签：tool_call / message_write
  // 等主进程评估入口据此回填 ctx.riskFlags（此前仅 runtime 事件自身携带，
  // 导致 fail_open_high_risk_only 兜底与 riskFlagsAny/All 规则在这些入口
  // 永远拿不到风险信号）。
  private sessionRiskFlags = new Map<string, string[]>();
  // 非 allow 决策因宿主能力边界无法下发时的去重集合（warn 只记一次）。
  private nonDeliverableWarned = new Set<string>();
  // bootstrap 期 runtime hook 探测结果（NODE_OPTIONS 是否真的
  // 预加载了 hook）与用户原始意图（是否主动关闭 runtimeHooks）。由
  // index.ts register() 在 initializePlugin 后写入，security.status 透传给
  // 面板持久状态条；undefined 表示 bootstrap 未上报（legacy 加载路径）。
  private runtimeHookProbeLoaded?: boolean;
  private runtimeHooksUserEnabled?: boolean;

  constructor(config?: SecurityMonitorConfig) {
    this.config = config || normalizeConfig({});
    this.collector = new EventBridgeCollector(this.config.collector);
    this.applicationCollector = new ApplicationCollector(
      this.collector,
      this.config.application || { enabled: true },
      this.config.environment,
      undefined,
      { reportBlockedEvents: this.config.intervention?.reportBlockedEvents }
    );
    this.networkCollector = new NetworkCollector(this.collector, this.config.network || { enabled: false });
    this.systemCollector = new SystemCollector(
      this.collector,
      this.config.system || { enabled: false },
      this.config.environment
    );
    this.runtimeHookCollector = this.createRuntimeHookCollector();
    this.assetCollector = new AssetCollector(
      this.collector,
      this.config.assetMonitor || { enabled: false },
      this.config.environment
    );
    this.interventionEngine = this.createInterventionEngine(this.config);
    this.openClawAdapter = new OpenClawAdapter({
      strictContextAdjust: this.config.intervention?.mode === 'enforce',
    });
    this.configureRuntimeHookEnvironment(this.config);
  }

  private createInterventionEngine(config: SecurityMonitorConfig): InterventionEngineImpl | undefined {
    const interventionConfig = config.intervention;
    if (!interventionConfig?.enabled) {
      return undefined;
    }

    return new InterventionEngineImpl({
      ruleLoader: {
        policyPath: interventionConfig.policyPath || '',
        reloadIntervalMs: interventionConfig.reloadIntervalMs,
      },
      decisionTimeoutMs: interventionConfig.decisionTimeoutMs,
      failStrategy: interventionConfig.failStrategy,
      highRiskFlags: interventionConfig.highRiskFlags,
      guidance: interventionConfig.guidance,
      degrade: interventionConfig.degrade,
      mode: interventionConfig.mode,
      audit: (event) => {
        // 策略缺失 / 规则隔离等 fail-open 面事件写入 NDJSON 留痕。
        this.emitPolicyAuditEvent(event).catch(() => {});
      },
      logger: {
        warn: (msg) => console.warn(msg),
        error: (msg) => console.error(msg),
      },
    });
  }

  /**
   * runtime hook 事件在落盘前回灌干预引擎，为 process_start /
   * network_http 两类 actionType 提供评估入口（此前引擎只在
   * agent_start / message_write / tool_call 三处被调用，导致策略中
   * 一批依赖 riskFlags 的规则运行时永不命中）。回调闭包惰性读取
   * this.interventionEngine，initialize() 重建引擎后自动生效。
   */
  private createRuntimeHookCollector(): RuntimeHookCollector {
    return new RuntimeHookCollector(
      this.collector,
      this.config.application?.runtimeHooks || { enabled: false },
      this.config.environment,
      { onEvent: (event) => this.evaluateRuntimeEvent(event) }
    );
  }

  /**
   * 把 runtime hook 事件翻译成干预上下文并评估：risk_flags 直接回灌
   * ctx.riskFlags（复用 runtime hook 已采集的标签，不新造检测逻辑），
   * chain 规则从 ActionHistory 取 previousActions。决策写回事件的
   * intervention 字段随 NDJSON 留痕。这是事后评估（进程已启动/请求已
   * 发出），决策只记录不拦截——同步拦截由 runtime hook 自身的 enforce
   * 路径在 exec 前完成。
   */
  private async evaluateRuntimeEvent(event: SecurityEvent): Promise<void> {
    const engine = this.interventionEngine;
    if (!engine || !this.enabled || !this.config.intervention?.enabled) {
      return;
    }

    let ctx: InterventionContext | undefined;
    if (event.event_type === 'process_start') {
      ctx = {
        actionType: 'process_start',
        toolName: event.tool_name || event.process_name || event.exe,
        params: { command: event.cmdline, exe: event.exe },
        riskFlags: event.risk_flags,
        sessionId: event.session_id ?? undefined,
        runId: event.run_id ?? undefined,
        agentId: event.agent_id ?? undefined,
        previousActions: this.actionHistory.recent(event.session_id),
      };
    } else if (event.event_type === 'network_http') {
      ctx = {
        actionType: 'network_http',
        toolName: event.tool_name || undefined,
        params: {
          direction: event.direction,
          host: event.host,
          domain_name: event.domain_name,
          url: event.url,
          request_url: event.request_url,
          method: event.method,
          code: event.code,
        },
        body: event.body ?? (typeof event.content === 'string' ? event.content : undefined),
        riskFlags: event.risk_flags,
        sessionId: event.session_id ?? undefined,
        runId: event.run_id ?? undefined,
        agentId: event.agent_id ?? undefined,
        previousActions: this.actionHistory.recent(event.session_id),
      };
    }
    if (!ctx) return;

    // 按会话沉淀 runtime 风险标签，供 tool_call / message_write 评估入口回填。
    if (event.session_id && Array.isArray(event.risk_flags) && event.risk_flags.length > 0) {
      const existing = this.sessionRiskFlags.get(event.session_id) ?? [];
      const merged = [...new Set([...existing, ...event.risk_flags])];
      this.sessionRiskFlags.set(event.session_id, merged);
      if (this.sessionRiskFlags.size > 500) {
        // 会话数有界，与 ActionHistory 同一淘汰口径（最久未新增）。
        const oldest = this.sessionRiskFlags.keys().next().value;
        if (oldest !== undefined) this.sessionRiskFlags.delete(oldest);
      }
    }

    try {
      const decision = await engine.evaluate(ctx);
      if (decision && decision.decision !== 'allow' && !event.intervention) {
        // matched_rules 透传到事件层（snake_case），便于面板按 severity
        // 维度聚合与 Event Stream severity 列渲染。matchedPolicies 是决策的内部审计
        // 标注（camelCase），仅在 engine 命中 ≥1 条规则时存在；空数组不写以省字节。
        const matchedRules = Array.isArray(decision.matchedPolicies) && decision.matchedPolicies.length > 0
          ? decision.matchedPolicies.map((m) => ({
              policy_id: m.policyId,
              policy_name: m.policyName,
              decision: m.decision,
              priority: m.priority,
              risk_level: m.riskLevel,
              category: m.category,
            }))
          : undefined;
        event.intervention = {
          decision: decision.decision,
          policy_id: decision.policyId,
          policy_name: decision.policyName,
          reason: decision.reason,
          block_reason: decision.blockReason,
          block_code: decision.blockCode,
          modified_params: decision.modifiedParams,
          ...(matchedRules ? { matched_rules: matchedRules } : {}),
        };
      }
    } catch (err) {
      console.error('[SecurityMonitorStore] runtime event intervention evaluation failed:', err);
    } finally {
      this.actionHistory.record(ctx.sessionId, { tool: ctx.actionType, params: ctx.params });
    }
  }

  /**
   * Propagate enforce-mode decisions to the Node.js runtime hooks via environment
   * variables. Child processes spawned by tools inherit these variables, so the
   * runtime hook can synchronously block high-risk commands before they execute.
   *
   * The effective values are also pinned on globalThis (see
   * pinHookEnv). The env writes remain — they carry the settings to child
   * processes forked afterwards — but the hooks prefer the pin once it exists,
   * so in-process tampering with process.env cannot flip enforcement.
   */
  private configureRuntimeHookEnvironment(config: SecurityMonitorConfig): void {
    const runtimeHooks = config.application?.runtimeHooks;
    const intervention = config.intervention;

    // Point the preload hooks at the same sink the RuntimeHookCollector tails.
    // The hooks read OPENCLAW_MONITOR_LOG_PATH lazily at emit time, so setting
    // it here (constructor + initialize) covers both the gateway process and
    // child processes forked afterwards; without it a custom logPath would
    // fork hook writes and collector reads onto two different files.
    if (runtimeHooks?.enabled && runtimeHooks.logPath) {
      process.env.OPENCLAW_MONITOR_LOG_PATH = runtimeHooks.logPath;
    }

    // networkEnabled=false must actually stop network interception: the
    // hook-mounter skips network.js on preload, and the already-loaded hook
    // checks the same env lazily. Missing value means "on" (default).
    const networkEnabled = runtimeHooks?.networkEnabled !== false;
    process.env.OPENCLAW_NETWORK_HOOK_ENABLED = networkEnabled ? 'true' : 'false';

    const enforceEnabled = intervention?.enabled && intervention?.mode === 'enforce' && runtimeHooks?.enabled;

    if (!enforceEnabled) {
      delete process.env.OPENCLAW_RUNTIME_ENFORCE;
      delete process.env.OPENCLAW_RUNTIME_BLOCKED_FLAGS;
      delete process.env.OPENCLAW_NETWORK_ENFORCE;
      pinHookEnv({
        OPENCLAW_RUNTIME_ENFORCE: undefined,
        OPENCLAW_RUNTIME_BLOCKED_FLAGS: undefined,
        OPENCLAW_NETWORK_ENFORCE: undefined,
        OPENCLAW_NETWORK_HOOK_ENABLED: networkEnabled ? 'true' : 'false',
      });
      return;
    }

    process.env.OPENCLAW_RUNTIME_ENFORCE = 'true';
    // 兜底名单与 config.ts 默认值同源自 generated-flag-defaults.ts
    // （spl.yaml metadata.flagRegistry.hookBlockedFlags）。
    const blockedFlags = runtimeHooks.blockedFlags && runtimeHooks.blockedFlags.length > 0
      ? runtimeHooks.blockedFlags
      : [...GENERATED_HOOK_BLOCKED_FLAGS];
    process.env.OPENCLAW_RUNTIME_BLOCKED_FLAGS = blockedFlags.join(',');

    if (networkEnabled) {
      process.env.OPENCLAW_NETWORK_ENFORCE = 'true';
    } else {
      delete process.env.OPENCLAW_NETWORK_ENFORCE;
    }

    pinHookEnv({
      OPENCLAW_RUNTIME_ENFORCE: 'true',
      OPENCLAW_RUNTIME_BLOCKED_FLAGS: blockedFlags.join(','),
      OPENCLAW_NETWORK_ENFORCE: networkEnabled ? 'true' : undefined,
      OPENCLAW_NETWORK_HOOK_ENABLED: networkEnabled ? 'true' : 'false',
    });
  }

  async initialize(config: Record<string, unknown>): Promise<void> {
    this.config = normalizeConfig(config);

    // The OpenClaw framework may construct this middleware before calling
    // initialize(), and it may call initialize() more than once. If we already
    // have a running collector from the constructor, shut it down first so we
    // do not end up with two EventCollector instances writing to the same
    // ndjsonPath and flushing the same queue twice.
    await this.shutdown();

    // Re-create collectors with normalized config
    this.collector = new EventBridgeCollector(this.config.collector);
    this.applicationCollector = new ApplicationCollector(
      this.collector,
      this.config.application || { enabled: true },
      this.config.environment,
      undefined,
      { reportBlockedEvents: this.config.intervention?.reportBlockedEvents }
    );
    this.networkCollector = new NetworkCollector(this.collector, this.config.network || { enabled: false });
    this.systemCollector = new SystemCollector(
      this.collector,
      this.config.system || { enabled: false },
      this.config.environment
    );
    this.runtimeHookCollector = this.createRuntimeHookCollector();
    this.assetCollector = new AssetCollector(
      this.collector,
      this.config.assetMonitor || { enabled: false },
      this.config.environment
    );
    this.interventionEngine = this.createInterventionEngine(this.config);
    this.openClawAdapter = new OpenClawAdapter({
      strictContextAdjust: this.config.intervention?.mode === 'enforce',
    });
    this.configureRuntimeHookEnvironment(this.config);

    await this.collector.initialize();
    await this.applicationCollector.initialize();
    await this.networkCollector.initialize();
    await this.systemCollector.initialize();
    await this.runtimeHookCollector.initialize();
    await this.assetCollector.initialize();
    if (this.interventionEngine) {
      await this.interventionEngine.initialize();
    }

    // Log the effective on/off state of every layer so an operator can verify
    // post-install that the recommended Day-1 baseline is actually live. This
    // is the first thing a user sees in the gateway log after register();
    // they can grep for "layer config" to confirm.
    const c = this.config;
    console.log(
      `[SecurityMonitorStore] layer config: ` +
        `application=${c.application?.enabled ? 'on' : 'off'} ` +
        `runtimeHooks=${c.application?.runtimeHooks?.enabled ? 'on' : 'off'} ` +
        `network=${c.application?.runtimeHooks?.networkEnabled ? 'on' : 'off'} ` +
        `system=${c.system?.enabled ? 'on' : 'off'} ` +
        `procfs=${c.system?.procfs?.enabled ? 'on' : 'off'} ` +
        `assetMonitor=${c.assetMonitor?.enabled ? 'on' : 'off'} ` +
        `intervention=${c.intervention?.enabled ? 'on' : 'off'} ` +
        `interventionMode=${c.intervention?.mode ?? 'n/a'} ` +
        `failStrategy=${c.intervention?.failStrategy ?? 'n/a'} ` +
        `outputPath=${c.collector?.ndjsonPath ?? 'n/a'}`
    );

    // 启动自保护自检：引擎规则空载 / 关键文件被删截断 → 留痕事件。
    this.startSelfProtectionSelfCheck();
  }

  async beforeAgentStart(ctx: AgentStartContext): Promise<AgentStartResult | void> {
    if (!this.enabled || !this.config.application?.enabled) {
      return;
    }

    // Evaluate agent_start phase intervention rules (e.g. system prompt guidance).
    // Run in both enforce and audit modes so the rule's guidance appears on the event;
    // only enforce mode actually blocks via OpenClawAdapter.
    let agentStartDecision: SecurityDecision | undefined;
    let interventionCtx: InterventionContext | undefined;
    if (this.interventionEngine) {
      try {
        const hostCtx: HostAdapterContext = {
          framework: 'openclaw',
          agentId: ctx.agentId,
          sessionId: ctx.sessionKey,
          phase: 'beforeAgentStart',
          auditMode: this.config.intervention?.mode !== 'enforce',
        };
        interventionCtx = this.openClawAdapter.toInterventionContext(ctx, hostCtx);
        agentStartDecision = await this.interventionEngine.evaluate(interventionCtx);
      } catch (err) {
        console.error('[SecurityMonitorStore] agent_start intervention evaluation failed:', err);
      }
    }

    try {
      await this.applicationCollector.onAgentStart(ctx, agentStartDecision, this.config.intervention?.mode);
    } catch (err) {
      console.error('[SecurityMonitorStore] beforeAgentStart failed:', err);
    }

    if (agentStartDecision && agentStartDecision.decision !== 'allow' && this.config.intervention?.mode === 'enforce' && interventionCtx) {
      const hostCtx: HostAdapterContext = {
        framework: 'openclaw',
        agentId: ctx.agentId,
        sessionId: ctx.sessionKey,
        phase: 'beforeAgentStart',
        auditMode: false,
      };
      const adapted = this.openClawAdapter.adaptAgentStart(agentStartDecision, interventionCtx, hostCtx);
      if (adapted) {
        return adapted;
      }
      // 决策非 allow 但无法下发宿主（9.4 before_agent_run 仅支持
      // pass/block，context_adjust/guidance 需要 before_prompt_build，属
      // Guidance 方案 A 范围）。显式记录不支持原因，决策本身已由
      // applicationCollector.onAgentStart 写入事件，避免静默丢弃。
      this.warnDecisionNotDeliverable('agent_start', agentStartDecision);
    }
  }

  async afterAgentComplete(ctx: AgentCompleteContext): Promise<void> {
    if (!this.enabled || !this.config.application?.enabled) {
      return;
    }
    try {
      await this.applicationCollector.onAgentComplete(ctx);
    } catch (err) {
      console.error('[SecurityMonitorStore] afterAgentComplete failed:', err);
    }
  }

  async onSessionEnd(ctx: SessionEndContext): Promise<void> {
    if (!this.enabled || !this.config.application?.enabled) {
      return;
    }
    try {
      await this.applicationCollector.onSessionEnd(ctx);
    } catch (err) {
      console.error('[SecurityMonitorStore] onSessionEnd failed:', err);
    }
  }

  async onSubagentStart(ctx: SubagentContext): Promise<void> {
    if (!this.enabled || !this.config.application?.enabled) {
      return;
    }
    try {
      await this.applicationCollector.onSubagentStart(ctx);
    } catch (err) {
      console.error('[SecurityMonitorStore] onSubagentStart failed:', err);
    }
  }

  async onSubagentProgress(ctx: SubagentContext): Promise<void> {
    if (!this.enabled || !this.config.application?.enabled) {
      return;
    }
    try {
      await this.applicationCollector.onSubagentProgress(ctx);
    } catch (err) {
      console.error('[SecurityMonitorStore] onSubagentProgress failed:', err);
    }
  }

  async onSubagentEnd(ctx: SubagentContext): Promise<void> {
    if (!this.enabled || !this.config.application?.enabled) {
      return;
    }
    try {
      await this.applicationCollector.onSubagentEnd(ctx);
    } catch (err) {
      console.error('[SecurityMonitorStore] onSubagentEnd failed:', err);
    }
  }

  async onCronEvent(ctx: CronEventContext): Promise<void> {
    if (!this.enabled || !this.config.application?.enabled) {
      return;
    }
    try {
      await this.applicationCollector.onCronEvent(ctx);
    } catch (err) {
      console.error('[SecurityMonitorStore] onCronEvent failed:', err);
    }
  }

  /**
   * Async message_write entry — used by the legacy InternalHookEvent path and
   * the session_start hook. Event collection is awaited here.
   */
  async beforeMessageWrite(
    ctx: MessageWriteContext
  ): Promise<MessageWriteResult | void> {
    if (!this.enabled || !this.config.application?.enabled) {
      return;
    }
    let outcome: { decision: SecurityDecision | undefined; result: MessageWriteResult | void } | undefined;
    try {
      outcome = this.evaluateMessageWrite(ctx);
    } catch (err) {
      console.error('[SecurityMonitorStore] message write evaluation failed:', err);
    }
    try {
      await this.applicationCollector.onMessageWrite(ctx, outcome?.decision, this.config.intervention?.mode);
    } catch (err) {
      console.error('[SecurityMonitorStore] beforeMessageWrite failed:', err);
    }
    return outcome?.result;
  }

  /**
   * synchronous message_write entry for OpenClaw 2026.9.4's typed
   * before_message_write hook. That hook is SYNC-ONLY in the 9.4 host
   * (hooks.ts runSyncMessageHookStep: a Promise result is ignored with a
   * warning), so an async handler can never land a policy block. This method
   * evaluates SelfProtection + policy synchronously and returns the
   * MessageWriteResult directly; event collection stays fire-and-forget.
   */
  beforeMessageWriteSync(ctx: MessageWriteContext): MessageWriteResult | void {
    if (!this.enabled || !this.config.application?.enabled) {
      return;
    }
    let outcome: { decision: SecurityDecision | undefined; result: MessageWriteResult | void } | undefined;
    try {
      outcome = this.evaluateMessageWrite(ctx);
    } catch (err) {
      console.error('[SecurityMonitorStore] message write evaluation failed:', err);
      return;
    }
    // 事件采集 fire-and-forget：宿主 sync hook 不等待 Promise，拒绝由内部捕获。
    this.applicationCollector
      .onMessageWrite(ctx, outcome.decision, this.config.intervention?.mode)
      .catch((err) => {
        console.error('[SecurityMonitorStore] beforeMessageWrite event collection failed:', err);
      });
    return outcome.result;
  }

  /**
   * Shared synchronous message_write evaluation: policy engine
   * first so policy blocks (e.g. self-protection-block-uninstall-message)
   * land with policy attribution in enforce mode, then the SelfProtection
   * hardcoded path as the backstop for when the policy does not match,
   * intervention is disabled, or the mode is audit. Returns the decision
   * (for event attribution) and the host-consumable result.
   */
  private evaluateMessageWrite(
    ctx: MessageWriteContext
  ): { decision: SecurityDecision | undefined; result: MessageWriteResult | void } {
    let policyDecision: SecurityDecision | undefined;

    // 1. Policy engine (runs in both enforce and audit modes so the decision
    //    appears on the event; only enforce converts a block into a result).
    if (this.interventionEngine && ctx.role === 'user') {
      try {
        const interventionCtx = this.buildMessageInterventionContext(ctx);
        const decision = this.interventionEngine.evaluateSync(interventionCtx);
        if (decision && decision.decision !== 'allow') {
          policyDecision = decision;
          if (this.config.intervention?.mode === 'enforce') {
            const hostCtx: HostAdapterContext = {
              framework: 'openclaw',
              sessionId: ctx.sessionKey,
              runId: ctx.runId,
              phase: 'beforeMessageWrite',
              auditMode: false,
            };
            const adapted = this.openClawAdapter.adaptMessageWrite(decision, interventionCtx, hostCtx);
            if (adapted?.content !== undefined) {
              return { decision, result: adapted };
            }
            // 决策非 allow 但无法下发宿主（before_message_write 为 sync
            // hook，仅支持 block / message 替换；guidance 注入需 before_prompt_build，
            // 属 Guidance 方案 A 范围）。显式记录不支持原因，决策本身随事件留痕。
            this.warnDecisionNotDeliverable('message_write', decision);
          }
        }
      } catch (err) {
        console.error('[SecurityMonitorStore] message intervention evaluation failed:', err);
      }
    }

    // 2. Self-protection backstop: reject user messages that attempt to
    //    disable/uninstall the security monitor plugin, even when the policy
    //    does not match or policy-based intervention is off. Evaluation
    //    failures are treated as "not blocked".
    if (ctx.role === 'user') {
      const interventionCtx = this.buildMessageInterventionContext(ctx);
      try {
        const selfProtection = SelfProtection.evaluateMessageWrite(interventionCtx);
        if (selfProtection.blocked && selfProtection.decision) {
          console.warn(
            `[SecurityMonitorStore] self-protection blocked user message: ${selfProtection.decision.blockReason}`
          );
          return { decision: selfProtection.decision, result: { content: selfProtection.decision.blockReason } };
        }
      } catch (err) {
        console.error('[SecurityMonitorStore] self-protection message evaluation failed:', err);
      }
    }

    return { decision: policyDecision, result: undefined };
  }

  /**
   * 非 allow 决策因宿主能力边界无法下发时的显式留痕。同一
   * 阶段+策略+决策类型只告警一次，避免高频 hook 刷爆日志；决策本身
   * 已由事件采集写入 NDJSON。
   */
  private warnDecisionNotDeliverable(phase: 'agent_start' | 'message_write', decision: SecurityDecision): void {
    const key = `${phase}:${decision.policyId ?? 'unknown'}:${decision.decision}`;
    if (this.nonDeliverableWarned.has(key)) {
      return;
    }
    this.nonDeliverableWarned.add(key);
    const boundary =
      phase === 'agent_start'
        ? 'before_agent_run gate only supports pass/block (no systemPromptAddition)'
        : 'before_message_write is a sync hook supporting only block/message replacement';
    console.warn(
      `[SecurityMonitorStore] ${phase} decision not deliverable to host: ` +
        `decision=${decision.decision} policy=${decision.policyId ?? 'n/a'} — ` +
        `OpenClaw 2026.9.4 ${boundary}; guidance/context_adjust injection requires ` +
        `before_prompt_build (Guidance plan A, out of scope). Decision is recorded on the event only.`
    );
  }

  async beforeToolCall(ctx: MiddlewareContext): Promise<MiddlewareResult> {
    if (!this.enabled || !this.config.application?.enabled) {
      return { block: false };
    }

    const interventionCtx = this.buildInterventionContext(ctx);

    // 0. Hard-coded self-protection: never allow the agent to uninstall or
    // disable the security monitor plugin itself, regardless of policy config.
    let selfProtectionDecision: SecurityDecision | undefined;
    let selfProtectionBlocked = false;
    try {
      const { blocked, decision: spDecision } = SelfProtection.evaluate(interventionCtx);
      selfProtectionBlocked = blocked;
      if (blocked && spDecision) {
        console.warn(
          `[SecurityMonitorStore] self-protection blocked ${ctx.toolName}: ${spDecision.blockReason}`
        );
        selfProtectionDecision = spDecision;
      }
    } catch (err) {
      console.error('[SecurityMonitorStore] self-protection evaluation failed:', err);
    }

    // 1. Synchronous intervention decision (before collection to include it in the same event)
    let decision: SecurityDecision | undefined = selfProtectionDecision;
    if (!decision && this.interventionEngine) {
      try {
        decision = await this.interventionEngine.evaluate(interventionCtx);
      } catch (err) {
        console.error('[SecurityMonitorStore] intervention evaluation failed:', err);
      }
    }

    // tool_call 动作记入历史，chain 规则的 previousActions 才有真实数据源。
    this.actionHistory.record(ctx.sessionKey, { tool: 'agent_tool_call', params: interventionCtx.params });

    // 2. Collection: emit agent_tool_call event with intervention fields
    try {
      await this.applicationCollector.onBeforeToolCall(ctx, decision, this.config.intervention?.mode);
    } catch (err) {
      console.error('[SecurityMonitorStore] onBeforeToolCall failed:', err);
    }

    // 3. If enforce mode (or self-protection) and a decision exists, translate via OpenClawAdapter
    if (decision && (this.config.intervention?.mode === 'enforce' || selfProtectionBlocked)) {
      const hostCtx: HostAdapterContext = {
        framework: 'openclaw',
        agentId: ctx.agentId,
        sessionId: ctx.sessionKey,
        runId: ctx.runId,
        phase: 'beforeToolCall',
        auditMode: false,
      };
      const result = this.openClawAdapter.adapt(decision, interventionCtx, hostCtx);
      return result.native;
    }

    // Enter high-frequency burst scan mode while tools are executing, so the
    // system-layer monitors have a chance to observe short-lived child processes
    // and resource spikes.
    if (this.config.system?.enabled && (this.config.system.procfs?.enabled || this.config.system.cgroups?.enabled)) {
      try {
        this.systemCollector.enterBurstScan();
      } catch (err) {
        console.error('[SecurityMonitorStore] enterBurstScan failed:', err);
      }
    }

    // Bind the current Agent process tree to the OpenClaw context so the
    // system-layer monitor can tag spawned processes with session/run/agent/tool.
    if (this.config.system?.enabled && (this.config.system.procfs?.enabled || this.config.system.cgroups?.enabled)) {
      try {
        const effectiveAgentId = this.applicationCollector.resolveAgentId(ctx.agentId, ctx.sessionKey);
        this.systemCollector.bindProcessContext({
          rootPid: process.pid,
          sessionId: ctx.sessionKey,
          runId: ctx.runId,
          agentId: effectiveAgentId,
          toolName: ctx.toolName,
          toolCallId: this.applicationCollector.getCurrentToolCallId(),
        });
      } catch (err) {
        console.error('[SecurityMonitorStore] bindProcessContext failed:', err);
      }
    }

    // 4. In audit mode, record but never block — unless self-protection fired,
    //    in which case we always block regardless of configured mode. Burst scan
    //    and process binding above still run so audit-mode tool calls are
    //    observed and attributed by the system layer.
    if (this.config.intervention?.mode === 'audit' && !selfProtectionBlocked) {
      return { block: false };
    }

    return { block: false };
  }

  async afterToolCall(ctx: MiddlewareContext, result: unknown): Promise<void> {
    if (!this.enabled || !this.config.application?.enabled) {
      return;
    }

    // agent_tool_result 评估入口。工具结果回灌干预引擎——
    // tool_result 是指示注入（"忽略先前指令"类内容）进入对话的主通道，
    // 此前策略引擎无任何入口可命中 agent_tool_result 类规则。语义与
    // evaluateRuntimeEvent 一致：事后评估（工具已执行），决策只写入事件
    // intervention 标注、不拦截；block 决策同样只留痕（宿主 after_tool_call
    // 链路此处不做结果改写）。评估在事件采集前完成，标注随同一事件落盘。
    let resultDecision: SecurityDecision | undefined;
    if (this.interventionEngine) {
      try {
        const decision = await this.interventionEngine.evaluate(
          this.buildToolResultInterventionContext(ctx, result)
        );
        if (decision && decision.decision !== 'allow') {
          resultDecision = decision;
        }
      } catch (err) {
        console.error('[SecurityMonitorStore] tool result intervention evaluation failed:', err);
      }
    }

    try {
      await this.applicationCollector.onAfterToolCall(ctx, result, resultDecision);
    } catch (err) {
      console.error('[SecurityMonitorStore] afterToolCall failed:', err);
    }

    // Leave high-frequency burst scan mode once the tool call has completed.
    if (this.config.system?.enabled && (this.config.system.procfs?.enabled || this.config.system.cgroups?.enabled)) {
      try {
        this.systemCollector.exitBurstScan();
      } catch (err) {
        console.error('[SecurityMonitorStore] exitBurstScan failed:', err);
      }
    }
  }

  private buildMessageInterventionContext(ctx: MessageWriteContext): InterventionContext {
    let content = typeof ctx.content === 'string' ? ctx.content : JSON.stringify(ctx.content ?? '');
    // Backfill: OpenClaw sometimes passes an empty ctx.content to
    // beforeMessageWrite; fall back to the last cached user message for the
    // session so bodyRegex rules can still match.
    if (!content && ctx.role === 'user') {
      const cached = this.applicationCollector.getLastUserMessage(ctx.sessionKey);
      if (cached) content = cached;
    }
    return {
      actionType: 'agent_message',
      toolName: 'user_message',
      body: content,
      userPrompt: content,
      riskFlags: this.recentRiskFlags(ctx.sessionKey),
      sessionId: ctx.sessionKey,
      runId: ctx.runId,
      previousActions: this.actionHistory.recent(ctx.sessionKey),
    };
  }

  private buildInterventionContext(ctx: MiddlewareContext): InterventionContext {
    const params = this.normalizeFilePathParams(ctx.params || {});
    return {
      actionType: 'agent_tool_call',
      toolName: ctx.toolName,
      params,
      riskFlags: this.recentRiskFlags(ctx.sessionKey),
      sessionId: ctx.sessionKey,
      runId: ctx.runId,
      agentId: ctx.agentId,
      previousActions: this.actionHistory.recent(ctx.sessionKey),
    };
  }

  /**
   * agent_tool_result 评估上下文：body 承载工具结果文本
   * （注入检测规则的匹配面），非字符串结果 JSON 序列化后截断——结果体
   * 可能极大（构建产物/日志），评估侧只需要前缀即可命中注入话术模式。
   */
  private buildToolResultInterventionContext(ctx: MiddlewareContext, result: unknown): InterventionContext {
    const TOOL_RESULT_BODY_MAX = 8192;
    let body: string | undefined;
    if (typeof result === 'string') {
      body = result;
    } else if (result !== undefined && result !== null) {
      try {
        body = JSON.stringify(result);
      } catch {
        body = String(result);
      }
    }
    if (body !== undefined && body.length > TOOL_RESULT_BODY_MAX) {
      body = body.slice(0, TOOL_RESULT_BODY_MAX);
    }
    return {
      actionType: 'agent_tool_result',
      toolName: ctx.toolName,
      body,
      riskFlags: this.recentRiskFlags(ctx.sessionKey),
      sessionId: ctx.sessionKey,
      runId: ctx.runId,
      agentId: ctx.agentId,
      previousActions: this.actionHistory.recent(ctx.sessionKey),
    };
  }

  /** 同会话最近的 runtime 风险标签；无记录时返回 undefined。 */
  private recentRiskFlags(sessionKey: string | undefined): string[] | undefined {
    const flags = sessionKey ? this.sessionRiskFlags.get(sessionKey) : undefined;
    return flags && flags.length > 0 ? flags : undefined;
  }

  private normalizeFilePathParams(
    params: Record<string, unknown>
  ): Record<string, unknown> {
    // OpenClaw native file tools (read/write/delete) use `file_path`, while
    // generic file tools often use `path`. Several agents and wrappers rename
    // the same field to camelCase (`filePath`) or compact lowercase (`filepath`).
    // Normalize all of them so policy rules can match without duplicating
    // every path-based rule.
    const result = { ...params };
    const pathAliases = [
      'file_path', 'filepath', 'filePath',
      'path', 'file',
      'src', 'source', 'target', 'destination',
    ];
    const existingKey = pathAliases.find((k) => typeof result[k] === 'string');
    if (!existingKey) {
      return result;
    }
    for (const alias of pathAliases) {
      if (result[alias] === undefined) {
        result[alias] = result[existingKey];
      }
    }
    return result;
  }

  // ---------------------------------------------------------------------------
  // Self-protection self-check (engine degraded + protected file integrity)
  // ---------------------------------------------------------------------------

  private startSelfProtectionSelfCheck(): void {
    if (this.selfCheckTimer) {
      clearInterval(this.selfCheckTimer);
      this.selfCheckTimer = undefined;
    }
    // 每 60 秒自检一次；自检只产生留痕事件，不阻断——低侵入。
    this.selfCheckTimer = setInterval(() => {
      this.runSelfProtectionSelfCheck().catch((err) => {
        console.error('[SecurityMonitorStore] self-protection self-check failed:', err);
      });
    }, 60_000);
    this.fileBaselines.clear();
    this.sessionRiskFlags.clear();
  }

  private async runSelfProtectionSelfCheck(): Promise<void> {
    // 1) 干预引擎空载（G6 检测侧）：enabled 但 0 条规则 → protection_degraded
    if (this.interventionEngine && this.config.intervention?.enabled) {
      const stats = this.interventionEngine.getStats();
      if (stats.rulesLoaded === 0) {
        await this.emitSelfProtectionEvent('protection_degraded', {
          detail: 'intervention engine enabled but 0 rules loaded',
          rulesLoaded: 0,
        });
      }
      // 引导预算状态按 stateTtlMs 过期（GuidanceEngine.cleanup 此前无调用方，
      // 挂现有自检节奏周期驱动，不新增定时器基础设施）。
      this.interventionEngine.cleanupGuidanceStates();
    }

    // 2) 关键文件被删/截断（G7 检测侧）：事件文件 / 策略文件 / 凭据文件
    for (const filePath of this.getSelfProtectionTrackedFiles()) {
      let size = -1;
      try {
        const st = await stat(filePath);
        size = st.size;
      } catch {
        size = -1; // 不存在
      }
      const prev = this.fileBaselines.get(filePath);
      if (prev !== undefined && prev > 0 && size === -1) {
        await this.emitSelfProtectionEvent('tamper_detected', {
          detail: 'protected file deleted',
          file: filePath,
          previousSize: prev,
        });
      } else if (prev !== undefined && prev > 0 && size === 0) {
        await this.emitSelfProtectionEvent('tamper_detected', {
          detail: 'protected file truncated to 0 bytes',
          file: filePath,
          previousSize: prev,
        });
      }
      this.fileBaselines.set(filePath, size);
    }
  }

  private getSelfProtectionTrackedFiles(): string[] {
    const paths: string[] = [];
    if (this.config.collector?.ndjsonPath) paths.push(this.config.collector.ndjsonPath);
    if (this.config.intervention?.policyPath) paths.push(this.config.intervention.policyPath);
    return paths;
  }

  /**
   * 记录 bootstrap 的 runtime hook 探测状态。同步调用（register
   * 路径上 collector 尚未就绪），事件留痕由
   * emitRuntimeHookProbeWarningIfNeeded() 在 initialize() 完成后补写。
   */
  setRuntimeHookProbeState(loaded: boolean, userEnabled: boolean): void {
    this.runtimeHookProbeLoaded = loaded;
    this.runtimeHooksUserEnabled = userEnabled;
  }

  /**
   * bootstrap 探测失败（runtimeHookLoaded===false）且用户
   * 未主动关闭 runtimeHooks 时，向事件流写一条 WARN 级安全事件
   * （risk_flag=unpatched_engine，"引擎防护组件未生效"）。每次启动至多一条，
   * 不去重。用户主动 application.runtimeHooks.enabled=false → 不告警。
   */
  async emitRuntimeHookProbeWarningIfNeeded(): Promise<void> {
    if (this.runtimeHookProbeLoaded !== false || this.runtimeHooksUserEnabled !== true) {
      return;
    }
    await this.emitSelfProtectionEvent('runtime_hook_unloaded', {
      severity: 'warn',
      risk_flags: ['unpatched_engine'],
      detail:
        'runtime hook probe failed: NODE_OPTIONS did not preload the bundled runtime hook — ' +
        'runtime process/network coverage is NOT active although application.runtimeHooks.enabled was requested',
    });
  }

  private async emitSelfProtectionEvent(
    eventType: 'protection_degraded' | 'tamper_detected' | 'runtime_hook_unloaded' | PolicyAuditEvent['eventType'],
    detail: Record<string, unknown>
  ): Promise<void> {
    const env = this.config.environment || {};
    const event = {
      comm: 'openclaw',
      event_id: generateUUID(),
      event_type: eventType,
      layer: 'application',
      ts: Date.now(),
      schema_version: '1.0.0',
      pid: process.pid,
      session_id: null,
      run_id: null,
      task_id: null,
      turn_id: null,
      agent_id: null,
      host_id: env.hostId,
      container_id: env.containerId,
      pod_name: env.podName,
      namespace: env.namespace,
      source: 'openclaw.v1',
      collection_method: 'agent_api',
      collector: {
        hook_name: eventType,
        middleware_name: 'sst-security-control-openclaw',
        collector_name: this.name,
      },
      ...detail,
    } as SecurityEvent;
    await this.collector.report(event);
    // 自保护事件高优先级：立即触发 flush，不等定时器（降级方案，不改队列结构）。
    await this.collector.flush().catch(() => {});
  }

  /** 策略引擎审计事件（policy_missing / policy_empty / rule_invalid_regex 等）留痕。 */
  private async emitPolicyAuditEvent(auditEvent: PolicyAuditEvent): Promise<void> {
    await this.emitSelfProtectionEvent(auditEvent.eventType, {
      detail: auditEvent.detail,
      rule_id: auditEvent.ruleId,
      pattern: auditEvent.pattern,
      policy_audit_ts: auditEvent.ts,
    });
  }

  getStatus(): { enabled: boolean; runtimeHookLoaded: boolean | null; runtimeHooksEnabled: boolean | null; stats: Record<string, unknown> } {
    return {
      enabled: this.enabled,
      // 面板持久状态条数据源。runtimeHookLoaded 是 bootstrap 探测
      // 结果（null = 未上报）；runtimeHooksEnabled 是用户原始配置意图
      // （bootstrap 强制降级前的值），用于区分"静默失效"与"用户主动关闭"。
      runtimeHookLoaded: this.runtimeHookProbeLoaded ?? null,
      runtimeHooksEnabled: this.runtimeHooksUserEnabled ?? this.config.application?.runtimeHooks?.enabled ?? null,
      stats: {
        collector: this.collector.getStats(),
        application: this.applicationCollector.getStats?.(),
        network: this.networkCollector.getStats?.(),
        system: this.systemCollector.getStats?.(),
        runtimeHook: this.runtimeHookCollector.getStats?.(),
        assetMonitor: this.assetCollector.getStats?.(),
        intervention: this.interventionEngine?.getStats?.(),
        config: {
          application: this.config.application?.enabled,
          network: this.config.network?.enabled,
          system: this.config.system?.enabled,
          assetMonitor: this.config.assetMonitor?.enabled,
          intervention: this.config.intervention?.enabled,
          interventionMode: this.config.intervention?.mode,
        },
      },
    };
  }

  /**
   * Evaluate an InterventionContext synchronously through the running engine.
   * Exposed for OpenClaw 2026.9.4 RPC methods (api.registerGatewayMethod
   * 'security.evaluate'). The caller decides whether to invoke the engine
   * from a synchronous hook handler — this method just delegates.
   */
  async evaluateIntervention(ctx: Parameters<InterventionEngineImpl['evaluate']>[0]): ReturnType<InterventionEngineImpl['evaluate']> {
    if (!this.interventionEngine) {
      return {
        decision: 'allow',
        policyId: undefined,
        policyName: undefined,
        policyVersion: undefined,
        blockReason: 'intervention engine disabled',
        blockCode: undefined,
        reason: undefined,
        priority: 0,
        riskLevel: undefined,
        riskSignal: undefined,
        appealable: false,
        modifiedParams: undefined,
        substitutedToolName: undefined,
        guidance: undefined,
        degradeMode: undefined,
        removedTools: undefined,
        latencyMs: 0,
        failStrategy: this.config.intervention?.failStrategy,
      } as SecurityDecision;
    }
    return this.interventionEngine.evaluate(ctx);
  }

  getCollectorNdjsonPath(): string | undefined {
    return this.config.collector?.ndjsonPath;
  }

  /** Control UI: read-only NDJSON query layer. */
  getControlUiService(): ControlUiService {
    return new ControlUiService(
      this.config.collector?.ndjsonPath,
      this.config.collector?.maxEventsInMemory,
    );
  }

  async shutdown(): Promise<void> {
    if (this.selfCheckTimer) {
      clearInterval(this.selfCheckTimer);
      this.selfCheckTimer = undefined;
    }
    this.sessionRiskFlags.clear();
    await Promise.allSettled([
      this.applicationCollector.shutdown(),
      this.systemCollector.shutdown(),
      this.runtimeHookCollector.shutdown(),
      this.assetCollector.shutdown(),
      this.networkCollector.shutdown(),
      this.interventionEngine?.shutdown(),
      this.collector.shutdown(),
    ]);
  }
}
