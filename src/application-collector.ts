import type {
  SecurityEvent,
  MiddlewareContext,
  AgentStartContext,
  AgentCompleteContext,
  MessageWriteContext,
  SessionEndContext,
  SubagentContext,
  CronEventContext,
  SessionContext,
  ApplicationLayerConfig,
  AgentConfig,
  ILayerCollector,
  EnvironmentConfig,
  EventType,
} from "./types.js";
import type { SecurityDecision } from './intervention/types.js';
// Inline interface for event reporting.
interface EventCollectorLike {
  report(event: SecurityEvent): Promise<void>;
}
// Inline type for agent snapshot registration (kept for constructor stability).
interface AgentSnapshotReporterLike {
  registerAgent(input: unknown): void | Promise<void>;
}
import { inferAgentIdFromSessionKey, inferAgentNameFromAgentDir } from './ctxExtract.js';
import { safeExtract, safeExtractArray } from './safe-extract.js';
import { truncateString, computeContentLength } from './truncate.js';
import { sha256Hex, stableStringify } from './asset-hash.js';
import { deriveSessionTitle } from './session-title.js';
import { redactSensitiveBody, redactSensitiveBodyWithKeys, redactEventForEmit } from './redact.js';
import { generateUUID } from './uuid.js';
import { PromptSidecar } from './prompt-sidecar.js';
import { pidBindingStore } from './utils/pid-binding-store.js';
import { canonicalizePathParams } from './utils/path-params.js';
import { homedir } from 'os';
import path from 'path';
import { readFileSync } from 'fs';

interface SessionCacheEntry {
  context: SessionContext;
  lastAccessTime: number;
}

interface RecentUserMessage {
  sessionKey: string;
  content: string;
  timestamp: number;
}

interface RunIdAgentCacheEntry {
  agentId: string;
  lastAccessTime: number;
}

const AGENT_START_CORRELATION_WINDOW_MS = 2000;

export class ApplicationCollector implements ILayerCollector {
  readonly name = 'application-collector';
  private collector: EventCollectorLike;
  private config: ApplicationLayerConfig;
  private environment: EnvironmentConfig;
  private sessionCache: Map<string, SessionCacheEntry> = new Map();
  private callStartTimes: Map<string, number[]> = new Map();
  /**
   * 进行中的工具调用 id，按 (sessionKey, toolName) 分桶的 FIFO。
   *
   * 1.1.0 之前这里只有一个全局 `currentCallId` 槽位（"最近一次开始的
   * 调用"）。after hook 拿不到同一个 ctx 对象时（框架对 before/after 传
   * 不同对象）只能回退到那个槽位，于是并发的第二个调用会把第一个的
   * 结果事件据为己有——实测 code-mode 的 exec 结果被记到了 ls 名下，
   * 连带把 ls 的开始时间弹出删除，exec 的耗时整个丢失。
   *
   * 改为按 (session, 工具名) 分桶后，回退只在**同名工具**之间发生，
   * 跨工具串号不可能再出现。
   */
  private inFlightCallIds: Map<string, string[]> = new Map();
  /** 最近一次开始的调用 id，按 (sessionKey, toolName) 记。 */
  private currentCallIds: Map<string, string> = new Map();
  /**
   * (sessionKey, toolName) 桶里最近一次**真实发出过**的调用 id。
   *
   * 与 `currentCallIds` 的区别：后者在在飞队列排空时被删掉（表示"没有在
   * 飞的调用了"），这里留着最后一次真实 id。after hook 拿不到任何在飞
   * 调用时（框架给 before/after 传了不同 ctx、且队列已被别的 after 抽干）
   * 只能回退到它——**绝不按当前 step 索引重算**：重算出来的 id 与任何一次
   * 真实调用都对不上，写进审计流就是一条指向虚空的关联。
   */
  private lastCallIds: Map<string, Map<string, string>> = new Map();
  /**
   * 会话内的调用序号。
   *
   * 确定性 id 原来是 `session:run:tool:step`，step 索引只在工具调用**结束**
   * 时才推进，于是"同一 step 内的并发调用"与"嵌套调用"会拿到同一个 id
   * （实测 code-mode 的外层 exec 与内层 exec 同为 `…:exec:1`），决策缓存
   * 互相覆盖。补一个会话内单调递增的序号做区分位，id 就唯一了。
   */
  private callSeqBySession: Map<string, number> = new Map();
  /**
   * 在飞调用登记（按开始顺序）。
   *
   * 用来判定嵌套关系：code-mode exec 在飞期间跑出来的工具调用，外层
   * call id 记到 `parent_tool_call_id` 上。
   */
  private inFlightCalls: Array<{
    detKey: string;
    sessionKey?: string;
    toolKind: string;
    startedAt: number;
  }> = [];
  // Deterministic call correlation: keyed by session/run/tool/step so that
  // onAfterToolCall does not depend on the same context object reference.
  private callIdMap: WeakMap<MiddlewareContext, string> = new WeakMap();
  // Cache the per-call SecurityDecision so afterToolCall can stamp the result
  // event with the same blockCode/blockReason/guidance returned to the LLM.
  private decisionCache: Map<string, SecurityDecision> = new Map();
  // Track agent start timestamps by runId to compute duration on agent_stop
  private agentStartTimes: Map<string, number> = new Map();
  /**
   * 进行中的智能体运行（按 sessionKey）。
   *
   * 宿主在消息事件上**不带 role**（实测 6/6 条 agent_message 的 role 都是
   * 'unknown'），于是"这条消息是用户说的还是模型说的"只能靠会话生命周期
   * 推断：智能体运行期间产生的消息是模型输出，运行之外到达的是用户输入。
   *
   * 这里记的是"有没有在跑"，不记 runId——占位 agent_start 常常没有
   * runId，但运行确实开始了。
   */
  private activeAgentRuns: Set<string> = new Set();
  private cleanupTimer?: ReturnType<typeof setInterval>;
  // OpenClaw may fire agent_start after message_received and without a session id.
  // We keep a short history of user messages so agent_start can borrow the real
  // session_id instead of emitting "unknown".
  private recentUserMessages: Map<string, RecentUserMessage> = new Map();
  // Track sessions for which we have already emitted agent_session_start so we
  // only send one lifecycle event per user<->agent conversation.
  private reportedSessionStarts = new Set<string>();
  // Adjacent-duplicate suppression per session. Some OpenClaw builds redeliver
  // the same user message multiple times (guidance/context-adjustment loops on
  // synchronous hooks), and assistant content can arrive via both
  // message_sending and tool_result_persist. Identical role+content back to
  // back means a redelivery, not a genuine repeat — a user intentionally
  // resending must have an assistant reply in between, so adjacency is a safe
  // criterion.
  private lastMessageBySession: Map<string, { role: string; content: string }> = new Map();
  // Some events (e.g. agent_message) arrive with a run_id but no agent metadata.
  // When a tool result reveals the agent (e.g. via details.cwd), we cache the
  // mapping so the whole run can be attributed to that agent.
  private runIdAgentCache: Map<string, RunIdAgentCacheEntry> = new Map();
  // 会话标题：每个 session 一条，first-write-wins（首条有效 user 消息决定）。
  //
  // 刻意不放 SessionContext：getSessionContext() 在缓存没有该 session 时返回的是
  // 一次性默认对象，写进去即丢——而"首条 user 消息"恰恰是这个时机（会话还没被
  // 任何 hook 建立缓存条目）。独立的 Map 与 recentUserMessages / reportedSessionStarts
  // 同一模式。
  private sessionTitles: Map<string, { title: string; lastAccessTime: number }> = new Map();
  private agentSnapshotReporter?: AgentSnapshotReporterLike;

  constructor(
    collector: EventCollectorLike,
    config: ApplicationLayerConfig,
    environment: EnvironmentConfig = {},
    agentSnapshotReporter?: AgentSnapshotReporterLike,
    options?: {
      reportBlockedEvents?: boolean;
      /** 系统提示词全文的 sidecar 存储（内容寻址）。未注入时退化为只算 ref 不落 sidecar。 */
      promptSidecar?: PromptSidecar;
    }
  ) {
    this.collector = collector;
    this.config = config;
    this.environment = environment;
    this.agentSnapshotReporter = agentSnapshotReporter;
    // intervention.reportBlockedEvents（默认 true）：false 时 blocked 事件不落盘。
    this.reportBlockedEvents = options?.reportBlockedEvents !== false;
    this.promptSidecar = options?.promptSidecar;
  }

  private readonly reportBlockedEvents: boolean;
  private readonly promptSidecar?: PromptSidecar;

  async initialize(): Promise<void> {
    const ttlMs = this.config.sessionTtlMs ?? 30 * 60 * 1000;
    // Periodically clean up expired session cache entries
    this.cleanupTimer = setInterval(() => {
      this.cleanupExpiredSessions(ttlMs);
    }, Math.min(ttlMs, 60000));
  }

  async report(event: SecurityEvent): Promise<void> {
    await this.emit(event);
  }

  /**
   * Internal emit helper. Always runs `redactEventForEmit` so PII / credential
   * content (user_prompt, content, code_content, params) cannot
   * reach the NDJSON sink in plaintext. F-12 fix.
   */
  private async emit(event: SecurityEvent): Promise<void> {
    await this.collector.report(redactEventForEmit(event as unknown as Record<string, unknown>) as unknown as SecurityEvent);
  }

  /** reportBlockedEvents=false 时 blocked 事件不落盘（默认 true，行为不变）。 */
  private shouldEmitEvent(event: SecurityEvent): boolean {
    return !(event.blocked && !this.reportBlockedEvents);
  }

  async shutdown(): Promise<void> {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = undefined;
    }
    this.recentUserMessages.clear();
    this.sessionTitles.clear();
  }

  getStats(): Record<string, unknown> {
    return {
      sessionCacheSize: this.sessionCache.size,
      pendingCallTimers: this.callStartTimes.size,
      runIdAgentCacheSize: this.runIdAgentCache.size,
    };
  }

  /**
   * Extract the run id from a hook context. OpenClaw uses `runId` on middleware
   * and message contexts; some older hooks may use `run_id`.
   */
  private extractRunId(ctx: unknown): string | undefined {
    if (ctx === null || typeof ctx !== 'object') return undefined;
    const record = ctx as Record<string, unknown>;
    const runId = typeof record.runId === 'string' ? record.runId : undefined;
    const run_id = typeof record.run_id === 'string' ? record.run_id : undefined;
    return runId || run_id;
  }

  /**
   * 未知会话（undefined / 'unknown'）统一归一到空串桶键，与
   * getSessionContext / initializeSessionCache 的归一保持一致：未知会话
   * 的事件相互共享一个桶，但不会与真实会话串数据。
   */
  private skey(sessionKey: string | undefined): string {
    return !sessionKey || sessionKey === 'unknown' ? '' : sessionKey;
  }

  /**
   * Look up the most recent user message for a given session.
   * Used by middleware to backfill user message content when OpenClaw passes
   * an empty ctx.content to beforeMessageWrite.
   */
  getLastUserMessage(sessionKey: string | undefined): string | undefined {
    let best: RecentUserMessage | undefined;
    for (const entry of this.recentUserMessages.values()) {
      if (entry.sessionKey !== sessionKey) continue;
      if (!best || entry.timestamp > best.timestamp) {
        best = entry;
      }
    }
    return best?.content;
  }

  // 决策层附带的完整命中标注（含 enforce 短路点之前的 warn/modify
  // 等规则）→ 事件 intervention.matched_rules，供审计与面板只读展示。
  private mapMatchedRules(decision: SecurityDecision): NonNullable<SecurityEvent['intervention']>['matched_rules'] {
    return decision.matchedPolicies?.map((m) => ({
      policy_id: m.policyId,
      policy_name: m.policyName,
      decision: m.decision,
      priority: m.priority,
      risk_level: m.riskLevel,
      category: m.category,
    }));
  }

  // ---------------------------------------------------------------------------
  // Agent lifecycle
  // ---------------------------------------------------------------------------

  async onAgentStart(ctx: AgentStartContext, decision?: SecurityDecision, mode?: 'audit' | 'enforce'): Promise<void> {
    const agentConfig = ctx.agentConfig;
    const runId = this.extractRunId(ctx);
    this.initializeSessionCache(ctx.sessionKey, agentConfig, ctx.systemPrompt, ctx.agentId, runId);

    // 运行一开始就登记，不能等到 emitAgentStart：占位 agent_start（没有
    // agent 配置的那种）不会产出事件，但它同样意味着"智能体跑起来了"。
    // 少了这一步，运行期间到达的消息会被误判成用户输入。
    if (ctx.sessionKey && ctx.sessionKey !== 'unknown') {
      this.activeAgentRuns.add(ctx.sessionKey);
    }

    // OpenClaw sometimes emits a placeholder agent_start that carries only the
    // raw user prompt but no real agent metadata (name, model, tools, skills).
    // It is not a distinct agent invocation; skip it to avoid duplicate events.
    if (!this.hasMeaningfulAgentConfig(agentConfig)) {
      return;
    }

    // OpenClaw sometimes fires agent_start after message_received and without a
    // session id. Borrow the session_id from the matching recent user message so
    // the agent_start event can be correlated with the rest of the conversation.
    let effectiveCtx = ctx;
    if (!ctx.sessionKey || ctx.sessionKey === 'unknown') {
      const correlatedSession = this.correlateAgentStartSession(agentConfig);
      if (correlatedSession) {
        effectiveCtx = { ...ctx, sessionKey: correlatedSession };
        this.initializeSessionCache(
          correlatedSession,
          agentConfig,
          ctx.systemPrompt,
          ctx.agentId,
          runId
        );
      }
    }

    await this.emitAgentStart(effectiveCtx, decision, mode);
  }

  private async emitAgentStart(ctx: AgentStartContext, decision?: SecurityDecision, mode?: 'audit' | 'enforce'): Promise<void> {
    const agentConfig = ctx.agentConfig;
    const runId = this.extractRunId(ctx);
    if (runId) {
      this.agentStartTimes.set(runId, Date.now());
    }
    // 会话 id 可能是在这里才被补全的（agent_start 不带 session 时从最近
    // 的 user 消息借一个），补全后的 id 同样要登记成"运行中"。
    if (ctx.sessionKey && ctx.sessionKey !== 'unknown') {
      this.activeAgentRuns.add(ctx.sessionKey);
    }
    const agentId = this.resolveAgentId(ctx.agentId, ctx.sessionKey, runId);
    const resolvedAgentName = agentConfig?.name || agentId;
    const event = this.buildBaseEvent(
      'agent_start',
      ctx.sessionKey,
      undefined,
      agentId
    );

    event.agent_name = resolvedAgentName;

    // Self-contained per-agent record: identity + description + model + system
    // prompt fingerprint + resource topology all in one element so consumers can
    // render the agent card without joining agent_config / agent_resources.
    // The system prompt *text* lives once per session (first agent_message that
    // carries it); this record only points at it via system_prompt_ref.
    const skillNames = safeExtractArray(() => ctx.skills).map(String);
    const toolNames = safeExtractArray(() => ctx.tools).map(String);
    const mcpServers = this.collectAgentMcpServerNames(ctx.agentConfig);
    const tools = toolNames.map((name) => ({ name, kind: 'native' as const }));
    const systemPrompt = this.config.captureSystemPrompt
      ? safeExtract(() => ctx.systemPrompt)
      : undefined;

    const agentRecord: Record<string, unknown> = {
      id: agentId ?? null,
      name: resolvedAgentName,
      // description / agent_dir / config are nullable: OpenClaw does not
      // guarantee these on the before_agent_start hook, so we emit the key
      // only when we actually have a value. JSON.stringify drops undefined,
      // so absent keys and undefined values produce identical payloads.
      description: safeExtract(() => agentConfig?.description),
      model_provider: safeExtract(
        () => agentConfig?.model?.provider ?? agentConfig?.provider
      ),
      model_name: safeExtract(() => agentConfig?.model?.name),
      // 只落指纹，不落全文。事件流里 system_prompt 全文已彻底移除（内容
      // 寻址，全文唯一一份在 security-prompts.jsonl）；这里的 ref 与
      // 会话内其他事件的 system_prompt_ref 同源同值。
      system_prompt_ref: systemPrompt ? sha256Hex(systemPrompt).slice(0, 16) : undefined,
      // agent_dir comes from ctx.agentDir (lifted into agentConfig.agentDir by
      // normalizeAgentStartContext). config path remains unset — ctx does not
      // expose it; authoritative paths flow through asset_* channel.
      agent_dir: safeExtract(() => agentConfig?.agentDir),
      // Always emit as arrays (even empty) so consumers can distinguish
      // "agent has no skills/mcp/tools" from "field was omitted". The shape
      // is then stable across agents regardless of which resources they load.
      skills: skillNames,
      mcp_servers: mcpServers,
      tools,
    };
    event.agents = [agentRecord];

    // 向清单上报器注册该智能体，供 periodic agent-snapshot 使用。
    const sourceAgentId = typeof agentRecord.id === 'string' && agentRecord.id.length > 0
      ? agentRecord.id
      : String(agentRecord.name || 'unknown');
    this.agentSnapshotReporter?.registerAgent({
      source_agent_id: sourceAgentId,
      name: String(agentRecord.name || sourceAgentId),
      agent_type: String(agentRecord.model_provider || 'unknown'),
      version: null,
      metadata: { lifecycle: 'running' },
    });

    if (decision) {
      event.blocked = decision.decision === 'block' && mode !== 'audit';
      event.intervention = {
        decision: decision.decision,
        policy_id: decision.policyId,
        policy_name: decision.policyName,
        block_code: decision.blockCode,
        block_reason: decision.blockReason,
        appealable: decision.appealable,
        remediation_hint: decision.remediationHint,
        matched_rules: this.mapMatchedRules(decision),
        guidance: decision.guidance
          ? {
              adjustment_id: decision.guidance.adjustmentId,
              rendered: decision.guidance.rendered,
              allowed_scope: decision.guidance.allowedScope,
              alternatives: decision.guidance.alternatives,
            }
          : undefined,
        mode: mode || 'audit',
        priority: decision.priority,
        risk_level: decision.riskLevel,
      };
    }

    if (this.shouldEmitEvent(event)) {
      await this.emit(event);
    }
  }

  private correlateAgentStartSession(config?: AgentConfig): string | undefined {
    const now = Date.now();
    this.cleanupRecentUserMessages(now);

    // First try an exact match against the prompt embedded in agent_config.
    const prompt = this.extractUserPromptFromAgentConfig(config);
    if (prompt) {
      const exact = this.recentUserMessages.get(prompt);
      if (exact && now - exact.timestamp <= AGENT_START_CORRELATION_WINDOW_MS) {
        this.recentUserMessages.delete(prompt);
        return exact.sessionKey;
      }
    }

    // Fallback: use the most recent user message within the correlation window.
    let best: RecentUserMessage | undefined;
    for (const entry of this.recentUserMessages.values()) {
      if (now - entry.timestamp > AGENT_START_CORRELATION_WINDOW_MS) continue;
      if (!best || entry.timestamp > best.timestamp) {
        best = entry;
      }
    }
    return best?.sessionKey;
  }

  private extractUserPromptFromAgentConfig(config?: AgentConfig): string | undefined {
    const rawShape = (config as Record<string, unknown> | undefined)?._raw_shape as
      | Record<string, unknown>
      | undefined;
    const prompt = rawShape?.prompt;
    if (typeof prompt !== 'string') return undefined;

    // OpenClaw wraps the real user content in metadata:
    //   Sender (untrusted metadata):
    //   ```json
    //   {...}
    //   ```
    //
    //   [Tue 2026-07-07 14:06 GMT+8] <actual user message>
    // Extract everything after the last ']' or, failing that, the last line.
    const idx = prompt.lastIndexOf(']');
    if (idx >= 0) {
      const after = prompt.slice(idx + 1).trim();
      if (after.length > 0) return after;
    }
    const lastLine = prompt.split('\n').pop()?.trim();
    return lastLine && lastLine.length > 0 ? lastLine : undefined;
  }

  private cleanupRecentUserMessages(now: number): void {
    for (const [key, entry] of this.recentUserMessages.entries()) {
      if (now - entry.timestamp > AGENT_START_CORRELATION_WINDOW_MS) {
        this.recentUserMessages.delete(key);
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Message handling
  // ---------------------------------------------------------------------------

  /**
   * 会话生命周期事件：每个会话至多一条。
   *
   * 门控是"**这个会话的第一条事件**"，不是"第一条 user 消息"。
   *
   * 以前 gate 在 `role === 'user'` 上，而宿主在消息事件上常常不带 role，
   * 角色只能靠生命周期推断——推断成 'assistant' 的首条消息就把会话开始
   * 事件整个吞掉了。实测采样里 agent_session_start 是 0 条：会话什么时候
   * 开始的、下游根本无从得知。
   */
  private async emitAgentSessionStartIfNeeded(
    ctx: {
      sessionKey: string | undefined;
      runId?: string;
      modelProvider?: string;
      modelName?: string;
    },
    agentId: string | undefined,
    sessionCtx: SessionContext
  ): Promise<void> {
    if (!ctx.sessionKey || ctx.sessionKey === 'unknown') {
      return;
    }
    if (this.reportedSessionStarts.has(ctx.sessionKey)) {
      return;
    }
    this.reportedSessionStarts.add(ctx.sessionKey);

    const event = this.buildBaseEvent(
      'agent_session_start',
      ctx.sessionKey,
      ctx.runId,
      agentId
    );
    event.model_provider = ctx.modelProvider || sessionCtx.agentConfig?.model?.provider || 'unknown';
    event.model_name = ctx.modelName || sessionCtx.agentConfig?.model?.name || 'unknown';
    this.attachSystemPrompt(event, sessionCtx);

    await this.emit(event);
  }

  /**
   * 会话开始。
   *
   * 宿主把 session_start 也走消息通道，之前它会变成一条 content="" 的
   * agent_message（噪声行），真正的会话生命周期事件反而不落盘。现在
   * 直接落 agent_session_start，与"首条 user 消息"触发的路径共用同一个
   * 幂等发射器（每个会话只出一条）。
   */
  async onSessionStart(ctx: MessageWriteContext): Promise<void> {
    if (!ctx.sessionKey || ctx.sessionKey === 'unknown') {
      return;
    }
    const sessionCtx = this.getSessionContext(ctx.sessionKey);
    const agentId = this.resolveAgentId(sessionCtx.agentId, ctx.sessionKey, ctx.runId);
    await this.emitAgentSessionStartIfNeeded(ctx, agentId, sessionCtx);
  }

  /**
   * 记录该 session 的会话标题。first-write-wins：首条"有效" user 消息决定标题，
   * 之后不再改写——空白消息与纯斜杠命令（/new、/clear）不算有效消息，会继续等
   * 下一条，避免把标题永久钉死在命令上。
   *
   * 标题是 user prompt 的派生物，所以与 captureUserPrompt 共用一个闸门：用户关了
   * prompt 采集，就不该再从 prompt 里派生内容落盘。
   */
  private latchSessionTitle(sessionKey: string | undefined, content: string): void {
    if (!sessionKey || sessionKey === 'unknown') return;
    if (this.sessionTitles.has(sessionKey)) return;
    if (!(this.config.captureUserPrompt ?? true)) return;
    const title = deriveSessionTitle(content);
    if (!title) return;
    this.sessionTitles.set(sessionKey, { title, lastAccessTime: Date.now() });
  }

  /**
   * 角色兜底推断。
   *
   * 宿主在消息事件上通常不带 role，ctxExtract 只能把角色解析成 'unknown'。
   * 这时按会话生命周期推断：智能体运行期间的消息是模型输出，运行之外
   * 到达的是用户输入。
   *
   * 推断出来的角色标为 'lifecycle'，落盘时写进 `role_source`，下游能分
   * 辨"这是事实"和"这是我们推的"。
   *
   * 规范（agent.json）role 枚举只有 user / assistant / system。宿主给的
   * 枚举外取值（如 tool / tool_result / 任意字符串）不能原样落盘——schema
   * 收紧后那是非法值；这里把它们当成"没拿到"，走同一套生命周期推断
   * （修写入端，而不是放宽枚举）。
   */
  private inferMessageRole(ctx: MessageWriteContext): { role: 'user' | 'assistant' | 'system'; source: string } {
    if (
      ctx.role &&
      ctx.role !== 'unknown' &&
      (ctx.role === 'user' || ctx.role === 'assistant' || ctx.role === 'system')
    ) {
      return { role: ctx.role, source: ctx.roleSource ?? 'explicit' };
    }
    const isAgentRunning = ctx.sessionKey ? this.activeAgentRuns.has(ctx.sessionKey) : false;
    return { role: isAgentRunning ? 'assistant' : 'user', source: 'lifecycle' };
  }

  /**
   * 对外暴露的角色解析入口。
   *
   * 策略评估（policy engine + 自保护兜底）gate 在 `role === 'user'` 上，
   * 而宿主在消息事件上不带 role——不先解析角色，消息级评估就整条不生效
   * （实测 6/6 条 agent_message 的 role 都是 'unknown'）。store 在评估
   * 之前调用本方法，拿到解析后的上下文。
   */
  resolveMessageRole(ctx: MessageWriteContext): MessageWriteContext {
    const inferred = this.inferMessageRole(ctx);
    if (inferred.role === ctx.role && inferred.source === ctx.roleSource) {
      return ctx;
    }
    return { ...ctx, role: inferred.role, roleSource: inferred.source };
  }

  async onMessageWrite(ctx: MessageWriteContext, decision?: SecurityDecision, mode?: 'audit' | 'enforce'): Promise<void> {
    // 角色先定下来：后面所有分支（去重、丢弃、用户 prompt 缓存、事件
    // 字段）都依赖它。
    const inferred = this.inferMessageRole(ctx);
    const role = inferred.role;
    const roleSource = inferred.source;

    // OpenClaw may fire both a plain message_received hook and a
    // before_prompt_build hook for the same user input. The latter wraps the
    // real input in metadata (timestamp etc.). After normalization the text
    // matches the earlier event, so skip the duplicate to avoid double logging.
    if (
      role === 'user' &&
      typeof ctx.content === 'string' &&
      ctx.content.length > 0 &&
      ctx.content === this.getSessionContext(ctx.sessionKey).userPrompt
    ) {
      return;
    }

    // 空消息一律丢弃，除非它带着推理内容（要采）或者带着一个非 allow 的
    // 决策（要留痕）。
    //
    // 之前这条规则只对 role==='assistant' 生效，而宿主恰恰不带 role，
    // 于是规则整条失效——实测采样里 5 条 content="" 的 agent_message
    // 就是这么漏下来的。现在按"有没有信息"判断，与角色无关。
    const hasContent = !(
      !ctx.content ||
      (typeof ctx.content === 'string' && ctx.content.trim().length === 0)
    );
    const hasDecision = decision !== undefined && decision.decision !== 'allow';
    if (!hasContent && !ctx.reasoning && !hasDecision) {
      return;
    }

    // Drop OpenClaw noise: lifecycle events (e.g. /new, session resume) get
    // routed through message_received with default user role and empty content,
    // and we also lack session metadata. Nothing actionable to record.
    if (
      role === 'user' &&
      (!ctx.sessionKey || ctx.sessionKey === 'unknown') &&
      (!hasContent)
    ) {
      return;
    }

    // Adjacent-duplicate suppression: same role+content as the last message we
    // already reported for this session means the upstream redelivered it
    // (synchronous-hook guidance loops, dual persist paths). See the field
    // comment above for why adjacency is the safe criterion.
    const normalizedContent = typeof ctx.content === 'string' ? ctx.content : '';
    const last = this.lastMessageBySession.get(this.skey(ctx.sessionKey));
    if (
      last &&
      last.role === role &&
      last.content.length > 0 &&
      last.content === normalizedContent
    ) {
      return;
    }

    // 标题必须早于任何事件构造落定：latch 之后，agent_session_start 与第一条
    // agent_message（就是这条 user 消息本身）才都带得上标题。
    if (role === 'user' && typeof ctx.content === 'string' && ctx.content.length > 0) {
      this.latchSessionTitle(ctx.sessionKey, ctx.content);
    }

    // 会话生命周期事件：这条消息是该会话的第一条事件时落一条
    // agent_session_start（幂等，每会话一条）。门控不再是"第一条 user
    // 消息"——角色常常推断不出来，等 user 消息等于永远等不到。
    await this.emitAgentSessionStartIfNeeded(
      ctx,
      this.resolveAgentId(undefined, ctx.sessionKey, ctx.runId),
      this.getSessionContext(ctx.sessionKey)
    );

    // Cache recent user messages so a later agent_start (which may lack a
    // session_id) can borrow the correct session_id for correlation.
    if (role === 'user' && typeof ctx.content === 'string' && ctx.content.length > 0) {
      this.recentUserMessages.set(ctx.content, {
        sessionKey: this.skey(ctx.sessionKey),
        content: ctx.content,
        timestamp: Date.now(),
      });
      this.cleanupRecentUserMessages(Date.now());
    }

    const sessionCtx = this.updateSessionFromMessage(ctx, role);
    const messageAgentId = this.resolveAgentId(sessionCtx.agentId, ctx.sessionKey, ctx.runId);

    const event = this.buildBaseEvent(
      'agent_message',
      ctx.sessionKey,
      ctx.runId,
      messageAgentId
    );

    event.role = role;
    // 角色来源一并落盘：下游据此区分"宿主明说的"和"我们推断的"。
    event.role_source = roleSource;
    // Backfill user message content from cache when OpenClaw passes empty content.
    const effectiveContent =
      (role === 'user' &&
        typeof ctx.content === 'string' &&
        ctx.content.length === 0 &&
        this.getLastUserMessage(ctx.sessionKey)) ||
      ctx.content;
    // user-role content IS the user prompt; honor captureUserPrompt the same
    // way tool_call.user_prompt does.
    const captureUserPrompt = this.config.captureUserPrompt ?? true;
    event.content =
      role === 'user' && !captureUserPrompt
        ? undefined
        : truncateString(effectiveContent, this.config.maxContentLength ?? 2000);
    event.content_length = computeContentLength(effectiveContent);
    event.reasoning =
      (this.config.captureReasoning ?? true)
        ? truncateString(ctx.reasoning, this.config.maxContentLength ?? 2000) || undefined
        : undefined;
    event.reasoning_length =
      (this.config.captureReasoning ?? true) && ctx.reasoning ? ctx.reasoning.length : undefined;
    event.message_id = ctx.messageId || undefined;
    event.parent_message_id = ctx.parentMessageId || undefined;
    // 序号 = 下一条落盘消息的序号：占号发生在确认落盘之后（见下方 emit
    // 处），被丢弃的消息（reportBlockedEvents=false 的 blocked 消息）不占
    // 号，下游看到的 message_index 严格连续、无跳号无空占。
    event.message_index = sessionCtx.messageIndex + 1;
    event.user_id = (this.config.captureUserId ?? true) ? sessionCtx.userId || undefined : undefined;
    this.attachSystemPrompt(event, sessionCtx);
    event.model_provider = ctx.modelProvider || undefined;
    event.model_name = ctx.modelName || undefined;
    event.agent_name = this.resolveAgentName(ctx.sessionKey);
    event.token_usage_prompt = ctx.tokenUsagePrompt;
    event.token_usage_completion = ctx.tokenUsageCompletion;
    event.token_usage_total = ctx.tokenUsageTotal;

    if (decision) {
      event.blocked = decision.decision === 'block' && mode !== 'audit';
      event.intervention = {
        decision: decision.decision,
        policy_id: decision.policyId,
        policy_name: decision.policyName,
        block_code: decision.blockCode,
        block_reason: decision.blockReason,
        appealable: decision.appealable,
        remediation_hint: decision.remediationHint,
        matched_rules: this.mapMatchedRules(decision),
        guidance: decision.guidance
          ? {
              adjustment_id: decision.guidance.adjustmentId,
              rendered: decision.guidance.rendered,
              allowed_scope: decision.guidance.allowedScope,
              alternatives: decision.guidance.alternatives,
            }
          : undefined,
        mode: mode || 'audit',
        priority: decision.priority,
        risk_level: decision.riskLevel,
      };
    }

    if (this.shouldEmitEvent(event)) {
      await this.emit(event);
      // 事件真的落盘了才占号并写回缓存：这条消息是本会话第
      // messageIndex 条落盘消息，下一条用 +1。
      sessionCtx.messageIndex += 1;
      this.sessionCache.set(this.skey(ctx.sessionKey), {
        context: sessionCtx,
        lastAccessTime: Date.now(),
      });
    }

    // Remember what we actually reported so the next message can be compared
    // for adjacency. Only track messages with non-empty content; empty ones
    // were already filtered above.
    if (normalizedContent.length > 0) {
      this.lastMessageBySession.set(this.skey(ctx.sessionKey), { role, content: normalizedContent });
    }
  }

  private classifyToolEventType(toolName?: string, toolKind?: string): EventType {
    if (toolKind === 'code_mode_exec') {
      return 'code_mode_exec';
    }
    if (!toolName) {
      return 'agent_tool_call';
    }
    const normalized = toolName.toLowerCase();
    const readTools = new Set([
      'read', 'file_read', 'fileread', 'fs.readfile', 'fs.readfilesync', 'readfile', 'readfilesync',
    ]);
    const writeTools = new Set([
      'write', 'file_write', 'filewrite', 'fs.writefile', 'fs.writefilesync', 'writefile', 'writefilesync',
      'edit', 'file_edit', 'fileedit', 'fs.appendfile', 'fs.appendfilesync', 'appendfile', 'appendfilesync',
    ]);
    const deleteTools = new Set([
      'delete', 'file_delete', 'filedelete', 'del', 'remove', 'fs.unlink', 'fs.unlinksync', 'unlink', 'rmdir', 'fs.rmdir', 'fs.rmdirsyn',
    ]);
    const privilegeTools = new Set([
      'chmod', 'chown', 'fs.chmod', 'fs.chmodsync', 'fs.chown', 'fs.chownsync', 'chmodsync', 'chownsync',
      'setpermission', 'setpermissions', 'changepermission', 'changepermissions',
    ]);

    if (readTools.has(normalized)) return 'file_read';
    if (writeTools.has(normalized)) return 'file_write';
    if (deleteTools.has(normalized)) return 'file_delete';
    if (privilegeTools.has(normalized)) return 'file_privilege';

    return 'agent_tool_call';
  }

  // ---------------------------------------------------------------------------
  // Tool call handling
  // ---------------------------------------------------------------------------

  async onBeforeToolCall(ctx: MiddlewareContext, decision?: SecurityDecision, mode?: 'audit' | 'enforce'): Promise<void> {
    const sessionCtx = this.getSessionContext(ctx.sessionKey);

    // 会话的第一条事件可能就是一次工具调用——定时任务、恢复的会话、
    // 直接调工具的 agent 运行都没有消息。生命周期事件不能因为"没等到
    // 消息"就永远缺席（幂等：每个会话至多一条）。
    await this.emitAgentSessionStartIfNeeded(
      { sessionKey: ctx.sessionKey, runId: ctx.runId },
      this.resolveAgentId(ctx.agentId, ctx.sessionKey, ctx.runId),
      sessionCtx
    );

    // Publish OpenClaw context so that runtime hooks can correlate command
    // executions with the current tool call.
    //
    // 这个 id 必须**只算一次**：运行时上下文、事件落盘、决策缓存、after
    // hook 的回溯全部用同一个值。以前 before hook 算了两次（一次给运行时
    // 上下文、一次给 detKey），两次靠"纯函数"才碰巧相等；一旦 id 带上
    // 序号就不再是纯函数，两处就会各拿一个 id，runtime hook 归到的调用与
    // 事件落盘的调用对不上。
    const callId = this.generateDeterministicCallId(ctx, sessionCtx.stepIndex);
    setRuntimeContext({
      sessionId: ctx.sessionKey,
      runId: ctx.runId,
      agentId: this.resolveAgentId(ctx.agentId, ctx.sessionKey, ctx.runId),
      toolCallId: callId,
      toolName: ctx.toolName,
    });

    // 被拦截的调用不会执行，宿主也不会为它跑 after hook——运行时上下文得
    // 当场摘掉。否则它会一直挂在"当前调用"的位置上，之后宿主自己的后台
    // 命令（探活、插件安装）会被挂到这个从未执行的调用名下。
    // 自保护在任何模式下都会真的拦截，policy 拦截只在 enforce 模式下拦截。
    if (
      decision?.decision === 'block' &&
      (mode === 'enforce' || decision.policyId === 'self-protection')
    ) {
      clearRuntimeContext(callId);
    }

    // Extract userId/plan from tool context metadata if available
    if (ctx.metadata) {
      if (this.config.captureUserId) {
        const userIdField = this.config.userIdField ?? 'userId';
        const userIdFromMetadata = safeExtract(() => ctx.metadata?.[userIdField] as string);
        if (userIdFromMetadata) {
          sessionCtx.userId = userIdFromMetadata;
        }
      }
      if (this.config.captureAgentPlan) {
        const planFromMetadata = safeExtract(() => ctx.metadata?.plan as string[]);
        if (planFromMetadata && planFromMetadata.length > 0) {
          sessionCtx.currentPlan = planFromMetadata;
        }
      }
    }

    const startTime = Date.now();
    // 与上面的 callId 是同一个值（同一个 id 只算一次，见上方注释）。
    const detKey = callId;
    const list = this.callStartTimes.get(detKey) ?? [];
    list.push(startTime);
    this.callStartTimes.set(detKey, list);

    // Store deterministic key so afterToolCall can correlate even when the
    // framework passes a different context object for the after hook.
    this.callIdMap.set(ctx, detKey);
    if (decision) this.decisionCache.set(detKey, decision);

    // Track the in-flight call per (session, tool) so afterToolCall can
    // recover the right id without falling back to a global "last call" slot.
    const bucket = this.callBucket(ctx.sessionKey, ctx.toolName);
    const queue = this.inFlightCallIds.get(bucket) ?? [];
    queue.push(detKey);
    this.inFlightCallIds.set(bucket, queue);
    // Also store the current call id so middleware can retrieve it for system-layer binding.
    this.currentCallIds.set(bucket, detKey);
    // 桶里最后一次真实发出的 id：在飞队列排空后仍然留着，after hook 兜底
    // 回退用（见 lastCallIds 的注释）。
    this.recordLastCallId(ctx.sessionKey, ctx.toolName, detKey);

    // 嵌套判定：code-mode exec 在飞期间跑出来的工具调用，外层 call id
    // 记在 parent_tool_call_id 上。内层 call id 仍然唯一（决策缓存不串号），
    // 父子关系显式落在事件里，不必再靠时间窗口反推。
    const parentToolCallId = this.findEnclosingCodeModeCall(ctx, detKey);
    this.inFlightCalls.push({
      detKey,
      sessionKey: ctx.sessionKey ?? undefined,
      toolKind: ctx.toolKind || 'native',
      startedAt: Date.now(),
    });

    // Ensure session context is cached
    this.sessionCache.set(this.skey(ctx.sessionKey), {
      context: sessionCtx,
      lastAccessTime: Date.now(),
    });

    const effectiveAgentId = this.resolveAgentId(ctx.agentId, ctx.sessionKey, ctx.runId);

    const event = this.buildBaseEvent(
      this.classifyToolEventType(ctx.toolName, ctx.toolKind),
      ctx.sessionKey,
      ctx.runId,
      effectiveAgentId
    );

    event.tool_call_id = callId;
    event.host_tool_call_id = this.extractHostToolCallId(ctx);
    if (parentToolCallId) {
      event.parent_tool_call_id = parentToolCallId;
    }
    event.tool_name = ctx.toolName;
    event.tool_kind = ctx.toolKind || 'native';
    event.tool_description = safeExtract(() => ctx.toolDescription);

    // Normalize file path for file operation events. Data standard: the path
    // field is exposed as `path` (not `file_path`) on the emitted event and
    // in the published tool_params payload so downstream
    // consumers see a single canonical name.
    const isFileEvent =
      !!event.event_type &&
      ['file_read', 'file_write', 'file_delete', 'file_privilege'].includes(event.event_type);
    let normalizedParams = ctx.params || {};
    if (isFileEvent) {
      const params = ctx.params || {};
      const filePath =
        (params.file_path as string) ||
        (params.path as string) ||
        (params.file as string) ||
        (params.src as string) ||
        (params.source as string) ||
        (params.target as string);
      if (filePath) {
        event.path = filePath;
        // Rewrite the published params to use `path` and drop the legacy
        // `file_path` alias so the data standard is consistent across
        // event.path and tool_params.
        if (typeof params.file_path === 'string') {
          // eslint-disable-next-line @typescript-eslint/no-unused-vars
          const { file_path: _unused, ...rest } = params;
          normalizedParams = { ...rest, path: filePath };
        }
      }
    }

    // 宿主（及各类 wrapper）会把同一个路径展开成全部别名（path /
    // file_path / filepath / filePath / file / src / source / target /
    // destination）再交给中间件——实测一份采样里 `read` 工具的参数带
    // 9 个同值别名。落盘时收敛成唯一的规范名 `path`（多路径语义保持
    // 原样）。收敛发生在写出去这一刻，策略匹配仍用内存里的展开形态。
    //
    // 先收敛再脱敏：反过来的话，两个不同的密钥都被脱敏成 '***'，会被
    // 误判成"同一个值"而错误合并。
    normalizedParams = canonicalizePathParams(normalizedParams);

    // 原始载荷的指纹要在脱敏**之前**算（规范 raw_params_hash：审计时核对
    // 原始内容）。stableStringify 递归排序键序，同一份参数无论键序如何
    // 都得到同一个 hash。算完只留下 hash 字符串——原始对象不额外留副本，
    // 明文也绝不进日志。循环引用等极端形态算不出确定序列化时整字段省略
    // （RangeError 可捕获），不影响事件落盘。
    try {
      event.raw_params_hash = sha256Hex(stableStringify(normalizedParams));
    } catch {
      // ignore：无法确定性序列化的载荷不附带指纹
    }

    // 脱敏只算一次：tool_params 落脱敏后的结果，同时收一级键名落
    // redacted_keys（规范脱敏四件套之一；空则省略字段）。
    const redacted = redactSensitiveBodyWithKeys(normalizedParams);

    const rawParamsText = JSON.stringify(redacted.value);
    const maxRawLen = this.config.maxRawParamsLength ?? 10000;
    // tool_params 是唯一的参数载荷字段（agent.json 1.1.0）：同一数据的
    // 对象视图 params 已删除——三份冗余表达收敛为一份字符串。
    event.tool_params =
      rawParamsText.length > maxRawLen ? rawParamsText.slice(0, maxRawLen) + '...' : rawParamsText;
    event.tool_params_length = rawParamsText.length;
    if (redacted.redactedKeys.length > 0) {
      event.redacted_keys = redacted.redactedKeys;
    }

    event.user_id = this.config.captureUserId ? sessionCtx.userId || undefined : undefined;
    event.agent_id = effectiveAgentId ?? null;

    // For file operation events, if the agent_id is still unknown/missing and the
    // path lives under an OpenClaw workspace directory, infer the agent identity
    // from the workspace basename (e.g. /root/.openclaw/workspace/main/ -> "main")
    // and cache it for the session.
    if (isFileEvent && (!effectiveAgentId || effectiveAgentId === 'unknown') && event.path) {
      const inferredFromPath = this.inferAgentIdFromPath(event.path);
      if (inferredFromPath) {
        event.agent_id = inferredFromPath;
        const sessionCtx = this.getSessionContext(ctx.sessionKey);
        if (!sessionCtx.agentId || sessionCtx.agentId === 'unknown') {
          sessionCtx.agentId = inferredFromPath;
        }
        if (!sessionCtx.agentName) {
          sessionCtx.agentName = inferredFromPath;
        }
        this.sessionCache.set(this.skey(ctx.sessionKey), { context: sessionCtx, lastAccessTime: Date.now() });
        if (ctx.runId && ctx.runId !== 'unknown') {
          this.runIdAgentCache.set(ctx.runId, {
            agentId: inferredFromPath,
            lastAccessTime: Date.now(),
          });
        }
      }
    }

    // user_prompt / agent_plan / previous_actions 都是会话内常量，之前每条
    // tool_call 原样复制一份（实测同一会话几十条调用驮着同一段 prompt）。
    // 与 system_prompt 同一套继承语义：首次出现或变化时才携带，其余事件
    // 省略字段，下游按 session 继承。策略匹配仍在内存原值上进行，这里只
    // 改落盘。
    if ((this.config.captureUserPrompt ?? true) && sessionCtx.userPrompt) {
      if (sessionCtx.userPrompt !== sessionCtx.emittedUserPrompt) {
        event.user_prompt = sessionCtx.userPrompt;
        sessionCtx.emittedUserPrompt = sessionCtx.userPrompt;
      }
    }
    this.attachSystemPrompt(event, sessionCtx);
    if (this.config.captureAgentPlan ?? true) {
      const plan = sessionCtx.currentPlan.length > 0 ? sessionCtx.currentPlan : undefined;
      const planKey = plan ? JSON.stringify(plan) : undefined;
      if (plan && planKey !== sessionCtx.emittedAgentPlanKey) {
        event.agent_plan = plan;
        sessionCtx.emittedAgentPlanKey = planKey;
      }
    }
    const actionsKey =
      sessionCtx.previousActions.length > 0 ? JSON.stringify(sessionCtx.previousActions) : undefined;
    if (actionsKey && actionsKey !== sessionCtx.emittedPreviousActionsKey) {
      // 深拷贝快照：previous_actions 会被后续调用继续 push/裁剪，事件必须
      // 冻结在发出这一刻的内容（NDJSON 同步序列化不受影响，但内存里的
      // 事件对象不该被事后改写）。
      event.previous_actions = JSON.parse(JSON.stringify(sessionCtx.previousActions)) as SecurityEvent['previous_actions'];
      sessionCtx.emittedPreviousActionsKey = actionsKey;
    }
    event.step_index = sessionCtx.stepIndex;
    event.is_code_mode = ctx.toolKind === 'code_mode_exec';
    const rawCodeContent =
      (this.config.captureCodeMode ?? true) && event.is_code_mode
        ? safeExtract(() => (ctx.params.code as string) || undefined)
        : undefined;
    const maxCodeLen = this.config.maxCodeContentLength ?? this.config.maxContentLength ?? 5000;
    event.code_content = rawCodeContent ? truncateString(rawCodeContent, maxCodeLen) : undefined;
    event.code_content_length = rawCodeContent ? rawCodeContent.length : undefined;
    event.code_language = event.is_code_mode
      ? safeExtract(() =>
          ((ctx.params.language || ctx.params.lang || ctx.params.codeLanguage) as string) ||
          undefined
        )
      : undefined;
    event.model_provider = safeExtract(() => sessionCtx.agentConfig?.model?.provider);
    event.model_name = safeExtract(() => sessionCtx.agentConfig?.model?.name);
    event.agent_name = this.resolveAgentName(ctx.sessionKey);
    event.metadata = safeExtract(() => ctx.metadata);

    if (decision) {
      // audit 模式下 plugin 不实际阻断，event.blocked 反映真实执行结果而非决策意图
      event.blocked = decision.decision === 'block' && mode !== 'audit';
      event.block_reason = decision.blockReason;
      event.intervention = {
        decision: decision.decision,
        policy_id: decision.policyId,
        policy_name: decision.policyName,
        policy_version: decision.policyVersion,
        reason: decision.reason,
        block_reason: decision.blockReason,
        block_code: decision.blockCode,
        appealable: decision.appealable,
        remediation_hint: decision.remediationHint,
        matched_rules: this.mapMatchedRules(decision),
        modified_params: canonicalizePathParams(decision.modifiedParams),
        substituted_tool_name: decision.substitutedToolName,
        guidance: decision.guidance
          ? {
              adjustment_id: decision.guidance.adjustmentId,
              template_id: decision.guidance.templateId,
              template_version: decision.guidance.templateVersion,
              rendered: decision.guidance.rendered,
              allowed_scope: decision.guidance.allowedScope,
              alternatives: decision.guidance.alternatives,
              attempts_remaining: decision.guidance.attemptsRemaining,
            }
          : undefined,
        degrade: decision.degradeMode
          ? {
              mode: decision.degradeMode,
              removed_tools: decision.removedTools,
            }
          : undefined,
        latency_ms: decision.latencyMs,
        fail_strategy: decision.failStrategy,
        mode: mode || 'audit',
        priority: decision.priority,
        risk_level: decision.riskLevel,
      };
      event.risk_assessment = decision.riskSignal
        ? {
            risk_score: decision.riskSignal.riskScore,
            risk_level: decision.riskSignal.riskLevel,
            reg_level: decision.riskSignal.regLevel,
            reg_clause: decision.riskSignal.regClause,
            dimensions: decision.riskSignal.dimensions,
            // 多规则命中时列出全部命中策略，而非仅最终决策的 policyId。
            matched_policies:
              decision.matchedPolicies && decision.matchedPolicies.length > 0
                ? decision.matchedPolicies.map((m) => m.policyId)
                : decision.policyId
                  ? [decision.policyId]
                  : undefined,
            evaluation_path: 'rule',
          }
        : undefined;
    }

    if (this.shouldEmitEvent(event)) {
      await this.emit(event);
    }
  }

  /**
   * @param resultDecision agent_tool_result 评估入口的事后决策
   *   （由 store.afterToolCall 在采集前评估）。仅当本次调用没有更早的
   *   beforeToolCall 决策（decisionCache 未命中）时用于事件 intervention
   *   标注——被阻断调用的阻断归因不被结果决策覆盖。
   */
  async onAfterToolCall(ctx: MiddlewareContext, result: unknown, resultDecision?: SecurityDecision): Promise<void> {
    // call id **只取一次**。
    //
    // 取第二次的话，在飞队列已经被第一次取空，只能落到"按当前 step 索引
    // 重算"的兜底分支——那个 id 与任何一次真实调用都对不上。实测就是
    // code-mode exec 的开始事件是 `…:exec:1`、结果事件却成了 `…:exec:5`：
    // 结果事件挂不上自己的开始事件，耗时与阻断归因全丢。
    const detKey = this.extractCallId(ctx);
    if (detKey !== undefined) {
      this.callIdMap.delete(ctx);
    }

    // 运行时上下文按调用摘除：只摘本次调用自己那一条，外层/并发的调用
    // 各自保留（摘掉之后外层上下文自动复位）。
    clearRuntimeContext(detKey);

    // 在飞登记销账（嵌套判定的依据）。
    this.releaseInFlightCall(detKey);

    const decision = detKey ? this.decisionCache.get(detKey) : undefined;
    if (detKey && decision !== undefined) this.decisionCache.delete(detKey);
    const list = detKey ? this.callStartTimes.get(detKey) : undefined;
    const startTime = list?.shift();
    if (detKey && list && list.length === 0) {
      this.callStartTimes.delete(detKey);
    }

    // Tool results sometimes reveal the agent workspace (details.cwd) or the
    // requester. Resolve and cache that identity before emitting the event so
    // the current event and future events in the same run get the right agent_id.
    const resultAgentId = this.extractAgentIdFromToolResult(result);
    if (resultAgentId) {
      const sessionCtx = this.getSessionContext(ctx.sessionKey);
      if (!sessionCtx.agentId || sessionCtx.agentId === 'unknown') {
        sessionCtx.agentId = resultAgentId;
      }
      if (!sessionCtx.agentName) {
        sessionCtx.agentName = resultAgentId;
      }
      this.sessionCache.set(this.skey(ctx.sessionKey), { context: sessionCtx, lastAccessTime: Date.now() });
      if (ctx.runId && ctx.runId !== 'unknown') {
        this.runIdAgentCache.set(ctx.runId, {
          agentId: resultAgentId,
          lastAccessTime: Date.now(),
        });
      }
    }

    const summary = this.summarizeResult(result);
    const effectiveAgentId = this.resolveAgentId(ctx.agentId, ctx.sessionKey, ctx.runId);

    const event = this.buildBaseEvent(
      'agent_tool_result',
      ctx.sessionKey,
      ctx.runId,
      effectiveAgentId
    );

    event.tool_call_id = detKey;
    event.host_tool_call_id = this.extractHostToolCallId(ctx);
    event.tool_name = ctx.toolName;
    event.tool_kind = ctx.toolKind || 'native';
    event.duration = startTime ? Date.now() - startTime : undefined;
    // When the call was blocked by policy the tool either never ran or its
    // output was replaced by a block notice. Report the blocked status so the
    // downstream does not mistake the call for a successful execution.
    const blockedByPolicy = decision?.decision === 'block';
    // 规范（agent.json）status 枚举里有 blocked 一档：被策略拦截就是
    // 'blocked'，不再借 'failure' 表达（failure 留给真正执行失败）。
    // blocked 布尔仍恒在，照顾只认布尔的老消费方。
    event.status = blockedByPolicy
      ? 'blocked'
      : summary.status === 'error'
        ? 'failure'
        : 'success';
    // `blocked` 恒在：1.1.0 之前它只在被拦截时才出现，下游按
    // `blocked === false` 过滤会漏掉"键缺失"的那部分事件。
    event.blocked = blockedByPolicy;
    event.result_size = summary.size;
    event.result_preview = summary.preview;
    event.error_message = summary.error;
    event.agent_name = this.resolveAgentName(ctx.sessionKey);
    // intervention 标注：调用期决策（decisionCache 命中）已标注在
    // agent_tool_call 事件上，此处不重复——一次阻断只计一次命中
    // （policy.hits / metrics.byDecision 按事件计数）。仅当没有调用期决策、
    // 只有 agent_tool_result 入口的事后决策时才在 result 上
    // 标注，那不是重复，是该决策的唯一记录。
    if (!decision && resultDecision) {
      event.intervention = {
        decision: resultDecision.decision,
        policy_id: resultDecision.policyId,
        policy_name: resultDecision.policyName,
        block_code: resultDecision.blockCode,
        block_reason: resultDecision.blockReason,
        appealable: resultDecision.appealable,
        remediation_hint: resultDecision.remediationHint,
        matched_rules: this.mapMatchedRules(resultDecision),
        guidance: resultDecision.guidance
          ? {
              adjustment_id: resultDecision.guidance.adjustmentId,
              rendered: resultDecision.guidance.rendered,
              allowed_scope: resultDecision.guidance.allowedScope,
              alternatives: resultDecision.guidance.alternatives,
            }
          : undefined,
        priority: resultDecision.priority,
        risk_level: resultDecision.riskLevel,
      };
    }

    await this.emit(event);
    this.updateSessionAfterToolCall(ctx, result);
  }

  async onSessionEnd(ctx: SessionEndContext): Promise<void> {
    const effectiveAgentId = this.resolveAgentId(ctx.agentId, ctx.sessionKey, ctx.runId);
    const event = this.buildBaseEvent('agent_session_end', ctx.sessionKey, ctx.runId, effectiveAgentId);
    // 宿主给的 status 是任意字符串，收敛进枚举：会话结束一律 'ended'，
    // 只有宿主明确报 error 时才落 'error'。枚举外取值不落盘（规范要求）。
    event.status = ctx.status === 'error' ? 'error' : 'ended';
    if (ctx.content !== undefined) {
      event.content = truncateString(ctx.content as string, this.config.maxContentLength ?? 2000);
    }
    // Cascade-evict PID bindings owned by this session, 防止后续 PID 被复用时
    // 误关联到已结束 session。session 失效前应已 emit 完 process_start。
    if (ctx.sessionKey) {
      pidBindingStore.evictBySession(ctx.sessionKey);
    }
    await this.emit(event);
  }

  async onSubagentStart(ctx: SubagentContext): Promise<void> {
    const effectiveAgentId = this.resolveAgentId(ctx.agentId, ctx.sessionKey, ctx.runId);
    const event = this.buildBaseEvent('x_openclaw_subagent_start', ctx.sessionKey, ctx.runId, effectiveAgentId);
    this.fillSubagentRecord(event, ctx);
    await this.emit(event);
  }

  async onSubagentProgress(ctx: SubagentContext): Promise<void> {
    const effectiveAgentId = this.resolveAgentId(ctx.agentId, ctx.sessionKey, ctx.runId);
    const event = this.buildBaseEvent('x_openclaw_subagent_progress', ctx.sessionKey, ctx.runId, effectiveAgentId);
    this.fillSubagentRecord(event, ctx);
    if (ctx.progress !== undefined) {
      event.content = truncateString(String(ctx.progress), this.config.maxContentLength ?? 2000);
    }
    await this.emit(event);
  }

  async onSubagentEnd(ctx: SubagentContext): Promise<void> {
    const effectiveAgentId = this.resolveAgentId(ctx.agentId, ctx.sessionKey, ctx.runId);
    const event = this.buildBaseEvent('x_openclaw_subagent_end', ctx.sessionKey, ctx.runId, effectiveAgentId);
    this.fillSubagentRecord(event, ctx);
    const failed = ctx.status === 'error' || ctx.error !== undefined;
    event.status = failed ? 'failure' : 'success';
    if (ctx.output !== undefined) {
      const preview = truncateString(String(ctx.output), this.config.maxResultPreviewLength ?? 500);
      event.result_preview = preview;
      event.result_size = computeContentLength(ctx.output);
    }
    if (ctx.error !== undefined) {
      event.error_message = truncateString(
        String((ctx.error as { message?: unknown })?.message ?? ctx.error),
        this.config.maxContentLength ?? 2000
      );
    }
    await this.emit(event);
  }

  private fillSubagentRecord(event: SecurityEvent, ctx: SubagentContext): void {
    event.task_id = ctx.subagentId || event.task_id;
    event.agent_name = ctx.subagentName || this.resolveAgentName(ctx.sessionKey);
    // the subagent task prompt is user-supplied; gate it on
    // captureUserPrompt like every other user_prompt field.
    event.user_prompt =
      (this.config.captureUserPrompt ?? true) ? ctx.prompt : undefined;
    event.metadata = {
      ...(ctx.parentRunId ? { parent_run_id: ctx.parentRunId } : {}),
      ...(ctx.subagentId ? { subagent_id: ctx.subagentId } : {}),
      ...(ctx.metadata ? { source: ctx.metadata } : {}),
    };
  }

  /**
   * cron 作业的运行中间状态，按 cronId（缺省回退 sessionKey）记。
   *
   * 8.2 每次 cron 触发都发 scheduled/started/finished 三条，其中前两条
   * 不再落盘，只在这里登记：开始时间（算 duration）以及作业名/表达式
   * （宿主经常只在三元组的某一条上带，finished 上反而没有——不在内存里
   * 记住的话 cron_run 的 metadata 会是空的）。运行结束收敛成单条
   * cron_run 后整条删除；插件在 started 与 finished 之间重启会丢掉起点，
   * 那种情况省略 duration，不编一个假的。
   */
  private cronRuns = new Map<string, { startedAt?: number; cronName?: string; schedule?: string }>();

  async onCronEvent(ctx: CronEventContext): Promise<void> {
    // 宿主没给作业 id 时回退到 cron 会话键：8.2 下每个 cron 作业拥有
    // 自己的会话键（实测同一作业的 scheduled/started/finished 三元组
    // 与跨多轮的重复触发共用同一个 session_id），它就是可用的作业身份。
    // 缺了这一步，metadata 会整个是 {}，下游连"这些事件属于同一个
    // 作业"都判断不出来。
    //
    // sessionKey 这一层拿不到就整体缺省：规范只允许 run_id 向下回退，
    // 这里绝不再退到 runId——不同作业可能共享 runId，退过去等于把
    // 作业身份张冠李戴。
    const cronKey =
      ctx.cronId ?? (ctx.sessionKey && ctx.sessionKey !== 'unknown' ? ctx.sessionKey : undefined);

    const rememberCronMeta = (): { startedAt?: number; cronName?: string; schedule?: string } => {
      if (!cronKey) return {};
      const entry = this.cronRuns.get(cronKey) ?? {};
      // 先记先赢：同一作业三元组里先到的名字/表达式才是宿主当下的口径。
      if (!entry.cronName && ctx.cronName) entry.cronName = ctx.cronName;
      if (!entry.schedule && ctx.schedule) entry.schedule = ctx.schedule;
      this.cronRuns.set(cronKey, entry);
      return entry;
    };

    // 运行中间事件（scheduled / started）不再单独落盘：它们只在内存里
    // 登记开始时间与作业元数据。实测采样 90 条/天的 cron 事件里绝大部
    // 分是这三元组，收敛后每次运行只有一条 cron_run，配置变化仍走
    // cron_changed。scheduled 与 started 载荷里没有值得单独留痕的信息
    // （schedule 在这里被记住并并进 cron_run，结果要到 finished 才有），
    // 直接丢弃不损语义。
    if (ctx.action === 'scheduled' || ctx.action === 'started') {
      if (cronKey) {
        const entry = rememberCronMeta();
        entry.startedAt = Date.now();
        this.cronRuns.set(cronKey, entry);
      }
      return;
    }

    const effectiveAgentId = this.resolveAgentId(ctx.agentId, ctx.sessionKey, ctx.runId);

    if (ctx.action === 'finished' || ctx.action === 'fired') {
      // 运行结束：单条 cron_run 汇总这次触发。status 只有
      // success/failure 两档；宿主报错时带 error_message。
      const event = this.buildBaseEvent('x_openclaw_cron_run', ctx.sessionKey, ctx.runId, effectiveAgentId);
      const runState = cronKey ? this.cronRuns.get(cronKey) : undefined;
      if (cronKey) {
        this.cronRuns.delete(cronKey);
      }
      const startedAt = runState?.startedAt;
      if (startedAt !== undefined) {
        event.started_at = startedAt;
        event.duration_ms = Date.now() - startedAt;
      }
      const hostError =
        ctx.firedResult !== null &&
        typeof ctx.firedResult === 'object' &&
        'error' in ctx.firedResult &&
        (ctx.firedResult as { error?: unknown }).error !== undefined
          ? safeExtract(
              () =>
                String(
                  ((ctx.firedResult as { error?: { message?: unknown } }).error as
                    | { message?: unknown }
                    | undefined)?.message ??
                    (ctx.firedResult as { error?: unknown }).error
                )
            )
          : undefined;
      event.status = hostError !== undefined ? 'failure' : 'success';
      if (hostError) {
        event.error_message = truncateString(hostError, this.config.maxContentLength ?? 2000);
      }
      // 作业名/表达式：finished 自带优先，否则用 scheduled/started 时
      // 记住的那份。
      const cronName = ctx.cronName ?? runState?.cronName;
      const schedule = ctx.schedule ?? runState?.schedule;
      event.metadata = {
        ...(cronKey ? { cron_id: cronKey } : {}),
        ...(cronName ? { cron_name: cronName } : {}),
        ...(schedule ? { schedule } : {}),
      };
      if (ctx.firedResult !== undefined) {
        event.fired_result = truncateString(
          typeof ctx.firedResult === 'string' ? ctx.firedResult : JSON.stringify(ctx.firedResult),
          this.config.maxResultPreviewLength ?? 500
        );
      }
      await this.emit(event);
      return;
    }

    // 其余 action（added/updated/removed 及未知取值）都是作业配置的真实
    // 变化：发 cron_changed，status 落 modified——平台已登记 schema 的
    // cron_changed 枚举是 started/stopped/modified/error（scheduled/
    // started/finished 运行语义已归 x_openclaw_cron_run）。
    const event = this.buildBaseEvent('cron_changed', ctx.sessionKey, ctx.runId, effectiveAgentId);
    event.status = 'modified';
    event.metadata = {
      ...(cronKey ? { cron_id: cronKey } : {}),
      ...(ctx.cronName ? { cron_name: ctx.cronName } : {}),
      ...(ctx.schedule ? { schedule: ctx.schedule } : {}),
    };
    if (typeof ctx.enabled === 'boolean') {
      event.metadata.enabled = ctx.enabled;
    }
    await this.emit(event);
  }

  async onAgentComplete(ctx: AgentCompleteContext): Promise<void> {
    const effectiveAgentId = this.resolveAgentId(ctx.agentId, ctx.sessionKey, ctx.runId);
    // 运行结束：此后到达的消息重新按"用户输入"看待。
    if (ctx.sessionKey && ctx.sessionKey !== 'unknown') {
      this.activeAgentRuns.delete(ctx.sessionKey);
    }
    const event = this.buildBaseEvent(
      'agent_stop',
      ctx.sessionKey,
      ctx.runId,
      effectiveAgentId
    );

    const status =
      ctx.status === 'error' || (ctx.error !== undefined && ctx.error !== null)
        ? 'error'
        : 'success';

    event.status = status === 'error' ? 'failure' : 'success'; // Standard event field
    event.exit_code = status === 'error' ? 1 : 0; // Standard event field
    // Compute duration from agent start time
    if (ctx.runId) {
      const startTime = this.agentStartTimes.get(ctx.runId);
      if (startTime !== undefined) {
        event.duration = Math.round(Date.now() - startTime);
        this.agentStartTimes.delete(ctx.runId);
      }
    }
    // Ensure duration is always set (schema requires it)
    if (event.duration === undefined) {
      event.duration = 0;
    }
    event.result_preview = ctx.output !== undefined ? truncateString(ctx.output, 500) : undefined;
    event.result_size = ctx.output !== undefined ? computeContentLength(ctx.output) : undefined;
    event.error_message =
      status === 'error'
        ? safeExtract(() =>
            String(
              (ctx.error as { message?: string } | undefined)?.message ||
                (ctx.error as unknown as string)
            )
          ) || 'unknown error'
        : undefined;
    event.agent_name = this.resolveAgentName(ctx.sessionKey);

    await this.emit(event);
  }

  // ---------------------------------------------------------------------------
  // Session cache management
  // ---------------------------------------------------------------------------

  // ---------------------------------------------------------------------------
  // agent_resources: explicit resource topology for agent_start
  // ---------------------------------------------------------------------------
  // agents[].mcp_servers — name list construction
  // ---------------------------------------------------------------------------

  /**
   * Source priority:
   *   1. ctx.agentConfig.mcpServers  (agent-private, when OpenClaw passes it)
   *   2. ~/.openclaw/mcp.json        (node-global fallback)
   *
   * The global fallback may list MCPs not actually referenced by this agent.
   * Consumers can detect this drift by joining against `asset_add` events
   * for `mcp_server` assets and reconciling which are claimed by which
   * agent_start.
   */
  private collectAgentMcpServerNames(config?: AgentConfig): string[] {
    const cfg = config as Record<string, unknown> | undefined;
    const mcpServers = cfg?.mcpServers;
    if (isRecord(mcpServers)) {
      return Object.keys(mcpServers);
    }
    const mcpPath = path.join(homedir(), '.openclaw', 'mcp.json');
    try {
      const doc = JSON.parse(readFileSync(mcpPath, 'utf8')) as unknown;
      if (!isRecord(doc)) return [];
      const fallback = doc.mcpServers;
      if (!isRecord(fallback)) return [];
      return Object.keys(fallback);
    } catch (err) {
      console.warn('[ApplicationCollector] collectAgentMcpServerNames fallback failed:', err instanceof Error ? err.message : String(err));
      return [];
    }
  }

  // ---------------------------------------------------------------------------

  getAgentId(sessionKey: string): string | undefined {
    return this.getSessionContext(sessionKey).agentId;
  }

  /**
   * 附上系统提示词引用（内容寻址）。
   *
   * 采样实测 system_prompt 全文占事件流约 54% 体积——每个会话的第一条
   * 消息驮一份，多会话之间同一份提示词反复内嵌。这里不再向任何事件
   * 内嵌全文（此前"会话首条事件带全文"的折中仍让多会话重复占体积）：
   * 所有事件一律只带 16 位指纹 `system_prompt_ref`，全文由 PromptSidecar
   * 按 hash 全局只落一份到 security-prompts.jsonl。
   *
   * 降级契约：sidecar 写失败不阻断事件——事件照常带 ref 落盘，只记
   * console.warn（见 PromptSidecar）。
   */
  private attachSystemPrompt(event: SecurityEvent, sessionCtx: SessionContext): void {
    if (!(this.config.captureSystemPrompt ?? true)) return;
    const prompt = sessionCtx.systemPrompt;
    if (!prompt) return;
    event.system_prompt_ref = this.promptSidecar
      ? this.promptSidecar.recordPrompt(prompt, event.session_id, event.host_id).ref
      : sha256Hex(prompt).slice(0, 16);
  }

  private resolveAgentName(sessionKey?: string): string | undefined {
    if (!sessionKey || sessionKey === 'unknown') {
      return undefined;
    }
    return this.getSessionContext(sessionKey).agentName;
  }

  /**
   * Resolve the effective agent id for an event.
   *
   * OpenClaw sometimes passes the literal string "unknown" for the agent id.
   * We treat that as missing and fall back to (in order):
   *   1. a real agent id from the incoming context
   *   2. a real agent id cached for the session
   *   3. a real agent id previously associated with the same run_id
   *      (e.g. recovered from a tool result's details.cwd / requester field)
   *   4. infer from the session key encoding
   *   5. the configured defaultAgentId (useful for single-agent deployments)
   */
  resolveAgentId(ctxAgentId?: string, sessionKey?: string, runId?: string): string | undefined {
    if (ctxAgentId && ctxAgentId !== 'unknown') {
      return ctxAgentId;
    }
    if (sessionKey) {
      const sessionCtx = this.getSessionContext(sessionKey);
      if (sessionCtx.agentId && sessionCtx.agentId !== 'unknown') {
        return sessionCtx.agentId;
      }
    }
    if (runId && runId !== 'unknown') {
      const runEntry = this.runIdAgentCache.get(runId);
      if (runEntry?.agentId && runEntry.agentId !== 'unknown') {
        runEntry.lastAccessTime = Date.now();
        // Also propagate to the session cache when we have a real session key,
        // so events that later lack a run_id can still reuse the resolved id.
        if (sessionKey && sessionKey !== 'unknown') {
          const sessionCtx = this.getSessionContext(sessionKey);
          if (!sessionCtx.agentId || sessionCtx.agentId === 'unknown') {
            sessionCtx.agentId = runEntry.agentId;
            if (!sessionCtx.agentName) {
              sessionCtx.agentName = runEntry.agentId;
            }
            this.sessionCache.set(sessionKey, { context: sessionCtx, lastAccessTime: Date.now() });
          }
        }
        return runEntry.agentId;
      }
    }
    if (sessionKey && sessionKey !== 'unknown') {
      const sessionCtx = this.getSessionContext(sessionKey);
      // OpenClaw session identifiers often encode the agent name directly.
      // Infer and cache it so subsequent events in the same session can reuse it.
      const inferred = inferAgentIdFromSessionKey(sessionKey);
      if (inferred) {
        sessionCtx.agentId = inferred;
        if (!sessionCtx.agentName) {
          sessionCtx.agentName = inferred;
        }
        this.sessionCache.set(sessionKey, { context: sessionCtx, lastAccessTime: Date.now() });
        return inferred;
      }
    }
    const defaultId = this.config.defaultAgentId;
    if (defaultId && defaultId !== 'unknown') {
      return defaultId;
    }
    return undefined;
  }

  private inferAgentIdFromAgentDir(agentConfig?: AgentConfig): string | undefined {
    const agentDir = agentConfig?.agentDir;
    return typeof agentDir === 'string' ? inferAgentNameFromAgentDir(agentDir) : undefined;
  }

  private inferAgentIdFromPath(filePath?: string): string | undefined {
    if (typeof filePath !== 'string') return undefined;
    // Only infer from the OpenClaw workspace directory segment; never fall back
    // to the bare filename (e.g. /tmp/test.txt must not yield "test.txt").
    const workspaceMatch = filePath.match(/[\\/]\.openclaw[\\/]workspace[\\/]([^\\/]+)(?:[\\/]|$)/);
    return workspaceMatch?.[1];
  }

  /**
   * Try to recover an agent id from a raw tool result. OpenClaw tool results
   * sometimes contain a details.cwd that points to the agent workspace, or a
   * requester field (e.g. from agents_list) that names the current agent.
   */
  private extractAgentIdFromToolResult(result: unknown): string | undefined {
    if (result === null || result === undefined) return undefined;

    // If the runtime passed a JSON string, parse it first.
    let value: unknown = result;
    if (typeof result === 'string') {
      try {
        value = JSON.parse(result);
      } catch (err) {
        console.warn('[ApplicationCollector] extractAgentIdFromToolResult JSON.parse failed:', err instanceof Error ? err.message : String(err));
        return undefined;
      }
    }

    if (!isRecord(value)) return undefined;

    // Prefer the cwd workspace segment when available.
    const details = value.details;
    if (isRecord(details) && typeof details.cwd === 'string') {
      const fromCwd = this.inferAgentIdFromPath(details.cwd);
      if (fromCwd) return fromCwd;
    }

    // Fall back to a requester field anywhere in the payload.
    const requester = this.findRequesterInValue(value);
    if (requester && requester !== 'unknown') return requester;

    return undefined;
  }

  /**
   * Recursively search a parsed result for a string `requester` field.
   * Handles JSON-encoded text payloads that OpenClaw wraps in content[] arrays.
   */
  private findRequesterInValue(value: unknown, depth = 0): string | undefined {
    if (depth > 10) return undefined;

    if (typeof value === 'string') {
      let parsed: unknown;
      try {
        parsed = JSON.parse(value);
      } catch (err) {
        console.warn('[ApplicationCollector] findRequesterInValue JSON.parse failed:', err instanceof Error ? err.message : String(err));
        return undefined;
      }
      return this.findRequesterInValue(parsed, depth + 1);
    }

    if (Array.isArray(value)) {
      for (const item of value) {
        const found = this.findRequesterInValue(item, depth + 1);
        if (found) return found;
      }
      return undefined;
    }

    if (!isRecord(value)) return undefined;

    if (typeof value.requester === 'string' && value.requester && value.requester !== 'unknown') {
      return value.requester;
    }

    for (const v of Object.values(value)) {
      const found = this.findRequesterInValue(v, depth + 1);
      if (found) return found;
    }
    return undefined;
  }

  private initializeSessionCache(
    sessionKey: string | undefined,
    agentConfig?: AgentConfig,
    systemPrompt?: string,
    agentId?: string,
    runId?: string
  ): void {
    // 未知会话（undefined / 'unknown'）统一归一到空串键，全部共享同一个
    // 默认桶——与 session 规范化之前的行为一致（那时 unknown 以 'unknown'
    // 字符串出现，也是单一共享桶）。
    sessionKey = !sessionKey || sessionKey === 'unknown' ? '' : sessionKey;
    // When OpenClaw cannot identify the session, it sends 'unknown'. We must
    // not wipe an existing cache that already tracks the current conversation.
    const isUnknownSession = !sessionKey || sessionKey === 'unknown';
    let resolvedAgentId = this.resolveAgentId(agentId, isUnknownSession ? undefined : sessionKey, runId);
    // If the context/agentId are still unknown, try to recover the agent identity
    // from the workspace directory carried in the agent config.
    if (!resolvedAgentId || resolvedAgentId === 'unknown') {
      const fromDir = this.inferAgentIdFromAgentDir(agentConfig);
      if (fromDir) resolvedAgentId = fromDir;
    }

    if (resolvedAgentId && runId && runId !== 'unknown') {
      this.runIdAgentCache.set(runId, { agentId: resolvedAgentId, lastAccessTime: Date.now() });
    }

    // 已知会话重复初始化（运行期间的后续 agent_start 等）只更新身份字段，
    // **保留 message/step 计数器**：整表覆写会把 messageIndex 清零，同一会话
    // 后半段的 message_index 又从 1 开始，下游看到重复序号。
    const existingEntry = this.sessionCache.get(sessionKey);
    if (!isUnknownSession && existingEntry) {
      const existing = existingEntry.context;
      if (systemPrompt) existing.systemPrompt = systemPrompt;
      if (agentConfig) {
        existing.agentConfig = agentConfig;
        if (agentConfig.name) existing.agentName = agentConfig.name;
      }
      if (resolvedAgentId) existing.agentId = resolvedAgentId;
      if (!existing.agentName && resolvedAgentId) existing.agentName = resolvedAgentId;
      this.sessionCache.set(sessionKey, {
        context: existing,
        lastAccessTime: Date.now(),
      });
      return;
    }

    if (isUnknownSession && this.sessionCache.has(sessionKey)) {
      const existing = this.sessionCache.get(sessionKey)!.context;
      // Only update fields we actually received; preserve message/step counters.
      if (systemPrompt) existing.systemPrompt = systemPrompt;
      if (agentConfig) {
        existing.agentConfig = agentConfig;
        if (agentConfig.name) existing.agentName = agentConfig.name;
      }
      if (resolvedAgentId) existing.agentId = resolvedAgentId;
      if (!existing.agentName && resolvedAgentId) existing.agentName = resolvedAgentId;
      this.sessionCache.set(sessionKey, {
        context: existing,
        lastAccessTime: Date.now(),
      });
      return;
    }

    this.sessionCache.set(sessionKey, {
      context: {
        userPrompt: '',
        systemPrompt: systemPrompt || '',
        currentPlan: [],
        previousActions: [],
        stepIndex: 0,
        messageIndex: 0,
        agentId: resolvedAgentId,
        agentName: agentConfig?.name || resolvedAgentId,
        agentConfig,
      },
      lastAccessTime: Date.now(),
    });
  }

  private getSessionContext(sessionKey: string | undefined): SessionContext {
    // 未知会话（undefined / 'unknown'）统一归一到空串键，与
    // initializeSessionCache 的归一保持一致。
    const key = !sessionKey || sessionKey === 'unknown' ? '' : sessionKey;
    const entry = this.sessionCache.get(key);
    if (entry) {
      entry.lastAccessTime = Date.now();
      return entry.context;
    }
    return {
      userPrompt: '',
      systemPrompt: '',
      currentPlan: [],
      previousActions: [],
      stepIndex: 0,
      messageIndex: 0,
    };
  }

  /**
   * 消息事件的会话内副作用（userPrompt / userId / plan 缓存）。
   *
   * 刻意**不在这里推进 messageIndex**：序号占号发生在 onMessageWrite 确认
   * 事件真的落盘之后——reportBlockedEvents=false 时 blocked 消息在占号点
   * 之后才被丢弃，先占号会让下游看到跳号。
   */
  private updateSessionFromMessage(ctx: MessageWriteContext, role: string = ctx.role): SessionContext {
    const existing = this.getSessionContext(ctx.sessionKey);

    if (role === 'user' && typeof ctx.content === 'string') {
      existing.userPrompt = ctx.content;
    }

    // Extract userId from message metadata if available
    if (this.config.captureUserId) {
      const userIdField = this.config.userIdField ?? 'userId';
      const userIdFromMetadata = safeExtract(() => ctx.metadata?.[userIdField] as string);
      if (userIdFromMetadata) {
        existing.userId = userIdFromMetadata;
      }
    }

    // Try to extract plan from message metadata
    if (this.config.captureAgentPlan) {
      const planFromMetadata = safeExtract(() => ctx.metadata?.plan as string[]);
      if (planFromMetadata && planFromMetadata.length > 0) {
        existing.currentPlan = planFromMetadata;
      }
    }

    this.sessionCache.set(this.skey(ctx.sessionKey), {
      context: existing,
      lastAccessTime: Date.now(),
    });

    return existing;
  }

  private updateSessionAfterToolCall(ctx: MiddlewareContext, result: unknown): void {
    const existing = this.getSessionContext(ctx.sessionKey);
    const maxHistory = this.config.maxPreviousActions ?? 50;
    existing.previousActions.push({
      tool: ctx.toolName,
      params: canonicalizePathParams(
        redactSensitiveBody(ctx.params) as Record<string, unknown> | undefined
      ),
      result_status: (result as { error?: unknown })?.error ? 'error' : 'success',
    });
    if (existing.previousActions.length > maxHistory) {
      existing.previousActions = existing.previousActions.slice(-maxHistory);
    }
    existing.stepIndex += 1;

    // Update plan if available in tool context metadata
    if (this.config.captureAgentPlan) {
      const planFromMetadata = safeExtract(() => ctx.metadata?.plan as string[]);
      if (planFromMetadata && planFromMetadata.length > 0) {
        existing.currentPlan = planFromMetadata;
      }
    }

    this.sessionCache.set(this.skey(ctx.sessionKey), {
      context: existing,
      lastAccessTime: Date.now(),
    });
  }

  private cleanupExpiredSessions(ttlMs: number): void {
    const now = Date.now();
    for (const [sessionKey, entry] of this.sessionCache.entries()) {
      if (now - entry.lastAccessTime > ttlMs) {
        this.sessionCache.delete(sessionKey);
      }
    }

    // Clean up orphaned call timers (afterToolCall was never invoked)
    for (const [detKey, startTimes] of this.callStartTimes.entries()) {
      const remaining = startTimes.filter((startTime) => now - startTime <= ttlMs);
      if (remaining.length === 0) {
        this.callStartTimes.delete(detKey);
      } else {
        this.callStartTimes.set(detKey, remaining);
      }
    }

    // cron 运行中间状态同 TTL：finished 永远不来的漏网作业（宿主中止）
    // 不能把起点和元数据永远留在表里。
    for (const [cronKey, runState] of this.cronRuns.entries()) {
      if (runState.startedAt !== undefined && now - runState.startedAt > ttlMs) {
        this.cronRuns.delete(cronKey);
      }
    }

    // Clean up stale run_id -> agent_id associations.
    for (const [runId, entry] of this.runIdAgentCache.entries()) {
      if (now - entry.lastAccessTime > ttlMs) {
        this.runIdAgentCache.delete(runId);
      }
    }

    // 会话标题与 session 缓存同 TTL：闲置超过 ttlMs 的会话连同标题一起过期，
    // 这样被复用的旧 sessionKey 不会带着上一段对话的标题。活跃会话靠
    // buildBaseEvent 里的续期保活，标题不会中途换掉。
    for (const [sessionKey, entry] of this.sessionTitles.entries()) {
      if (now - entry.lastAccessTime > ttlMs) {
        this.sessionTitles.delete(sessionKey);
      }
    }

    // 调用关联的辅助表同 TTL：过期会话的最后一次 call id 与调用序号不再
    // 保留（否则同 sessionKey 被复用时，兜底回退会指向上一段对话的调用）。
    for (const sessionKey of [...this.lastCallIds.keys()]) {
      if (!this.sessionCache.has(sessionKey)) {
        this.lastCallIds.delete(sessionKey);
      }
    }
    for (const sessionKey of [...this.callSeqBySession.keys()]) {
      if (!this.sessionCache.has(sessionKey)) {
        this.callSeqBySession.delete(sessionKey);
      }
    }

    // 在飞登记：after hook 没跑到的漏网调用不能永远留着当"外层调用"，
    // 过期后清掉。
    this.inFlightCalls = this.inFlightCalls.filter((e) => now - e.startedAt <= ttlMs);
  }

  // ---------------------------------------------------------------------------
  // Call correlation helpers
  // ---------------------------------------------------------------------------

  /**
   * 一次工具调用的关联 id：`session:run:tool:step#seq`。
   *
   * `seq` 是会话内单调递增的调用序号。少了它，id 会在两种情况下撞车：
   * 同一 step 内的并发调用（step 索引只在调用**结束**时推进），以及嵌套
   * 调用（外层 code-mode exec 与它内层跑出来的同名工具共享 step 索引）。
   * 撞车的后果不是"重名"这么轻：决策缓存按 id 存，一次调用会覆盖另一次
   * 的决策，阻断归因直接串到别的调用上。
   */
  private generateDeterministicCallId(ctx: MiddlewareContext, stepIndex: number): string {
    const seq = this.nextCallSeq(ctx.sessionKey);
    return `${ctx.sessionKey}:${ctx.runId}:${ctx.toolName}:${stepIndex}#${seq}`;
  }

  /** 会话内调用序号（单调递增）。 */
  private nextCallSeq(sessionKey: string | undefined): number {
    const key = sessionKey ?? '';
    const next = (this.callSeqBySession.get(key) ?? 0) + 1;
    this.callSeqBySession.set(key, next);
    return next;
  }

  private extractCallId(ctx: MiddlewareContext): string | undefined {
    // 1. 精确命中：before/after 拿到同一个 ctx 对象。
    const exact = this.callIdMap.get(ctx);
    if (exact) {
      this.consumeInFlightCall(ctx.sessionKey, ctx.toolName, exact);
      return exact;
    }
    // 2. 框架给 after hook 传了另一个 ctx 对象：按 (session, 工具名)
    //    取最早那条尚未消费的在飞调用。**绝不跨工具名回退**——那正是
    //    1.1.0 之前 exec 结果被记到 ls 名下的根因。
    const bucket = this.callBucket(ctx.sessionKey, ctx.toolName);
    const queue = this.inFlightCallIds.get(bucket);
    const queued = queue?.shift();
    if (queued) {
      if (queue && queue.length === 0) {
        this.inFlightCallIds.delete(bucket);
        this.currentCallIds.delete(bucket);
      }
      return queued;
    }
    // 3. 兜底：回退到这个 (会话, 工具) 最近一次真实发出过的 call id。
    //    **绝不按当前 step 索引重算**——重算出来的 id 与任何一次真实调用
    //    都对不上，写进审计流就是一条指向虚空的关联；宁可没有 id，也不要
    //    错 id（错 id 会把决策挂到别的调用上，空 id 只是"这次没关联上"）。
    return this.lastCallIds.get(ctx.sessionKey ?? '')?.get(ctx.toolName ?? '');
  }

  /** 记下这个 (会话, 工具) 最近一次真实发出的 call id。 */
  private recordLastCallId(
    sessionKey: string | undefined,
    toolName: string | undefined,
    callId: string
  ): void {
    const key = sessionKey ?? '';
    const byTool = this.lastCallIds.get(key) ?? new Map<string, string>();
    byTool.set(toolName ?? '', callId);
    this.lastCallIds.set(key, byTool);
  }

  /**
   * 找出包住本次调用的外层 code-mode 调用（没有则 undefined）。
   *
   * code-mode exec 在飞期间跑出来的工具调用（read/ls/exec …）在事件流里
   * 是"孤儿"：它们有自己的 call id，但看不出是谁发起的。这里按"同会话 +
   * 还在飞 + tool_kind 是 code_mode_exec"判定外层。
   *
   * 只在同一会话里找：跨会话的 code-mode 不会包住本次调用。
   */
  private findEnclosingCodeModeCall(
    ctx: MiddlewareContext,
    detKey: string
  ): string | undefined {
    const toolKind = ctx.toolKind || 'native';
    if (toolKind === 'code_mode_exec') return undefined;
    for (let i = this.inFlightCalls.length - 1; i >= 0; i--) {
      const entry = this.inFlightCalls[i];
      if (entry.detKey === detKey) continue;
      if (entry.sessionKey !== ctx.sessionKey) continue;
      if (entry.toolKind !== 'code_mode_exec') continue;
      return entry.detKey;
    }
    return undefined;
  }

  /** 在飞登记销账。 */
  private releaseInFlightCall(detKey: string | undefined): void {
    if (!detKey) return;
    const idx = this.inFlightCalls.findIndex((e) => e.detKey === detKey);
    if (idx >= 0) this.inFlightCalls.splice(idx, 1);
  }

  /** (sessionKey, toolName) 分桶键。 */
  private callBucket(sessionKey: string | undefined, toolName: string | undefined): string {
    return `${sessionKey ?? ''}::${toolName ?? ''}`;
  }

  /** 从在飞队列里摘掉一条已消费的调用 id（精确命中路径用）。 */
  private consumeInFlightCall(
    sessionKey: string | undefined,
    toolName: string | undefined,
    callId: string
  ): void {
    const bucket = this.callBucket(sessionKey, toolName);
    const queue = this.inFlightCallIds.get(bucket);
    if (!queue) return;
    const idx = queue.indexOf(callId);
    if (idx >= 0) {
      queue.splice(idx, 1);
    }
    if (queue.length === 0) {
      this.inFlightCallIds.delete(bucket);
      this.currentCallIds.delete(bucket);
    }
  }

  /**
   * Return the deterministic call id for the tool call that is currently
   * running. Used by middleware to bind system-layer monitoring context.
   *
   * 传入 sessionKey + toolName 时只在同名工具的桶里找，避免并发调用之间
   * 互相覆盖；两者缺一时回退到最近一次开始的调用（保持旧行为）。
   */
  getCurrentToolCallId(sessionKey?: string, toolName?: string): string | undefined {
    if (sessionKey && toolName) {
      const id = this.currentCallIds.get(this.callBucket(sessionKey, toolName));
      if (id) return id;
    }
    // 未指定工具名时回退到最近一次开始的调用（保持旧行为）。
    let latest: string | undefined;
    for (const id of this.currentCallIds.values()) {
      latest = id;
    }
    return latest;
  }

  /**
   * 宿主原始的工具调用 id（`tool_call:call_function_…`）。
   *
   * 与插件合成的 `tool_call_id` 是两套体系：前者用于跨系统对账，后者是
   * 本插件的关联权威键。1.1.0 之前宿主 id 只藏在 metadata 里，无法被
   * schema 约束。
   */
  private extractHostToolCallId(ctx: MiddlewareContext): string | undefined {
    const raw = ctx.metadata?.toolCallId ?? ctx.metadata?.tool_call_id;
    return typeof raw === 'string' && raw.length > 0 ? raw : undefined;
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  private buildBaseEvent(
    eventType: SecurityEvent['event_type'],
    sessionKey?: string,
    runId?: string,
    agentId?: string
  ): SecurityEvent {
    const now = Date.now();
    // File events belong to the system layer per file.json; everything else is application.
    const isFileEvent =
      typeof eventType === 'string' &&
      ['file_read', 'file_write', 'file_delete', 'file_privilege'].includes(eventType);
    const resolvedSessionId = sessionKey && sessionKey !== 'unknown' ? sessionKey : null;
    const resolvedRunId = runId && runId !== 'unknown' ? runId : null;
    const event: SecurityEvent = {
      comm: 'openclaw',
      event_id: generateUUID(),
      event_type: eventType,
      layer: isFileEvent ? 'system' : 'application',
      ts: now,
      schema_version: 1,
      pid: process.pid,
      session_id: resolvedSessionId,
      run_id: resolvedRunId,
      task_id: null,
      turn_id: null,
      agent_id: agentId ?? null,
      host_id: this.environment.hostId,
      container_id: this.environment.containerId,
      pod_name: this.environment.podName,
      namespace: this.environment.namespace,
      source: 'openclaw.v1',
      collection_method: 'agent_api',
      collector: {
        hook_name: eventType,
        middleware_name: 'sst-security-control-openclaw',
        collector_name: this.name,
      },
      // `blocked` 恒在（1.1.0 起）。此前它只在"确实被拦截"的事件上出现，
      // 其余事件整个键缺失——下游按 `blocked === false` 过滤会静默丢掉
      // 一批事件，也会把"未拦截"误读成"没评估过"。是否被策略命中
      // （warn / modify）看 `intervention.decision`，与本字段正交。
      blocked: false,
    };
    // 会话标题：首条有效 user 消息决定，latch 之后所有应用层事件都带。
    // 标题未确定时不出这个字段（缺失 = 尚未确定），而不是写空串。
    const title = resolvedSessionId ? this.sessionTitles.get(resolvedSessionId) : undefined;
    if (title) {
      // 每次使用都续期：活跃会话不会因为 TTL 到期把标题丢掉（那会让下一条
      // user 消息重新 latch 出另一个标题）。与 session 缓存的存活语义一致。
      title.lastAccessTime = now;
      event.session_title = title.title;
    }
    return event;
  }

  private hasMeaningfulAgentConfig(config?: AgentConfig): boolean {
    if (!config) return false;
    const c = config as AgentConfig & {
      agentDir?: unknown;
      mcpServers?: unknown;
      systemPrompt?: unknown;
    };
    return !!(
      config.name ||
      config.model ||
      config.provider ||
      config.description ||
      c.agentDir ||
      c.mcpServers ||
      c.systemPrompt ||
      config.tools?.length ||
      config.skills?.length
    );
  }

  private summarizeResult(result: unknown): {
    status: 'success' | 'error';
    size: number;
    fullLength: number;
    preview: string;
    error?: string;
  } {
    const text = typeof result === 'string' ? result : result === undefined ? '' : JSON.stringify(result);
    const hasError =
      result !== null &&
      result !== undefined &&
      typeof result === 'object' &&
      'error' in result &&
      (result as { error?: unknown }).error !== undefined;

    return {
      status: hasError ? 'error' : 'success',
      size: text.length,
      fullLength: text.length,
      preview: truncateString(result, this.config.maxResultPreviewLength ?? 500),
      error: hasError
        ? safeExtract(() => String((result as { error?: { message?: string } }).error?.message)) ||
          safeExtract(() => String((result as { error?: unknown }).error))
        : undefined,
    };
  }
}

// Runtime hook context helpers. These set global variables that the language-
// specific runtime hooks read to correlate command executions with the current
// OpenClaw tool call.
//
// 上下文按**在飞调用**登记，不是单一全局槽位：
//
// - 嵌套调用（code-mode exec 里跑的工具）：内层调用结束后必须把外层的
//   上下文恢复回来，否则外层后续 spawn 出来的命令会挂到内层调用名下；
// - 并发调用：结束其中一个不该把另一个的上下文一起抹掉。
//
// 所以这里维护一张"在飞调用 → 上下文"的表 + 一个开始顺序队列，当前上下文
// = 队列里最后一个还在飞的调用。

interface RuntimeContext {
  sessionId?: string;
  runId?: string;
  agentId?: string | undefined;
  toolCallId?: string;
  toolName?: string;
}

/** 在飞调用上限：超过就丢最老的一条（after hook 没跑到的漏网情况）。 */
const MAX_RUNTIME_CONTEXTS = 256;
/**
 * 在飞上下文的存活上限。
 *
 * after hook 没跑到的调用（宿主异常、插件被卸载）会留下一条永远"在飞"
 * 的上下文——它会在之后的每一次复位里被当成"最近的调用"选回来，把
 * runtime hook 事件挂到一个早就结束的老调用名下。超过这个时长就当它
 * 已经结束。
 */
const RUNTIME_CONTEXT_TTL_MS = 10 * 60 * 1000;

interface RuntimeContextEntry {
  ctx: RuntimeContext;
  setAt: number;
}

const runtimeContexts = new Map<string, RuntimeContextEntry>();
/** 开始顺序（队尾 = 最近开始的调用）。 */
const runtimeContextOrder: string[] = [];
let anonymousRuntimeContextSeq = 0;

function applyRuntimeContext(ctx: RuntimeContext | undefined): void {
  global.__OPENCLAW_SESSION_ID__ = ctx?.sessionId;
  global.__OPENCLAW_RUN_ID__ = ctx?.runId;
  global.__OPENCLAW_AGENT_ID__ = ctx?.agentId;
  global.__OPENCLAW_TOOL_CALL_ID__ = ctx?.toolCallId;
  global.__OPENCLAW_TOOL_NAME__ = ctx?.toolName;
}

/** 把当前上下文复位到"最近一个还在飞的调用"。 */
function restoreLatestRuntimeContext(): void {
  const now = Date.now();
  for (let i = runtimeContextOrder.length - 1; i >= 0; i--) {
    const key = runtimeContextOrder[i];
    const entry = runtimeContexts.get(key);
    if (entry && now - entry.setAt <= RUNTIME_CONTEXT_TTL_MS) {
      applyRuntimeContext(entry.ctx);
      return;
    }
    runtimeContextOrder.splice(i, 1);
    runtimeContexts.delete(key);
  }
  applyRuntimeContext(undefined);
}

export function setRuntimeContext(ctx: RuntimeContext): void {
  const key = ctx.toolCallId ?? `__anon_${++anonymousRuntimeContextSeq}`;
  if (!runtimeContexts.has(key)) {
    runtimeContextOrder.push(key);
  }
  runtimeContexts.set(key, { ctx, setAt: Date.now() });
  // 超出上限时丢最老的一条。
  while (runtimeContextOrder.length > MAX_RUNTIME_CONTEXTS) {
    const oldest = runtimeContextOrder.shift();
    if (oldest !== undefined) runtimeContexts.delete(oldest);
  }
  applyRuntimeContext(ctx);
}

/**
 * 摘掉一次调用的运行时上下文。
 *
 * 传 callId 时只摘那一条（嵌套/并发时外层与兄弟调用不受影响）；不传时
 * 摘掉最近开始的那条（兜底）。
 */
export function clearRuntimeContext(callId?: string): void {
  if (callId !== undefined) {
    runtimeContexts.delete(callId);
    const idx = runtimeContextOrder.indexOf(callId);
    if (idx >= 0) runtimeContextOrder.splice(idx, 1);
  } else {
    const latest = runtimeContextOrder.pop();
    if (latest !== undefined) runtimeContexts.delete(latest);
  }
  restoreLatestRuntimeContext();
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
