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
import { redactSensitiveBody, redactEventForEmit } from './redact.js';
import { generateUUID } from './uuid.js';
import { pidBindingStore } from './utils/pid-binding-store.js';
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
  private currentCallId?: string; // deterministicKey -> startTimes FIFO
  // Deterministic call correlation: keyed by session/run/tool/step so that
  // onAfterToolCall does not depend on the same context object reference.
  private callIdMap: WeakMap<MiddlewareContext, string> = new WeakMap();
  // Cache the per-call SecurityDecision so afterToolCall can stamp the result
  // event with the same blockCode/blockReason/guidance returned to the LLM.
  private decisionCache: Map<string, SecurityDecision> = new Map();
  // Track agent start timestamps by runId to compute duration on agent_stop
  private agentStartTimes: Map<string, number> = new Map();
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
  private agentSnapshotReporter?: AgentSnapshotReporterLike;

  constructor(
    collector: EventCollectorLike,
    config: ApplicationLayerConfig,
    environment: EnvironmentConfig = {},
    agentSnapshotReporter?: AgentSnapshotReporterLike,
    options?: { reportBlockedEvents?: boolean }
  ) {
    this.collector = collector;
    this.config = config;
    this.environment = environment;
    this.agentSnapshotReporter = agentSnapshotReporter;
    // intervention.reportBlockedEvents（默认 true）：false 时 blocked 事件不落盘。
    this.reportBlockedEvents = options?.reportBlockedEvents !== false;
  }

  private readonly reportBlockedEvents: boolean;

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
   * content (user_prompt, system_prompt, content, code_content, params) cannot
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
   * Look up the most recent user message for a given session.
   * Used by middleware to backfill user message content when OpenClaw passes
   * an empty ctx.content to beforeMessageWrite.
   */
  getLastUserMessage(sessionKey: string): string | undefined {
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
    const agentId = this.resolveAgentId(ctx.agentId, ctx.sessionKey, runId);
    const resolvedAgentName = agentConfig?.name || agentId;
    const event = this.buildBaseEvent(
      'agent_start',
      ctx.sessionKey,
      undefined,
      agentId
    );

    event.agent_name = resolvedAgentName;

    // Self-contained per-agent record: identity + description + model + system prompt
    // + resource topology all in one element so consumers can render the agent
    // card without joining agent_config / system_prompt / agent_resources.
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
      system_prompt: systemPrompt,
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

  private async emitAgentSessionStartIfNeeded(
    ctx: MessageWriteContext,
    agentId: string | undefined,
    sessionCtx: SessionContext
  ): Promise<void> {
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

    await this.emit(event);
  }

  async onMessageWrite(ctx: MessageWriteContext, decision?: SecurityDecision, mode?: 'audit' | 'enforce'): Promise<void> {
    // OpenClaw may fire both a plain message_received hook and a
    // before_prompt_build hook for the same user input. The latter wraps the
    // real input in metadata (timestamp etc.). After normalization the text
    // matches the earlier event, so skip the duplicate to avoid double logging.
    if (
      ctx.role === 'user' &&
      typeof ctx.content === 'string' &&
      ctx.content.length > 0 &&
      ctx.content === this.getSessionContext(ctx.sessionKey).userPrompt
    ) {
      return;
    }

    // OpenClaw sometimes emits an empty assistant placeholder before the real
    // assistant response arrives (e.g. streaming start or pre-delta hook).
    // Drop it so the event stream only contains meaningful content, unless it
    // carries reasoning that we want to capture.
    if (
      ctx.role === 'assistant' &&
      (!ctx.content || (typeof ctx.content === 'string' && ctx.content.trim().length === 0)) &&
      !ctx.reasoning
    ) {
      return;
    }

    // Drop OpenClaw noise: lifecycle events (e.g. /new, session resume) get
    // routed through message_received with default user role and empty content,
    // and we also lack session metadata. Nothing actionable to record.
    if (
      ctx.role === 'user' &&
      (!ctx.sessionKey || ctx.sessionKey === 'unknown') &&
      (!ctx.content || (typeof ctx.content === 'string' && ctx.content.trim().length === 0))
    ) {
      return;
    }

    // Adjacent-duplicate suppression: same role+content as the last message we
    // already reported for this session means the upstream redelivered it
    // (synchronous-hook guidance loops, dual persist paths). See the field
    // comment above for why adjacency is the safe criterion.
    const normalizedContent = typeof ctx.content === 'string' ? ctx.content : '';
    const last = this.lastMessageBySession.get(ctx.sessionKey);
    if (
      last &&
      last.role === ctx.role &&
      last.content.length > 0 &&
      last.content === normalizedContent
    ) {
      return;
    }

    // Cache recent user messages so a later agent_start (which may lack a
    // session_id) can borrow the correct session_id for correlation.
    if (ctx.role === 'user' && typeof ctx.content === 'string' && ctx.content.length > 0) {
      this.recentUserMessages.set(ctx.content, {
        sessionKey: ctx.sessionKey,
        content: ctx.content,
        timestamp: Date.now(),
      });
      this.cleanupRecentUserMessages(Date.now());
    }

    const sessionCtx = this.updateSessionFromMessage(ctx);
    const messageAgentId = this.resolveAgentId(sessionCtx.agentId, ctx.sessionKey, ctx.runId);

    // Emit agent_session_start once per conversation when the first real user
    // message arrives. This separates the agent/process lifecycle (agent_start)
    // from the user<->agent session lifecycle per project_standards.
    if (ctx.role === 'user' && ctx.sessionKey && ctx.sessionKey !== 'unknown') {
      await this.emitAgentSessionStartIfNeeded(ctx, messageAgentId, sessionCtx);
    }

    const event = this.buildBaseEvent(
      'agent_message',
      ctx.sessionKey,
      ctx.runId,
      messageAgentId
    );

    event.role = ctx.role;
    // Backfill user message content from cache when OpenClaw passes empty content.
    const effectiveContent =
      (ctx.role === 'user' &&
        typeof ctx.content === 'string' &&
        ctx.content.length === 0 &&
        this.getLastUserMessage(ctx.sessionKey)) ||
      ctx.content;
    // user-role content IS the user prompt; honor captureUserPrompt the same
    // way tool_call.user_prompt does.
    const captureUserPrompt = this.config.captureUserPrompt ?? true;
    event.content =
      ctx.role === 'user' && !captureUserPrompt
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
    event.message_index = sessionCtx.messageIndex;
    event.user_id = (this.config.captureUserId ?? true) ? sessionCtx.userId || undefined : undefined;
    event.system_prompt =
      (this.config.captureSystemPrompt ?? true)
        ? sessionCtx.systemPrompt || undefined
        : undefined;
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
    }

    // Remember what we actually reported so the next message can be compared
    // for adjacency. Only track messages with non-empty content; empty ones
    // were already filtered above.
    if (normalizedContent.length > 0) {
      this.lastMessageBySession.set(ctx.sessionKey, { role: ctx.role, content: normalizedContent });
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

    // Publish OpenClaw context so that runtime hooks can correlate command
    // executions with the current tool call.
    const callId = this.generateDeterministicCallId(ctx, sessionCtx.stepIndex);
    setRuntimeContext({
      sessionId: ctx.sessionKey,
      runId: ctx.runId,
      agentId: this.resolveAgentId(ctx.agentId, ctx.sessionKey, ctx.runId),
      toolCallId: callId,
      toolName: ctx.toolName,
    });

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
    const detKey = this.generateDeterministicCallId(ctx, sessionCtx.stepIndex);
    const list = this.callStartTimes.get(detKey) ?? [];
    list.push(startTime);
    this.callStartTimes.set(detKey, list);

    // Store deterministic key so afterToolCall can correlate even when the
    // framework passes a different context object for the after hook.
    this.callIdMap.set(ctx, detKey);
    if (decision) this.decisionCache.set(detKey, decision);

    // Also store the current call id so middleware can retrieve it for system-layer binding.
    this.currentCallId = detKey;

    // Ensure session context is cached
    this.sessionCache.set(ctx.sessionKey, {
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
    event.tool_name = ctx.toolName;
    event.tool_kind = ctx.toolKind || 'native';
    event.tool_description = safeExtract(() => ctx.toolDescription);

    // Normalize file path for file operation events. Data standard: the path
    // field is exposed as `path` (not `file_path`) on the emitted event and
    // in the published params/raw_params/tool_params payloads so downstream
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
        // event.path, event.params.path, raw_params and tool_params.
        if (typeof params.file_path === 'string') {
          // eslint-disable-next-line @typescript-eslint/no-unused-vars
          const { file_path: _unused, ...rest } = params;
          normalizedParams = { ...rest, path: filePath };
        }
      }
    }

    event.params = redactSensitiveBody(normalizedParams) as Record<string, unknown> | undefined;

    const redactedParams = redactSensitiveBody(normalizedParams);
    const rawParamsText = JSON.stringify(redactedParams);
    const maxRawLen = this.config.maxRawParamsLength ?? 10000;
    event.raw_params =
      rawParamsText.length > maxRawLen ? rawParamsText.slice(0, maxRawLen) + '...' : rawParamsText;
    event.raw_params_length = rawParamsText.length;
    event.tool_params = event.raw_params; // Standard event field

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
        this.sessionCache.set(ctx.sessionKey, { context: sessionCtx, lastAccessTime: Date.now() });
        if (ctx.runId && ctx.runId !== 'unknown') {
          this.runIdAgentCache.set(ctx.runId, {
            agentId: inferredFromPath,
            lastAccessTime: Date.now(),
          });
        }
      }
    }

    event.user_prompt =
      (this.config.captureUserPrompt ?? true) ? sessionCtx.userPrompt || undefined : undefined;
    event.system_prompt =
      (this.config.captureSystemPrompt ?? true)
        ? sessionCtx.systemPrompt || undefined
        : undefined;
    event.agent_plan =
      (this.config.captureAgentPlan ?? true)
        ? sessionCtx.currentPlan.length > 0
          ? sessionCtx.currentPlan
          : undefined
        : undefined;
    event.previous_actions =
      sessionCtx.previousActions.length > 0 ? sessionCtx.previousActions : undefined;
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
        modified_params: decision.modifiedParams,
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
    // Clear runtime hook context after the tool call finishes. This is best-
    // effort for sequential tool execution; concurrent calls may overlap.
    clearRuntimeContext();

    const detKey = this.extractCallId(ctx);
    if (detKey !== undefined) {
      this.callIdMap.delete(ctx);
    }
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
      this.sessionCache.set(ctx.sessionKey, { context: sessionCtx, lastAccessTime: Date.now() });
      if (ctx.runId && ctx.runId !== 'unknown') {
        this.runIdAgentCache.set(ctx.runId, {
          agentId: resultAgentId,
          lastAccessTime: Date.now(),
        });
      }
    }

    const summary = this.summarizeResult(result);
    const effectiveAgentId = this.resolveAgentId(ctx.agentId, ctx.sessionKey, ctx.runId);
    const callId = this.extractCallId(ctx);

    const event = this.buildBaseEvent(
      'agent_tool_result',
      ctx.sessionKey,
      ctx.runId,
      effectiveAgentId
    );

    event.tool_call_id = callId;
    event.tool_name = ctx.toolName;
    event.tool_kind = ctx.toolKind || 'native';
    event.execution_duration_ms = startTime ? Date.now() - startTime : undefined;
    event.duration = event.execution_duration_ms; // Standard event field
    // When the call was blocked by policy the tool either never ran or its
    // output was replaced by a block notice. Report a blocked status so the
    // downstream does not mistake the call for a successful execution.
    const blockedByPolicy = decision?.decision === 'block';
    event.execution_status = blockedByPolicy ? 'blocked' : summary.status;
    event.status = blockedByPolicy
      ? 'failure'
      : summary.status === 'error'
        ? 'failure'
        : 'success'; // Standard event field (enum: success/failure)
    if (blockedByPolicy) {
      event.blocked = true; // Required when tool call is blocked by policy
    }
    event.result_size = summary.size;
    event.result_preview = summary.preview;
    event.result_preview_length = summary.fullLength;
    event.result = summary.preview; // Standard event field: JSON string result
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
    event.status = ctx.status || 'ended';
    event.execution_status = event.status;
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
    const event = this.buildBaseEvent('agent_subagent_start', ctx.sessionKey, ctx.runId, effectiveAgentId);
    this.fillSubagentRecord(event, ctx);
    await this.emit(event);
  }

  async onSubagentProgress(ctx: SubagentContext): Promise<void> {
    const effectiveAgentId = this.resolveAgentId(ctx.agentId, ctx.sessionKey, ctx.runId);
    const event = this.buildBaseEvent('agent_subagent_progress', ctx.sessionKey, ctx.runId, effectiveAgentId);
    this.fillSubagentRecord(event, ctx);
    if (ctx.progress !== undefined) {
      event.content = truncateString(String(ctx.progress), this.config.maxContentLength ?? 2000);
    }
    await this.emit(event);
  }

  async onSubagentEnd(ctx: SubagentContext): Promise<void> {
    const effectiveAgentId = this.resolveAgentId(ctx.agentId, ctx.sessionKey, ctx.runId);
    const event = this.buildBaseEvent('agent_subagent_end', ctx.sessionKey, ctx.runId, effectiveAgentId);
    this.fillSubagentRecord(event, ctx);
    const failed = ctx.status === 'error' || ctx.error !== undefined;
    event.execution_status = failed ? 'error' : ctx.status || 'success';
    event.status = failed ? 'failure' : 'success';
    if (ctx.output !== undefined) {
      const preview = truncateString(String(ctx.output), this.config.maxResultPreviewLength ?? 500);
      event.result = preview;
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

  async onCronEvent(ctx: CronEventContext): Promise<void> {
    const effectiveAgentId = this.resolveAgentId(ctx.agentId, ctx.sessionKey, ctx.runId);
    const event = this.buildBaseEvent('cron_changed', ctx.sessionKey, ctx.runId, effectiveAgentId);
    event.status = ctx.action || 'changed';
    event.metadata = {
      ...(ctx.cronId ? { cron_id: ctx.cronId } : {}),
      ...(ctx.cronName ? { cron_name: ctx.cronName } : {}),
      ...(ctx.schedule ? { schedule: ctx.schedule } : {}),
    };
    if (typeof ctx.enabled === 'boolean') {
      event.metadata.enabled = ctx.enabled;
    }
    if (ctx.firedResult !== undefined) {
      event.metadata.fired_result = truncateString(
        String(ctx.firedResult),
        this.config.maxResultPreviewLength ?? 500
      );
    }
    await this.emit(event);
  }

  async onAgentComplete(ctx: AgentCompleteContext): Promise<void> {
    const effectiveAgentId = this.resolveAgentId(ctx.agentId, ctx.sessionKey, ctx.runId);
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

    event.execution_status = status;
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
    event.result_preview_length =
      ctx.output !== undefined ? computeContentLength(ctx.output) : undefined;
    event.result = event.result_preview; // Standard event field
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
    sessionKey: string,
    agentConfig?: AgentConfig,
    systemPrompt?: string,
    agentId?: string,
    runId?: string
  ): void {
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

  private getSessionContext(sessionKey: string): SessionContext {
    const entry = this.sessionCache.get(sessionKey);
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

  private updateSessionFromMessage(ctx: MessageWriteContext): SessionContext {
    const existing = this.getSessionContext(ctx.sessionKey);

    existing.messageIndex += 1;

    if (ctx.role === 'user' && typeof ctx.content === 'string') {
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

    this.sessionCache.set(ctx.sessionKey, {
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
      params: redactSensitiveBody(ctx.params) as Record<string, unknown> | undefined,
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

    this.sessionCache.set(ctx.sessionKey, {
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

    // Clean up stale run_id -> agent_id associations.
    for (const [runId, entry] of this.runIdAgentCache.entries()) {
      if (now - entry.lastAccessTime > ttlMs) {
        this.runIdAgentCache.delete(runId);
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Call correlation helpers
  // ---------------------------------------------------------------------------

  private generateDeterministicCallId(ctx: MiddlewareContext, stepIndex: number): string {
    return `${ctx.sessionKey}:${ctx.runId}:${ctx.toolName}:${stepIndex}`;
  }

  private extractCallId(ctx: MiddlewareContext): string | undefined {
    return (
      this.callIdMap.get(ctx) ??
      this.currentCallId ??
      this.generateDeterministicCallId(
        ctx,
        this.getSessionContext(ctx.sessionKey).stepIndex
      )
    );
  }

  /**
   * Return the deterministic call id for the current/last tool call.
   * Used by middleware to bind system-layer monitoring context.
   */
  getCurrentToolCallId(): string | undefined {
    return this.currentCallId;
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
    return {
      comm: 'openclaw',
      event_id: generateUUID(),
      event_type: eventType,
      layer: isFileEvent ? 'system' : 'application',
      ts: now,
      schema_version: '1.0.0',
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
    };
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
// OpenClaw tool call. The context is best-effort for sequential execution.

interface RuntimeContext {
  sessionId?: string;
  runId?: string;
  agentId?: string | undefined;
  toolCallId?: string;
  toolName?: string;
}

export function setRuntimeContext(ctx: RuntimeContext): void {
  global.__OPENCLAW_SESSION_ID__ = ctx.sessionId;
  global.__OPENCLAW_RUN_ID__ = ctx.runId;
  global.__OPENCLAW_AGENT_ID__ = ctx.agentId;
  global.__OPENCLAW_TOOL_CALL_ID__ = ctx.toolCallId;
  global.__OPENCLAW_TOOL_NAME__ = ctx.toolName;
}

export function clearRuntimeContext(): void {
  global.__OPENCLAW_SESSION_ID__ = undefined;
  global.__OPENCLAW_RUN_ID__ = undefined;
  global.__OPENCLAW_AGENT_ID__ = undefined;
  global.__OPENCLAW_TOOL_CALL_ID__ = undefined;
  global.__OPENCLAW_TOOL_NAME__ = undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
