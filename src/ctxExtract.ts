// Pure helpers for extracting structured fields from arbitrary OpenClaw hook
// envelopes. Every function tolerates unknown shapes (different OpenClaw
// versions, partial envelopes, JSON-stringified payloads). No I/O, no global
// state — safe to import from any layer.

import type {
  AgentStartContext,
  AgentCompleteContext,
  MiddlewareContext,
  MessageWriteContext,
  SessionEndContext,
  SubagentContext,
  CronEventContext,
} from './types.js';

export function extractEventContext(input: unknown): Record<string, unknown> {
  if (!input || typeof input !== 'object') return {};
  const evt = input as Record<string, unknown>;
  const context =
    evt.context && typeof evt.context === 'object' && !Array.isArray(evt.context)
      ? (evt.context as Record<string, unknown>)
      : {};
  // Context fields take precedence over event envelope fields.
  return { ...evt, ...context };
}

/**
 * Merge OpenClaw 8.2 `(event, ctx)` hook arguments into a single object.
 * Legacy single-argument hooks pass through unchanged.
 */
export function mergeHookArgs(args: unknown[]): unknown {
  if (args.length === 0) return undefined;
  if (args.length === 1) return args[0];

  const [event, ctx] = args;

  // Heuristic: if the second arg is not object-shaped, treat the first arg as
  // the only meaningful payload (legacy or unusual signature).
  if (!ctx || typeof ctx !== 'object' || Array.isArray(ctx)) {
    return event;
  }

  // If the event itself is not object-shaped, return the context.
  if (!event || typeof event !== 'object' || Array.isArray(event)) {
    return ctx;
  }

  // Merge event and ctx, with ctx identity fields taking precedence.
  // Any additional positional args are ignored; typed hooks in 8.2 only use two.
  const merged: Record<string, unknown> = { ...(event as Record<string, unknown>) };
  const ctxObj = ctx as Record<string, unknown>;
  for (const key of Object.keys(ctxObj)) {
    if (ctxObj[key] !== undefined) {
      merged[key] = ctxObj[key];
    }
  }
  return merged;
}

export function coalesceString(
  ctx: Record<string, unknown>,
  keys: string[]
): string | undefined {
  for (const key of keys) {
    const value = ctx[key];
    if (typeof value === 'string' && value.length > 0) {
      return value;
    }
    if (value && typeof value === 'object') {
      // Some frameworks nest ids under objects, e.g. session.id, agent.id
      const nested = value as Record<string, unknown>;
      for (const sub of ['id', 'key', 'name']) {
        const subValue = nested[sub];
        if (typeof subValue === 'string' && subValue.length > 0) {
          return subValue;
        }
      }
    }
  }
  return undefined;
}

/**
 * 从消息/工具 metadata 里按优先级归并执行用户标识（审计归因）。
 *
 * 优先级：`metadata[userIdField]`（默认 'userId'，第一优先级与原单字段
 * 提取完全同口径）→ `__openclaw.senderIdentity.id` → `__openclaw.senderName`
 * → `__openclaw.senderUsername` → `senderId`，第一个非空字符串胜出。
 * 宿主把用户身份挂在消息 `__openclaw` 元数据块里；userIdField 取不到时
 * 靠这层回退保住归因。`captureUserId === false` 的闸门由调用处负责。
 */
export function coalesceUserId(
  metadata: Record<string, unknown> | undefined,
  userIdField: string
): string | undefined {
  if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) {
    return undefined;
  }
  const direct = metadata[userIdField];
  if (typeof direct === 'string' && direct.length > 0) return direct;

  const openclaw = metadata.__openclaw;
  const openclawMeta =
    openclaw && typeof openclaw === 'object' && !Array.isArray(openclaw)
      ? (openclaw as Record<string, unknown>)
      : undefined;
  if (openclawMeta) {
    const identity = openclawMeta.senderIdentity;
    if (identity && typeof identity === 'object' && !Array.isArray(identity)) {
      const id = (identity as Record<string, unknown>).id;
      if (typeof id === 'string' && id.length > 0) return id;
    }
    const name = openclawMeta.senderName;
    if (typeof name === 'string' && name.length > 0) return name;
    const username = openclawMeta.senderUsername;
    if (typeof username === 'string' && username.length > 0) return username;
  }

  const senderId = metadata.senderId;
  if (typeof senderId === 'string' && senderId.length > 0) return senderId;
  return undefined;
}

/**
 * 抽取会话键。
 *
 * 注意：这里**不收** runId / run_id / run——规范（common.json）只允许
 * run_id 向下回退 task_id / session_id；反向把 session 键填成 run_id 会把
 * 不同会话的事件假性关联成同一会话。平台侧同样要求"无法取得真实编号时保留
 * 缺失，不能保存假编号"（docs/knowledge/collector-compatibility.md）。
 * run 身份走 extractRunId 自己的通道。
 */
export function extractSessionKey(ctx: Record<string, unknown>): string | undefined {
  // 注意：这里**不收** runId / run_id / run——规范（common.json）只允许
  // run_id 向下回退 task_id/session_id，反向把 session 键填成 run_id 会把
  // 不同会话的事件假性关联成同一会话。run 身份走 extractRunId 自己的通道。
  const topLevel = coalesceString(ctx, [
    'sessionKey',
    'session_id',
    'sessionId',
    'sessionID',
    'session',
    'threadId',
    'thread_id',
    'threadID',
    'thread',
    'chatId',
    'chat_id',
    'chatID',
    'chat',
    'conversationId',
    'conversation_id',
    'conversation',
    'id',
  ]);
  if (topLevel) return topLevel;

  // Some OpenClaw hooks only expose the conversation id inside metadata.
  const metadata = (ctx.metadata || ctx.context) as Record<string, unknown> | undefined;
  if (metadata && typeof metadata === 'object') {
    return coalesceString(metadata, [
      'sessionKey',
      'session_id',
      'sessionId',
      'sessionID',
      'session',
      'messageId',
      'message_id',
      'messageID',
      'threadId',
      'thread_id',
      'threadID',
      'thread',
      'chatId',
      'chat_id',
      'chatID',
      'chat',
      'conversationId',
      'conversation_id',
      'conversation',
      'id',
    ]);
  }

  return undefined;
}

/**
 * Best-effort inference of an agent identity from an OpenClaw session key.
 * OpenClaw does not always expose an explicit agentId, but its session_id
 * naming conventions encode the agent name:
 *   - "agent:<name>:<suffix>"   -> "<name>"
 *   - "<name>-<timestamp>"      -> "<name>"
 * Values that are "unknown" or empty are ignored.
 */
export function inferAgentIdFromSessionKey(sessionKey: string): string | undefined {
  if (!sessionKey || sessionKey === 'unknown') return undefined;

  if (sessionKey.startsWith('agent:')) {
    const parts = sessionKey.split(':');
    if (parts.length >= 2 && parts[1] && parts[1] !== 'unknown') {
      return parts[1];
    }
  }

  const match = sessionKey.match(/^(.+)-\d{13,}$/);
  if (match && match[1] && match[1] !== 'unknown') {
    return match[1];
  }

  return undefined;
}

/**
 * Infer an agent name from the on-disk workspace directory OpenClaw uses for
 * the agent. Paths such as "/root/.openclaw/workspace/main/" yield "main".
 */
export function inferAgentNameFromAgentDir(agentDir: string): string | undefined {
  if (!agentDir || agentDir === 'unknown') return undefined;

  const workspaceMatch = agentDir.match(/[\\/]\.openclaw[\\/]workspace[\\/]([^\\/]+)(?:[\\/]|$)/);
  if (workspaceMatch && workspaceMatch[1] && workspaceMatch[1] !== 'unknown') {
    return workspaceMatch[1];
  }

  const segments = agentDir.split(/[\\/]/).filter(Boolean);
  const last = segments[segments.length - 1];
  if (last && last !== 'unknown') return last;

  return undefined;
}

export function extractAgentId(ctx: Record<string, unknown>): string | undefined {
  const topLevel = coalesceString(ctx, [
    'agentId',
    'agent_id',
    'agentID',
    'agent',
    'agentName',
    'agent_name',
  ]);
  if (topLevel) return topLevel;

  // OpenClaw sometimes flattens agent metadata (name) or nests it in agentConfig/agent.
  const agentConfig =
    (ctx.agentConfig as Record<string, unknown> | undefined) ||
    (ctx.agent_config as Record<string, unknown> | undefined) ||
    (ctx.agent as Record<string, unknown> | undefined);
  if (agentConfig && typeof agentConfig === 'object') {
    const fromConfig = coalesceString(agentConfig, ['name', 'id', 'agentId', 'agent_id']);
    if (fromConfig) return fromConfig;
  }

  const metadata = (ctx.metadata || ctx.context) as Record<string, unknown> | undefined;
  if (metadata && typeof metadata === 'object') {
    const fromMetadata = coalesceString(metadata, ['agentId', 'agent_id', 'agentID', 'agent', 'agentName', 'agent_name']);
    if (fromMetadata) return fromMetadata;
  }

  // Last-resort fallback: infer the agent name from the session key itself.
  const sessionKey = coalesceString(ctx, ['session_id', 'sessionId', 'sessionKey', 'session']);
  if (sessionKey) {
    const inferred = inferAgentIdFromSessionKey(sessionKey);
    if (inferred) return inferred;
  }

  return undefined;
}

export function extractRunId(ctx: Record<string, unknown>): string | undefined {
  return coalesceString(ctx, ['runId', 'run_id', 'runID', 'run', 'jobId', 'job_id', 'jobID']);
}

export function extractTextFromMessageContent(content: unknown): string | undefined {
  if (typeof content === 'string' && content.length > 0) return content;
  if (Array.isArray(content)) {
    const texts: string[] = [];
    for (const item of content) {
      if (item && typeof item === 'object' && typeof (item as Record<string, unknown>).text === 'string') {
        texts.push((item as Record<string, unknown>).text as string);
      }
    }
    return texts.length > 0 ? texts.join('\n') : undefined;
  }
  return undefined;
}

export function findMessageByRole(
  messages: unknown,
  role: string
): string | undefined {
  if (!Array.isArray(messages)) return undefined;
  for (const msg of messages) {
    if (msg && typeof msg === 'object' && (msg as Record<string, unknown>).role === role) {
      const text = extractTextFromMessageContent((msg as Record<string, unknown>).content);
      if (text) return text;
    }
  }
  return undefined;
}

export function extractModelFromMessages(
  messages: unknown
): { provider?: string; name?: string } | undefined {
  if (!Array.isArray(messages)) return undefined;
  // Prefer the most recent assistant message that carries model info.
  for (let i = messages.length - 1; i >= 0; i--) {
    const msg = messages[i];
    if (!msg || typeof msg !== 'object') continue;
    const record = msg as Record<string, unknown>;
    if (record.role !== 'assistant') continue;
    const provider = typeof record.provider === 'string' ? record.provider : undefined;
    const name = typeof record.model === 'string' ? record.model : undefined;
    if (provider || name) {
      return { provider, name };
    }
  }
  return undefined;
}

export function normalizeAgentStartContext(input: unknown): AgentStartContext | undefined {
  if (!input || typeof input !== 'object') return undefined;
  const ctx = extractEventContext(input);

  const messages = Array.isArray(ctx.messages) ? ctx.messages : undefined;
  // Prefer explicit systemPrompt; otherwise look for role=system in messages.
  // Do NOT fall back to ctx.prompt because that is usually the user input.
  const systemPrompt =
    (ctx.systemPrompt as string | undefined) ||
    (ctx.system_prompt as string | undefined) ||
    findMessageByRole(messages, 'system');

  let agentConfig =
    (ctx.agentConfig as AgentStartContext['agentConfig']) ||
    (ctx.agent_config as AgentStartContext['agentConfig']) ||
    (ctx.agent as AgentStartContext['agentConfig']) ||
    undefined;

  // Some OpenClaw versions nest the agent config under ctx.config.agent or ctx.agent.config.
  if (!agentConfig || Object.keys(agentConfig).length === 0) {
    const configObj = ctx.config as Record<string, unknown> | undefined;
    agentConfig =
      (configObj?.agent as AgentStartContext['agentConfig']) ||
      (configObj?.agentConfig as AgentStartContext['agentConfig']) ||
      agentConfig;
  }
  if (!agentConfig || Object.keys(agentConfig).length === 0) {
    const agentObj = ctx.agent as Record<string, unknown> | undefined;
    agentConfig =
      (agentObj?.config as AgentStartContext['agentConfig'] | undefined) || agentConfig;
  }

  // Some OpenClaw versions flatten agent metadata into the hook context itself
  // (name, model, skills, tools). Lift those into the agent config when present.
  const liftedFields: Record<string, unknown> = {};
  if (!agentConfig?.name && typeof ctx.name === 'string') {
    liftedFields.name = ctx.name;
  }
  if (!agentConfig?.model) {
    const modelObj = ctx.model as Record<string, unknown> | undefined;
    if (modelObj && typeof modelObj === 'object') {
      liftedFields.model = modelObj;
    } else if (typeof ctx.model === 'string') {
      liftedFields.model = { name: ctx.model };
    }
  }
  if (!agentConfig?.provider && typeof ctx.provider === 'string') {
    liftedFields.provider = ctx.provider;
  }
  // 8.2 exposes model identity as modelProviderId/modelId (authoritative, set by
  // the runtime) — use them when no legacy model payload is present.
  if (!agentConfig?.model?.name && typeof ctx.modelId === 'string') {
    liftedFields.model = {
      name: ctx.modelId,
      provider:
        (typeof ctx.modelProviderId === 'string' ? ctx.modelProviderId : undefined) ||
        agentConfig?.model?.provider ||
        liftedFields.provider,
    };
  }
  if (!agentConfig?.description && typeof ctx.description === 'string') {
    liftedFields.description = ctx.description;
  }
  // OpenClaw 8.2 exposes the on-disk workspace as `workspaceDir` on the agent
  // context. Prefer it over the agentConfig path because it is bound by the
  // runtime and stable across hooks; both are accepted.
  if (!agentConfig?.agentDir) {
    const dir = ctx.workspaceDir ?? ctx.workspace_dir ?? ctx.agentDir;
    if (typeof dir === 'string' && dir.length > 0) {
      liftedFields.agentDir = dir;
    }
  }
  // If the agent config still lacks a name, try to infer it from the on-disk
  // workspace directory (e.g. /root/.openclaw/workspace/main/ -> "main").
  if (!agentConfig?.name && !liftedFields.name) {
    const agentDir =
      (liftedFields.agentDir as string | undefined) ||
      (agentConfig?.agentDir as string | undefined) ||
      (ctx.agentDir as string | undefined);
    const inferredName = typeof agentDir === 'string' ? inferAgentNameFromAgentDir(agentDir) : undefined;
    if (inferredName) {
      liftedFields.name = inferredName;
    }
  }

  // OpenClaw's agent_start hook carries conversation history in messages[].
  // The latest assistant entry often includes provider/model info we can reuse.
  const modelFromHistory = extractModelFromMessages(messages);
  if (modelFromHistory?.provider && !liftedFields.provider) {
    liftedFields.provider = modelFromHistory.provider;
  }
  if (modelFromHistory?.name && !liftedFields.model) {
    liftedFields.model = { name: modelFromHistory.name };
  }

  // Always include a lightweight raw-shape summary for debugging, because
  // OpenClaw versions vary widely in what they pass to before_agent_start.
  // For messages[], preserve metadata and usage numbers but collapse content
  // so the event stays compact. Increase depth slightly so usage numbers are
  // not truncated by the generic shape summarizer.
  const rawShapeForDebug = {
    ...ctx,
    messages: summarizeMessagesForAgentStart(ctx.messages),
  };
  const debugInfo = {
    _debug_keys: Object.keys(ctx),
    _raw_shape: summarizeRawShape(rawShapeForDebug, 5),
  };
  agentConfig = agentConfig
    ? { ...agentConfig, ...liftedFields, ...debugInfo }
    : ({ ...liftedFields, ...debugInfo } as AgentStartContext['agentConfig']);

  return {
    // Prefer the stable sessionKey over raw sessionId: some OpenClaw versions
    // pass both (sessionId as a UUID, sessionKey as agent:main:main), and other
    // hooks only carry sessionKey. Mixing them would break per-session
    // correlation, so sessionKey always wins; sessionId remains a fallback
    // inside extractSessionKey for versions without sessionKey.
    //
    // 规范（common.json）：session 未知必须写 null，只允许 run_id 向下回退
    // task_id/session_id——反向把 session_id 填成 run_id 会把不同会话的事件
    // 假性关联成同一会话。拿不到就是 undefined，由 buildBaseEvent 落 null。
    sessionKey: extractSessionKey(ctx),
    agentId:
      (ctx.agentId as string | undefined) ||
      (ctx.agent_id as string | undefined) ||
      extractAgentId(ctx) ||
      agentConfig?.name ||
      'unknown',
    agentConfig,
    systemPrompt,
    skills: Array.isArray(ctx.skills) ? (ctx.skills as string[]) : undefined,
    tools: Array.isArray(ctx.tools) ? (ctx.tools as string[]) : undefined,
  };
}

export function normalizeAgentCompleteContext(
  input: unknown
): AgentCompleteContext | undefined {
  if (!input || typeof input !== 'object') return undefined;
  const ctx = extractEventContext(input);

  const status =
    (ctx.status as string | undefined) ||
    (ctx.runStatus as string | undefined) ||
    (ctx.execution_status as string | undefined);

  const output =
    ctx.output !== undefined
      ? ctx.output
      : ctx.result !== undefined
      ? ctx.result
      : ctx.response !== undefined
      ? ctx.response
      : undefined;

  const runId = extractRunId(ctx);
  return {
    // session 未知就是 undefined（见 normalizeAgentStartContext），不回退 runId。
    sessionKey: extractSessionKey(ctx),
    agentId: extractAgentId(ctx) || 'unknown',
    runId,
    status,
    output,
    error: ctx.error,
  };
}

export function normalizeSessionEndContext(
  input: unknown
): SessionEndContext | undefined {
  if (!input || typeof input !== 'object') return undefined;
  const ctx = extractEventContext(input);

  const runId = extractRunId(ctx);
  const sessionKey = extractSessionKey(ctx);
  // Skip envelopes without any identity — nothing actionable to report.
  if (!sessionKey && !runId && !extractAgentId(ctx)) return undefined;

  return {
    // session 未知就是 undefined，不回退 runId（规范：session 未知写 null）。
    sessionKey,
    runId,
    agentId: extractAgentId(ctx),
    status: extractStringField(ctx, ['status', 'runStatus', 'execution_status']),
    content:
      ctx.content !== undefined
        ? ctx.content
        : ctx.lastMessage !== undefined
        ? ctx.lastMessage
        : undefined,
    metadata: ctx.metadata as Record<string, unknown> | undefined,
  };
}

export function normalizeSubagentContext(
  input: unknown,
  defaultStatus?: string
): SubagentContext | undefined {
  if (!input || typeof input !== 'object') return undefined;
  const ctx = extractEventContext(input);

  const runId = extractRunId(ctx);
  // session 未知就是 undefined，不回退 runId（规范：session 未知写 null）。
  const sessionKey = extractSessionKey(ctx);

  // subagent metadata may be flattened on the ctx or nested under subagent /
  // subagentInfo. Tolerate both.
  const subagent = (
    (ctx.subagent as Record<string, unknown> | undefined) ||
    (ctx.subagentInfo as Record<string, unknown> | undefined) ||
    {}
  ) as Record<string, unknown>;

  const subagentId =
    coalesceString(ctx, ['subagentId', 'subagent_id', 'subAgentId', 'subagentID', 'id']) ||
    (typeof subagent.id === 'string' && subagent.id ? subagent.id : undefined);
  const subagentName =
    coalesceString(ctx, ['subagentName', 'subagent_name', 'subAgentName', 'name']) ||
    (typeof subagent.name === 'string' && subagent.name ? subagent.name : undefined);
  const parentRunId =
    coalesceString(ctx, ['parentRunId', 'parent_run_id', 'parentRun', 'parent']) ||
    (typeof subagent.parentRunId === 'string' ? subagent.parentRunId : undefined);
  const prompt = ctx.prompt ?? subagent.prompt;

  return {
    sessionKey,
    runId,
    agentId: extractAgentId(ctx) || (typeof subagent.agentId === 'string' ? subagent.agentId : undefined),
    parentRunId,
    subagentId,
    subagentName,
    status: extractStringField(ctx, ['status', 'runStatus']) || defaultStatus,
    prompt: typeof prompt === 'string' && prompt.length > 0 ? prompt : undefined,
    output: ctx.output !== undefined ? ctx.output : ctx.result !== undefined ? ctx.result : undefined,
    error: ctx.error,
    progress: ctx.progress,
    metadata: ctx.metadata as Record<string, unknown> | undefined,
  };
}

export function normalizeCronEventContext(
  input: unknown
): CronEventContext | undefined {
  if (!input || typeof input !== 'object') return undefined;
  const ctx = extractEventContext(input);

  const runId = extractRunId(ctx);
  // session 未知就是 undefined，不回退 runId（规范：session 未知写 null）。
  const sessionKey = extractSessionKey(ctx);

  // 8.2 cron_changed payloads nest the job under cron/cronTask; tolerates both.
  //
  // 1.1.0 之前这里是 `(ctx.cron || ctx.cronTask || {})`：`||` 只看真值，
  // 不看类型。当宿主把 cron **表达式字符串**放在 `ctx.cron` 时，短路后
  // `ctx.cronTask` 永远不会被探测，而字符串上的 `.id/.name/.schedule`
  // 全是 undefined —— 作业身份整个丢失（实测 13/13 条 cron_changed 的
  // metadata 都是 {}）。现在按"第一个是对象的候选"来选容器，并把字符串
  // 形态的 `ctx.cron` 当成 schedule 收下。
  const cronJob = pickCronJobObject(ctx);
  const inlineCronExpr =
    typeof ctx.cron === 'string' && ctx.cron.length > 0 ? ctx.cron : undefined;

  const action = extractStringField(ctx, ['action', 'changeType', 'eventType']);
  return {
    sessionKey,
    runId,
    agentId: extractAgentId(ctx),
    cronId:
      coalesceString(ctx, ['cronId', 'cron_id', 'jobId', 'job_id', 'taskId', 'task_id', 'id']) ||
      pickCronJobString(cronJob, ['id', 'jobId', 'job_id', 'taskId', 'task_id', 'key']),
    cronName:
      coalesceString(ctx, ['cronName', 'cron_name', 'jobName', 'job_name', 'taskName', 'task_name', 'name']) ||
      pickCronJobString(cronJob, ['name', 'jobName', 'job_name', 'taskName', 'task_name', 'title']),
    action,
    schedule:
      extractStringField(ctx, ['schedule', 'cronExpr', 'cron_expression', 'cronExpression', 'interval']) ||
      pickCronJobString(cronJob, ['schedule', 'cronExpr', 'cron_expression', 'cronExpression', 'interval']) ||
      inlineCronExpr,
    enabled: (ctx.enabled ?? (cronJob?.enabled as boolean | undefined)) as boolean | undefined,
    firedResult: ctx.output !== undefined ? ctx.output : ctx.result !== undefined ? ctx.result : undefined,
    metadata: ctx.metadata as Record<string, unknown> | undefined,
  };
}

/** 宿主可能把 cron 作业对象放在这些键下。 */
const CRON_JOB_CONTAINER_KEYS = [
  'cron',
  'cronTask',
  'cronJob',
  'task',
  'job',
  'scheduledTask',
] as const;

/**
 * 取第一个**是对象**的 cron 作业容器。
 *
 * 不能用 `a || b`：`ctx.cron` 若是字符串（cron 表达式）会短路掉
 * `ctx.cronTask`，作业身份随之丢失。
 */
function pickCronJobObject(
  ctx: Record<string, unknown>
): Record<string, unknown> | undefined {
  for (const key of CRON_JOB_CONTAINER_KEYS) {
    const value = ctx[key];
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      return value as Record<string, unknown>;
    }
  }
  return undefined;
}

/** 从 cron 作业对象里按别名取第一个非空字符串。 */
function pickCronJobString(
  job: Record<string, unknown> | undefined,
  keys: string[]
): string | undefined {
  if (!job) return undefined;
  for (const key of keys) {
    const value = job[key];
    if (typeof value === 'string' && value.length > 0) return value;
  }
  return undefined;
}

export function extractStringField(
  obj: Record<string, unknown>,
  keys: string[]
): string | undefined {
  for (const key of keys) {
    const value = obj[key];
    if (typeof value === 'string' && value.length > 0) return value;
  }
  return undefined;
}

export function extractNestedString(
  obj: Record<string, unknown>,
  path: string[]
): string | undefined {
  let current: unknown = obj;
  for (const key of path) {
    if (!current || typeof current !== 'object') return undefined;
    current = (current as Record<string, unknown>)[key];
  }
  return typeof current === 'string' && current.length > 0 ? current : undefined;
}

export function extractContentFromLLMResponse(ctx: Record<string, unknown>): string | undefined {
  // 标准 LLM 响应格式: choices[0].message.content
  const choices = ctx.choices as Array<Record<string, unknown>> | undefined;
  if (choices && choices.length > 0) {
    const choice = choices[0];
    const message = choice?.message as Record<string, unknown> | undefined;
    if (message && typeof message.content === 'string') return message.content;
    // 流式 delta 格式: choices[0].delta.content
    const delta = choice?.delta as Record<string, unknown> | undefined;
    if (delta && typeof delta.content === 'string') return delta.content;
  }

  // 通用 content block 格式: content[0].text
  const content = ctx.content;
  if (Array.isArray(content) && content.length > 0) {
    const first = content[0];
    if (first && typeof first === 'object' && typeof (first as Record<string, unknown>).text === 'string') {
      return (first as Record<string, unknown>).text as string;
    }
  }

  // Nested response wrapper
  const response = ctx.response as Record<string, unknown> | undefined;
  if (response) {
    const nested = extractContentFromLLMResponse(response);
    if (nested) return nested;
  }

  return undefined;
}

export function extractTextFromContentBlocks(content: unknown): string | undefined {
  if (!Array.isArray(content)) return undefined;
  const texts: string[] = [];
  for (const item of content) {
    if (item && typeof item === 'object') {
      const text = (item as Record<string, unknown>).text;
      if (typeof text === 'string' && text.length > 0) texts.push(text);
    }
  }
  return texts.length > 0 ? texts.join('\n') : undefined;
}

export function extractAnyTextContent(ctx: Record<string, unknown>): string | undefined {
  // OpenClaw assistant message shape: assistantTexts: string[]
  const assistantTexts = ctx.assistantTexts as string[] | undefined;
  if (assistantTexts && assistantTexts.length > 0) {
    return assistantTexts.join('\n');
  }

  // OpenClaw assistant message shape: lastAssistant.content (content blocks)
  const lastAssistant = ctx.lastAssistant as Record<string, unknown> | undefined;
  if (lastAssistant) {
    const fromBlocks = extractTextFromContentBlocks(lastAssistant.content);
    if (fromBlocks) return fromBlocks;
    const directText = extractStringField(lastAssistant, ['text', 'content']);
    if (directText) return directText;
  }

  // Direct string fields commonly used by frameworks
  const direct = extractStringField(ctx, [
    'text',
    'value',
    'data',
    'answer',
    'reply',
    'result',
    'payload',
    'body',
  ]);
  if (direct) return direct;

  // Nested message objects
  for (const path of [
    ['message', 'content'],
    ['message', 'text'],
    ['delta', 'content'],
    ['delta', 'text'],
    ['delta', 'value'],
    ['output', 'content'],
    ['output', 'text'],
    ['response', 'content'],
    ['response', 'text'],
  ]) {
    const value = extractNestedString(ctx, path);
    if (value) return value;
  }

  // 通用 LLM 响应包装器
  const llmContent = extractContentFromLLMResponse(ctx);
  if (llmContent) return llmContent;

  // If there is an array of content blocks, concatenate text blocks
  const fromContentBlocks = extractTextFromContentBlocks(ctx.content);
  if (fromContentBlocks) return fromContentBlocks;

  return undefined;
}

export function summarizeRawShape(input: unknown, maxDepth = 3, depth = 0): unknown {
  if (depth > maxDepth) return '...';
  if (input === null || input === undefined) return input;
  if (typeof input === 'string') {
    // Keep a readable preview of long strings (especially prompts) while
    // avoiding massive payloads.
    if (input.length <= 300) return input;
    return input.slice(0, 300) + `... (${input.length} chars)`;
  }
  if (typeof input === 'number' || typeof input === 'boolean') return input;
  if (Array.isArray(input)) {
    return input.slice(0, 3).map((item) => summarizeRawShape(item, maxDepth, depth + 1));
  }
  if (typeof input === 'object') {
    const obj = input as Record<string, unknown>;
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj)) {
      result[key] = summarizeRawShape(value, maxDepth, depth + 1);
    }
    return result;
  }
  return typeof input;
}

// Summarize a message content array/string to just its size so that
// agent_start raw shapes stay compact.
function summarizeMessageContentForDebug(content: unknown): unknown {
  if (typeof content === 'string') {
    return content.length <= 100 ? content : `string(${content.length})`;
  }
  if (Array.isArray(content)) {
    return `content_blocks(${content.length})`;
  }
  return summarizeRawShape(content, 1, 0);
}

// Preserve numeric usage fields (input/output/tokens/cost) but keep strings
// short. Usage numbers are valuable for cost/trend analysis.
function summarizeUsageForDebug(usage: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(usage)) {
    if (typeof value === 'number' || typeof value === 'boolean') {
      result[key] = value;
    } else if (typeof value === 'string') {
      result[key] = value.length <= 50 ? value : `string(${value.length})`;
    } else {
      result[key] = summarizeRawShape(value, 2, 0);
    }
  }
  return result;
}

// For agent_start debugging: keep message metadata (role, provider, model,
// api, stopReason, timestamp) and usage numbers, but collapse content.
function summarizeMessagesForAgentStart(messages: unknown): unknown {
  if (!Array.isArray(messages)) return messages;
  return messages.map((msg) => {
    if (!msg || typeof msg !== 'object') return msg;
    const record = msg as Record<string, unknown>;
    const summary: Record<string, unknown> = {};
    for (const key of ['role', 'provider', 'model', 'api', 'stopReason', 'timestamp']) {
      if (record[key] !== undefined) summary[key] = record[key];
    }
    if (record.content !== undefined) {
      summary.content = summarizeMessageContentForDebug(record.content);
    }
    if (record.usage && typeof record.usage === 'object' && !Array.isArray(record.usage)) {
      summary.usage = summarizeUsageForDebug(record.usage as Record<string, unknown>);
    }
    return summary;
  });
}

export function extractReasoningFromLLMResponse(ctx: Record<string, unknown>): string | undefined {
  // LLM reasoning 字段提取: choices[0].message.reasoning_content
  const choices = ctx.choices as Array<Record<string, unknown>> | undefined;
  if (choices && choices.length > 0) {
    const message = choices[0]?.message as Record<string, unknown> | undefined;
    if (message) {
      const rc = message.reasoning_content;
      if (typeof rc === 'string' && rc.length > 0) return rc;
    }
  }

  // LLM thinking 字段提取: content[].thinking
  const content = ctx.content;
  if (Array.isArray(content)) {
    for (const item of content) {
      if (item && typeof item === 'object' && typeof (item as Record<string, unknown>).thinking === 'string') {
        return (item as Record<string, unknown>).thinking as string;
      }
    }
  }

  return undefined;
}

export function extractMessageId(ctx: Record<string, unknown>): string | undefined {
  return coalesceString(ctx, [
    'messageId',
    'message_id',
    'messageID',
    'id',
  ]);
}

export function extractParentMessageId(ctx: Record<string, unknown>): string | undefined {
  return coalesceString(ctx, [
    'parentMessageId',
    'parent_message_id',
    'parentMessageID',
    'parentId',
    'parent_id',
  ]);
}

export function cleanUserPromptText(input: string): string {
  // Strip OpenClaw prompt metadata wrappers ("Sender (untrusted metadata):",
  // system-context block markers) so duplicate user messages emitted by
  // different hooks collapse to the same text.
  let text = input;
  // Drop trailing metadata block if present.
  const senderIdx = text.indexOf('Sender (untrusted metadata)');
  if (senderIdx > 0) text = text.slice(0, senderIdx);
  // Trim trailing whitespace and zero-width separators.
  return text.replace(/[\s\u200B-\u200D\uFEFF]+$/u, '');
}

export function detectInjectedUserContent(content: string): boolean {
  // OpenClaw injects instructions (slug generation, timestamp context, etc.)
  // into the user stream. Tag them as system so they are not mistaken for
  // genuine user input.
  const markers = [
    'Generate a random slug',
    'current date and time',
    'Respond as helpfully as possible',
    'Here is the conversation so far',
  ];
  return markers.some((m) => content.includes(m));
}

/**
 * 角色同义词归一。
 *
 * 宿主对"谁在说话"的叫法不统一：human / user、ai / model / bot / agent、
 * tool_result / function。落到事件字段上必须收敛成一套，否则下游没法用
 * 一个等值判断把消息分成"用户输入"和"模型输出"两类。
 */
const ROLE_SYNONYMS: Record<string, MessageWriteContext['role']> = {
  user: 'user',
  human: 'user',
  assistant: 'assistant',
  ai: 'assistant',
  model: 'assistant',
  bot: 'assistant',
  agent: 'assistant',
  system: 'system',
  tool: 'tool',
  tool_result: 'tool',
  function: 'tool',
};

/** 把任意角色取值归一成规范角色；无法识别时返回 undefined。 */
export function normalizeRoleValue(raw: unknown): MessageWriteContext['role'] | undefined {
  if (typeof raw !== 'string') return undefined;
  const trimmed = raw.trim();
  if (!trimmed) return undefined;
  const lower = trimmed.toLowerCase();
  if (lower === 'unknown') return undefined; // 'unknown' 是"没拿到"，不是一种角色
  return ROLE_SYNONYMS[lower] ?? trimmed;
}

/** 角色判定的来源，写进事件里让下游知道这个角色有多可信。 */
export type RoleSource = 'explicit' | 'inferred' | 'lifecycle' | 'default';

export interface ResolvedRole {
  role: MessageWriteContext['role'];
  source: RoleSource;
}

/**
 * 显式定位消息角色。
 *
 * 只做"找"，不做"猜"：宿主给了哪个字段就用哪个，一个都没给就回落到
 * defaultRole（'unknown'），交给上层按会话生命周期推断（见
 * application-collector 的 inferMessageRole）。
 *
 * 探测顺序（先具体后笼统）：
 *   1. role 字段：ctx / ctx.context / ctx.message / ctx.metadata；
 *   2. 作者类字段：author / sender / participant / speaker / from；
 *   3. 会话数组 ctx.messages 里最后一条带 role 的消息；
 *   4. 形态推断：带 prompt 的是用户输入，带 completion/response 的是模型输出。
 *
 * 第 4 步是"形态推断"而不是"读取事实"，所以标记为 inferred；前 3 步都
 * 是宿主明确给出的，标记为 explicit。
 */
export function resolveMessageRole(
  ctx: Record<string, unknown>,
  defaultRole: MessageWriteContext['role'] = 'unknown'
): ResolvedRole {
  const sources: Array<Record<string, unknown> | undefined> = [
    ctx,
    ctx.context as Record<string, unknown> | undefined,
    ctx.message as Record<string, unknown> | undefined,
    ctx.metadata as Record<string, unknown> | undefined,
  ];
  for (const source of sources) {
    if (!source || typeof source !== 'object') continue;
    const role = normalizeRoleValue(source.role);
    if (role) return { role, source: 'explicit' };
  }

  for (const key of ['author', 'sender', 'participant', 'speaker', 'from']) {
    const role = normalizeRoleValue(ctx[key]);
    if (role) return { role, source: 'explicit' };
  }

  const messages = Array.isArray(ctx.messages) ? ctx.messages : undefined;
  if (messages) {
    for (let i = messages.length - 1; i >= 0; i--) {
      const message = messages[i];
      if (!message || typeof message !== 'object') continue;
      const role = normalizeRoleValue((message as Record<string, unknown>).role);
      if (role) return { role, source: 'explicit' };
    }
  }

  if (typeof ctx.prompt === 'string' && ctx.prompt.length > 0) {
    return { role: 'user', source: 'inferred' };
  }
  if (typeof ctx.completion === 'string' || typeof ctx.response === 'string') {
    return { role: 'assistant', source: 'inferred' };
  }

  return { role: defaultRole, source: 'default' };
}

export function normalizeMessageWriteContext(
  input: unknown,
  defaultRole: MessageWriteContext['role'] = 'unknown'
): MessageWriteContext | undefined {
  if (!input || typeof input !== 'object') return undefined;
  const ctx = extractEventContext(input);

  // OpenClaw 'command' event shape: { type, action, sessionKey, context, timestamp, messages }
  let content: unknown = ctx.content;
  // 角色与内容**分开**解析：内容能不能找到，跟角色在不在是两件事。
  // 之前只有"内容没找到"时才会去会话数组里翻角色，于是宿主在顶层不带
  // role 时，真实存在的角色也被一起丢掉（实测 6/6 条 agent_message 的
  // role 都是 'unknown'）。
  const resolvedRole = resolveMessageRole(ctx, defaultRole);
  let role: MessageWriteContext['role'] = resolvedRole.role;
  let roleSource: RoleSource = resolvedRole.source;

  // If content is missing or does not look like actual text, try to extract
  // text from a variety of known wrapper shapes.
  const hasContent = typeof content === 'string' && content.length > 0;
  if (!hasContent) {
    const anyContent = extractAnyTextContent(ctx);
    if (anyContent !== undefined) {
      content = anyContent;
    }
  }

  if (content === undefined && typeof ctx.action === 'string') {
    content = ctx.action;
  }
  if (content === undefined && typeof ctx.message === 'string') {
    content = ctx.message;
  }
  if (content === undefined && typeof ctx.output === 'string') {
    content = ctx.output;
  }

  const messages = Array.isArray(ctx.messages)
    ? (ctx.messages as Array<Record<string, unknown>>)
    : undefined;
  if (!hasContent && messages && messages.length > 0) {
    // Prefer the last message matching the expected role; otherwise use the very last.
    let matching: Record<string, unknown> | undefined;
    for (let i = messages.length - 1; i >= 0; i--) {
      if (messages[i].role === role) {
        matching = messages[i];
        break;
      }
    }
    if (!matching) {
      matching = messages[messages.length - 1];
    }
    if (matching) {
      // 会话数组里的 role 是宿主明确给出的，优先于任何推断。
      const matchedRole = normalizeRoleValue(matching.role);
      if (matchedRole) {
        role = matchedRole;
        roleSource = 'explicit';
      }
      if (typeof matching.content === 'string') {
        content = matching.content;
      } else {
        const text = extractTextFromContentBlocks(matching.content);
        if (text) {
          content = text;
        }
      }
    }
  }

  // Extract reasoning if present
  let reasoning: string | undefined = extractStringField(ctx, [
    'reasoning',
    'thinking',
    'thought',
    'reasoning_content',
    'reasoning_text',
  ]);
  if (!reasoning) {
    reasoning = extractReasoningFromLLMResponse(ctx);
  }

  // OpenClaw passes the user input inside a larger prompt string that includes
  // workspace context and metadata. Try to extract just the user's final line.
  if (role === 'user' && !hasContent && typeof ctx.prompt === 'string') {
    const lines = ctx.prompt.split('\n');
    for (let i = lines.length - 1; i >= 0; i--) {
      const line = lines[i].trim();
      if (
        line &&
        !line.startsWith('```') &&
        !line.startsWith('{') &&
        line !== ')' &&
        !line.startsWith('Sender (untrusted metadata)')
      ) {
        content = line;
        break;
      }
    }
  }

  // Strip OpenClaw prompt metadata wrappers from user inputs so duplicate
  // user messages emitted by different hooks collapse to the same text.
  if (role === 'user' && typeof content === 'string') {
    content = cleanUserPromptText(content);
  }

  // OpenClaw injects instructions (slug generation, timestamp context, etc.)
  // into the user stream. Tag them as system so they are not mistaken for
  // genuine user input.
  if (role === 'user' && typeof content === 'string' && detectInjectedUserContent(content)) {
    role = 'system';
    roleSource = 'inferred';
  }

  // 宿主把框架级提示（"上一轮被网关重启打断"之类）以 "[System] ..." 的
  // 形式混在消息流里。它不是用户输入——标成 system，免得下游把它当成
  // 用户 prompt 送去策略引擎评估。
  if (role === 'user' && typeof content === 'string' && content.trimStart().startsWith('[System]')) {
    role = 'system';
    roleSource = 'inferred';
  }

  // Extract model and token usage info exposed by OpenClaw for assistant messages.
  let modelProvider: string | undefined;
  let modelName: string | undefined;
  let tokenUsagePrompt: number | undefined;
  let tokenUsageCompletion: number | undefined;
  let tokenUsageTotal: number | undefined;

  if (role === 'assistant') {
    modelProvider = extractStringField(ctx, ['provider']);
    modelName = extractStringField(ctx, ['model']);
    const usage = ctx.usage as Record<string, unknown> | undefined;
    if (usage) {
      tokenUsagePrompt = typeof usage.input === 'number' ? usage.input : undefined;
      tokenUsageCompletion =
        typeof usage.output === 'number' ? usage.output : undefined;
      tokenUsageTotal =
        typeof usage.totalTokens === 'number' ? usage.totalTokens : undefined;
    }
  }

  let metadata = (ctx.metadata || ctx.context || undefined) as
    | Record<string, unknown>
    | undefined;

  // 宿主若把 payload 以 message 子对象传入，metadata||context 归一化取不到
  // message.__openclaw 里的用户身份（senderIdentity.id / senderName / ...）。
  // 合并进 metadata：__openclaw 块整体挂在 metadata.__openclaw 下供
  // coalesceUserId 消费，其键也铺到顶层（不覆盖已存在的 metadata 键）。
  const messageObj =
    ctx.message && typeof ctx.message === 'object' && !Array.isArray(ctx.message)
      ? (ctx.message as Record<string, unknown>)
      : undefined;
  const openclawMeta = messageObj?.__openclaw;
  if (
    openclawMeta &&
    typeof openclawMeta === 'object' &&
    !Array.isArray(openclawMeta)
  ) {
    const existingOpenclaw =
      metadata &&
      metadata.__openclaw &&
      typeof metadata.__openclaw === 'object' &&
      !Array.isArray(metadata.__openclaw)
        ? (metadata.__openclaw as Record<string, unknown>)
        : undefined;
    metadata = {
      ...(openclawMeta as Record<string, unknown>),
      ...(metadata || {}),
      __openclaw: {
        ...(openclawMeta as Record<string, unknown>),
        ...(existingOpenclaw || {}),
      },
    };
  }

  const runId = extractRunId(ctx);
  return {
    // session 未知就是 undefined，不回退 runId（规范：session 未知写 null）。
    sessionKey: extractSessionKey(ctx),
    runId,
    role,
    roleSource,
    content: (content || '') as string | unknown,
    reasoning,
    messageId: extractMessageId(ctx),
    parentMessageId: extractParentMessageId(ctx),
    modelProvider,
    modelName,
    tokenUsagePrompt,
    tokenUsageCompletion,
    tokenUsageTotal,
    metadata,
  };
}

export function parseJsonObject(value: unknown): Record<string, unknown> | undefined {
  if (typeof value === 'string') {
    try {
      const parsed = JSON.parse(value);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        return parsed as Record<string, unknown>;
      }
    } catch {
      // ignore
    }
  }
  return undefined;
}

export function extractToolParams(ctx: Record<string, unknown>): Record<string, unknown> {
  // Try direct params fields
  for (const key of ['params', 'parameters', 'arguments', 'args', 'input', 'toolInput']) {
    const value = ctx[key];
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      return value as Record<string, unknown>;
    }
    const parsed = parseJsonObject(value);
    if (parsed) return parsed;
  }

  // 通用 tool call 格式: toolCall.function.arguments is a JSON string
  const toolCall = ctx.toolCall as Record<string, unknown> | undefined;
  const func = toolCall?.function as Record<string, unknown> | undefined;
  if (typeof func?.arguments === 'string') {
    const parsed = parseJsonObject(func.arguments);
    if (parsed) return parsed;
  }
  if (toolCall && typeof toolCall.arguments === 'object' && !Array.isArray(toolCall.arguments)) {
    return toolCall.arguments as Record<string, unknown>;
  }

  // Some runtimes put the tool input under tool.input or payload/body
  const tool = ctx.tool as Record<string, unknown> | undefined;
  if (tool && typeof tool.input === 'object' && !Array.isArray(tool.input)) {
    return tool.input as Record<string, unknown>;
  }
  if (tool && typeof tool.arguments === 'object' && !Array.isArray(tool.arguments)) {
    return tool.arguments as Record<string, unknown>;
  }
  for (const key of ['payload', 'body', 'request', 'toolInput']) {
    const value = ctx[key];
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      const candidate = value as Record<string, unknown>;
      // Only use it if it looks like tool arguments (has a known command key or non-empty)
      if (Object.keys(candidate).length > 0) {
        return candidate;
      }
    }
  }

  return {};
}

export function normalizeToolContext(input: unknown): MiddlewareContext | undefined {
  if (!input || typeof input !== 'object') return undefined;
  const ctx = extractEventContext(input);

  // OpenClaw may pass tool as an object { name, kind, description }
  const tool = ctx.tool as Record<string, unknown> | undefined;
  const toolName = tool?.name ?? ctx.toolName ?? ctx.tool_name ?? 'unknown';
  const toolKind = (tool?.kind ?? ctx.toolKind ?? ctx.tool_kind) as string | undefined;
  const toolDescription = (tool?.description ?? ctx.toolDescription ?? ctx.tool_description) as
    | string
    | undefined;

  const runId = extractRunId(ctx);
  return {
    // session 未知就是 undefined，不回退 runId（规范：session 未知写 null）。
    sessionKey: extractSessionKey(ctx),
    agentId: extractAgentId(ctx) || 'unknown',
    runId: runId || 'unknown',
    toolName: toolName as string,
    toolKind,
    toolDescription,
    params: extractToolParams(ctx),
    metadata: (ctx.metadata || (ctx.toolCallId ? { toolCallId: ctx.toolCallId } : undefined)) as
      | Record<string, unknown>
      | undefined,
  };
}

export function looksLikeToolContext(arg: unknown): boolean {
  if (!arg || typeof arg !== 'object') return false;
  const ctx = arg as Record<string, unknown>;
  const keys = Object.keys(ctx);
  const markers = ['toolName', 'tool_name', 'toolCallId', 'tool_call_id', 'toolCall', 'tool', 'sessionKey', 'session_id', 'sessionId', 'agentId', 'agent_id', 'runId', 'run_id'];
  return markers.some((m) => keys.includes(m));
}

export function looksLikeResult(arg: unknown): boolean {
  // A "result" is anything object-shaped that does not look like a tool context.
  // We intentionally keep this loose; pickToolContextArg/findResultArg apply
  // the more precise discrimination.
  return !!arg && typeof arg === 'object' && !Array.isArray(arg);
}

export function findResultArg(args: unknown[]): unknown | undefined {
  // Prefer an arg that looks like a result and is NOT the tool context.
  const candidates = args.filter((a) => !looksLikeToolContext(a) && looksLikeResult(a));
  if (candidates.length > 0) return candidates[0];
  // If every arg looks like a tool context, extract result from the first one.
  for (const arg of args) {
    if (looksLikeToolContext(arg)) {
      const extracted = extractRealResult(arg);
      if (extracted !== undefined) return extracted;
    }
  }
  return undefined;
}

export function extractRealResult(input: unknown): unknown {
  if (!input || typeof input !== 'object') return input;
  const ctx = input as Record<string, unknown>;

  // If the object is clearly a result payload (no tool markers), return it as-is.
  if (!looksLikeToolContext(input)) {
    return input;
  }

  // Otherwise it is probably a tool context envelope: dig out the actual output.
  for (const key of ['output', 'result', 'content', 'stdout', 'stderr', 'data', 'value', 'message']) {
    if (key in ctx) return ctx[key];
  }
  return undefined;
}

