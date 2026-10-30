/**
 * OpenClaw Security Monitor Plugin - Type Definitions
 */

// ============================================================================
// OpenClaw Framework Types (mocked for compilation independence)
// ============================================================================

export interface MiddlewareContext {
  /**
   * 会话键。规范（common.json）：session 未知时必须为 undefined → 事件上
   * 落 null；绝不回退 runId（只允许 run_id 向下回退 task/session）。
   */
  sessionKey: string | undefined;
  agentId: string;
  runId: string;
  toolName: string;
  toolKind?: string;
  toolDescription?: string;
  params: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}

export interface MiddlewareResult {
  block: boolean;
  reason?: string;
  modifiedParams?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}

export interface AgentStartContext {
  /** 会话键；undefined = 宿主没给会话（事件上落 null，见 MiddlewareContext）。 */
  sessionKey: string | undefined;
  agentId: string;
  agentConfig?: AgentConfig;
  systemPrompt?: string;
  skills?: string[];
  tools?: string[];
}

export interface AgentStartResult {
  systemPromptAddition?: string;
  /**
   * OpenClaw before_agent_run gate decision。
   * InputGateDecision 仅支持 pass/block（hook-decision-types.ts），
   * 不存在 systemPromptAddition；block 决策以 { outcome: 'block', reason }
   * 形态返回宿主。引导类（context_adjust/guidance）决策无法经该 hook 下发。
   */
  outcome?: 'pass' | 'block';
  reason?: string;
}

export interface MessageWriteContext {
  /** 会话键；undefined = 宿主没给会话（事件上落 null，见 MiddlewareContext）。 */
  sessionKey: string | undefined;
  runId?: string;
  role: 'user' | 'assistant' | 'tool' | string;
  /**
   * 角色是怎么来的。'explicit' = 宿主明确给出；'inferred' = 由载荷形态
   * 推断；'lifecycle' = 由会话生命周期推断（见 application-collector）；
   * 'default' = 都没拿到，走了兜底。
   *
   * 1.1.0 起落盘：宿主在 message 事件上经常不带 role，导致下游拿到的
   * 角色全是 'unknown'，等于没有角色。标出来源，下游才知道哪些行可以
   * 当成事实用。
   */
  roleSource?: 'explicit' | 'inferred' | 'lifecycle' | 'default' | string;
  content: string | unknown;
  reasoning?: string;
  messageId?: string;
  parentMessageId?: string;
  modelProvider?: string;
  modelName?: string;
  tokenUsagePrompt?: number;
  tokenUsageCompletion?: number;
  tokenUsageTotal?: number;
  metadata?: Record<string, unknown>;
}

export interface MessageWriteResult {
  content?: string | unknown;
}

export interface AgentCompleteContext {
  /** 会话键；undefined = 宿主没给会话（事件上落 null，见 MiddlewareContext）。 */
  sessionKey: string | undefined;
  agentId: string;
  runId?: string;
  status?: 'success' | 'error' | string;
  output?: string | unknown;
  error?: { message?: string; [key: string]: unknown } | unknown;
}

export interface SessionEndContext {
  sessionKey?: string;
  runId?: string;
  agentId?: string;
  status?: string;
  content?: string | unknown;
  metadata?: Record<string, unknown>;
}

export interface SubagentContext {
  sessionKey?: string;
  runId?: string;
  agentId?: string;
  parentRunId?: string;
  subagentId?: string;
  subagentName?: string;
  status?: string;
  prompt?: string;
  output?: unknown;
  error?: unknown;
  progress?: unknown;
  metadata?: Record<string, unknown>;
}

export interface CronEventContext {
  sessionKey?: string;
  runId?: string;
  agentId?: string;
  cronId?: string;
  cronName?: string;
  action?: 'added' | 'updated' | 'removed' | 'fired' | string;
  schedule?: string;
  enabled?: boolean;
  firedResult?: unknown;
  metadata?: Record<string, unknown>;
}

export interface AgentConfig {
  name?: string;
  description?: string;
  provider?: string;
  model?: {
    provider?: string;
    name?: string;
  };
  tools?: string[];
  skills?: string[];
  /** Agent's on-disk directory, lifted from ctx.agentDir when exposed. */
  agentDir?: string;
}

export interface OpenClawPluginAPI {
  config: {
    get: (key: string) => Record<string, unknown> | undefined;
  };
  middleware: {
    register: (middleware: OpenClawMiddleware) => void;
  };
  logger: {
    info: (message: string) => void;
    warn: (message: string) => void;
    error: (message: string) => void;
  };
  runtime?: {
    registerHelper?: (name: string, helpers: Record<string, unknown>) => void;
  };
}

export interface OpenClawMiddleware {
  readonly name: string;
  /**
   * 宿主契约里该字段是可选的（见 src/openclaw-sdk/plugin-api.ts 的
   * `version?: string`）。这里保持同样可选：强制要求等于要在每个实现类里
   * 手抄一份包版本，而版本已经由 package.json 单一权威 + 运行时解析
   * （index.ts resolvePluginVersion）提供，副本只会漂移。
   */
  readonly version?: string;
  initialize?: (config: Record<string, unknown>) => Promise<void>;
  beforeToolCall?: (context: MiddlewareContext) => Promise<MiddlewareResult>;
  afterToolCall?: (context: MiddlewareContext, result: unknown) => Promise<void>;
  beforeAgentStart?: (context: AgentStartContext) => Promise<AgentStartResult | void>;
  beforeMessageWrite?: (context: MessageWriteContext) => Promise<MessageWriteResult | void>;
  getStatus?: () => { enabled: boolean; stats?: Record<string, unknown> };
  shutdown?: () => Promise<void>;
}

export interface OpenClawPlugin {
  name: string;
  version: string;
  initialize: (api: OpenClawPluginAPI) => Promise<void>;
  shutdown?: () => Promise<void>;
}

// ============================================================================
// Security Event Types
// ============================================================================

export type EventType =
  | 'agent_start'
  | 'agent_stop'
  | 'agent_session_start'
  | 'agent_session_end'
  // ---------------------------------------------------------------------
  // 以下类型带 `x_openclaw_` 前缀：平台 aise-agent-governance 的
  // validate_batch 对**未登记且无 x_<project>_ 前缀**的 event_type 直接
  // UnsupportedEventType 并整批拒绝 NDJSON；未登记的 x_ 前缀扩展只校验
  // 公共字段后放行。这是 project_standards 的扩展命名约定，改名前这些
  // 裸名类型会触发整批拒收。
  // ---------------------------------------------------------------------
  | 'x_openclaw_subagent_start'
  | 'x_openclaw_subagent_progress'
  | 'x_openclaw_subagent_end'
  // cron 配置变化事件。保留裸名：平台已登记 deprecated →
  // x_openclaw_cron_changed 的 alias；其 status 枚举是 started/stopped/
  // modified/error，故本插件发 modified。
  | 'cron_changed'
  // 一次 cron 运行的单条收敛事件：宿主每次触发发的
  // scheduled/started/finished 三元组收敛为运行结束这一条。
  | 'x_openclaw_cron_run'
  | 'agent_message'
  | 'agent_tool_call'
  | 'agent_tool_result'
  | 'code_mode_exec'
  // 'reasoning' 只在类型 union 里保留（宿主可能扩展），本插件不发出——
  // 未发出就不会触发平台的整批拒收，无需加前缀。
  | 'reasoning'
  | 'runtime_log'
  | 'trace_span'
  // Deprecated alias kept for backward compatibility with older runtime hooks;
  // command-execution events are emitted as process_start per the data standard.
  | 'command_execution'
  // Application layer file operation events
  | 'file_read'
  | 'file_write'
  | 'file_delete'
  | 'file_privilege'
  // Network layer HTTP request/response events
  | 'network_http'
  | 'network_connect'
  | 'network_dns'
  // System layer process lifecycle events
  | 'process_start'
  | 'x_openclaw_process_change'
  | 'process_exit'
  | 'x_openclaw_process_snapshot'
  // System layer cgroup events
  | 'x_openclaw_cgroup_snapshot'
  | 'x_openclaw_cgroup_anomaly'
  // Asset layer events (agent config / skill / MCP asset monitoring)
  | 'asset_add'
  | 'asset_change'
  | 'asset_remove'
  | 'asset_snapshot'
  // Self-protection events (intervention engine degraded / protected file tampered)
  | 'x_openclaw_protection_degraded'
  | 'x_openclaw_tamper_detected'
  // 运行时 hook 被宿主卸载（自保护留痕）。
  | 'x_openclaw_runtime_hook_unloaded';

// Per project_standards/event-schema/common.json: layer is one of
// 'application' | 'system' | 'asset'. The legacy 'network' value is mapped to
// 'system' + collection_method='runtime' on emit.
export type SourceLayer = 'application' | 'system' | 'asset';


export interface SecurityEvent {
  // Common fields (all layers)
  comm?: string;
  event_id: string;
  event_type: EventType | string;
  layer: SourceLayer;
  ts: number;
  /**
   * 事件 schema 版本。**整数 1**（project_standards schema-versions.md：
   * 只允许 JSON 整数，兼容新增字段继续沿用 1）——1.1.0 之前误用字符串
   * "1.0.0"，平台接收层按整数归一，字符串型会被判类型不符。
   */
  schema_version?: number;
  pid?: number;
  /**
   * 发起方进程 pid（谁调用了 spawn）。
   *
   * 1.1.0 之前 `pid` 就是这个语义（发起方），而**被拉起的子进程 pid 从来
   * 没被采集过**——审计链上只有"谁发起的"，没有"哪个进程真的跑起来
   * 了"。现在两者分开：`spawner_pid` = 发起方，`child_pid` = 子进程。
   * `pid` 保留为发起方 pid 的兼容别名。
   */
  spawner_pid?: number;
  /** 被拉起的子进程 pid。spawn 之前拿不到，所以 process_start 事件里可能缺失。 */
  child_pid?: number;
  session_id?: string | null;
  run_id?: string | null;
  task_id?: string | null;
  turn_id?: string | null;
  agent_id?: string | null;
  host_id?: string;
  container_id?: string;
  pod_name?: string;
  namespace?: string;

  /**
   * Source identifier — must be a string per common.json. Format:
   *   <project>.<component>.<version>     e.g. "openclaw.v1", "openclaw.runtime-hooks.v1"
   * Structured metadata about the hook/middleware/collector must live in
   * the `collector` object instead.
   */
  source?: string;
  /** How the event was collected: hook | runtime | ebpf | procfs | agent_api | skill_sync … */
  collection_method?: string;
  /** Structured source metadata. The spec requires this to be an object, never merged into `source`. */
  collector?: {
    hook_name?: string;
    middleware_name?: string;
    collector_name?: string;
  };

  // Application layer fields
  agent_name?: string;
  user_id?: string;
  tool_name?: string | null;
  tool_kind?: string;
  tool_description?: string;
  path?: string;
  /**
   * 工具参数的规范化 JSON 字符串（唯一的参数载荷字段，agent.json 1.1.0）。
   *
   * 历史上同一数据落过三份：`raw_params`（字符串）、`tool_params`（同一
   * 字符串）、`params`（同一份数据的对象视图）。现只保留 `tool_params`
   * 一份；要对象形态的消费方 JSON.parse 即可。
   */
  tool_params?: string;
  /** `tool_params` 截断前的原始长度（截断阈值 application.maxRawParamsLength）。 */
  tool_params_length?: number;
  /**
   * 原始参数在**脱敏前**的 SHA-256（规范化键序后序列化，与 tool_params
   * 同源但先于 redact）。
   *
   * 规范（common.json）脱敏四件套之一：审计时凭它核对原始内容，原始明文
   * 走独立安全通道、绝不落事件流。无法确定性序列化的极端载荷（循环引用）
   * 省略本字段。
   */
  raw_params_hash?: string;
  /**
   * 本次落盘时被脱敏替换的一级键名列表（去重；空则省略本字段）。
   *
   * 规范（common.json）脱敏四件套之一：raw_params_hash / raw_params_length /
   * redacted_keys / obfuscation。下游据此知道"哪个参数被抹掉了"，而不必
   * 靠对 tool_params 里的 '***' 做形态猜测。只记录键名被替换的键；
   * 值内容模式（JWT/AKIA 等）命中属于"值被改写"，不算键被替换。
   */
  redacted_keys?: string[];
  user_prompt?: string;
  /**
   * 系统提示词的内容指纹（sha256 前 16 位十六进制，内容寻址）。
   *
   * 事件流里不再出现 system_prompt 全文（实测它占事件流约 54% 体积，
   * 同一提示词被每个会话的第一条消息反复内嵌）。全文全局只落一份到与
   * security-events.jsonl 同目录的 security-prompts.jsonl，按完整
   * prompt_hash（= ref 的 64 位原值）检索；所有事件一律只带这个 ref，
   * 下游按 ref 回 sidecar 取全文即可。
   */
  system_prompt_ref?: string;
  /**
   * 会话标题：由该 session 首条有效 user 消息派生（脱敏 → 取首个非空行 →
   * 压行内空白 → 截断 ≤30 字）。first-write-wins，之后不再改写。
   *
   * 标题在首条 user 消息落盘之后才确定，因此早于它的少数事件（例如
   * agent_start）没有这个字段——"字段缺失"即"标题尚未确定"。
   */
  session_title?: string;
  agent_plan?: string[];
  previous_actions?: ActionRecord[];
  step_index?: number;
  is_code_mode?: boolean;
  code_content?: string;
  code_content_length?: number;
  code_language?: string;
  model_provider?: string;
  model_name?: string;
  /**
   * 消息角色（agent_message）。规范（agent.json）枚举只有
   * user / assistant / system；写入端（inferMessageRole）保证枚举外取值
   * （如宿主给的 tool / 任意字符串）不会落盘——它们按"未知"走生命周期推断。
   */
  role?: 'user' | 'assistant' | 'system';
  /**
   * 角色来源（1.1.0）：`explicit` 宿主明确给出 / `inferred` 载荷形态推断 /
   * `lifecycle` 会话生命周期推断 / `default` 兜底。
   *
   * 宿主在消息事件上经常不带 role，没有这个标记时下游分不清"这是用户
   * 说的"和"这是我们猜的"。
   */
  role_source?: 'explicit' | 'inferred' | 'lifecycle' | 'default' | string;
  content?: string;
  content_length?: number;
  reasoning?: string;
  reasoning_length?: number;
  message_id?: string;
  parent_message_id?: string;
  message_index?: number;
  /** 执行耗时（毫秒）。1.1.0 起取代同值的 `execution_duration_ms`。 */
  duration?: number;
  /**
   * cron_run：本次运行的开始时间（Unix 毫秒）。scheduled/started 中间
   * 事件不落盘，起点在内存里按 cronId 记；started 缺失（如插件重启过）
   * 时本字段与 duration_ms 一起省略，不编造假值。
   */
  started_at?: number;
  /** cron_run：本次运行耗时（毫秒）= 落盘时刻 - started_at。 */
  duration_ms?: number;
  /**
   * cron_run：宿主回传的触发结果（截断 ≤500 字）。字符串原样收，对象
   * 序列化后收。
   */
  fired_result?: string;
  /**
   * 事件状态。取值随事件类型而异（写入端实际产出的全部取值）：
   *   - 工具/子代理/智能体结果类：success | failure | blocked | error
   *     （blocked = 被策略拦截，blocked 布尔恒在，双写是为了旧消费方兼容）；
   *   - cron_changed（配置变化）：modified（平台已登记 schema 的枚举是
   *     started/stopped/modified/error，发 changed 会校验失败）；
   *   - cron_run（一次运行收敛后的单条事件）：success | failure；
   *   - agent_session_end：ended | error。
   * 1.1.0 起取代同值的 `execution_status`；宿主给的任意字符串在写入端
   * 收敛进上述枚举，不会原样落盘。
   */
  status?: 'success' | 'failure' | 'blocked' | 'error' | 'modified' | 'ended';
  /** 工具结果原始长度（字节/字符数，未截断）。 */
  result_size?: number;
  /** 工具结果预览（截断后的字符串）。 */
  result_preview?: string;
  error_message?: string;
  loaded_skills?: string[];
  loaded_tools?: string[];
  skills?: string[];
  tools?: Array<Record<string, unknown> | string>;
  agents?: Array<{
    id?: string;
    name?: string;
    description?: string;
    model_provider?: string;
    model_name?: string;
    /**
     * 系统提示词内容指纹（sha256 前 16 位十六进制），与事件层
     * `system_prompt_ref` 同源同值。
     *
     * 事件流里不再内联系统提示词全文——agent_start 的 agents[] 与会话内
     * 消息事件携带的原文逐字节相同，重复落盘一份 25KB 级别的私有载荷
     * 没有收益。全文全局唯一一份落在 security-prompts.jsonl，消费方按
     * ref 对应的完整 prompt_hash 取回。
     */
    system_prompt_ref?: string;
    /** Best-effort agent directory; omitted when it cannot be reliably resolved. */
    agent_dir?: string;
    /** Best-effort config file path; omitted when it cannot be reliably resolved. */
    config?: string;
    /** Skills loaded by this specific agent — name list only; path/hash via asset_* channel. */
    skills?: string[];
    /** MCP servers referenced by this agent — name list only; transport/command/auth via asset_* channel. */
    mcp_servers?: string[];
    /** Tools brought online by this agent. */
    tools?: AgentToolRef[];
  }>;
  exit_code?: number;
  /** 子进程被信号终止时的信号名（process_exit）。 */
  exit_signal?: string;
  metadata?: Record<string, unknown>;

  // Application runtime hook fields (process_start)
  runtime?: 'node' | 'python' | string;
  api?: string;
  shell_involved?: boolean;
  shell?: string;
  target_pid?: number;
  caller?: {
    function?: string;
    file?: string;
    line?: number;
    column?: number;
  };
  risk_flags?: string[];
  /**
  /**
   * hook 传播被绕过的具体原因。
   *
   * - `explicit_skip`：调用方显式要求跳过传播 → 子进程真的裸跑，覆盖丢了；
   * - `env_stripped`：调用方给了不带 NODE_OPTIONS 的 env → hook 已把它
   *   补回去，覆盖没丢（此前这种情形也被算成 `self_protection_bypass`，
   *   宿主自己的探活命令因此刷出大量假告警）。
   */
  bypass_reason?: string;
  /**
   * ⭐ **恒在**（#470 缺陷 C）—— 必须是 `boolean`，**不允许缺省/缺失**。
   *
   * ## 为什么「缺省 false」不等于「没有这个字段」
   *
   *   下游按 `blocked === false` **过滤/聚合**（"没被拦的请求"）⇒
   *   「键缺失」与「`false`」在 `===` 判定下**完全等价**，但在
   *   `Object.keys` / `in` / schema 校验 / 「缺失即异常」的批处理里**不等价**
   *   ⇒ 键缺失 ⇒ 静默失真（#470 实测 484 条 LLM 事件缺这个键）。
   *
   * ## 三重护栏
   *
   *   1. **类型层**：本字段**必带** ⇒ `tsc` 把每个构造点都逼出来。
   *   2. **出口层**：`EventBridgeCollector.report` 兜底补 `false`
   *      （覆盖绕过类型系统的路径：hook JSON、`as` 断言）。
   *   3. **schema 层**：`schemas/security-event-v1.schema.json` 里
   *      `blocked` 进 `required` ⇒ 读侧校验会**拒收**缺这个键的存量行。
   */
  blocked: boolean;
  block_reason?: string;
  /** 关联键：一次工具调用的唯一标识（插件合成，权威）。 */
  tool_call_id?: string | null;
  /**
   * 宿主原始的工具调用 id（`tool_call:call_function_…`）。
   *
   * 与 `tool_call_id` 是两套体系：`tool_call_id` 是本插件的关联权威键，
   * 这个字段仅用于与宿主日志对账。1.1.0 之前宿主原始 id 只藏在
   * `metadata.toolCallId` 里，与其他 metadata 字段混在一起，无法被
   * schema 约束，也无法作为 join 键。
   */
  host_tool_call_id?: string | null;
  /**
   * 外层调用 id（嵌套调用时才有）。
   *
   * code-mode exec 在飞行期间跑的工具调用（read/ls/exec …）各自有独立的
   * `tool_call_id`（保持唯一，决策缓存不串号），外层那次 code-mode exec
   * 的 id 记在这里——这样"这段工具调用是 code-mode 脚本发起的"这件事在
   * 事件流里是显式的，不必再靠时间窗口或 step 索引反推。
   */
  parent_tool_call_id?: string | null;
  /**
   * 采集侧降级留痕：runtime hook 事件的干预评估队列积压达到
   * 上限时，该事件跳过评估、仅落盘，原因记于此字段。评估被跳过意味着
   * `intervention` 决策缺失（非 allow），chain 规则的时序也不再保证。
   */
  evaluation_skipped?: {
    reason: 'runtime_dispatch_backlog' | string;
    /** 跳过时的队列积压长度。 */
    backlog: number;
  };

  // Phase 1+ intervention fields (SDP decisions)
  intervention?: {
    // DecisionComposer 运行时仍可能产生 substitute/context_adjust/degrade
    // （决策链 / 条件决策 fallback）。事件层的 decision 字段允许这些运行时
    // 备用值，便于审计留痕。
    decision: RuntimeDecisionType;
    policy_id?: string;
    policy_name?: string;
    policy_version?: string;
    reason?: string;
    block_reason?: string;
    block_code?: string;
    /**
     * 展示字段：true = 可联系管理员复核 / 申请调整策略（误报救济，
     * 面板渲染"可复核"徽标）；false = 硬性安全底线。无在线申诉动作。
     */
    appealable?: boolean;
    /** 阻断后的修复建议；appealable=true 且策略未显式配置时由决策层补缺省复核指引。 */
    remediation_hint?: string;
    /**
     * 本次评估命中的全部规则，含 enforce 短路点之前已匹配的
     * warn/modify 等规则；audit 标注用途，与最终 decision 互补。
     */
    matched_rules?: Array<{
      policy_id?: string;
      policy_name?: string;
      decision?: string;
      priority?: number;
      risk_level?: 'low' | 'medium' | 'high' | 'critical' | 'extreme';
      category?: string;
      /**
       * 命中证据（#469-D）：这条规则**凭哪一段文本**命中。
       *
       * ⛔ `matched_text` 必然已打码（长度 ≥6 的 token 段替换为 `***`）
       *   ⇒ 可定位，但不会把被拦下来的凭据原文抄进事件。
       *
       * ⚠️ `matched_text` 已打码 ⇒ 其长度**不等于**
       *   `match_end - match_start`（后者是**原始**字段值里的字符区间）。
       *
       * 缺省 = 该规则不是靠文本正则命中的 ⇒ **缺证据 ≠ 没命中**。
       *
       * ⭐ 形状与 SDK `MatchEvidence` 逐字段对齐 ⇒ local / SDK 两形态
       *   同一口径，SDK 侧把 `matched_text` 填实后无需再改插件。
       */
      evidence?: {
        /** 命中的字段名（paramsRegex 的 key / `body` / `sessionId`）。 */
        field_name?: string;
        /** 命中的正则原文（来自规则，不是用户数据）。 */
        pattern?: string;
        /** 命中类别（paramsRegex / bodyRegex / sessionRegex）。 */
        match_type?: string;
        /** 命中片段（⛔ 已打码）。 */
        matched_text?: string;
        /** 命中片段在字段原始值中的字符起点。 */
        match_start?: number;
        /** 命中片段在字段原始值中的字符终点（不含）。 */
        match_end?: number;
      };
    }>;
    modified_params?: Record<string, unknown>;
    substituted_tool_name?: string;
    guidance?: {
      adjustment_id?: string;
      template_id?: string;
      template_version?: string;
      rendered?: string;
      allowed_scope?: string;
      alternatives?: string[];
      attempts_remaining?: number;
      guidance_count?: number;
    };
    degrade?: {
      mode?: 'readonly' | 'sandbox' | 'limited_tools';
      removed_tools?: string[];
    };
    latency_ms?: number;
    fail_strategy?: 'fail_open' | 'fail_closed' | 'fail_open_high_risk_only';
    mode?: 'audit' | 'enforce';
    priority?: number;
    risk_level?: 'low' | 'medium' | 'high' | 'critical' | 'extreme';

    /**
     * ⭐ **观测到的额外判定**（#470 缺陷 B）。
     *
     * ## 为什么需要它（而不是覆盖 `intervention` 本身）
     *
     *   事件上**已经有** intervention 时，后续评估（尤其是**语义**判定）
     *   原来会被 `!event.intervention` 守卫**整个丢弃** ⇒
     *   **语义阻断在事件流里零留痕**（#470 实测：418 条 `network_http`
     *   语义 block，事件流里一条都查不到）。
     *
     *   ⇒ 现在改成**合并**：权威判定（谁真正决定了这次动作）留在
     *     `intervention.decision` / `policy_id`，被观测到的额外判定记在
     *     `observed` 里 ⇒ **既不覆盖权威判定，也不丢留痕**。
     *
     * ⭐ `source` 标明这次观测**来自哪一层**（`semantic` / `rule` / …）。
     */
    observed?: {
      decision: RuntimeDecisionType;
      policy_id?: string;
      policy_name?: string;
      reason?: string;
      block_reason?: string;
      block_code?: string;
      /** 观测来源（`semantic` = 语义层；`rule` = 规则层；…）。 */
      source: string;
    };
    /**
     * ⭐ **合并前的原始决策**（#470 缺陷 B）——
     * `observed` 存在时，它记的是**被观测到的那一份**，本字段记的是
     * **事件上原来那一份** ⇒ 两者可对照（谁先谁后、谁赢）。
     */
    original_decision?: RuntimeDecisionType;
  };

  // Risk assessment (Phase 1.5)
  risk_assessment?: {
    risk_score: number;
    risk_level: 'low' | 'medium' | 'high' | 'critical' | 'extreme';
    reg_level?: '低风险' | '中风险' | '高风险';
    reg_clause?: string[];
    dimensions?: Record<string, number>;
    matched_policies?: string[];
    evaluation_path?: 'cache' | 'rule' | 'model' | 'fallback';
  };
  request_id?: string;
  trace_id?: string;
  protocol_type?: string;
  llm_provider?: string;
  request_method?: string;
  request_url?: string;
  request_path?: string;
  request_host?: string;
  request_headers?: Record<string, string>;
  request_body?: unknown;
  response_status?: number;
  response_headers?: Record<string, string>;
  response_body?: unknown;
  // Standard network_http event fields
  service?: string;
  direction?: 'send' | 'recv' | string;
  method?: string;
  url?: string;
  host?: string;
  code?: number;
  header?: string;
  body?: string;
  /**
   * 载荷是否被截断。
   *
   * 1.1.0 之前 network_http 的 `content` 由 runtime hook 原样透传，
   * 不受 `application.maxContentLength` 约束（实测落盘 4099 字符，
   * 而配置声明 2000），且 `content_length` 照抄 hook 值，无法区分
   * "完整响应"与"被截断的响应"。现在 content 按配置截断，
   * `content_length` 恒为**原始**长度，截断与否由本字段表达。
   */
  content_truncated?: boolean;
  /** Network event five-tuple per network.json. */
  local_ip?: string;
  local_port?: number;
  remote_ip?: string;
  remote_port?: number;
  /** Legacy fields from older runtime hooks — accept but prefer the five-tuple. */
  src_ip?: string;
  dst_ip?: string;
  src_port?: number;
  dst_port?: number;
  domain_name?: string;
  dns_query_type?: string;
  dns_response_code?: string;
  resolved_ips?: string[];
  token_usage_prompt?: number;
  token_usage_completion?: number;
  token_usage_total?: number;
  latency_ms?: number;
  tls_version?: string;
  sni?: string;
  packets?: number;
  bytes?: number;
  flow_action?: string;
  flow_start?: number;
  flow_end?: number;

  // System layer fields (reserved for system-collector expansion)
  ppid?: number;
  pgid?: number;
  sid?: number;
  process_name?: string;
  /** Full command line as a single string. Replaces the deprecated `command_line`
   *  and `argv` fields (process.json). */
  cmdline?: string;
  exe_path?: string;
  exe?: string;
  cwd?: string;
  username?: string;
  uid?: number;
  gid?: number;
  euid?: number;
  create_time?: number;
  process_status?: string;
  open_files?: Array<{ path: string; fd: number }>;
  connections?: Array<{
    local_addr?: string;
    remote_addr?: string;
    status?: string;
  }>;
  child_pids?: number[];
  cpu_percent?: number;
  memory_rss?: number;
  cgroup_path?: string;
  cgroup_version?: 'v1' | 'v2';
  memory_current?: number;
  memory_max?: number;
  cpu_usage_usec?: number;
  // Cgroup snapshot fields
  cpu?: {
    usage_nanos?: number;
    user_nanos?: number;
    system_nanos?: number;
    cfs_period_us?: number;
    cfs_quota_us?: number;
    usage_percent?: number;
  };
  memory?: {
    current_bytes?: number;
    limit_bytes?: number;
    rss_bytes?: number;
    swap_bytes?: number;
    usage_percent?: number;
  };
  blkio?: {
    read_bytes?: number;
    write_bytes?: number;
  };
  pids?: {
    current?: number;
    max?: number;
  };
  // Cgroup anomaly fields
  anomaly_type?: string;
  severity?: 'low' | 'medium' | 'high' | 'critical';
  description?: string;
  baseline?: Record<string, unknown>;
  current?: Record<string, unknown>;
  file_event_path?: string;
  file_event_type?: string;
  file_event_mask?: string;
  audit_syscall?: number;
  audit_syscall_name?: string;
  audit_arch?: string;
  audit_key?: string;
  audit_a0?: string;
  audit_success?: boolean;
  docker_event_type?: string;
  docker_container_id?: string;

  // Asset layer fields (agent config / skill / MCP asset monitoring)
  /** Stable asset identifier derived from host_id + asset_type + path. */
  asset_id?: string;
  asset_type?: 'agent_config' | 'skill' | 'mcp_server' | string;
  asset_path?: string;
  /** SHA-256 of the normalized plaintext content (computed before obfuscation). */
  content_hash?: string;
  /** Previous content hash, carried on changed/removed events. */
  prev_hash?: string;
  /** Structured asset summary; sensitive values are obf:v1 envelopes. */
  parsed?: Record<string, unknown>;
  /**
   * 资产包（zip）的内容寻址 sha256（对 asset_package.data 的编码文本计算）。
   *
   * 1.1.0 起事件不再内嵌 asset_package 全文（base64 zip 是 asset 事件的
   * 体积大头）；包体原文写在 `<ndjsonDir>/asset-blobs/<asset_package_hash>`，
   * 消费方按 hash 取回。asset_change/asset_remove 不携带包字段。
   */
  asset_package_hash?: string;
  file_size?: number;
  file_mtime?: number;
}

export interface AssetPackageInfo {
  /** Archive format; currently always 'zip'. */
  format: 'zip';
  /** Encoding of `data`; consumers decode accordingly ('base64' or 'hex'). */
  encoding: 'base64' | 'hex';
  /** Encoded archive bytes: base64(zip) or hex(zip). */
  data: string;
  /** Sum of uncompressed file bytes. */
  original_bytes: number;
  /** Archive size in bytes before encoding. */
  compressed_bytes: number;
  file_count: number;
}

// ---------------------------------------------------------------------------
// agent_start.agents[] element — per-agent resource topology
// ---------------------------------------------------------------------------

// Design notes:
// - Skills/MCP are emitted as name lists only. OpenClaw's before_agent_start
//   hook gives us skill names in ctx.skills with full authority, but the
//   on-disk path of each SKILL.md can only be inferred by heuristics.
//   Authoritative path + hash flows through the asset_* channel as `skill`
//   assets, joinable by name on the consumer side.
// - mcp_servers likewise ships only `name`. The full transport / command /
//   headers / auth payload (which may include secrets) is owned by the
//   asset_* `mcp_server` channel.
// - tools carries `kind` because tool kind is OpenClaw-authoritative from
//   the hook context and not derivable from any asset file.

export interface AgentToolRef {
  name: string;
  /** 'native' for OpenClaw built-ins; custom kinds come from agent config. */
  kind?: string;
}

export interface ActionRecord {
  tool: string;
  params?: Record<string, unknown>;
  result_status?: string;
}

export interface SessionContext {
  userPrompt: string;
  systemPrompt: string;
  currentPlan: string[];
  previousActions: ActionRecord[];
  stepIndex: number;
  messageIndex: number;
  userId?: string;
  agentId?: string;
  agentName?: string;
  agentConfig?: AgentConfig;
  /**
   * tool_call 上最近一次已落盘的 user_prompt。user_prompt 是会话内常量，
   * 逐条复制是纯冗余；只在首次出现或内容变化时携带，其余事件省略字段，
   * 下游按 session 继承（与 system_prompt_ref 同一语义）。
   */
  emittedUserPrompt?: string;
  /** 同上去重：agent_plan 的 JSON 序列化键，undefined 表示当前为空。 */
  emittedAgentPlanKey?: string;
  /** 同上去重：previous_actions 的 JSON 序列化键，undefined 表示当前为空。 */
  emittedPreviousActionsKey?: string;
}

// ============================================================================
// Collector Types
// ============================================================================

/**
 * The plugin only writes events to a local NDJSON sink. HTTP transport,
 * batching, retry, and transport-specific encoding are the responsibility of
 * the sidecar SDK that tails this file.
 */

export interface CollectorConfig {
  /**
   * Local NDJSON file path. Each event is appended on its own line so the
   * sidecar SDK can `tail -F` the file and forward events over whatever
   * transport it owns. The plugin itself never opens a network socket.
   */
  ndjsonPath?: string;
  /**
   * Rotate `ndjsonPath` once its size exceeds this many bytes. The oversized
   * file is renamed to `${ndjsonPath}.rotated` (overwriting any previous
   * `.rotated`) and a fresh file is created at the same path. Sidecar SDK
   * must also tail `.rotated` to avoid missing events at the rotation point.
   * Set to `0` to disable rotation. Default: 100 MB.
   */
  maxFileSizeBytes?: number;
  /**
   * Cap the in-memory event cache used by the Control UI panel. When the
   * NDJSON file holds more events than this, the cache keeps only the most
   * recent N. Aggregate counters (metrics.* / stats.*) stay global and are
   * unaffected. Lower values cut panel heap usage; higher values let the
   * Event Stream / Policy Hits drill deeper into history. Default: 5000.
   */
  maxEventsInMemory?: number;
}

export interface EventCollector {
  initialize(config: Record<string, unknown>): Promise<void>;
  report(event: SecurityEvent): Promise<void>;
  flush(): Promise<void>;
  getStats(): CollectorStats;
  shutdown(): Promise<void>;
}

export interface CollectorStats {
  totalReported: number;
  totalFailed: number;
  queueSize: number;
  lastFlushTime?: number;
}

export interface ILayerCollector {
  readonly name: string;
  initialize(config?: Record<string, unknown>): Promise<void>;
  report(event: SecurityEvent): Promise<void>;
  shutdown(): Promise<void>;
  getStats?(): Record<string, unknown>;
}

// ============================================================================
// Plugin Configuration
// ============================================================================

import type { InterventionConfig, RuntimeDecisionType } from './intervention/types.js';

export interface SecurityMonitorConfig {
  collector: CollectorConfig;
  application?: ApplicationLayerConfig;
  network?: NetworkLayerConfig; // reserved (network-collector stub)
  system?: SystemLayerConfig; // procfs process monitoring
  intervention?: InterventionConfig; // blocking decisions
  assetMonitor?: AssetMonitorConfig; // Asset layer (agent config / skill / MCP)
  environment?: EnvironmentConfig;
  /** Plugin self-bootstrap behaviour (idempotent host-config writes, etc.). */
  bootstrap?: BootstrapConfig;
}

export interface BootstrapConfig {
  /**
   * When true (default), the plugin writes host-side plugin-entry defaults
   * into `~/.openclaw/openclaw.json` on first boot so the host UI and
   * runtime hook policy match what the plugin actually needs.
   * Set to false to opt out (e.g. on locked-down hosts where writing the
   * host config is not allowed).
   */
  entryDefaults?: boolean;
}

export interface AssetMonitorConfig {
  enabled?: boolean;
  /** Periodic scan interval in milliseconds. Scans detect changes; they do NOT imply reporting — only real content changes emit events. */
  scanIntervalMs?: number;
  /** Full reconciliation snapshot interval in milliseconds. 0 disables periodic snapshots. */
  fullSnapshotIntervalMs?: number;
  /** Extra files or directories to collect as agent_config assets (whitelist). */
  watchPaths?: string[];
  /** Extra skill search roots (merged with the built-in defaults). Each root is searched recursively (depth ≤ 4) for directories containing SKILL.md. */
  skillPaths?: string[];
  /** Extra standalone MCP config files (merged with the default ~/.openclaw/mcp.json). */
  mcpPaths?: string[];
  /** Whether to include (sensitive-field-obfuscated) file content in parsed.content. Default false: summary + hash only. */
  collectContent?: boolean;
  /** Files larger than this are reported as metadata + hash only (no parsing). */
  maxFileSizeBytes?: number;
  /** Path of the local asset state file used to survive restarts without re-baselining. */
  statePersistencePath?: string;
  /** Keys matching any of these substrings (case-insensitive) have their values obfuscated with obf:v1. */
  sensitiveKeyPatterns?: string[];
  /** Whether to attach a ZIP package of the entire skill directory to skill events (added/changed/snapshot), for downstream audit scanning. */
  collectSkillPackage?: boolean;
  /** Whether to attach a single-file ZIP of each config file to agent_config events. Package content is raw (not obfuscated) for audit fidelity. */
  collectConfigPackage?: boolean;
  /** Maximum ZIP size in bytes; larger skills are reported manifest-only with parsed.package_omitted. */
  maxPackageBytes?: number;
  /** Single files larger than this are excluded from the skill ZIP (kept in the files manifest with hash + excluded flag) so packages stay small. Default 2 MB. */
  maxPackageEntryBytes?: number;
  /** Wire encoding for asset_package.data. Default 'base64' (1.33x size); 'hex' (2x size) only if the consumer requires it. */
  packageEncoding?: 'base64' | 'hex';
}

export interface ApplicationLayerConfig {
  enabled?: boolean;
  captureUserPrompt?: boolean;
  captureSystemPrompt?: boolean;
  captureAgentPlan?: boolean;
  captureCodeMode?: boolean;
  captureUserId?: boolean;
  captureReasoning?: boolean;
  userIdField?: string;
  maxContentLength?: number;
  maxResultPreviewLength?: number;
  maxRawParamsLength?: number;
  maxCodeContentLength?: number;
  sessionTtlMs?: number;
  maxPreviousActions?: number;
  /**
   * Fallback agent id used when the OpenClaw runtime cannot identify the agent
   * (e.g. passes "unknown"). Useful for single-agent deployments.
   */
  defaultAgentId?: string;
  /**
   * Panel UI language. `auto` negotiates from `?lang=` / `Accept-Language` and
   * falls back to English; `en` / `zh` pin the panel regardless of the browser.
   * Written by the header language switcher, also editable on the Config tab.
   */
  panelLocale?: 'auto' | 'en' | 'zh';
  runtimeHooks?: RuntimeHooksConfig;
}

export interface RuntimeHooksConfig {
  /** Whether to collect command execution events from runtime hooks. */
  enabled?: boolean;
  /** Whether to enable the network request runtime hook. */
  networkEnabled?: boolean;
  /** Path to the JSONL file written by the runtime hook. */
  logPath?: string;
  /**
   * Whether to replay the existing log file on the very first startup.
   *
   * Default: `false`. Without a persisted cursor, the collector starts at the
   * current end-of-file, so historical noise (e.g. a 100 MB log accumulated
   * across previous runs) is NOT replayed.
   *
   * Set to `true` only for debugging or when you specifically need to drain
   * every line of a pre-existing file. After the first successful run the
   * collector persists a sidecar cursor and resumes from there, so this
   * flag only governs the *very first* start.
   */
  replayOnFirstRun?: boolean;
  /**
   * Look-back window in bytes for the *very first* startup (when there is
   * no persisted cursor). Reads up to N bytes before the current EOF to
   * recover events written by the runtime hook in the race window between
   * hook load and collector initialization.
   *
   * Default: `0` (no look-back). Set to e.g. `65536` if you want to keep
   * the small "early events" window without replaying the whole file.
   */
  firstRunLookbackBytes?: number;
  /**
   * Maximum size of the runtime hook log file in bytes before it is rotated.
   * Set to `0` to disable rotation. Default: 50 MB.
   */
  maxLogSizeBytes?: number;
  /**
   * Polling interval in milliseconds used as a fallback to detect log file
   * changes. `fs.watchFile` can miss rapid appends on some filesystems, so the
   * collector also polls at this interval. Set to `0` to disable polling.
   * Default: `100`.
   */
  pollIntervalMs?: number;
  /** Risk flags that should trigger an immediate security event. */
  blockedFlags?: string[];
  /**
   * Regex patterns for command lines that should be excluded from collection.
   * Useful for filtering periodic internal noise (e.g. "ip neigh show" or
   * maintenance cron scripts). Patterns are matched case-insensitively.
   */
  excludeCommandLines?: string[];
  /**
   * 是否排除宿主自有内部 worker 的子进程事件（1.1.0 起默认开启）。
   *
   * 宿主网关在空闲期会周期性拉起自己的只读 worker（sqlite 只读子进程、
   * 数据库校验 worker 等）。实测 43 条 process_start 里 26 条属于这一类，
   * 其中 20 条命令行完全一致、只差 pid 与时间戳——它们把真正的子进程
   * 信号淹没在 17% 的文件体积里。
   *
   * 内置判据只匹配宿主自己派生的**子进程标记**（如 `--openclaw-sqlite-
   * readonly-child`），不匹配宿主内部的模块路径：宿主改版换掉内部文件
   * 名时内置规则会失配（表现为噪声回来，而不是误杀别的进程）。
   * 需要完整审计时置 `false`。
   */
  excludeHostInternalProcesses?: boolean;
  /**
   * 是否排除宿主自身的**只读维护探针**（1.1.0 起默认开启）。
   *
   * 宿主网关在空闲期会周期性拉起一批只读的自身维护命令（端口探活
   * lsof、systemd 状态查询、busctl 版本查询、全局包根目录查询、git
   * 工作区状态查询、用户/路由/磁盘查询）。实测 1139 条 process_start
   * 里约 560 条属于这一类，其中 lsof 一条命令就重复了 203 次，且 360 条
   * 还带着 `self_protection_bypass` 误标，把真正的子进程信号淹没。
   *
   * 排除需要**两道闸门同时成立**：事件没有任何 agent 归属（不是某个
   * agent 动作的产物）+ 命令行逐字命中一条已知的只读探针形态
   * （见 src/host-internal-probe.ts）。因此带凭据或带拓扑信息的命令
   * （`gh auth token`、`crontab -l`、`npm config list`、`git config
   * --get remote.origin.url`、`claude auth status`）一律不会被排除。
   *
   * 宿主改版换掉探针写法时规则失配——表现是噪声回来，而不是误杀别的
   * 进程。失配方向是安全的一侧。需要完整审计时置 `false`。
   */
  excludeHostInternalProbeCommands?: boolean;
  /**
  /**
   * runtime 采集事件的单字段最大长度（字符）。
   *
   * 1.1.0 之前 runtime hook 的 `content` 原样透传，不受
   * `application.maxContentLength` 约束（实测落盘 4099 字符而配置声明
   * 2000）。现在按本项截断，`content_length` 恒为原始长度，截断与否
   * 由 `content_truncated` 表达。Default: 2000。
   */
  maxContentLength?: number;
  /**
   * 是否启用 runtime hook 的**模式级 Tier-1 阻断**（默认开启）。
   *
   * 判定源是 `policies/security-policy.spl.yaml` 的 `hookBlockPatterns` 段
   * （构建期生成 `hooks/generated-patterns.json.blockPatterns`）——它与
   * `blockedFlags`（flag 级阻断名单）是**两档独立判定**：
   *   · flag 级：命令命中某个风险标签且该标签在阻断名单里 ⇒ 拦；
   *   · 模式级：命令形态命中 Tier-1 模式（读 /etc/shadow、读 ~/.aws/credentials
   *     …）⇒ 拦，且**不产生任何风险标签**。
   *
   * ⚠️ 关掉它 = 只关模式级这一档，flag 级阻断不受影响。
   * ⚠️ 它与 `OPENCLAW_RUNTIME_BLOCK_PATTERNS` 环境变量同义（配置优先）。
   */
  blockPatternsEnabled?: boolean;
  /**
   * Regex patterns for network HTTP requests that should be excluded from
   * collection. Each pattern is tested against the concatenated string
   * `<host><url>` (e.g. `192.0.2.1/api/v1/events`) case-insensitively.
   * Useful for suppressing traffic generated by the collector itself.
   */
  excludeNetworkUrls?: string[];
  /**
   * 干预评估队列的最大积压长度（事件条数）。评估是纯同步 CPU
   * 工作且与落盘串行，事件速率超过评估吞吐时 Promise 链与内存会无界增长、
   * 审计落盘被一并拖住。达到该上限后新事件跳过评估、仅落盘留痕
   * （`evaluation_skipped` 字段 + 计数），评估恢复空闲后自动继续。
   * 设为 `0` 关闭限制（不建议）。Default: 1000。
   */
  maxEvaluationBacklog?: number;
}

export interface NetworkLayerConfig {
  enabled?: boolean;
  llmGateway?: {
    enabled?: boolean;
    listenPort?: number;
    upstreamProviders?: Record<string, string>;
  };
  mcpMiddleware?: {
    enabled?: boolean;
    monitoredServers?: string[];
  };
  dnsLogs?: {
    enabled?: boolean;
    source?: 'dnstap' | 'systemd-resolved' | 'dnsmasq';
  };
  flowLogs?: {
    enabled?: boolean;
    provider?: 'aws' | 'azure' | 'gcp';
  };
}

export interface SystemLayerConfig {
  enabled?: boolean;
  procfs?: {
    enabled?: boolean;
    /** Path to the Python interpreter used to run the embedded monitor. */
    pythonPath?: string;
    /** Process scan interval in milliseconds. */
    scanIntervalMs?: number;
    /** Periodic full snapshot interval in milliseconds. 0 disables periodic snapshots. */
    snapshotIntervalMs?: number;
    /** Whether to enable temporary high-frequency scanning while tools are executing. */
    burstScanEnabled?: boolean;
    /** Scan interval used during burst mode in milliseconds. */
    burstScanIntervalMs?: number;
    /** How long burst mode stays active after a tool call ends, in milliseconds. */
    burstScanDurationMs?: number;
    /** Whether to scan all matching processes globally during burst mode, useful when child processes are spawned outside the bound process tree. */
    burstScanGlobal?: boolean;
    /** Process names / command-line substrings used to identify agent-related processes. */
    processNames?: string[];
    /** Command-line substrings used to exclude processes (e.g. the monitor itself). */
    excludeCommandLines?: string[];
    /** Whether to collect the list of files opened by each process. */
    collectOpenFiles?: boolean;
    /** Whether to collect network connections for each process. */
    collectConnections?: boolean;
    /** Whether to collect child PID lists for each process. */
    collectChildren?: boolean;
    /** Whether to collect CPU percent for each process (requires a short sample interval). */
    collectCpuPercent?: boolean;
    /** Fields that trigger a process_change event when they differ from the previous scan. */
    changeDetectionFields?: string[];
    /**
     * Minimum absolute change in memory_rss (bytes) before it is considered changed.
     * Helps suppress noise from small memory fluctuations in long-running processes.
     * 0 or unset disables the threshold.
     */
    memoryRssChangeThresholdBytes?: number;
    /**
     * Opt-in automatic termination of high-risk processes detected by the
     * procfs monitor. Defaults to false so existing deployments are not surprised.
     */
    autoKill?: boolean;
    /** Risk flags that are allowed to trigger auto-kill. Defaults to high-risk flags. */
    riskFlags?: string[];
    /** Minimum risk_score before auto-kill is considered. Defaults to 1.0. */
    riskThreshold?: number;
    /** PIDs that must never be killed by auto-kill or killProcess. */
    protectedPids?: number[];
    /** Signal used for auto-kill and killProcess. Defaults to SIGTERM. */
    killSignal?: string | number;
  };
  cgroups?: {
    enabled?: boolean;
    /** Cgroup scan interval in milliseconds during normal mode. */
    scanIntervalMs?: number;
    /** Cgroup scan interval in milliseconds during burst mode (while tool calls are executing). */
    burstScanIntervalMs?: number;
    /** CPU usage percent change threshold before emitting a cgroup_snapshot event. */
    cpuChangeThresholdPercent?: number;
    /** Memory usage percent change threshold before emitting a cgroup_snapshot event. */
    memoryChangeThresholdPercent?: number;
    /** IO change threshold in bytes before emitting a cgroup_snapshot event. */
    ioChangeThresholdBytes?: number;
    /** CPU spike threshold in percent to trigger a cgroup_anomaly event. */
    anomalyCpuSpikeThresholdPercent?: number;
    /** Memory usage threshold in percent to trigger a cgroup_anomaly event. */
    anomalyMemoryThresholdPercent?: number;
    /** Whether to emit full cgroup fields only during burst mode. */
    fullFieldsInBurstOnly?: boolean;
    /** Whether to emit periodic heartbeat snapshots in normal mode. */
    heartbeatEnabled?: boolean;
    /** Aggregation window in seconds for normal-mode snapshots. */
    aggregateWindowSeconds?: number;
  };
}

export interface EnvironmentConfig {
  hostId?: string;
  containerId?: string;
  podName?: string;
  namespace?: string;
}

declare global {
  // eslint-disable-next-line no-var
  var __OPENCLAW_SESSION_ID__: string | undefined;
  // eslint-disable-next-line no-var
  var __OPENCLAW_RUN_ID__: string | undefined;
  // eslint-disable-next-line no-var
  var __OPENCLAW_AGENT_ID__: string | undefined;
  // eslint-disable-next-line no-var
  var __OPENCLAW_TOOL_CALL_ID__: string | undefined;
  // eslint-disable-next-line no-var
  var __OPENCLAW_TOOL_NAME__: string | undefined;
  // eslint-disable-next-line no-var
  var __openclaw_runtime_hook_installed: boolean | undefined;
}
