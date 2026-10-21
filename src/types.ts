/**
 * OpenClaw Security Monitor Plugin - Type Definitions
 */

// ============================================================================
// OpenClaw Framework Types (mocked for compilation independence)
// ============================================================================

export interface MiddlewareContext {
  sessionKey: string;
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
  sessionKey: string;
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
  sessionKey: string;
  runId?: string;
  role: 'user' | 'assistant' | 'tool' | string;
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
  sessionKey: string;
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
  readonly version: string;
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
  | 'agent_subagent_start'
  | 'agent_subagent_progress'
  | 'agent_subagent_end'
  | 'cron_changed'
  | 'agent_message'
  | 'agent_tool_call'
  | 'agent_tool_result'
  | 'code_mode_exec'
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
  | 'process_change'
  | 'process_exit'
  | 'process_snapshot'
  // System layer cgroup events
  | 'cgroup_snapshot'
  | 'cgroup_anomaly'
  // Asset layer events (agent config / skill / MCP asset monitoring)
  | 'asset_add'
  | 'asset_change'
  | 'asset_remove'
  | 'asset_snapshot'
  // Self-protection events (intervention engine degraded / protected file tampered)
  | 'protection_degraded'
  | 'tamper_detected';

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
  /** Event schema version per project_standards (e.g. "1.0.0"). */
  schema_version?: string;
  pid?: number;
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
  tool_name?: string;
  tool_kind?: string;
  tool_description?: string;
  path?: string;
  params?: Record<string, unknown>;
  tool_params?: string;
  raw_params?: string;
  raw_params_length?: number;
  user_prompt?: string;
  system_prompt?: string;
  agent_plan?: string[];
  previous_actions?: ActionRecord[];
  step_index?: number;
  is_code_mode?: boolean;
  code_content?: string;
  code_content_length?: number;
  code_language?: string;
  model_provider?: string;
  model_name?: string;
  role?: string;
  content?: string;
  content_length?: number;
  reasoning?: string;
  reasoning_length?: number;
  message_id?: string;
  parent_message_id?: string;
  message_index?: number;
  execution_duration_ms?: number;
  duration?: number;
  execution_status?: 'success' | 'error' | string;
  status?: 'success' | 'failure' | string;
  result?: string;
  result_size?: number;
  result_preview?: string;
  result_preview_length?: number;
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
    system_prompt?: string;
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
  blocked?: boolean;
  block_reason?: string;
  tool_call_id?: string;
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
  /** Full skill directory package (present when collectSkillPackage is on and the package fits maxPackageBytes). */
  asset_package?: AssetPackageInfo;
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
