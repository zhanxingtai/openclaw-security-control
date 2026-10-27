/**
 * OpenClaw Security Monitor - Intervention Engine Types
 *
 * Synchronous decision protocol (SDP) for cross-host intervention. The
 * SecurityDecision returned by InterventionEngine is host-independent; each
 * host (OpenClaw or other host platforms) translates it to its native
 * hook return format via a HostAdapter.
 */

import type { ActionRecord } from '../types.js';
import { GENERATED_ENGINE_HIGH_RISK_FLAGS } from './generated-flag-defaults.js';

export type InterventionDecisionType =
  | 'allow'
  | 'warn'
  | 'block'
  | 'modify'
  | 'audit'
  // 扩展位（escalate）。OpenClaw 暂不下发 escalate 决策值，
  // loader 读取时落地映射为 warn + WARN。
  | 'escalate';

/**
 * 顶层 severity 字段五档。语义锚点：low=可恢复用户级；
 * medium=数据/会话级；high=凭据/持久化级；critical=系统/多用户级；extreme
 * 保留给不可逆系统级破坏（当前可为空档）。
 * loader 不接受 v1 `evaluate.risk_level` 迁移映射；v1 策略直接抛
 * `unsupported SPL apiVersion`。
 */
export type Severity = 'low' | 'medium' | 'high' | 'critical' | 'extreme';

/**
 * category 8 值枚举。loader 校验拼写（throw + 单规则隔离）；
 * 仅用于组织与统计，不参与匹配与裁决。
 *
 * shipped 策略当前只用到 5 值（self_protection / intrusion_defense /
 * data_leak_monitoring / behavior_guidance / data_desensitization）；
 * ssrf / supply_chain / sensitive_data_access 留给后续规则扩展。
 */
export type SPLCategory =
  | 'self_protection'
  | 'intrusion_defense'
  | 'data_leak_monitoring'
  | 'sensitive_data_access'
  | 'supply_chain'
  | 'ssrf'
  | 'behavior_guidance'
  | 'data_desensitization';

/**
 * SPL apiVersion 字面量类型。loader 仅接受 v2，v1 策略抛错。
 */
export type SPLApiVersion = 'security.use/v1' | 'security.use/v2';

export type FailStrategy = 'fail_open' | 'fail_closed' | 'fail_open_high_risk_only';

export interface RiskSignal {
  /** Risk score, 0-100. */
  riskScore: number;
  /** Risk level. */
  riskLevel: 'low' | 'medium' | 'high' | 'critical' | 'extreme';
  /** Regulatory risk level mapping. */
  regLevel?: '低风险' | '中风险' | '高风险';
  /** Triggered regulatory clauses, e.g. ["4.6", "4.12"]. */
  regClause?: string[];
  /** Per-dimension scores. */
  dimensions?: Record<string, number>;
}

/**
 * 单条命中规则的标注。enforce 模式命中 block 即短路停扫，
 * 短路点之前已匹配的 warn/modify 等规则不会进入最终决策，通过该结构
 * 完整保留在事件标注里供审计/面板展示。仅标注用途，不参与裁决。
 */
export interface MatchedPolicyHit {
  /** Matched rule id. */
  policyId: string;
  /** Matched rule human-readable name. */
  policyName?: string;
  /** 该规则自身的裁决类型（非多条规则合成后的最终决策）。 */
  // 删除值（substitute/context_adjust/degrade）已从
  // InterventionDecisionType 移除，但 DecisionComposer 运行时仍可能产生这些  // 值（决策链 / 条件决策 fallback）。Match to 标注允许记录这些运行时备用值。
  decision: RuntimeDecisionType;
  /** Rule priority. */
  priority?: number;
  /** Risk level of the matched rule. */
  riskLevel?: 'low' | 'medium' | 'high' | 'critical' | 'extreme';
  /** Rule category (e.g. data_leak_monitoring), 不参与匹配与裁决。 */
  category?: SPLCategory;
}

export interface GuidanceResult {
  /** Unique adjustment id. */
  adjustmentId: string;
  /** Triggering policy id. */
  policyId: string;
  /** Triggering policy version. */
  policyVersion?: string;
  /** Risk signal that triggered the guidance. */
  riskSignal?: RiskSignal;
  /** Rendered guidance text. */
  rendered: string;
  /** Allowed scope description. */
  allowedScope?: string;
  /** Suggested alternative actions. */
  alternatives?: string[];
  /** 距升级阻断还剩的引导次数（引导预算阈值 - 已引导次数）。 */
  attemptsRemaining?: number;
  /** Whether this guidance should be non-overridable. */
  nonOverridable?: boolean;
  /** Template id used for rendering. */
  templateId?: string;
  /** Template version. */
  templateVersion?: string;
}

/**
 * Platform-independent synchronous decision (SDP).
 *
 * 决策枚举已收窄：substitute / context_adjust / degrade 为删除值。
 * RuntimeDecisionType 仍保留为兼容位别名，事件层
 * 写出的旧 fixture 字符串字面量（substitute / context_adjust / degrade）
 * 仍能通过类型校验；引擎层不再产出（loader 抛错 + 单规则隔离），
 * 仅在兜底分支按 audit/allow 留痕。
 */
export type RuntimeDecisionType =
  | InterventionDecisionType
  | 'substitute'
  | 'context_adjust'
  | 'degrade';

export interface SecurityDecision {
  /** Final decision. */
  decision: RuntimeDecisionType;
  /** Risk signal that informed the decision. */
  riskSignal?: RiskSignal;
  /** Human-readable reason (logs / audit). */
  reason?: string;
  /** Regulatory clauses triggered. */
  regClause?: string[];

  // Block fields
  /** Structured reason returned to the agent when blocked. */
  blockReason?: string;
  /** Remediation hint for re-planning. */
  remediationHint?: string;
  /**
   * Machine-readable block code.
   * 格式 `<CATEGORY 大写>_<威胁>_<NNN>`，第一段必须等于
   * category.uppercase() 首词；加载期 WARN 校验。
   * @pattern ^[A-Z][A-Z0-9_]*_[0-9]{3}$
   */
  blockCode?: string;
  /**
   * 展示字段（方案 B：不实施在线申诉链路，面板保持只读）：
   * true = 该阻断可联系管理员复核 / 申请调整策略（误报救济路径），
   *        appealable=true 且未显式配置 remediationHint 时，决策层会补
   *        一条含 policyId 的缺省复核指引；
   * false = 硬性安全底线，不可复核。
   * 面板据此事后渲染"可复核"徽标，无写 RPC、无申诉交互。
   */
  appealable?: boolean;

  /**
   * 本次评估命中的全部规则，含 enforce 短路点之前已匹配的
   * warn/modify 等规则。纯审计标注，不改变最终决策语义。
   */
  matchedPolicies?: MatchedPolicyHit[];

  // Modify fields
  /** Rewritten parameters for `modify`. */
  modifiedParams?: Record<string, unknown>;
  /**
   * @deprecated 删除 substitute 决策；DecisionComposer 不再生产该字段。
   * 仅保留为可选类型位供 application-collector 历史事件序列化。
   * 新代码不应读取 / 写入；加载期 loader 拒绝 substitute 决策，引擎层不消费。
   */
  substitutedToolName?: string;
  /**
   * @deprecated 删除 substitute 决策；同 substitutedToolName，仅类型位保留。
   */
  paramMapping?: Record<string, string>;

  // Guidance fields (保留：事件层审计标注仍用，loader 不产)
  /** Guidance output. */
  guidance?: GuidanceResult;

  // Degrade fields (保留：事件层审计标注仍用，loader 不产)
  /** Degrade mode. */
  degradeMode?: 'readonly' | 'sandbox' | 'limited_tools';
  /** Tools to remove when degrading. */
  removedTools?: string[];

  // Audit / metadata fields
  /** Matched policy id. */
  policyId?: string;
  /** Matched policy human-readable name. */
  policyName?: string;
  /** Matched policy version. */
  policyVersion?: string;
  /** Decision latency in milliseconds. */
  latencyMs?: number;
  /** Failure strategy used when the decision was generated as a fallback. */
  failStrategy?: FailStrategy;
  /** Matched rule priority. */
  priority?: number;
  /** Risk level of the matched rule. */
  riskLevel?: 'low' | 'medium' | 'high' | 'critical' | 'extreme';
}

export interface InterventionContext {
  /** Action type, e.g. tool_call, command_execution, network_http. */
  actionType: string;
  /** Tool or command name. */
  toolName?: string;
  /** Tool / command parameters. */
  params?: Record<string, unknown>;
  /** Request body, for network/http actions. */
  body?: string;
  /** Request headers, for network/http actions. */
  headers?: Record<string, string | string[]>;
  /** Risk flags already computed by collectors (e.g. reverse_shell). */
  riskFlags?: string[];
  /** Session id. */
  sessionId?: string;
  /** Run id. */
  runId?: string;
  /** Agent id. */
  agentId?: string;
  /** User prompt for the current session. */
  userPrompt?: string;
  /** Current plan. */
  agentPlan?: string[];
  /** Previous actions in the session. */
  previousActions?: ActionRecord[];
  /** User authorization state. */
  userAuthzState?: 'anonymous' | 'pending' | 'granted';
  /** User roles. */
  userRoles?: string[];
}

export interface PolicyRuleMatch {
  /** Action types to match. */
  actionType?: string[];
  /** Tool or command names to match. */
  actionName?: string[];
  /** Legacy alias for actionName. */
  toolName?: string[];
  /** Parameter regex matches. */
  paramsRegex?: Record<string, PolicyRegexEntry[]>;
  /** Parameter regex exclusions: if any pattern matches, the rule does NOT match. */
  paramsNotRegex?: Record<string, PolicyRegexEntry[]>;
  /** Parameter field equality checks. */
  fieldEquals?: Record<string, unknown>;
  /** Parameter field in-list checks. */
  fieldIn?: Record<string, unknown[]>;
  /** Body regex matches. */
  bodyRegex?: PolicyRegexEntry[];
  /** Risk flags where at least one must be present. */
  riskFlagsAny?: string[];
  /** Risk flags where all must be present. */
  riskFlagsAll?: string[];
  /** Session id regex matches. */
  sessionRegex?: PolicyRegexEntry[];
  /** Chain matching: prior actions within N steps. */
  chain?: {
    withinSteps?: number;
    prior?: Array<{
      action?: string;
      actionName?: string;
      pathRegex?: PolicyRegexEntry[];
      urlRegex?: PolicyRegexEntry[];
      bodyRegex?: PolicyRegexEntry[];
    }>;
  };
}

// SPL v2 评估区段废弃。
// 原 PolicyRuleEvaluate（risk_level / reg_clause / risk_dimensions）已迁移到
// 顶层 severity / regClause 字段；evaluate 区段整体移除——loader 不再解析。

export interface PolicyRuleActionModify {
  /** Fields to redact (nested keys supported with dot notation). */
  redactFields?: string[];
  /** Redact policy reference. */
  redactPolicyRef?: string;
  /** Pattern replacements. */
  substitutePatterns?: Array<{
    pattern: string;
    replacement: string;
    flags?: string;
  }>;
  /** Whitelist constraints: if a param does not match, keep original. */
  whitelistConstraint?: Record<string, string>;
}

// PolicyRuleActionSubstitute / PolicyRuleActionDegrade 已删除
//（loader 抛错 + 单规则隔离），类型层同步移除。
// PolicyRuleActionGuidance 保留：仅用于事件层审计 / 历史 fixture 类型位。
// 新代码不应再引用 substitute / degrade 决策的 action 字段。

export interface PolicyRuleActionGuidance {
  /** Template reference. */
  templateRef?: string;
  /** Template parameters. */
  templateParams?: Record<string, unknown>;
  /** Non-overridable flag. */
  nonOverridable?: boolean;
  /** Max guidance attempts before the block upgrade. */
  maxAttempts?: number;
  /** Guidance attempt threshold override (reaching it upgrades to block). */
  budgetThreshold?: number;
  /** On-call parameter modifications forwarded to framework adapters. */
  modifyOnCall?: Record<string, unknown>;
}

export interface PolicyRuleActionBlock {
  /** Block reason text. */
  blockReason?: string;
  /** Machine-readable block code. */
  blockCode?: string;
  /** Remediation hint. */
  remediationHint?: string;
  /**
   * 展示字段：true = 可联系管理员复核 / 申请调整策略（误报救济，
   * 面板渲染"可复核"徽标）；false = 硬性安全底线。不触发任何在线申诉动作。
   */
  appealable?: boolean;
}

export interface DecisionChainItem {
  /** Decision in this chain step. */
  decision: InterventionDecisionType;
  /** When to activate this step (simple expression or keyword). */
  when?: string;
  /** Max attempts for this step. */
  maxAttempts?: number;
  /** Guidance details (loader 不再产出，类型位保留以兼容历史 fixture）。 */
  guidance?: PolicyRuleActionGuidance;
  /** Modify details for modify. */
  modify?: PolicyRuleActionModify;
  /** Block details for block. */
  block?: PolicyRuleActionBlock;
}

export interface ConditionalDecision {
  /** Condition expression. */
  condition: string;
  /** Decision when condition matches. */
  decision: InterventionDecisionType;
  /** Guidance details (loader 不再产出，类型位保留以兼容历史 fixture)。 */
  guidance?: PolicyRuleActionGuidance;
  /** Modify details. */
  modify?: PolicyRuleActionModify;
  /** Block details. */
  block?: PolicyRuleActionBlock;
}

export interface PolicyRuleAction {
  /** Single decision. */
  decision?: InterventionDecisionType;
  /** Decision chain: executed in order with state machine. */
  decisionChain?: DecisionChainItem[];
  /** Conditional decisions: first matching condition wins. */
  conditionalDecisions?: ConditionalDecision[];

  /** Shared action details. */
  block?: PolicyRuleActionBlock;
  modify?: PolicyRuleActionModify;
  guidance?: PolicyRuleActionGuidance;

  /** Retry limit before the block upgrade (legacy). */
  retryLimit?: number;
}

export interface PolicyRule {
  /** Unique rule id. */
  id: string;
  /** Human-readable name. */
  name?: string;
  /** Whether the rule is enabled. */
  enabled?: boolean;
  /** Higher priority rules are evaluated first. */
  priority?: number;
  /**
   * Rule category（如 data_leak_monitoring /
   * intrusion_defense / self_protection）。仅用于组织与统计，不参与匹配与裁决。
   * 8 值枚举；loader 校验拼写（throw 时单规则隔离）。
   */
  category?: SPLCategory;
  /**
   * 顶层 severity 字段（v2 必填）。语义锚点见 {@link Severity}。
   * loader 不再从 `evaluate.risk_level` 回落；缺省 severity 的 v2 规则直接
   * 抛错（loader 校验拼写 throw）。
   */
  severity?: Severity;
  /**
   * 规则级正则标志：本规则 match 全部正则维度的默认 flags
   * （条目级 flags 优先），取代 PCRE 内联 `(?i:...)` 写法。仅允许 i/m/s。
   */
  flags?: string;
  /**
   * runtime hook 层 cmdline 检测正则，按 flag 分组。仅供构建期
   * 收集分发（hooks/generated-patterns.json），引擎不评估本字段，与规则
   * enabled 状态无关。
   */
  hookPatterns?: LayeredPatternMap;
  /**
   * process monitor 层 cmdline 检测正则，按 flag 分组。仅供
   * 构建期收集分发（monitor/generated-patterns.json），引擎不评估本字段。
   */
  monitorPatterns?: LayeredPatternMap;
  /**
   * SelfProtection 层模式组。仅供构建期收集分发
   * （self-protection-patterns.generated.json），引擎不评估本字段。
   */
  selfProtectionPatterns?: Record<string, SelfProtectionPatternGroup>;
  /** Match conditions. */
  match: PolicyRuleMatch;
  /** Action to take when matched. */
  action: PolicyRuleAction;
  /**
   * 字段全集：设计意图 / 误伤面 / 评审
   * 记录。启发式规则（paramsRegex 宽口径 / riskFlagsAny 命中面广的规则）
   * 必填误伤面说明；面板 / 审计 / 合规追溯原样消费。
   */
  notes?: string;
  /**
   * 字段全集：合规条款引用（v1 `evaluate.reg_clause` 上移顶层）。
   */
  regClause?: string[];
  /** Declarative test cases. */
  testCases?: PolicyRuleTestCase[];
}

export interface PolicyRuleTestCase {
  name: string;
  input: Record<string, unknown>;
  expectedDecision?: InterventionDecisionType;
  expectedModified?: Record<string, unknown>;
  expectedGuidanceContains?: string[];
}

export interface PolicyResources {
  /** Shared prompt templates. */
  promptTemplates?: Record<string, GuidanceTemplateRef>;
  /** Shared redact policies. */
  redactPolicies?: Record<string, RedactPolicy>;
}

export interface GuidanceTemplateRef {
  /** Template id. */
  id?: string;
  /** Template file path. */
  path?: string;
  /** Template version. */
  version?: string;
}

export interface RedactPolicy {
  /** Fields to redact. */
  fields?: string[];
  /** Replacement string. */
  replacement?: string;
  /** Pattern-based replacements. */
  patterns?: Array<{
    pattern: string;
    replacement: string;
  }>;
}

/**
 * 带标志的正则条目：对象形态的 flags 取代 PCRE 内联
 * `(?i:...)` 写法；仅允许 JS/Python 公共子集 i/m/s。字符串形态等价于
 * `{ pattern: <string> }`（无 flags）。
 *
 * `except` 是条目级的专属豁免：命中其中任一模式即认为"本条目未匹配"，
 * 但不影响同一规则里的其它条目。规则级 `paramsNotRegex` 仍是整条规则的
 * 一票否决——两者语义不同，前者用于"这一条形态在某种上下文下不算违规"，
 * 后者用于"整条规则在某种上下文下不适用"。
 */
export interface PolicyRegexPatternObject {
  pattern: string;
  flags?: string;
  except?: Array<string | { pattern: string; flags?: string }>;
}

export type PolicyRegexEntry = string | PolicyRegexPatternObject;

/**
 * 分层检测正则条目：runtime hook / process monitor
 * 层消费的 cmdline 正则。`input` 仅 hook 层有意义：lowercased（默认，
 * 匹配小写化后的 redacted 命令行）或 raw（原始大小写 redacted，用于
 * AKIA/JWT 等大小写敏感模式）。
 */
export interface LayeredPattern {
  pattern: string;
  flags?: string;
  input?: 'lowercased' | 'raw';
}

/** 分层 pattern 映射：flag 名 → 正则条目列表（flag 名 ⊆ risk-flags.json enum，构建期校验）。 */
export type LayeredPatternMap = Record<string, Array<string | LayeredPattern>>;

/** SelfProtection 模式组：一组同 flags 的正则。 */
export interface SelfProtectionPatternGroup {
  flags?: string;
  patterns: string[];
}

/** 顶层 SelfProtection 模式区（与 rules 同级），构建期生成 JSON 供 SelfProtection.ts 加载。 */
export interface SelfProtectionSection {
  /** 全组统一编译 flags（SelfProtection 历史行为为 i）。 */
  flags?: string;
  /** 模式组：组名 → 正则列表。 */
  groups: Record<string, string[]>;
  /** 结构化判定正则：名称 → 单条正则。 */
  structural: Record<string, string>;
}

/**
 * risk flag 注册表：三套默认处置名单的唯一
 * 数据源，构建期分发给 runtime hook（本地阻断）、process monitor
 * （autokill 默认）与引擎（fail_open_high_risk_only 高危回退）。
 */
export interface PolicyFlagRegistry {
  /** runtime hook 本地阻断默认名单（hooks/runtime.js DEFAULT_BLOCKED_FLAGS）。 */
  hookBlockedFlags?: string[];
  /** process monitor autokill 默认名单（DEFAULT_CONFIG.riskFlags）。 */
  monitorAutoKillFlags?: string[];
  /** 引擎 fail_open_high_risk_only 高危回退（DEFAULT_HIGH_RISK_FLAGS）。 */
  engineHighRiskFlags?: string[];
}

export interface PolicyMetadata {
  id: string;
  name: string;
  version: string;
  description?: string;
  author?: string;
  tags?: string[];
  references?: string[];
  /** Policy source: builtin, template, custom, auto, intel, derived. */
  source?: 'builtin' | 'template' | 'custom' | 'auto' | 'intel' | 'derived';
  sourceRef?: string;
  ttl?: string;
  /** risk flag 注册表。 */
  flagRegistry?: PolicyFlagRegistry;
}

export interface PolicyScope {
  /** Target hosts (OpenClaw or other host platforms). */
  hosts?: string[];
  /** Target agent ids. */
  agents?: string[];
  /** Target tenants. */
  tenants?: string[];
  /** Target workflows on hosts that support workflow scoping. */
  workflows?: string[];
}

export interface PolicyRollout {
  /** Rollout strategy. */
  strategy?: 'percentage' | 'agent_filter' | 'canary' | 'schedule' | 'manual' | 'all';
  /** Percentage for percentage strategy. */
  percentage?: number;
  startAt?: string;
  endAt?: string;
  /** Filter tags for agent_filter strategy. */
  filters?: {
    agentTags?: string[];
    regions?: string[];
  };
}

export interface PolicyFile {
  /** SPL apiVersion. loader 仅接受 v2。 */
  apiVersion?: SPLApiVersion | string;
  /** Kind. */
  kind?: 'Policy';
  /** Metadata. */
  metadata: PolicyMetadata;
  /** Scope. */
  scope?: PolicyScope;
  /** Mode: audit or enforce. */
  mode?: 'audit' | 'enforce';
  /** Rollout strategy. */
  rollout?: PolicyRollout;
  /** Shared resources. */
  resources?: PolicyResources;
  /** Rules. */
  rules: PolicyRule[];
  /**
   * 顶层采集层模式区（与 rules 同级）。runtime hook / process
   * monitor 层的 cmdline 检测正则，引擎不评估，仅供构建期收集分发
   * （scripts/generate-detection-patterns.mjs）。
   */
  hookPatterns?: LayeredPatternMap;
  /** process monitor 层模式区，同 hookPatterns。 */
  monitorPatterns?: LayeredPatternMap;
  /**
   * 项目扩展区段名 `x-openclaw-selfProtection`
   *（openclaw 私有 SelfProtection 模式区）。构建期由
   * generate-detection-patterns.mjs 读取并生成
   * `self-protection-patterns.generated.json` 供 SelfProtection.ts 加载。
   */
  'x-openclaw-selfProtection'?: SelfProtectionSection;
  /** Legacy: policy file version. */
  version?: string;
  /** Legacy: default action. */
  defaultAction?: InterventionDecisionType;
  /**
   * Top-level failure strategy (SPL 顶层 failStrategy)。合法值生效并覆盖
   * config 默认值；非法值在加载期告警并回退 config。
   */
  failStrategy?: FailStrategy;
}

export interface InterventionStats {
  /** Number of rules currently loaded. */
  rulesLoaded: number;
  /** Total number of evaluations. */
  evaluations: number;
  /** Number of block decisions. */
  blocks: number;
  /** Number of modify decisions. */
  modifies: number;
  /**
   * @deprecated 删除 substitute 决策；
   * 保留为可选数值位以兼容历史面板 / 心跳上报 schema。loader 不再产出，
   * 引擎层不再自增；新代码不得写入。
   */
  substitutes?: number;
  /** Number of context_adjust decisions（保留：决策链/条件决策 fallback 仍可能产出）。 */
  guidanceAdjustments: number;
  /**
   * @deprecated 删除 degrade 决策；
   * 同 substitutes，保留为可选数值位以兼容历史面板 schema。
   */
  degrades?: number;
  /** Number of audit decisions（仅记录审计，不拦截）。 */
  audits: number;
  /** Number of fallback decisions. */
  fallbacks: number;
  /** 评估延迟累计（ms），用于心跳上报平均值。 */
  latencyTotalMs?: number;
  /** 平均评估延迟（ms），由 getStats 计算。 */
  avgLatencyMs?: number;
}

export interface InterventionEngine {
  initialize(): Promise<void>;
  evaluate(ctx: InterventionContext): Promise<SecurityDecision>;
  getStats(): InterventionStats;
  shutdown(): Promise<void>;
}

export interface RuleLoaderOptions {
  /** Policy file path. */
  policyPath: string;
  /** Reload interval in milliseconds. 0 disables hot reload. */
  reloadIntervalMs?: number;
  /** Optional logger. */
  logger?: { warn: (msg: string) => void; error: (msg: string) => void };
  /** 加载期规则正则问题（非法 / 审计判定为灾难性回溯）回调，用于写安全事件留痕。 */
  onRuleIssue?: (issue: { ruleId: string; pattern: string; kind: 'invalid' | 'unsafe' }) => void;
  /** Strategy-level audit callback (policy_missing / policy_load_failed). */
  audit?: (event: PolicyAuditEvent) => void;
}

/** 策略引擎留痕事件类型：策略缺失/加载失败/规则被隔离。 */
export type PolicyAuditEventType =
  | 'policy_missing'
  | 'policy_load_failed'
  | 'policy_empty'
  | 'rule_invalid_regex'
  | 'rule_unsafe_regex';

/** 策略引擎审计事件：由 InterventionEngine 产出，宿主层负责写入事件 NDJSON。 */
export interface PolicyAuditEvent {
  eventType: PolicyAuditEventType;
  /** 相关规则 id（规则隔离类事件）。 */
  ruleId?: string;
  /** 相关正则模式（规则隔离类事件）。 */
  pattern?: string;
  /** 补充说明。 */
  detail?: string;
  ts: number;
}

export interface GuidanceConfig {
  /** Whether guidance is enabled. */
  enabled?: boolean;
  /** Paths to search for guidance templates. */
  templatePaths?: string[];
  /** Default template id. */
  defaultTemplateId?: string;
  /** 引导预算阈值（按风险等级的次数上限；达到后升级为 block）。 */
  budgetThresholds?: Record<string, number>;
  /** State TTL in milliseconds. */
  stateTtlMs?: number;
  /** Steps window to consider guidance effective. */
  guidanceWindowSteps?: number;
}

export interface DegradeConfig {
  /** Whether degrade is enabled. */
  enabled?: boolean;
}

export interface InterventionEngineOptions {
  /** Rule loader options. */
  ruleLoader: RuleLoaderOptions;
  /**
   * Decision timeout in milliseconds.
   * 保留字段：评估核心全同步，超时分支结构性不触发
   * （见 InterventionEngine.evaluateWithTimeout 注释）；面板已隐藏，
   * 待后续重构为异步评估后生效。
   */
  decisionTimeoutMs?: number;
  /** Failure strategy. */
  failStrategy?: FailStrategy;
  /** High-risk flags used by fail_open_high_risk_only. */
  highRiskFlags?: string[];
  /** Guidance configuration. */
  guidance?: GuidanceConfig;
  /** Degrade configuration. */
  degrade?: DegradeConfig;
  /** Run mode: audit records only; enforce actually blocks when no rule matches. */
  mode?: 'audit' | 'enforce';
  /** 审计回调：策略缺失、规则隔离、未知 actionType 等 fail-open 面事件留痕。 */
  audit?: (event: PolicyAuditEvent) => void;
  /** Optional logger. */
  logger?: { warn: (msg: string) => void; error: (msg: string) => void };
}

export interface InterventionConfig {
  /** Whether intervention is enabled. */
  enabled?: boolean;
  /** Run mode: audit records only; enforce actually blocks. */
  mode?: 'audit' | 'enforce';
  /** Policy file path. */
  policyPath?: string;
  /** Rule reload interval. */
  reloadIntervalMs?: number;
  /** Decision timeout. */
  decisionTimeoutMs?: number;
  /** Failure strategy on error/timeout. */
  failStrategy?: FailStrategy;
  /** Whether to report blocked/modified events. */
  reportBlockedEvents?: boolean;
  /** High-risk flags for fail_open_high_risk_only. */
  highRiskFlags?: string[];
  /** Guidance configuration. */
  guidance?: GuidanceConfig;
  /** Degrade configuration. */
  degrade?: DegradeConfig;
}

/**
 * 引擎 fail_open_high_risk_only 高危回退名单。唯一数据源是
 * policies/security-policy.spl.yaml 的 metadata.flagRegistry.engineHighRiskFlags，
 * 构建期经 generated-flag-defaults.ts 注入；此处不再
 * 维护独立拷贝。
 */
export const DEFAULT_HIGH_RISK_FLAGS = [...GENERATED_ENGINE_HIGH_RISK_FLAGS];

export const DEFAULT_GUIDANCE_THRESHOLDS: Record<string, number> = {
  low: 6,
  medium: 4,
  high: 3,
  critical: 1,
  extreme: 1,
};
