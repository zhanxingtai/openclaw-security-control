/**
 * OpenClaw Security Monitor - SPL Rule Loader
 *
 * Loads SPL format policy files (apiVersion: security.use/v2).
 *
 * loader 仅接受 v2 apiVersion；旧 v1 文件（evaluate.risk_level /
 * selfProtection 区段）一律拒绝加载。
 *
 * substitute / context_adjust / degrade 决策值及对应 action.substitute /
 * action.degrade 字段在加载期抛错（单规则隔离）；modify.substitutePatterns
 * （属于 modify 决策）与 guidance.* 字段（事件层审计标注）
 * 正常解析。
 */

import type { PolicyFile, PolicyMetadata, PolicyScope, PolicyRollout, PolicyResources, PolicyRule, PolicyRegexEntry, LayeredPattern, LayeredPatternMap, SelfProtectionPatternGroup, SelfProtectionSection, PolicyFlagRegistry, InterventionDecisionType } from './types.js';
import { normalizeActionTypes } from './splActionType.js';
import { hasLegacyInlineFlags } from './RuleRegexCache.js';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export interface SPLParseOptions {
  /** Validate schema strictly. */
  strict?: boolean;
  /** Logger. */
  logger?: { warn: (msg: string) => void; error: (msg: string) => void };
}

/** 正则 flags 仅允许 JS/Python 公共子集 i/m/s（禁 g/y：stateful lastIndex 交替命中）。 */
const VALID_REGEX_FLAGS = /^[ims]*$/;

/**
 * category 8 值枚举。loader 校验拼写（throw + 单规则隔离
 * 单规则隔离）。`type.ts` `SPLCategory` 字面量联合以此为单一事实源。
 */
const SPL_CATEGORIES = [
  'self_protection',
  'intrusion_defense',
  'data_leak_monitoring',
  'sensitive_data_access',
  'supply_chain',
  'ssrf',
  'behavior_guidance',
  'data_desensitization',
] as const;

function isValidCategory(value: unknown): value is (typeof SPL_CATEGORIES)[number] {
  return typeof value === 'string' && (SPL_CATEGORIES as readonly string[]).includes(value);
}

/**
 * riskFlag 字典缓存（懒加载）。读
 * `policies/risk-flags.json` `definitions.flag_name.enum` 数组，loader 期校验
 * `riskFlagsAny/All` 拼写；同时读 `registry[*].deprecated`（since-version 字符串）
 * 给出 deprecated flag 映射，加载期 WARN 提示迁移到替代 flag。
 *
 * 失败兜底：找不到文件 / 解析失败 → 缓存 null，校验跳过 + 模块级一次性 WARN
 * （不阻断策略加载，但给运维留痕）。生产环境走 import.meta.url 路径（bundled
 * 后相对路径仍正确）；测试环境兜底走 process.cwd()。
 */
let riskFlagDictCache: { flags: ReadonlySet<string>; deprecated: ReadonlyMap<string, string> } | null | undefined;
let riskFlagDictWarned = false;

function loadRiskFlagDict(logger?: { warn: (msg: string) => void }):
  | { flags: ReadonlySet<string>; deprecated: ReadonlyMap<string, string> }
  | null {
  if (riskFlagDictCache !== undefined) return riskFlagDictCache;
  const candidates = [
    // bundled ESM：相对 loader 源文件位置定位仓库根目录的 policies/
    (() => {
      try {
        const here = dirname(fileURLToPath(import.meta.url));
        return resolve(here, '..', '..', 'policies', 'risk-flags.json');
      } catch {
        return null;
      }
    })(),
    // 测试 / CJS 兜底：cwd 相对路径
    resolve(process.cwd(), 'policies', 'risk-flags.json'),
  ].filter((p): p is string => typeof p === 'string' && existsSync(p));
  for (const path of candidates) {
    try {
      const raw = JSON.parse(readFileSync(path, 'utf8')) as {
        definitions?: { flag_name?: { enum?: unknown } };
        registry?: Array<{ name?: string; deprecated?: string | null }>;
      };
      const arr = raw?.definitions?.flag_name?.enum;
      if (Array.isArray(arr)) {
        const flags = new Set(arr.map(String));
        const deprecated = new Map<string, string>();
        if (Array.isArray(raw.registry)) {
          for (const entry of raw.registry) {
            if (
              entry &&
              typeof entry.name === 'string' &&
              typeof entry.deprecated === 'string' &&
              entry.deprecated.length > 0
            ) {
              deprecated.set(entry.name, entry.deprecated);
            }
          }
        }
        riskFlagDictCache = { flags, deprecated };
        return riskFlagDictCache;
      }
    } catch {
      // 继续尝试下一路径
    }
  }
  riskFlagDictCache = null;
  if (!riskFlagDictWarned) {
    riskFlagDictWarned = true;
    logger?.warn?.(
      `[SPLRuleLoader] risk-flag 字典 policies/risk-flags.json 读取失败；riskFlagsAny/All 拼写校验跳过`
    );
  }
  return null;
}

/**
 * PCRE 内联 flag 加载期 WARN 去重集合——同 ruleId 多次加载
 * 仅 WARN 一次。与 RuleLoader.rebuildCompiledRegexCache 的 WARN 双层并存，
 * 不去重跨层（触发时机不同：loader 期 vs 编译期）。
 */
const warnedLegacyInlineFlags = new Set<string>();

/**
 * Deprecated risk flag 加载期 WARN 去重集合——key = `${ruleId}|${flag}`，
 * 同 rule 同 flag 多次加载仅 WARN 一次。当前 registry 中已知 deprecated：
 * - `secret_in_content`（since 1.0.0）→ 替代 `credential_exposure`
 */
const warnedDeprecatedFlags = new Set<string>();

/**
 * parseSPLPolicy 末尾对所有解析后规则做一次 PCRE 内联 flag
 * 扫描，复用 RuleRegexCache.hasLegacyInlineFlags 静态审计。
 */
function policyPatternsAudit(rules: PolicyRule[], options: SPLParseOptions): void {
  for (const rule of rules) {
    if (!rule.id || warnedLegacyInlineFlags.has(rule.id)) continue;
    if (hasLegacyInlineFlags(rule)) {
      warnedLegacyInlineFlags.add(rule.id);
      options.logger?.warn?.(
        `[SPLRuleLoader] rule ${rule.id}: pattern uses PCRE inline (?i:...) flag（禁内联 flag）；` +
          `请改用 match 条目级 flags: "i"`
      );
    }
  }
}

function sanitizeFlags(value: unknown, where: string, options: SPLParseOptions): string | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'string' || !VALID_REGEX_FLAGS.test(value)) {
    options.logger?.warn?.(
      `[SPLRuleLoader] ${where}: invalid regex flags ${JSON.stringify(value)} (allowed: i/m/s); flags ignored`
    );
    return undefined;
  }
  return value.length > 0 ? value : undefined;
}

/**
 * 正则条目规范化：字符串 → 原样；对象形态 { pattern, flags } →
 * 保留 flags（取代 PCRE 内联 (?i:...) 写法）。非法条目记 warn 并丢弃。
 */
function normalizeRegexEntry(value: unknown, where: string, options: SPLParseOptions): PolicyRegexEntry | undefined {
  if (typeof value === 'string') return value;
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    const entry = value as Record<string, unknown>;
    if (typeof entry.pattern !== 'string' || entry.pattern.length === 0) {
      options.logger?.warn?.(
        `[SPLRuleLoader] ${where}: pattern entry missing non-empty "pattern" string; entry dropped`
      );
      return undefined;
    }
    const flags = sanitizeFlags(entry.flags, where, options);
    // 条目级专属豁免（except）：命中任一即视为"本条目未匹配"，不影响同规则
    // 其它条目。与规则级 paramsNotRegex（整条规则一票否决）语义不同。
    const except = normalizeExceptList(entry.except, `${where}.except`, options);
    const normalized: { pattern: string; flags?: string; except?: Array<string | { pattern: string; flags?: string }> } =
      flags ? { pattern: entry.pattern, flags } : { pattern: entry.pattern };
    if (except && except.length > 0) normalized.except = except;
    return normalized;
  }
  options.logger?.warn?.(
    `[SPLRuleLoader] ${where}: unsupported regex entry ${JSON.stringify(value)}; entry dropped`
  );
  return undefined;
}

/**
 * 归一化条目级豁免列表。豁免条目只支持 pattern/flags（不再嵌套 except），
 * 非法条目丢弃并记 WARN。
 */
function normalizeExceptList(
  value: unknown,
  where: string,
  options: SPLParseOptions
): Array<string | { pattern: string; flags?: string }> | undefined {
  if (value === undefined || value === null) return undefined;
  const raw = Array.isArray(value) ? value : [value];
  const out: Array<string | { pattern: string; flags?: string }> = [];
  for (const [i, item] of raw.entries()) {
    if (typeof item === 'string') {
      if (item.length === 0) continue;
      out.push(item);
      continue;
    }
    if (item && typeof item === 'object' && !Array.isArray(item)) {
      const entry = item as Record<string, unknown>;
      if (typeof entry.pattern !== 'string' || entry.pattern.length === 0) {
        options.logger?.warn?.(
          `[SPLRuleLoader] ${where}[${i}]: exemption entry missing non-empty "pattern" string; entry dropped`
        );
        continue;
      }
      // 豁免条目内不再接受嵌套豁免
      const flags = sanitizeFlags(entry.flags, `${where}[${i}]`, options);
      out.push(flags ? { pattern: entry.pattern, flags } : { pattern: entry.pattern });
    }
  }
  return out.length > 0 ? out : undefined;
}

function normalizeRegexList(value: unknown, where: string, options: SPLParseOptions): PolicyRegexEntry[] | undefined {
  if (typeof value === 'string') return [value];
  if (!Array.isArray(value)) return undefined;
  const out: PolicyRegexEntry[] = [];
  for (const [i, item] of value.entries()) {
    const entry = normalizeRegexEntry(item, `${where}[${i}]`, options);
    if (entry !== undefined) out.push(entry);
  }
  return out.length > 0 ? out : undefined;
}

export function parseSPLPolicy(parsed: unknown, options: SPLParseOptions = {}): PolicyFile {
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('SPL policy file must be an object');
  }

  const policy = parsed as Record<string, unknown>;

  // loader 仅接受 security.use/v2。v1 文件 / 缺失 apiVersion / 其他版本均
  // throw，不再走迁移层。
  const apiVersionRaw = policy.apiVersion;
  if (apiVersionRaw !== 'security.use/v2') {
    throw new Error(
      `unsupported SPL apiVersion: ${String(apiVersionRaw)}（要求 security.use/v2；v1 兼容期已结束）`
    );
  }
  if (policy.kind !== 'Policy' && policy.kind !== undefined) {
    options.logger?.warn?.(`[SPLRuleLoader] unexpected kind: ${policy.kind}`);
  }

  const metadata = parseMetadata(policy.metadata);
  const scope = parseScope(policy.scope);
  const mode = parseMode(policy.mode);
  const failStrategy = parseFailStrategy(policy.failStrategy, options);
  const rollout = parseRollout(policy.rollout);
  const resources = parseResources(policy.resources);
  const rules = parseRules(policy.rules, options);
  // 加载期 PCRE 内联 flag 扫描（去重 WARN）。
  policyPatternsAudit(rules, options);
  // 顶层采集层模式区（与 rules 同级）。引擎不评估这些区段，
  // 只做形状校验与透传，构建期由 generate-detection-patterns.mjs 收集。
  const hookPatterns = parseLayeredPatternMap(policy.hookPatterns, 'top-level hookPatterns', options);
  const monitorPatterns = parseLayeredPatternMap(policy.monitorPatterns, 'top-level monitorPatterns', options);
  // 项目扩展区段：v2 必读 x-openclaw-selfProtection；
  // legacy selfProtection 区段不再 fallback。
  const selfProtection = parseSelfProtectionSection(
    policy['x-openclaw-selfProtection'],
    'x-openclaw-selfProtection',
    options
  );

  return {
    apiVersion: 'security.use/v2',
    kind: 'Policy',
    metadata,
    scope,
    mode,
    failStrategy,
    rollout,
    resources,
    rules,
    hookPatterns,
    monitorPatterns,
    'x-openclaw-selfProtection': selfProtection,
  };
}

/**
 * 顶层 x-openclaw-selfProtection 区段解析（{flags, groups, structural} 透传）。
 * 只接受 x- 入口（v1 legacy selfProtection 区段不再读取）。通过 `where` 参数化日志位置。
 */
function parseSelfProtectionSection(value: unknown, where: string, options: SPLParseOptions): SelfProtectionSection | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const raw = value as Record<string, unknown>;
  const flags = sanitizeFlags(raw.flags, `top-level ${where}`, options);
  const groups: Record<string, string[]> = {};
  if (raw.groups && typeof raw.groups === 'object' && !Array.isArray(raw.groups)) {
    for (const [name, list] of Object.entries(raw.groups as Record<string, unknown>)) {
      if (Array.isArray(list) && list.length > 0) {
        groups[name] = list.map((p) => String(p));
      } else {
        options.logger?.warn?.(
          `[SPLRuleLoader] ${where}.groups.${name}: expected non-empty array; group dropped`
        );
      }
    }
  }
  const structural: Record<string, string> = {};
  if (raw.structural && typeof raw.structural === 'object' && !Array.isArray(raw.structural)) {
    for (const [name, pattern] of Object.entries(raw.structural as Record<string, unknown>)) {
      if (typeof pattern === 'string' && pattern.length > 0) {
        structural[name] = pattern;
      } else {
        options.logger?.warn?.(
          `[SPLRuleLoader] ${where}.structural.${name}: expected non-empty string; entry dropped`
        );
      }
    }
  }
  if (Object.keys(groups).length === 0 && Object.keys(structural).length === 0) return undefined;
  return { ...(flags ? { flags } : {}), groups, structural };
}

function parseMetadata(value: unknown): PolicyMetadata {
  if (!value || typeof value !== 'object') {
    throw new Error('SPL policy metadata is required');
  }
  const m = value as Record<string, unknown>;
  if (typeof m.id !== 'string' || m.id.length === 0) {
    throw new Error('SPL policy metadata.id is required and must be a non-empty string');
  }
  if (typeof m.name !== 'string' || m.name.length === 0) {
    throw new Error('SPL policy metadata.name is required and must be a non-empty string');
  }
  if (typeof m.version !== 'string' || m.version.length === 0) {
    throw new Error('SPL policy metadata.version is required and must be a non-empty string');
  }
  return {
    id: m.id,
    name: m.name,
    version: m.version,
    description: typeof m.description === 'string' ? m.description : undefined,
    author: typeof m.author === 'string' ? m.author : undefined,
    tags: Array.isArray(m.tags) ? m.tags.map((t) => String(t)) : undefined,
    references: Array.isArray(m.references) ? m.references.map((r) => String(r)) : undefined,
    source: isValidSource(m.source) ? m.source : undefined,
    sourceRef: typeof m.sourceRef === 'string' ? m.sourceRef : undefined,
    ttl: typeof m.ttl === 'string' ? m.ttl : undefined,
    flagRegistry: parseFlagRegistry(m.flagRegistry),
  };
}

/** metadata.flagRegistry 解析（三套默认处置名单的单源注册表）。 */
function parseFlagRegistry(value: unknown): PolicyFlagRegistry | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const r = value as Record<string, unknown>;
  const toList = (v: unknown): string[] | undefined =>
    Array.isArray(v) ? v.map((f) => String(f)) : undefined;
  const registry: PolicyFlagRegistry = {
    hookBlockedFlags: toList(r.hookBlockedFlags),
    monitorAutoKillFlags: toList(r.monitorAutoKillFlags),
    engineHighRiskFlags: toList(r.engineHighRiskFlags),
  };
  return registry.hookBlockedFlags || registry.monitorAutoKillFlags || registry.engineHighRiskFlags
    ? registry
    : undefined;
}

function isValidSource(value: unknown): value is PolicyMetadata['source'] {
  return (
    typeof value === 'string' &&
    ['builtin', 'template', 'custom', 'auto', 'intel', 'derived'].includes(value)
  );
}

function parseScope(value: unknown): PolicyScope | undefined {
  if (!value || typeof value !== 'object') return undefined;
  const s = value as Record<string, unknown>;
  // Back-compat: older policies write `platforms:`; new ones write `hosts:`.
  const hostList = Array.isArray(s.hosts)
    ? s.hosts
    : Array.isArray(s.platforms)
      ? s.platforms
      : undefined;
  return {
    hosts: hostList ? hostList.map((p) => String(p)) : undefined,
    agents: Array.isArray(s.agents) ? s.agents.map((a) => String(a)) : undefined,
    tenants: Array.isArray(s.tenants) ? s.tenants.map((t) => String(t)) : undefined,
    workflows: Array.isArray(s.workflows) ? s.workflows.map((w) => String(w)) : undefined,
  };
}

function parseMode(value: unknown): 'audit' | 'enforce' | undefined {
  if (value === 'audit' || value === 'enforce') return value;
  return undefined;
}

/**
 * SPL 顶层 failStrategy：合法值生效并覆盖 config 默认值（消除"策略文件写的是
 * 不生效的假配置"）；非法值记 warn 并回退 config，保持默认行为不变。
 */
function parseFailStrategy(
  value: unknown,
  options: SPLParseOptions
): PolicyFile['failStrategy'] {
  if (value === undefined || value === null) return undefined;
  if (value === 'fail_open' || value === 'fail_closed' || value === 'fail_open_high_risk_only') {
    return value;
  }
  options.logger?.warn?.(
    `[SPLRuleLoader] invalid top-level failStrategy: ${String(value)}; falling back to config default`
  );
  return undefined;
}

function parseRollout(value: unknown): PolicyRollout | undefined {
  if (!value || typeof value !== 'object') return undefined;
  const r = value as Record<string, unknown>;
  const strategy = typeof r.strategy === 'string' ? r.strategy : undefined;
  if (!strategy) return undefined;

  return {
    strategy: strategy as PolicyRollout['strategy'],
    percentage: typeof r.percentage === 'number' ? r.percentage : undefined,
    startAt: typeof r.startAt === 'string' ? r.startAt : undefined,
    endAt: typeof r.endAt === 'string' ? r.endAt : undefined,
    filters: r.filters && typeof r.filters === 'object' ? (r.filters as PolicyRollout['filters']) : undefined,
  };
}

function parseResources(value: unknown): PolicyResources | undefined {
  if (!value || typeof value !== 'object') return undefined;
  const r = value as Record<string, unknown>;
  return {
    promptTemplates: r.promptTemplates as PolicyResources['promptTemplates'],
    redactPolicies: r.redactPolicies as PolicyResources['redactPolicies'],
  };
}

function parseRules(value: unknown, options: SPLParseOptions): PolicyRule[] {
  if (!Array.isArray(value)) return [];
  const rules: PolicyRule[] = [];
  for (const [index, rule] of value.entries()) {
    try {
      rules.push(parseRule(rule, index, options));
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      // 顶层 severity 必填，v2 起无兼容期——
      // 缺失即 throw，且必须穿透单规则容错层向上传播，不能让整策略静默
      // 退化为"该规则丢弃"的空分级状态（面板分级与评审矩阵依赖）。
      if (msg.includes('severity is required at top level')) {
        throw err;
      }
      // 单规则容错：其他单条规则缺陷（如 actionType 笔误）只隔离该规则
      // （warn 留痕），不得让整策略加载失败退回空策略（fail-open 面）。
      const id = rule && typeof rule === 'object' ? String((rule as Record<string, unknown>).id ?? `index ${index}`) : `index ${index}`;
      options.logger?.warn?.(
        `[SPLRuleLoader] rule ${id} skipped: ${msg}`
      );
    }
  }
  return rules;
}

function parseRule(value: unknown, index: number, options: SPLParseOptions): PolicyRule {
  if (!value || typeof value !== 'object') {
    throw new Error(`rule at index ${index} is not an object`);
  }
  const rule = value as Record<string, unknown>;
  const id = typeof rule.id === 'string' ? rule.id : `rule-${index}`;
  const match = parseMatch(rule.match, id, options);
  const action = parseAction(rule.action, id, options);
  const enabled = parseEnabled(rule.enabled, id, options);
  const flags = sanitizeFlags(rule.flags, `rule ${id} flags`, options);

  // 不可交付决策 + 缺 notes → 加载期 WARN。
  // 在 severity 校验前调用——severity 缺失会 throw，但本规则不阻断，仅留痕。
  warnUndeliverableNotesMissing(
    {
      id,
      match: rule.match as { actionType?: unknown } | undefined,
      action: rule.action as { decision?: unknown } | undefined,
      notes: rule.notes as string | undefined,
    },
    options
  );

  // blockCode 模式 + 语义校验（CATEGORY_威胁_NNN，
  // 第一段等于 category.uppercase()）。当前阶段 WARN，不阻断加载。
  warnBlockCodeSemanticMismatch(
    {
      id,
      category: rule.category as string | undefined,
      action: rule.action as { blockCode?: unknown } | undefined,
    },
    options
  );

  // 顶层 severity 字段（v2 必填，无兼容期）。
  //   - 非法值：WARN + 置空（防御性，仍可加载）
  //   - 缺失：throw 阻断策略加载（v2 起无兼容期，必填约束落地；
  //     下游面板分级消费与决策评审矩阵都依赖该字段）
  const severityRaw = rule.severity;
  let severity: PolicyRule['severity'];
  if (isValidSeverity(severityRaw)) {
    severity = severityRaw;
  } else if (severityRaw !== undefined && severityRaw !== null) {
    options.logger?.warn?.(
      `[SPLRuleLoader] rule ${id}: severity must be one of low/medium/high/critical/extreme, ` +
        `got ${JSON.stringify(severityRaw)}; treating as missing`
    );
    severity = undefined;
  } else {
    throw new Error(
      `SPLRuleLoader rule ${id}: severity is required at top level (v2 has no compatibility fallback); ` +
        `面板分级消费与决策评审矩阵依赖该字段`
    );
  }

  return {
    id,
    name: typeof rule.name === 'string' ? rule.name : id,
    // 单规则容错：enabled 仅接受严格 boolean。字符串 "no" 等真值被
    // Boolean() 静默当 true 启用（"no" 作者的意图几乎必然是禁用）；
    // 非 boolean 一律记 warn 并按禁用处理——启用只能是显式 `true`。
    enabled,
    priority: typeof rule.priority === 'number' ? rule.priority : 0,
    // 8 值枚举校验；非法值 throw 让单规则隔离 + WARN。
    category: parseCategory(rule.category, id, options),
    severity,
    flags,
    hookPatterns: parseLayeredPatternMap(rule.hookPatterns, `rule ${id} hookPatterns`, options),
    monitorPatterns: parseLayeredPatternMap(rule.monitorPatterns, `rule ${id} monitorPatterns`, options),
    selfProtectionPatterns: parseSelfProtectionPatterns(rule.selfProtectionPatterns, `rule ${id}`, options),
    match,
    action,
    // 字段全集：notes（设计意图 / 误伤面 / 评审记录；启发式规则必填误伤面）
    // + regClause（合规条款引用，v1 `evaluate.reg_clause` 上移顶层）。
    // 解析层只做形状校验与透传，下游
    // 面板 / 审计 / 合规追溯原样消费；空值不注入（保持键不出现）。
    ...(typeof rule.notes === 'string' && rule.notes.length > 0
      ? { notes: rule.notes }
      : {}),
    ...(Array.isArray(rule.regClause)
      ? (() => {
          const filtered = rule.regClause.filter(
            (c): c is string => typeof c === 'string' && c.length > 0
          );
          return filtered.length > 0 ? { regClause: filtered } : {};
        })()
      : {}),
    testCases: parseTestCases(rule.testCases || rule.test_cases),
  };
}

/** severity 五档合法性校验。 */
function isValidSeverity(value: unknown): value is NonNullable<PolicyRule['severity']> {
  return typeof value === 'string' && ['low', 'medium', 'high', 'critical', 'extreme'].includes(value);
}

/**
 * category 8 值校验。缺失合法（未声明 category 不
 * 视为错误，category 仅用于组织与统计）；声明但拼错 → throw + 单规则隔离。
 */
function parseCategory(value: unknown, ruleId: string, _options: SPLParseOptions): PolicyRule['category'] {
  if (value === undefined || value === null) return undefined;
  if (isValidCategory(value)) return value;
  throw new Error(
    `rule ${ruleId}: category must be one of ${SPL_CATEGORIES.join('|')}, got ${JSON.stringify(value)}`
  );
}

/**
 * 不可交付决策白名单 + notes 缺失条件 WARN。
 * HOST_DELIVERABLE_DECISIONS（store.ts 定义）仅支持
 * agent_tool_call / agent_message 入口下发 block/modify/escalate 等非
 * RECORD_ONLY 决策；其他入口（process_start / network_http /
 * agent_tool_result）上挂非 RECORD_ONLY 决策属不可交付行为——运行期由
 * store.ts warnDecisionNotDeliverable 留痕。loader 层加载期必须 WARN
 * 提醒规则作者：notes 必须写明"为何不可交付仍要 block"的设计意图
 * （含替代的留痕机制），否则审计无法追溯。
 *
 * 单一职责：本函数只判定"该规则是否命中不可交付组合"与"是否缺 notes"，
 * 不复用已删的 `warnUndeliverableDecisions`（决议：单一
 * 职责拆函数，避免循环引用与功能膨胀）。
 */
const UNDELIVERABLE_DECISIONS: ReadonlySet<string> = new Set(['block', 'modify', 'escalate']);
const UNDELIVERABLE_ACTIONTYPES: ReadonlySet<string> = new Set([
  'process_start',
  'network_http',
  'agent_tool_result',
]);

function warnUndeliverableNotesMissing(rule: {
  id: string;
  match?: { actionType?: unknown };
  action?: { decision?: unknown };
  notes?: string;
}, options: SPLParseOptions): void {
  const decision = rule.action?.decision;
  if (typeof decision !== 'string' || !UNDELIVERABLE_DECISIONS.has(decision)) return;
  const actionTypes = Array.isArray(rule.match?.actionType)
    ? rule.match.actionType.map(String)
    : [];
  if (!actionTypes.some((at) => UNDELIVERABLE_ACTIONTYPES.has(at))) return;
  if (typeof rule.notes === 'string' && rule.notes.length > 0) return;
  options.logger?.warn?.(
    `[SPLRuleLoader] rule ${rule.id}: 顶层 notes 缺失但命中不可交付组合 ` +
      `(decision=${decision} on ${actionTypes.filter((at) => UNDELIVERABLE_ACTIONTYPES.has(at)).join('/')}); ` +
      `不可交付规则必须 notes 写明设计意图与替代留痕机制`
  );
}

/**
 * blockCode 语义校验。
 *   - 模式：^[A-Z][A-Z0-9_]*_[0-9]{3}$（多段命名，末段为 _NNN 数字编号）
 *   - 第一段必须等于 rule.category.uppercase() 的第一个单词（即多词 category
 *     仅首词进入 blockCode 第一段；如 self_protection → SELF）
 *   - 当前阶段仅 WARN（不 throw），避免破坏现行命名规范；命名规范稳定后可
 *     收紧为 throw
 */
function warnBlockCodeSemanticMismatch(rule: {
  id: string;
  category?: string;
  action?: { blockCode?: unknown };
}, options: SPLParseOptions): void {
  const blockCode = rule.action?.blockCode;
  if (typeof blockCode !== 'string' || blockCode.length === 0) return;
  const pattern = /^[A-Z][A-Z0-9_]*_[0-9]{3}$/;
  if (!pattern.test(blockCode)) {
    options.logger?.warn?.(
      `[SPLRuleLoader] rule ${rule.id}: blockCode "${blockCode}" 模式不符合 ` +
        `^[A-Z][A-Z0-9_]*_[0-9]{3}$ （CATEGORY_威胁_NNN）`
    );
    return;
  }
  if (typeof rule.category === 'string' && rule.category.length > 0) {
    const expectedFirstSegment = rule.category.toUpperCase().split(/[_-]/)[0];
    const actualFirstSegment = blockCode.split('_')[0];
    if (actualFirstSegment !== expectedFirstSegment) {
      options.logger?.warn?.(
        `[SPLRuleLoader] rule ${rule.id}: blockCode "${blockCode}" 第一段 "${actualFirstSegment}" ` +
          `与 category.uppercase() 首词 "${expectedFirstSegment}" 不一致（强制约束）`
      );
    }
  }
}

/**
 * 分层 pattern 映射解析：flag → 条目列表。条目支持字符串简写
 * 或 { pattern, flags, input } 对象；flags 缺省继承规则级 flags 的逻辑在
 * 消费侧（生成脚本）处理，这里只做形状校验与透传。
 */
function parseLayeredPatternMap(value: unknown, where: string, options: SPLParseOptions): LayeredPatternMap | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const result: LayeredPatternMap = {};
  for (const [flag, list] of Object.entries(value as Record<string, unknown>)) {
    if (!Array.isArray(list)) {
      options.logger?.warn?.(
        `[SPLRuleLoader] ${where}.${flag}: expected an array of patterns; entry dropped`
      );
      continue;
    }
    const entries: Array<string | LayeredPattern> = [];
    for (const [i, item] of list.entries()) {
      if (typeof item === 'string') {
        entries.push(item);
        continue;
      }
      if (item && typeof item === 'object' && !Array.isArray(item)) {
        const e = item as Record<string, unknown>;
        if (typeof e.pattern !== 'string' || e.pattern.length === 0) {
          options.logger?.warn?.(
            `[SPLRuleLoader] ${where}.${flag}[${i}]: missing non-empty "pattern" string; entry dropped`
          );
          continue;
        }
        const entry: LayeredPattern = { pattern: e.pattern };
        const flags = sanitizeFlags(e.flags, `${where}.${flag}[${i}]`, options);
        if (flags) entry.flags = flags;
        if (e.input === 'lowercased' || e.input === 'raw') entry.input = e.input;
        entries.push(entry);
        continue;
      }
      options.logger?.warn?.(
        `[SPLRuleLoader] ${where}.${flag}[${i}]: unsupported entry; dropped`
      );
    }
    if (entries.length > 0) result[flag] = entries;
  }
  return Object.keys(result).length > 0 ? result : undefined;
}

/** SelfProtection 模式组解析：组名 → { flags, patterns } 透传。 */
function parseSelfProtectionPatterns(value: unknown, where: string, options: SPLParseOptions): Record<string, SelfProtectionPatternGroup> | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const result: Record<string, SelfProtectionPatternGroup> = {};
  for (const [group, raw] of Object.entries(value as Record<string, unknown>)) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      options.logger?.warn?.(
        `[SPLRuleLoader] ${where} selfProtectionPatterns.${group}: expected { flags?, patterns }; group dropped`
      );
      continue;
    }
    const g = raw as Record<string, unknown>;
    if (!Array.isArray(g.patterns) || g.patterns.length === 0) {
      options.logger?.warn?.(
        `[SPLRuleLoader] ${where} selfProtectionPatterns.${group}: missing non-empty patterns array; group dropped`
      );
      continue;
    }
    const flags = sanitizeFlags(g.flags, `${where} selfProtectionPatterns.${group}`, options);
    result[group] = { patterns: g.patterns.map((p) => String(p)), ...(flags ? { flags } : {}) };
  }
  return Object.keys(result).length > 0 ? result : undefined;
}

/**
 * risk_level== 条件表达式已从评估侧移除（无运行时 risk 信号来源，
 * 原为恒 false 死分支）；残留声明按"未知表达式恒真"处理，语义由"永不命中"
 * 变为"恒真"，加载期必须告警而不是静默改变行为。
 */
function warnRiskLevelCondition(expr: string | undefined, where: string, options: SPLParseOptions): void {
  if (expr && /risk_level\s*==?/i.test(expr)) {
    options.logger?.warn?.(
      `[SPLRuleLoader] ${where}: condition "${expr}" uses risk_level==, which is no longer evaluated ` +
      `(no runtime risk signal source); it now falls through as always-true`
    );
  }
}

function parseEnabled(value: unknown, ruleId: string, options: SPLParseOptions): boolean {
  if (value === undefined || value === null) return true;
  if (typeof value === 'boolean') return value;
  options.logger?.warn?.(
    `[SPLRuleLoader] rule ${ruleId}: enabled must be a boolean, got ${JSON.stringify(value)}; treating as disabled`
  );
  return false;
}

function parseMatch(value: unknown, ruleId: string, options: SPLParseOptions): PolicyRule['match'] {
  if (!value || typeof value !== 'object') return {};
  const m = value as Record<string, unknown>;

  const match: PolicyRule['match'] = {};

  // actionType: accept string or array; normalize aliases to canonical values.
  const actionTypeRaw = m.actionType ?? m.action_type;
  const actionTypeList: string[] | undefined =
    typeof actionTypeRaw === 'string'
      ? [actionTypeRaw]
      : Array.isArray(actionTypeRaw)
        ? actionTypeRaw.map((t) => String(t))
        : undefined;
  if (actionTypeList && actionTypeList.length > 0) {
    // 别名展开走加载期 WARN（按 原值→规范值 全局去重）。
    match.actionType = normalizeActionTypes(
      actionTypeList,
      { ruleId },
      { logger: options.logger }
    );
  }

  if (Array.isArray(m.actionName)) match.actionName = m.actionName.map((t) => String(t));
  if (Array.isArray(m.action_name)) match.actionName = m.action_name.map((t) => String(t));
  if (Array.isArray(m.toolName)) match.toolName = m.toolName.map((t) => String(t));
  if (Array.isArray(m.tool_name)) match.toolName = m.tool_name.map((t) => String(t));

  // Canonical SPL top-level match fields. 条目支持字符串或 { pattern, flags }
  // 对象形态（flags 取代内联 (?i:...) 写法）。
  const bodyRegex = normalizeRegexList(m.bodyRegex, `rule ${ruleId} match.bodyRegex`, options);
  if (bodyRegex) match.bodyRegex = bodyRegex;
  const bodyRegexSnake = normalizeRegexList(m.body_regex, `rule ${ruleId} match.body_regex`, options);
  if (bodyRegexSnake) match.bodyRegex = [...(match.bodyRegex || []), ...bodyRegexSnake];
  if (m.paramsRegex && typeof m.paramsRegex === 'object') {
    match.paramsRegex = normalizeParamsRegex(m.paramsRegex, `rule ${ruleId} match.paramsRegex`, options);
  }
  if (m.paramsNotRegex && typeof m.paramsNotRegex === 'object') {
    match.paramsNotRegex = normalizeParamsRegex(m.paramsNotRegex, `rule ${ruleId} match.paramsNotRegex`, options);
  }

  // Compact `params` block (legacy / human-friendly shorthand) can coexist with
  // top-level `paramsRegex`. We merge instead of overwrite so that a rule can
  // mix `path_regex` and `command` patterns without silently dropping one side.
  const params = m.params;
  if (params && typeof params === 'object') {
    const p = params as Record<string, unknown>;
    const pathRegex = normalizeRegexList(p.path_regex, `rule ${ruleId} match.params.path_regex`, options);
    if (pathRegex) {
      match.paramsRegex = mergeParamsRegex(match.paramsRegex, { path: pathRegex });
    }
    const pathNotRegex = normalizeRegexList(p.path_not_regex, `rule ${ruleId} match.params.path_not_regex`, options);
    if (pathNotRegex) {
      match.paramsNotRegex = mergeParamsRegex(match.paramsNotRegex, { path: pathNotRegex });
    }
    const commandNotRegex = normalizeRegexList(p.command_not_regex, `rule ${ruleId} match.params.command_not_regex`, options);
    if (commandNotRegex) {
      match.paramsNotRegex = mergeParamsRegex(match.paramsNotRegex, { command: commandNotRegex });
    }
    const urlRegex = normalizeRegexList(p.url_regex, `rule ${ruleId} match.params.url_regex`, options);
    if (urlRegex) {
      match.bodyRegex = [...(match.bodyRegex || []), ...urlRegex];
    }
    const paramsBodyRegex = normalizeRegexList(p.body_regex, `rule ${ruleId} match.params.body_regex`, options);
    if (paramsBodyRegex) {
      match.bodyRegex = [...(match.bodyRegex || []), ...paramsBodyRegex];
    }
    if (p.field_equals && typeof p.field_equals === 'object') match.fieldEquals = p.field_equals as Record<string, unknown>;
    if (p.field_in && typeof p.field_in === 'object') match.fieldIn = p.field_in as Record<string, unknown[]>;
    if (p.paramsRegex && typeof p.paramsRegex === 'object') {
      match.paramsRegex = mergeParamsRegex(match.paramsRegex, normalizeParamsRegex(p.paramsRegex, `rule ${ruleId} match.params.paramsRegex`, options));
    }
  }

  // riskFlagsAny/All ⊆ risk-flags.json 字典校验；
  // 非法 flag throw + 单规则隔离。snake_case 别名（risk_flags_any 等）
  // 合并后再校验。同时若 flag 命中 registry[*].deprecated，加载期 WARN 提示
  // 替代 flag（已弃用 flag 决策）。
  const riskFlagDict = loadRiskFlagDict(options.logger);
  const validateFlagList = (list: unknown[], where: string): string[] => {
    if (!riskFlagDict) return list.map((f) => String(f));
    const bad = list.filter((f) => !riskFlagDict.flags.has(String(f)));
    if (bad.length > 0) {
      throw new Error(
        `rule ${ruleId}: ${where} contains unknown flags: ${bad.map((b) => JSON.stringify(b)).join(', ')}（拼写校验）`
      );
    }
    for (const f of list) {
      const since = riskFlagDict.deprecated.get(String(f));
      if (since !== undefined && !warnedDeprecatedFlags.has(`${ruleId}|${f}`)) {
        warnedDeprecatedFlags.add(`${ruleId}|${f}`);
        options.logger?.warn?.(
          `[SPLRuleLoader] rule ${ruleId}: ${where} uses deprecated flag "${f}" (deprecated since ${since}); ` +
            `请按 policies/risk-flags.json registry 替代 flag 迁移`
        );
      }
    }
    return list.map((f) => String(f));
  };
  if (Array.isArray(m.riskFlagsAny)) match.riskFlagsAny = validateFlagList(m.riskFlagsAny, 'riskFlagsAny');
  if (Array.isArray(m.risk_flags_any)) match.riskFlagsAny = validateFlagList(m.risk_flags_any, 'risk_flags_any');
  if (Array.isArray(m.riskFlagsAll)) match.riskFlagsAll = validateFlagList(m.riskFlagsAll, 'riskFlagsAll');
  if (Array.isArray(m.risk_flags_all)) match.riskFlagsAll = validateFlagList(m.risk_flags_all, 'risk_flags_all');
  const sessionRegex = normalizeRegexList(m.sessionRegex, `rule ${ruleId} match.sessionRegex`, options);
  if (sessionRegex) match.sessionRegex = sessionRegex;
  const sessionRegexSnake = normalizeRegexList(m.session_regex, `rule ${ruleId} match.session_regex`, options);
  if (sessionRegexSnake) match.sessionRegex = sessionRegexSnake;
  if (m.chain && typeof m.chain === 'object') match.chain = parseChain(m.chain, ruleId, options);

  // 未实现字段 WARN 通则。match.assetType 当前 OpenClaw 引擎未实现语义，
  // 加载期 WARN 提示"该字段将被忽略"。
  if (m.assetType !== undefined) {
    options.logger?.warn?.(
      `[SPLRuleLoader] rule ${ruleId} declares match.assetType; ` +
        `OpenClaw 引擎未实现该字段语义，` +
        `加载期将被忽略。请改用 match.actionType 或 match.paramsRegex。`
    );
  }

  return match;
}

function mergeParamsRegex(
  left: Record<string, PolicyRegexEntry[]> | undefined,
  right: Record<string, PolicyRegexEntry[]> | undefined
): Record<string, PolicyRegexEntry[]> | undefined {
  if (!left && !right) return undefined;
  const result: Record<string, PolicyRegexEntry[]> = {};
  for (const [key, values] of Object.entries(left || {})) {
    result[key] = [...values];
  }
  for (const [key, values] of Object.entries(right || {})) {
    result[key] = [...(result[key] || []), ...values];
  }
  return Object.keys(result).length > 0 ? result : undefined;
}

function normalizeParamsRegex(value: unknown, where: string, options: SPLParseOptions): Record<string, PolicyRegexEntry[]> | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const result: Record<string, PolicyRegexEntry[]> = {};
  for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
    if (Array.isArray(val)) {
      const list = normalizeRegexList(val, `${where}.${key}`, options);
      if (list) result[key] = list;
    } else if (typeof val === 'string') {
      result[key] = [val];
    }
  }
  return Object.keys(result).length > 0 ? result : undefined;
}

function parseChain(value: unknown, ruleId: string, options: SPLParseOptions): PolicyRule['match']['chain'] {
  // 数组形态（见 spl-policy-v2.schema.json）：
  // 每个链节为 match 子集，映射到内部 prior 结构（链节不支持 riskFlags，
  // 历史事件的 ActionRecord 不携带风险标签，请用 paramsRegex 内容条件表达）。
  if (Array.isArray(value)) {
    const prior: NonNullable<PolicyRule['match']['chain']>['prior'] = [];
    for (const [i, item] of value.entries()) {
      const link = parseChainLink(item, `rule ${ruleId} match.chain[${i}]`, options);
      if (link) prior.push(link);
    }
    // 数组形态无从携带 withinSteps（YAML 数组无兄弟键），按全历史窗口回退；
    // 需要窗口语义请改用对象形态（withinSteps + prior）。
    return { withinSteps: undefined, prior };
  }
  if (!value || typeof value !== 'object') return undefined;
  const c = value as Record<string, unknown>;
  const withinSteps = typeof c.withinSteps === 'number' ? c.withinSteps : undefined;
  const within_steps = typeof c.within_steps === 'number' ? c.within_steps : undefined;
  const priorRaw = c.prior || c.priors;
  const prior: NonNullable<PolicyRule['match']['chain']>['prior'] = [];
  if (Array.isArray(priorRaw)) {
    for (const [i, item] of priorRaw.entries()) {
      if (!item || typeof item !== 'object') continue;
      const p = item as Record<string, unknown>;
      // 对象形态链节同时接受显式维度（pathRegex/urlRegex/bodyRegex）与
      // paramsRegex 简写（command/url/path 映射到内容扫描维度），与数组形态
      // 链节（parseChainLink）达到同义（数组形态无法表达
      // withinSteps，窗口语义经对象形态落地）。p 已确认为对象，parseChainLink
      // 必有返回。
      const link = parseChainLink(p, `rule ${ruleId} match.chain.prior[${i}]`, options)!;
      const actionTypeRaw = p.actionType ?? p.action_type;
      if (!link.action) {
        link.action = typeof actionTypeRaw === 'string' ? actionTypeRaw : Array.isArray(actionTypeRaw) && actionTypeRaw.length > 0 ? String(actionTypeRaw[0]) : undefined;
      }
      const toolNameRaw = p.toolName ?? p.tool_name;
      if (!link.actionName && typeof toolNameRaw === 'string') link.actionName = toolNameRaw;
      prior.push(link);
    }
  }
  return {
    withinSteps: withinSteps ?? within_steps,
    prior,
  };
}

/**
 * 数组形态链节（match 子集）→ 内部 prior 条目。
 * actionType 取首个值（多为单值）；paramsRegex.command 与 bodyRegex 统一走
 * prior.bodyRegex（RuleMatcher 对历史事件 params 做全字符串扫描）。
 */
function parseChainLink(item: unknown, where: string, options: SPLParseOptions): { action?: string; actionName?: string; pathRegex?: PolicyRegexEntry[]; urlRegex?: PolicyRegexEntry[]; bodyRegex?: PolicyRegexEntry[] } | undefined {
  if (!item || typeof item !== 'object') return undefined;
  const p = item as Record<string, unknown>;
  const actionTypeRaw = p.actionType ?? p.action_type;
  const toolNameRaw = p.toolName ?? p.tool_name;
  const paramsRegex = p.paramsRegex && typeof p.paramsRegex === 'object' && !Array.isArray(p.paramsRegex)
    ? (p.paramsRegex as Record<string, unknown>)
    : {};
  const commandPatterns = normalizeRegexList(paramsRegex.command, `${where} paramsRegex.command`, options) || [];
  const bodyPatterns = normalizeRegexList(p.bodyRegex, `${where} bodyRegex`, options) || [];
  return {
    action: typeof actionTypeRaw === 'string' ? actionTypeRaw : Array.isArray(actionTypeRaw) && actionTypeRaw.length > 0 ? String(actionTypeRaw[0]) : undefined,
    actionName: typeof toolNameRaw === 'string' ? toolNameRaw : Array.isArray(toolNameRaw) && toolNameRaw.length > 0 ? String(toolNameRaw[0]) : undefined,
    pathRegex: normalizeRegexList(paramsRegex.path, `${where} paramsRegex.path`, options),
    urlRegex: normalizeRegexList(paramsRegex.url, `${where} paramsRegex.url`, options),
    bodyRegex: [...commandPatterns, ...bodyPatterns].length > 0 ? [...commandPatterns, ...bodyPatterns] : undefined,
  };
}

function parseAction(value: unknown, ruleId: string, options: SPLParseOptions): PolicyRule['action'] {
  if (!value || typeof value !== 'object') {
    return { decision: 'allow' };
  }
  const a = value as Record<string, unknown>;
  const action: PolicyRule['action'] = {};

  // 决策枚举收窄。loader 行为：
  // - 合法值（核心 4+扩展 2：allow/warn/block/modify/audit/escalate）：保留
  // - escalate 决策（扩展位）：落地映射为 warn + WARN +
  //   notes 注入（OpenClaw 暂不下发 escalate，不支持项目行为）
  // - 删除值（substitute/context_adjust/degrade/guide/approve）：loader
  //   拒绝加载，规则被单规则容错层跳过 + WARN。
  if (a.decision === 'escalate') {
    options.logger?.warn?.(
      `[SPLRuleLoader] rule ${ruleId} declares decision "escalate"; ` +
        `OpenClaw 当前不支持 HITL 升级下发（扩展位），落地映射为 warn ` +
        `并在 notes 字段标注"escalate 不可下发，已降级为 warn"`
    );
    action.decision = 'warn';
  } else if (isValidDecision(a.decision)) {
    action.decision = a.decision as PolicyRule['action']['decision'];
  } else if (isDeprecatedDecision(a.decision)) {
    // substitute/context_adjust/degrade/guide/approve：删除值；
    // 抛错让单规则容错层把规则跳过 + WARN。
    throw new Error(
      `rule ${ruleId} declares removed decision "${a.decision}"（删除值）; ` +
        `v2 策略必须使用 allow/warn/block/modify/audit/escalate 之一。`
    );
  } else {
    warnUnsupportedDecision(a.decision, `rule ${ruleId}`, options);
  }

  if (Array.isArray(a.decisionChain) || Array.isArray(a.decision_chain)) {
    action.decisionChain = parseDecisionChain(a.decisionChain || a.decision_chain, ruleId, options);
  }

  if (Array.isArray(a.conditionalDecisions) || Array.isArray(a.conditional_decisions)) {
    action.conditionalDecisions = parseConditionalDecisions(a.conditionalDecisions || a.conditional_decisions, ruleId, options);
  }

  if (a.block || a.blockReason !== undefined) {
    // block 决策 blockCode/blockReason 必填；缺
    // 则 throw + 单规则隔离，杜绝 audit 提到的"脱敏形同虚设"链路——
    // 顶层 block 缺 blockCode 会让 DecisionComposer 静默回退 POLICY_BLOCK，
    // 下游面板审计无法追溯来源。
    const blockPayload = (a.block as Record<string, unknown> | undefined) ?? {};
    const blockCode = typeof a.blockCode === 'string'
      ? a.blockCode
      : typeof blockPayload.blockCode === 'string' ? blockPayload.blockCode : undefined;
    const blockReason = typeof a.blockReason === 'string'
      ? a.blockReason
      : typeof blockPayload.blockReason === 'string' ? blockPayload.blockReason : undefined;
    if (typeof blockCode !== 'string' || blockCode.length === 0) {
      throw new Error(
        `rule ${ruleId}: action.block requires non-empty blockCode；loader 拒绝静默回退 POLICY_BLOCK`
      );
    }
    if (typeof blockReason !== 'string' || blockReason.length === 0) {
      throw new Error(
        `rule ${ruleId}: action.block requires non-empty blockReason`
      );
    }
    action.block = {
      blockReason,
      blockCode,
      remediationHint: typeof blockPayload.remediationHint === 'string' ? blockPayload.remediationHint : undefined,
      appealable: a.appealable !== undefined
        ? Boolean(a.appealable)
        : blockPayload.appealable !== undefined ? Boolean(blockPayload.appealable) : undefined,
    };
  }

  // modify 决策必须有 redactFields|substitutePatterns|
  // whitelistConstraint 至少一项；空 modify 静默 no-op 让脱敏形同虚设——
  // loader 期 throw + 单规则隔离。
  if (a.modify) {
    const m = a.modify as NonNullable<PolicyRule['action']['modify']>;
    const hasAny =
      (Array.isArray(m.redactFields) && m.redactFields.length > 0) ||
      (Array.isArray(m.substitutePatterns) && m.substitutePatterns.length > 0) ||
      (m.whitelistConstraint !== undefined && Object.keys(m.whitelistConstraint).length > 0);
    if (!hasAny) {
      throw new Error(
        `rule ${ruleId}: action.modify must define at least one of redactFields|substitutePatterns|whitelistConstraint`
      );
    }
    action.modify = m;
  }
  // action.substitute / action.degrade 已删除，loader 不再解析
  // 这两个字段——顶层 decision 校验已抛错，链节 / 条件决策
  // fallback 路径在 parseDecisionChain / parseConditionalDecisions 内同步收紧。
  // 历史 fixture 中残留的 substitute / degrade 顶层字段在加载期静默丢弃
  // （单规则隔离已先行 throw，不进到此分支）。
  if (a.guidance) action.guidance = parseGuidance(a.guidance);
  if (typeof a.retryLimit === 'number') action.retryLimit = a.retryLimit;

  // 未实现字段 WARN 通则。loader/schema 已定义但引擎
  // 未实现语义的字段，加载期必须 WARN 提示"该字段将被忽略"，禁止静默吞掉。
  //
  // 当前 OpenClaw 未实现的 spec 字段：
  // - action.message（warn/allow 的说明文本）：当前 types 未声明
  //   message 字段，loader 静默丢弃。新规则暂不应使用此字段。
  if (typeof a.message === 'string' && a.message.length > 0) {
    options.logger?.warn?.(
      `[SPLRuleLoader] rule ${ruleId} declares action.message="${a.message.slice(0, 60)}"; ` +
        `OpenClaw 引擎未实现该字段语义，加载期将被忽略。请改用 notes 字段记录说明。`
    );
  }

  if (!action.decision && !action.decisionChain && !action.conditionalDecisions) {
    options.logger?.warn?.(`[SPLRuleLoader] rule ${ruleId} has no explicit decision; defaulting to allow`);
    action.decision = 'allow';
  }

  return action;
}

function parseDecisionChain(
  value: unknown,
  ruleId: string,
  options: SPLParseOptions
): PolicyRule['action']['decisionChain'] {
  if (!Array.isArray(value)) return undefined;
  return value.map((item, index) => {
    if (!item || typeof item !== 'object') {
      throw new Error(`decision chain item ${index} is not an object`);
    }
    const i = item as Record<string, unknown>;
    // 决策链项 deprecated 决策（substitute/context_adjust/
    // degrade/guide/approve）抛错，与 parseAction 顶层行为一致——消除 audit
    // 指明的"行为不一致"（顶层 throw + 单规则隔离 / chain 项 demote allow）。
    let decision: InterventionDecisionType;
    if (isDeprecatedDecision(i.decision)) {
      throw new Error(
        `rule ${ruleId} decision chain item ${index}: removed decision "${i.decision}"（删除值）; ` +
          `v2 策略必须使用 allow/warn/block/modify/audit/escalate 之一。`
      );
    }
    if (isValidDecision(i.decision)) {
      decision = i.decision as InterventionDecisionType;
    } else {
      warnUnsupportedDecision(i.decision, `rule ${ruleId} decision chain item ${index}`, options);
      decision = 'allow';
    }
    warnRiskLevelCondition(typeof i.when === 'string' ? i.when : undefined, `rule ${ruleId} decision chain item ${index}`, options);
    return {
      decision,
      when: typeof i.when === 'string' ? i.when : undefined,
      maxAttempts: typeof i.maxAttempts === 'number' ? i.maxAttempts : typeof i.max_attempts === 'number' ? i.max_attempts : undefined,
      guidance: i.guidance as PolicyRule['action']['guidance'],
      modify: i.modify as PolicyRule['action']['modify'],
      block: i.block as PolicyRule['action']['block'],
    };
  });
}

function parseConditionalDecisions(
  value: unknown,
  ruleId: string,
  options: SPLParseOptions
): PolicyRule['action']['conditionalDecisions'] {
  if (!Array.isArray(value)) return undefined;
  return value.map((item, index) => {
    if (!item || typeof item !== 'object') {
      throw new Error(`conditional decision item ${index} is not an object`);
    }
    const i = item as Record<string, unknown>;
    // conditional 项 deprecated 决策同样 throw（与决策链项
    // 及顶层 action 行为一致）。
    let decision: InterventionDecisionType;
    if (isDeprecatedDecision(i.decision)) {
      throw new Error(
        `rule ${ruleId} conditional decision item ${index}: removed decision "${i.decision}"（删除值）; ` +
          `v2 策略必须使用 allow/warn/block/modify/audit/escalate 之一。`
      );
    }
    if (isValidDecision(i.decision)) {
      decision = i.decision as InterventionDecisionType;
    } else {
      warnUnsupportedDecision(i.decision, `rule ${ruleId} conditional decision item ${index}`, options);
      decision = 'allow';
    }
    warnRiskLevelCondition(typeof i.condition === 'string' ? i.condition : undefined, `rule ${ruleId} conditional decision item ${index}`, options);
    return {
      condition: typeof i.condition === 'string' ? i.condition : 'false',
      decision,
      guidance: i.guidance as PolicyRule['action']['guidance'],
      modify: i.modify as PolicyRule['action']['modify'],
      block: i.block as PolicyRule['action']['block'],
    };
  });
}

function parseTestCases(value: unknown): PolicyRule['testCases'] {
  if (!Array.isArray(value)) return undefined;
  return value.map((item) => {
    if (!item || typeof item !== 'object') return undefined;
    const t = item as Record<string, unknown>;
    return {
      name: typeof t.name === 'string' ? t.name : 'unnamed',
      input: typeof t.input === 'object' && t.input !== null ? (t.input as Record<string, unknown>) : {},
      expectedDecision: isValidDecision(t.expectedDecision) ? (t.expectedDecision as PolicyRule['action']['decision']) : undefined,
      expectedModified: typeof t.expectedModified === 'object' && t.expectedModified !== null ? (t.expectedModified as Record<string, unknown>) : undefined,
      expectedGuidanceContains: Array.isArray(t.expectedGuidanceContains) ? t.expectedGuidanceContains.map((s) => String(s)) : undefined,
    };
  }).filter((t): t is NonNullable<typeof t> => t !== undefined);
}

function parseGuidance(value: unknown): PolicyRule['action']['guidance'] {
  if (!value || typeof value !== 'object') return undefined;
  const g = value as Record<string, unknown>;
  return {
    templateRef: typeof g.templateRef === 'string' ? g.templateRef : typeof g.template_ref === 'string' ? g.template_ref : undefined,
    templateParams: (g.templateParams || g.template_params) as NonNullable<PolicyRule['action']['guidance']>['templateParams'],
    nonOverridable: g.nonOverridable !== undefined ? Boolean(g.nonOverridable) : g.non_overridable !== undefined ? Boolean(g.non_overridable) : undefined,
    maxAttempts: typeof g.maxAttempts === 'number' ? g.maxAttempts : typeof g.max_attempts === 'number' ? g.max_attempts : undefined,
    budgetThreshold: typeof g.budgetThreshold === 'number' ? g.budgetThreshold : typeof g.budget_threshold === 'number' ? g.budget_threshold : undefined,
  };
}

function isValidDecision(value: unknown): value is PolicyRule['action']['decision'] {
  return (
    typeof value === 'string' &&
    // 决策枚举核心 4+扩展 2。删除值（substitute/
    // context_adjust/degrade/guide/approve）不在此列，让 isDeprecatedDecision
    // 分支统一处理（throw，单规则容错层把规则跳过 + WARN）。
    ['allow', 'warn', 'block', 'modify', 'audit', 'escalate'].includes(value)
  );
}

/** 删除值（substitute/context_adjust/degrade/guide/approve）；
 * loader 一律拒绝加载，单规则容错层把规则跳过 + WARN。 */
function isDeprecatedDecision(value: unknown): boolean {
  return typeof value === 'string' && ['substitute', 'context_adjust', 'degrade', 'guide', 'approve'].includes(value);
}

/**
 * 声明了决策但取值不被支持（典型：升级前策略文件里的 `escalate`，自 0.9.2 起
 * 更名为 `audit`）时告警。当前仍按既有约定回落到 allow，但不能静默——
 * 安全规则的静默放行正是本告警要消除的缺陷。
 */
function warnUnsupportedDecision(value: unknown, where: string, options: SPLParseOptions): void {
  if (typeof value !== 'string' || value.length === 0) return;
  options.logger?.warn?.(
    `[SPLRuleLoader] ${where} declares unsupported decision "${value}"; defaulting to allow`
      + '（自 0.9.2 起 escalate 已更名为 audit，请更新策略）'
  );
}
