/**
 * SPL actionType canonicalization per project_standards/policy-schema/spl-policy-v2.schema.json.
 *
 * The standard defines 21 canonical trigger points plus 12 historical aliases.
 * Aliases must be expanded to canonical values before rule matching; unknown
 * actionTypes are rejected at load time.
 */

export const SPL_CANONICAL_ACTION_TYPES = new Set([
  'agent_start',
  'agent_stop',
  'agent_session_start',
  'agent_session_end',
  'agent_message',
  'agent_tool_call',
  'agent_tool_result',
  'process_start',
  'process_exit',
  'process_change',
  'network_http',
  'network_connect',
  'network_dns',
  'file_read',
  'file_write',
  'file_delete',
  'file_privilege',
  'asset_add',
  'asset_change',
  'asset_remove',
  'security_audit',
] as const);

export type SPLCanonicalActionType = typeof SPL_CANONICAL_ACTION_TYPES extends Set<infer T> ? T : never;

const SPL_ACTION_TYPE_ALIASES: Record<string, string | string[]> = {
  tool_call: 'agent_tool_call',
  http_request: 'network_http',
  message_write: 'agent_message',
  pre_llm_call: ['agent_message', 'agent_session_start'],
  post_llm_call: 'agent_message',
  pre_api_request: 'network_http',
  post_api_request: 'network_http',
  pre_tool_call: 'agent_tool_call',
  post_tool_call: ['agent_tool_call', 'agent_tool_result'],
  transform_tool_result: 'agent_tool_result',
  transform_terminal_output: 'agent_message',
  transform_llm_output: 'agent_message',
  // command_execution：历史别名。映射到 process_start 使既有 SPL
  // 策略文件保持可加载；否则含 `actionType: [command_execution, …]` 的
  // 规则会在加载期被隔离（RuleLoader.load 回退空策略的 fail-open 面）。
  command_execution: 'process_start',
};

/**
 * Expand a single actionType value into one or more canonical values.
 * Returns the canonical value for canonical inputs; expands aliases;
 * returns undefined for unknown values so the caller can decide how to report.
 */
export function expandActionType(value: string): string[] {
  if (value === '*') {
    return ['*'];
  }
  if (SPL_CANONICAL_ACTION_TYPES.has(value as SPLCanonicalActionType)) {
    return [value];
  }
  const mapped = SPL_ACTION_TYPE_ALIASES[value];
  if (mapped) {
    return Array.isArray(mapped) ? mapped : [mapped];
  }
  return [];
}

/**
 * Validate and normalize a list of actionType values.
 * Throws if any value is not a canonical value or a known alias.
 *
 * 别名展开（tool_call → agent_tool_call 等）在加载期通过 options.logger
 * 发一次 WARN，按 (原值→规范值) 集合去重——
 * 同一进程加载 N 条共用别名的规则只发一次，避免日志爆炸。
 * 规范名（无别名映射）不写日志；未声明 alias 的未知值仍按既有约定 throw。
 */
export function normalizeActionTypes(
  values: string[],
  { ruleId }: { ruleId: string },
  options?: { logger?: { warn: (msg: string) => void } }
): string[] {
  const result = new Set<string>();
  for (const value of values) {
    if (value === '*') {
      result.add('*');
      continue;
    }
    const expanded = expandActionType(value);
    if (expanded.length === 0) {
      throw new Error(
        `rule ${ruleId}: unsupported actionType "${value}". ` +
          `Use a canonical value or a known alias.`
      );
    }
    // 别名展开加载期 WARN（全局去重）。直接命中规范值时不发。
    if (value !== expanded[0] && options?.logger) {
      const key = `${value}→${expanded[0]}`;
      if (!warnedActionTypeAliases.has(key)) {
        warnedActionTypeAliases.add(key);
        // 集合有界防止异常场景内存增长。
        if (warnedActionTypeAliases.size > 100) warnedActionTypeAliases.clear();
        options.logger.warn(
          `[splActionType] rule ${ruleId}: actionType alias "${value}" normalized to "${expanded[0]}"（请更新策略使用规范名）`
        );
      }
    }
    for (const canonical of expanded) {
      result.add(canonical);
    }
  }
  return Array.from(result);
}

/**
 * Normalize the actionType carried on an InterventionContext to its canonical
 * form before rule matching. Unknown runtime values are left as-is but logged
 * (宿主行为变化需要可观测，而不是静默不匹配)。
 */
const warnedUnknownActionTypes = new Set<string>();

/**
 * 别名展开的加载期 WARN 去重集合，按 (原值→规范值) key
 * 全局唯一——同一进程多次加载同一别名策略仅 WARN 一次。
 */
const warnedActionTypeAliases = new Set<string>();

export function canonicalizeContextActionType(
  actionType: string,
  logger?: { warn: (msg: string) => void }
): string {
  if (actionType === '*') return actionType;
  if (SPL_CANONICAL_ACTION_TYPES.has(actionType as SPLCanonicalActionType)) {
    return actionType;
  }
  const expanded = expandActionType(actionType);
  if (expanded.length === 1) {
    return expanded[0];
  }
  if (expanded.length === 0 && logger && !warnedUnknownActionTypes.has(actionType)) {
    // 每个未知值只告警一次，避免高频评估刷爆日志；集合有界防止异常场景内存增长。
    warnedUnknownActionTypes.add(actionType);
    if (warnedUnknownActionTypes.size > 100) warnedUnknownActionTypes.clear();
    logger.warn(
      `[splActionType] unknown runtime actionType "${actionType}"; ` +
        'rules will not match it (host behavior change needs attention)'
    );
  }
  // One-to-many aliases (e.g. post_tool_call) cannot be reduced to a single
  // canonical type; return the original alias and let the caller handle it.
  return actionType;
}
