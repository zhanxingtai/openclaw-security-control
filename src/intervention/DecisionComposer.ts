/**
 * OpenClaw Security Monitor - Decision Composer
 *
 * Composes the final SDP SecurityDecision from matched policy rules.
 * Supports single decisions, conditional decisions, and decision chains.
 */

// Prototype-pollution guard: setNestedValue refuses to walk or write any of
// these keys. Policy-driven paths must never reach into Object.prototype.
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

import type {
  InterventionContext,
  PolicyRule,
  SecurityDecision,
  PolicyRuleAction,
  InterventionDecisionType,
  RuntimeDecisionType,
  DecisionChainItem,
  ConditionalDecision,
  PolicyRuleActionBlock,
  PolicyRuleActionModify,
  MatchedPolicyHit,
} from './types.js';
import type { GuidanceEngine } from './GuidanceEngine.js';

export interface DecisionComposerOptions {
  /** Default action when no rule matches. */
  defaultAction?: InterventionDecisionType;
  /**
   * context_adjust 已删除（loader 抛错 + 单规则隔离），
   * guidanceEngine / guidanceEnabled 开关已无运行时行为。保留为构造参数
   * 以维持 OpenClaw 2026.9.x 配置 schema 兼容位（运维侧 flagReg/degrade
   * 配置未拆，下个 minor 可下线）。
   */
  guidanceEngine?: GuidanceEngine;
  guidanceEnabled?: boolean;
  /**
   * 同 guidanceEnabled：degrade 决策已删除，degradeEnabled 开关保留为
   * 配置兼容位，无运行时效果。
   */
  degradeEnabled?: boolean;
}

export interface ComposeDetailedResult {
  /** 最终合成决策。 */
  decision: SecurityDecision;
  /**
   * 全部命中规则的标注：含被最终决策掩盖的 warn/modify 等
   * 规则，enforce 短路点之前的命中也完整保留，供事件审计标注。
   */
  matched: MatchedPolicyHit[];
}

// Decision priority. 加载器 isValidDecision
// 只接受下列决策值；guide/approve 永不出现，若列入会造成"存在第 9/10 种
// 决策"的误读。substitute / context_adjust 已删除（loader
// 抛错 + 单规则隔离），优先级表不含；degrade 同为删除值。
// block > modify > warn > audit > allow
const DECISION_PRIORITY: Record<string, number> = {
  block: 900,
  modify: 600,
  warn: 400,
  // audit 仅记录审计事件（放行语义不变），故排在所有具行为影响的决策之后。
  audit: 350,
  allow: 0,
};

function decisionPriority(decision: string): number {
  return DECISION_PRIORITY[decision] ?? 0;
}

export class DecisionComposer {
  private defaultAction: InterventionDecisionType;
  private guidanceEngine?: GuidanceEngine;
  private guidanceEnabled: boolean;
  constructor(options: DecisionComposerOptions = {}) {
    this.defaultAction = options.defaultAction || 'allow';
    this.guidanceEngine = options.guidanceEngine;
    this.guidanceEnabled = options.guidanceEnabled !== false;
  }

  /**
   * Compose a final decision from all matched rules.
   * Rules are expected to be sorted by priority descending.
   * Decision type outranks rule order; within the same decision type the highest
   * priority rule wins, and modify/substitute decisions are merged in order.
   */
  compose(_ctx: InterventionContext, rules: PolicyRule[]): SecurityDecision {
    return this.composeDetailed(_ctx, rules).decision;
  }

  /**
   * compose + 完整命中标注。决策合成逻辑与 compose 完全一致，
   * 额外返回每条命中规则的标注（含被更高优先级决策掩盖的规则），
   * 供 enforce 短路场景下事件审计仍能列出全部命中规则。
   */
  composeDetailed(_ctx: InterventionContext, rules: PolicyRule[]): ComposeDetailedResult {
    if (!rules || rules.length === 0) {
      return { decision: { decision: this.defaultAction }, matched: [] };
    }

    // Build decisions for every matched rule (rules are already priority-sorted).
    const decisions = rules.map((rule) => this.buildDecision(_ctx, rule));
    if (decisions.length === 0) {
      return { decision: { decision: this.defaultAction }, matched: [] };
    }

    const matched: MatchedPolicyHit[] = rules.map((rule, i) => ({
      policyId: rule.id,
      policyName: rule.name || rule.id,
      decision: decisions[i].decision,
      priority: rule.priority,
      // 顶层 severity 字段取代 evaluate.riskLevel。
      riskLevel: rule.severity,
      category: rule.category,
    }));

    // Group by decision type and pick the highest-priority group.
    const grouped = new Map<string, SecurityDecision[]>();
    for (const d of decisions) {
      const list = grouped.get(d.decision) || [];
      list.push(d);
      grouped.set(d.decision, list);
    }

    const winningType = [...grouped.keys()].sort(
      (a, b) => decisionPriority(b) - decisionPriority(a)
    )[0];
    const winners = grouped.get(winningType)!;

    // Merge modify in priority order; otherwise return the first (highest priority) decision.
    if (winningType === 'modify') {
      return { decision: this.mergeModificationDecisions(_ctx, winners), matched };
    }

    return { decision: winners[0], matched };
  }

  /**
   * Merge multiple modify decisions by applying them in priority order.
   * The caller passes `decisions` with `decisions[0]` as the top-priority rule.
   * Iterate from LOWEST priority (end) to HIGHEST priority (start); once a key
   * has been set by any decision, higher-priority decisions overwrite it only
   * when they explicitly include that key. The previous implementation did the
   * opposite (later overwrote earlier) which let a low-priority rule undo a
   * high-priority redaction — e.g. priority-1000 `token → ***` overwritten by
   * priority-100 `token → $token`.
   *
   * substitute 决策已删除，仅 modify 进入合并。
   */
  private mergeModificationDecisions(_ctx: InterventionContext, decisions: SecurityDecision[]): SecurityDecision {
    if (decisions.length === 0) {
      return { decision: this.defaultAction };
    }
    const merged: Record<string, unknown> = {};
    for (let i = decisions.length - 1; i >= 0; i--) {
      const d = decisions[i];
      if (!d.modifiedParams) continue;
      for (const [key, value] of Object.entries(d.modifiedParams)) {
        if (!(key in merged)) {
          merged[key] = value;
        }
      }
    }
    // Use the top-priority decision as the carrier for the merged payload.
    return { ...decisions[0], modifiedParams: merged };
  }

  private buildDecision(ctx: InterventionContext, rule: PolicyRule): SecurityDecision {
    const action = rule.action || ({} as PolicyRuleAction);

    if (action.conditionalDecisions && action.conditionalDecisions.length > 0) {
      const match = this.findConditionalDecision(ctx, action.conditionalDecisions);
      if (match) {
        return this.buildDecisionFromItem(ctx, rule, match.decision, match);
      }
    }

    if (action.decisionChain && action.decisionChain.length > 0) {
      const item = this.resolveDecisionChain(ctx, rule, action.decisionChain);
      if (item) {
        return this.buildDecisionFromItem(ctx, rule, item.decision, item);
      }
    }

    return this.buildDecisionFromItem(ctx, rule, action.decision || this.defaultAction, action);
  }

  private findConditionalDecision(
    ctx: InterventionContext,
    decisions: ConditionalDecision[]
  ): ConditionalDecision | undefined {
    for (const item of decisions) {
      if (this.evaluateCondition(ctx, item.condition)) {
        return item;
      }
    }
    return undefined;
  }

  private resolveDecisionChain(
    ctx: InterventionContext,
    rule: PolicyRule,
    chain: DecisionChainItem[]
  ): DecisionChainItem | undefined {
    if (!this.guidanceEngine || !this.guidanceEnabled) {
      // 引导引擎缺失或 guidance.enabled=false：直接取链首项；链尾项若仍
      // 引用已删除的 context_adjust 决策，buildDecisionFromItem 会拦截
      // 为 block（删除值兜底）。
      return chain[0];
    }

    const state = this.guidanceEngine.getState(ctx, rule);
    const attempts = state?.attempts || 0;
    const budgetExhausted = state?.budgetExhausted || false;

    for (const item of chain) {
      if (this.evaluateWhen(ctx, item.when, { attempts, budgetExhausted })) {
        return item;
      }
    }

    return chain[chain.length - 1];
  }

  private evaluateWhen(
    ctx: InterventionContext,
    when: string | undefined,
    state: { attempts: number; budgetExhausted: boolean }
  ): boolean {
    if (!when) return true;

    const normalized = when.trim().toLowerCase();

    if (normalized === 'first') return state.attempts === 0;
    if (normalized === 'repeat') return state.attempts > 0;
    if (normalized === 'budget_exhausted') return state.budgetExhausted;
    if (normalized === 'budget_available') return !state.budgetExhausted;
    if (normalized === 'high_risk') return (ctx.riskFlags || []).some((f) => ['reverse_shell', 'download_execute', 'mass_deletion', 'privilege_escalation', 'data_exfiltration'].includes(f));

    // Simple numeric expression: attempts > 2, attempts <= 3, etc.
    const match = normalized.match(/attempts\s*([<>!=]+)\s*(\d+)/);
    if (match) {
      const op = match[1];
      const value = parseInt(match[2], 10);
      const attempts = state.attempts;
      switch (op) {
        case '>':
          return attempts > value;
        case '>=':
          return attempts >= value;
        case '<':
          return attempts < value;
        case '<=':
          return attempts <= value;
        case '=':
        case '==':
          return attempts === value;
        case '!=':
          return attempts !== value;
      }
    }

    // risk_level== 死分支已删除（无运行时 risk 信号来源，恒 false）；
    // 残留声明按未知表达式恒真处理，SPLRuleLoader 加载期对此告警。

    return true;
  }

  private evaluateCondition(ctx: InterventionContext, condition: string): boolean {
    const normalized = condition.trim().toLowerCase();

    if (normalized === 'true' || normalized === '') return true;
    if (normalized === 'false') return false;

    if (normalized === 'high_risk') {
      return (ctx.riskFlags || []).some((f) =>
        ['reverse_shell', 'download_execute', 'mass_deletion', 'privilege_escalation', 'data_exfiltration'].includes(f)
      );
    }

    // risk_level== 死分支已删除，同 evaluateWhen。

    return true;
  }

  private buildDecisionFromItem(
    ctx: InterventionContext,
    rule: PolicyRule,
    decision: RuntimeDecisionType,
    item: DecisionChainItem | PolicyRuleAction
  ): SecurityDecision {
    const base: SecurityDecision = {
      decision,
      policyId: rule.id,
      policyName: rule.name || rule.id,
      priority: rule.priority,
      // 顶层 severity 字段取代 evaluate.riskLevel。
      riskLevel: rule.severity,
    };

    // context_adjust 决策已删除（loader 抛错 + 单规则隔离），DecisionComposer 不再支持该决策值。若历史 fixture 仍以字符串
    // 字面量写入，落此处统一兜底为 block + GUIDANCE_REMOVED。
    if (decision === 'context_adjust') {
      return {
        ...base,
        ...this.buildBlockDecision({ appealable: false } as PolicyRuleActionBlock, rule),
        blockCode: 'GUIDANCE_REMOVED',
        blockReason: 'context_adjust 已删除，该操作按策略直接阻断',
      };
    }

    // degrade 决策同样为删除值。degradeEnabled 配置位保留为 schema 兼容
    // （无运行时效果）。degrade 字面量兜底走下方 switch default 收口为
    // allow + audit 留痕。

    switch (decision) {
      case 'block':
        return { ...base, ...this.buildBlockDecision(item.block || {}, rule) };
      case 'modify':
        return { ...base, ...this.buildModifyDecision(ctx, item.modify || {}) };
      case 'audit':
        // audit 无附加载荷：决策本身即"放行 + 审计留痕"，事件侧据该标签归类。
        return base;
      case 'substitute':
      case 'degrade':
        // 删除值兜底：loader 不产，但 RuntimeDecisionType 字符串
        // 字面量仍在历史事件层流通。新事件流经此处一律落 allow + audit 留痕。
        return { ...base, decision: 'allow', reason: `removed decision ${decision} fell through to allow` };
      case 'allow':
      case 'warn':
      case 'escalate':
      default:
        return base;
    }
  }

  private buildBlockDecision(block: PolicyRuleActionBlock, rule: PolicyRule): Partial<SecurityDecision> {
    const appealable = block.appealable ?? false;
    return {
      decision: 'block',
      blockReason: block.blockReason || '操作被安全策略阻断',
      blockCode: block.blockCode || 'POLICY_BLOCK',
      // appealable 是展示字段（方案 B，无在线申诉链路）。未显式配置
      // remediationHint 时补一条含 policyId 的缺省复核指引，指明误报救济路径
      // （联系管理员复核 / 调整策略）；显式配置一律优先，不被缺省文案覆盖。
      remediationHint: block.remediationHint ?? (appealable
        ? `如需继续使用该操作，请联系管理员复核并调整策略（策略 ID: ${rule.id}）；误报可凭此 ID 申请放行`
        : undefined),
      appealable,
    };
  }

  private buildModifyDecision(
    ctx: InterventionContext,
    modify: PolicyRuleActionModify
  ): Partial<SecurityDecision> {
    return {
      decision: 'modify',
      modifiedParams: this.applyModification(ctx, modify),
      reason: '参数被安全策略改写',
    };
  }

  // substitute / context_adjust / degrade 已删除（loader 抛错
  // + 单规则隔离）。DecisionComposer 不再实现 buildSubstituteDecision /
  // buildContextAdjustDecision / buildDegradeDecision；残留删除值字面量走
  // switch default 兜底为 allow + audit 留痕。

  private applyModification(
    ctx: InterventionContext,
    modify: PolicyRuleActionModify
  ): Record<string, unknown> {
    const result: Record<string, unknown> = {};

    if (ctx.params) {
      for (const [key, value] of Object.entries(ctx.params)) {
        result[key] = value;
      }
    }

    if (modify.redactFields && modify.redactFields.length > 0) {
      for (const field of modify.redactFields) {
        this.redactField(result, field);
      }
    }

    if (modify.substitutePatterns && modify.substitutePatterns.length > 0) {
      // Capacity budget for the entire modify step. A policy author who
      // writes `replacement: "$0$0$0..."` with a long match string can
      // otherwise blow the modified payload past any reasonable size and
      // hang the synchronous evaluation path. We skip a substitutePatterns
      // entry if applying it would push result past 1 MiB.
      const MAX_RESULT_BYTES = 1 << 20;
      for (const { pattern, replacement, flags } of modify.substitutePatterns) {
        let regex: RegExp;
        try {
          regex = new RegExp(pattern, flags || 'g');
        } catch {
          // 策略里的非法替换模式：单条跳过，其余修改照常生效（同类隔离），
          // 不得让 compose 整体异常走 failStrategy 兜底。
          continue;
        }
        // ReDoS / blowup defence: cap the replacement string length so a
        // hostile `$0` (whole-match) expansion cannot push the modified
        // payload past any reasonable size. Also reject `$<n>` references
        // that exceed the number of capture groups — these would yield
        // literal "$5" in V8 instead of failing closed.
        const cappedReplacement = String(replacement).slice(0, 256);
        const groupCount = (() => {
          try {
            // Cheap approximate group count by scanning the source pattern.
            // False positives are tolerable: the worst case is one extra
            // rejected reference that V8 would already stringify to "$N".
            const re = new RegExp(pattern) as RegExp & { groups?: Record<string, string> };
            const namedGroups = re.groups ? Object.keys(re.groups).length : 0;
            const numberedGroups = (pattern.match(/\((?!\?)/g) || []).length;
            return Math.max(namedGroups, numberedGroups);
          } catch { return 0; }
        })();
        const safeReplacement = cappedReplacement.replace(/\$(\d+|\$|&)/g, (m, idx) => {
          if (idx === '$' || idx === '&') return m;
          const n = Number(idx);
          return n <= groupCount ? m : ''; // remove out-of-range backrefs
        });
        for (const key of Object.keys(result)) {
          const value = result[key];
          if (typeof value !== 'string') continue;
          // Pre-flight: skip this substitutePatterns entry if its worst-case
          // replacement would blow the budget. Worst case ≈ match length ×
          // replacement.length per field × number of fields. We use a
          // conservative ceiling so legitimate small substitutions still pass.
          const projectedSize = value.length + (safeReplacement.length * 4);
          if (projectedSize > MAX_RESULT_BYTES) continue;
          const replaced = value.replace(regex, safeReplacement);
          if (Buffer.byteLength(replaced, 'utf8') > MAX_RESULT_BYTES) continue;
          result[key] = replaced;
        }
      }
    }

    // whitelistConstraint: after every other modify step has run, ensure
    // each named string field matches its allowed pattern. If a modified
    // value escaped the whitelist, fall back to the original ctx value
    // (per the type contract); if the original also fails, drop the field.
    if (modify.whitelistConstraint && ctx.params) {
      for (const [key, patternStr] of Object.entries(modify.whitelistConstraint)) {
        let pattern: RegExp;
        try {
          pattern = new RegExp(patternStr);
        } catch {
          continue; // malformed constraint — skip rather than crash compose
        }
        const current = result[key];
        if (typeof current === 'string' && !pattern.test(current)) {
          const original = ctx.params[key];
          if (typeof original === 'string' && pattern.test(original)) {
            result[key] = original;
          } else {
            delete result[key];
          }
        }
      }
    }

    return result;
  }

  private redactField(obj: Record<string, unknown>, field: string): void {
    const value = this.getNestedValue(obj, field);
    if (value === undefined) return;
    this.setNestedValue(obj, field, '***');
  }

  private getNestedValue(obj: Record<string, unknown>, path: string): unknown {
    const parts = path.split('.');
    let current: unknown = obj;
    for (const part of parts) {
      if (!current || typeof current !== 'object' || Array.isArray(current)) {
        return undefined;
      }
      current = (current as Record<string, unknown>)[part];
    }
    return current;
  }

  private setNestedValue(obj: Record<string, unknown>, path: string, value: unknown): void {
    const parts = path.split('.');
    let current: Record<string, unknown> = obj;
    for (let i = 0; i < parts.length - 1; i++) {
      const part = parts[i];
      if (FORBIDDEN_KEYS.has(part)) return; // prototype-pollution guard
      if (!(part in current) || typeof current[part] !== 'object' || Array.isArray(current[part])) {
        current[part] = {};
      }
      current = current[part] as Record<string, unknown>;
    }
    const last = parts[parts.length - 1];
    if (FORBIDDEN_KEYS.has(last)) return; // prototype-pollution guard
    current[last] = value;
  }
}
