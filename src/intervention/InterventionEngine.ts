/**
 * OpenClaw Security Monitor - Intervention Engine
 *
 * Synchronous policy evaluation for blocking, modifying, and auditing
 * agent actions. substitute / context_adjust / degrade 已删除
 *（loader 抛错 + 单规则隔离）。
 */

import type {
  InterventionContext,
  SecurityDecision,
  InterventionEngineOptions,
  InterventionStats,
  PolicyRule,
  FailStrategy,
  PolicyAuditEvent,
  PolicyAuditEventType,
  RuleHit,
} from './types.js';
import { DEFAULT_HIGH_RISK_FLAGS } from './types.js';
import { RuleLoader } from './RuleLoader.js';
import { RuleMatcher } from './RuleMatcher.js';
import { DecisionComposer } from './DecisionComposer.js';
import { GuidanceEngine } from './GuidanceEngine.js';
import { canonicalizeContextActionType } from './splActionType.js';

export class InterventionEngineImpl {
  private options: InterventionEngineOptions;
  private loader: RuleLoader;
  private composer: DecisionComposer;
  private stats: InterventionStats;
  private guidanceEngine: GuidanceEngine;
  private initialized = false;
  // 排序结果缓存。策略数组在 reload 时被整体
  // 替换，用源数组引用做缓存键，reload 后自动失效重建，无需手动清理。
  private sortedRulesCache?: { source: PolicyRule[]; sorted: PolicyRule[] };
  // 单规则隔离的去重集合，避免同一问题在每次评估重复告警/留痕。
  private isolatedRuleWarned = new Set<string>();
  // config 层默认 failStrategy：策略文件顶层值缺失时回退用。
  private readonly configFailStrategy: FailStrategy;
  // 已发过审计事件的策略加载状态签名，同一状态只发一次。
  private auditedPolicyState?: string;

  constructor(options: InterventionEngineOptions) {
    this.options = {
      decisionTimeoutMs: 50,
      failStrategy: 'fail_open' as FailStrategy,
      highRiskFlags: DEFAULT_HIGH_RISK_FLAGS,
      logger: {
        warn: () => {},
        error: () => {},
      },
      ...options,
      ruleLoader: options.ruleLoader,
    };
    // options.failStrategy 此后不再被覆写：策略层取值在兜底路径现场解析，
    // 热 reload 后立即生效。
    this.configFailStrategy = this.options.failStrategy ?? 'fail_open';

    this.loader = new RuleLoader({
      ...this.options.ruleLoader,
      // 加载期告警（非法正则 / 嵌套量词 / 非法 failStrategy）与评估期走同一 logger。
      logger: this.options.ruleLoader.logger ?? this.options.logger,
      onRuleIssue: (issue) => {
        this.audit({
          eventType: issue.kind === 'unsafe' ? 'rule_unsafe_regex' : 'rule_invalid_regex',
          ruleId: issue.ruleId,
          pattern: issue.pattern,
          detail: `rule ${issue.ruleId} skipped: ${issue.kind} regex pattern`,
        });
      },
    });
    this.guidanceEngine = new GuidanceEngine({
      config: this.options.guidance,
      logger: this.options.logger,
    });
    this.composer = new DecisionComposer({
      defaultAction: 'allow',
      guidanceEngine: this.guidanceEngine,
      guidanceEnabled: this.options.guidance?.enabled !== false,
      degradeEnabled: this.options.degrade?.enabled !== false,
    });
    this.stats = {
      rulesLoaded: 0,
      evaluations: 0,
      blocks: 0,
      modifies: 0,
      guidanceAdjustments: 0,
      audits: 0,
      fallbacks: 0,
      // 评估延迟累计，用于心跳上报 avgLatencyMs。
      latencyTotalMs: 0,
      // substitutes / degrades 已停止自增（已删除），
      // 保留为可选数值位以兼容历史面板 schema。
    };
    this.sortedRulesCache = undefined;
  }

  async initialize(): Promise<void> {
    if (this.initialized) {
      return;
    }
    await this.loader.initialize();
    const policy = this.loader.getPolicy();
    this.composer = new DecisionComposer({
      defaultAction: policy.defaultAction || 'allow',
      guidanceEngine: this.guidanceEngine,
      guidanceEnabled: this.options.guidance?.enabled !== false,
      degradeEnabled: this.options.degrade?.enabled !== false,
    });
    this.stats.rulesLoaded = policy.rules.length;
    this.initialized = true;
    // 策略缺失 / 加载失败 / 0 规则必须有安全事件留痕，而不是只剩 console 输出。
    // 与评估期的漂移检查共用同一去重口径。
    this.syncPolicyLoadState();
    const mode = this.options.mode || policy.mode || policy.defaultAction || 'allow';
    console.log(`[InterventionEngine] initialized with ${policy.rules.length} rule(s), mode=${mode}, failStrategy=${this.effectiveFailStrategy()}`);
    if (policy.rules.length === 0) {
      console.warn('[InterventionEngine] warning: 0 rules loaded; all actions will be allowed');
    }
  }

  async shutdown(): Promise<void> {
    await this.loader.shutdown();
    this.initialized = false;
  }

  getStats(): InterventionStats {
    // 平均评估延迟随 stats 暴露，供心跳上报。
    const stats: InterventionStats = { ...this.stats };
    stats.avgLatencyMs =
      stats.evaluations > 0 ? Math.round((stats.latencyTotalMs ?? 0) / stats.evaluations * 100) / 100 : 0;
    return stats;
  }

  getRuleLoader(): RuleLoader {
    return this.loader;
  }

  /**
   * 清理过期的引导预算状态（stateTtlMs）。 GuidanceEngine.cleanup 本身
   * 无调用方，由宿主现有周期节奏驱动（store 自检 tick）：
   * 过期后同会话同规则的引导计数归零，可重新引导而非永久 block。
   */
  cleanupGuidanceStates(): number {
    return this.guidanceEngine.cleanup();
  }

  async evaluate(ctx: InterventionContext): Promise<SecurityDecision> {
    if (!this.initialized) {
      // Same hard fail-closed window as evaluateSync: the host may have
      // wired async hooks that arrive before initialize() completes.
      await this.initialize();
      if (!this.initialized) {
        return {
          decision: 'block',
          blockReason: 'intervention engine not initialized yet (startup race window); fail-closed default',
          blockCode: 'INTERVENTION_NOT_INITIALIZED',
          failStrategy: 'fail_closed',
        };
      }
    }

    const start = Date.now();
    const timeout = this.options.decisionTimeoutMs ?? 50;

    try {
      const { decision } = await this.evaluateWithTimeout(ctx, timeout);
      decision.latencyMs = Date.now() - start;
      this.updateStats(decision, false);
      return decision;
    } catch (err) {
      const fallback = this.fallbackDecision(ctx, err, []);
      fallback.latencyMs = Date.now() - start;
      this.updateStats(fallback, true);
      return fallback;
    }
  }

  /**
   * synchronous evaluation path for host sync-only hooks
   * (OpenClaw 2026.9.4 before_message_write ignores Promise handler results,
   * so the async evaluate() can never land a block there). Same matching /
   * composition / failStrategy fallback as evaluate(), minus the async
   * timeout race: the rule-matching core is fully synchronous.
   */
  evaluateSync(ctx: InterventionContext): SecurityDecision {
    if (!this.initialized) {
      // Sync hooks cannot await loader init; kick it off so later calls are
      // initialized, but BLOCK (fail-closed) until rules are loaded. The
      // previous path called fallbackDecision() which honoured
      // failStrategy — if an operator misconfigured fail-open, every
      // startup-window call slipped through as allow, defeating the audit
      // surface entirely. Hard block here so a slow init (NFS policy file,
      // large yaml, js-yaml dynamic import) can never silently widen the
      // attack window.
      void this.initialize().catch(() => {});
      return {
        decision: 'block',
        blockReason: 'intervention engine not initialized yet (startup race window); fail-closed default',
        blockCode: 'INTERVENTION_NOT_INITIALIZED',
        failStrategy: 'fail_closed',
      };
    }

    const start = Date.now();
    try {
      const { decision } = this.evaluateInternalSync(ctx);
      decision.latencyMs = Date.now() - start;
      this.updateStats(decision, false);
      return decision;
    } catch (err) {
      const fallback = this.fallbackDecision(ctx, err, []);
      fallback.latencyMs = Date.now() - start;
      this.updateStats(fallback, true);
      return fallback;
    }
  }

  // NOTE: 规则评估核心是同步的——evaluateInternalSync 在
  // Promise.race 建立之前就已执行完毕，timeout 分支永远不会触发。
  private async evaluateWithTimeout(
    ctx: InterventionContext,
    timeoutMs: number
  ): Promise<{ decision: SecurityDecision; matchedRules: PolicyRule[] }> {
    const evaluatePromise = Promise.resolve(this.evaluateInternalSync(ctx));

    if (timeoutMs <= 0) {
      return evaluatePromise;
    }

    return Promise.race([
      evaluatePromise,
      new Promise<{ decision: SecurityDecision; matchedRules: PolicyRule[] }>((_, reject) =>
        setTimeout(() => reject(new Error(`intervention decision timeout after ${timeoutMs}ms`)), timeoutMs)
      ),
    ]);
  }

  private evaluateInternalSync(
    ctx: InterventionContext
  ): { decision: SecurityDecision; matchedRules: PolicyRule[] } {
    // 评估前比对策略加载状态：运行期策略被删改后同样要留痕。
    this.syncPolicyLoadState();
    // 策略没加载上时 0 条规则会让下面所有匹配都落空、最终评估成 allow —— 静默 fail-open。
    // 只看 loadError，不看规则数：全部规则 enabled:false 是合法配置。
    const loadError = this.loader.getLoadError();
    if (loadError) {
      return { decision: this.policyLoadFailureDecision(ctx, loadError), matchedRules: [] };
    }
    // matchedHits 在 try 外声明并与 findMatches 共享引用：匹配中途抛错时
    // 兜底决策仍能拿到已命中的规则（fail_open_high_risk_only 的高危判定），
    // 而不是一律退化为空数组放行。
    let matchedHits: RuleHit[] = [];
    try {
      const policy = this.loader.getPolicy();
      const sortedRules = this.getSortedRules(policy.rules);
      // Normalize runtime actionType aliases (e.g. 'tool_call') to canonical values
      // before matching so rules written with canonical or alias actionTypes both hit.
      // 未知 actionType 在此记 warn（宿主行为变化可观测）。
      const canonicalCtx = { ...ctx, actionType: canonicalizeContextActionType(ctx.actionType, this.options.logger) };
      const enforceShortCircuit = (this.options.mode || policy.mode) === 'enforce';
      matchedHits = this.findMatches(canonicalCtx, sortedRules, enforceShortCircuit, matchedHits);
      const matchedRules = matchedHits.map((h) => h.rule);
      // composeDetailed 同时返回完整命中标注。enforce 短路本身保留
      // （命中 block 即停扫，性能语义不变），短路点之前已匹配的 warn/modify 等
      // 规则随 matchedPolicies 进入决策对象，由采集层写入事件审计标注。
      const { decision, matched } = this.composer.composeDetailed(canonicalCtx, matchedHits);
      if (matched.length > 0) {
        decision.matchedPolicies = matched;
      }

      if (matchedRules.length > 0 && decision.decision !== 'allow') {
        console.log(
          `[InterventionEngine] rule matched: actionType=${ctx.actionType}, toolName=${ctx.toolName}, decision=${decision.decision}, policyId=${decision.policyId || matchedRules[0].id}`
        );
      }

      const defaultAction = policy.defaultAction || 'allow';
      if (decision.decision === defaultAction && matchedRules.length === 0) {
        return { decision: { decision: defaultAction }, matchedRules: [] };
      }

      return { decision, matchedRules };
    } catch (err) {
      // Internal evaluation error (not timeout): use the configured fail strategy.
      // Partial matched rules accumulated before the throw are passed through so
      // fail_open_high_risk_only can still see high-risk hits;
      // with none available the fallback uses ctx.riskFlags as secondary signal.
      const matchedRules = matchedHits.map((h) => h.rule);
      return { decision: this.fallbackDecision(ctx, err, matchedRules), matchedRules };
    }
  }

  private highestRiskLevel(rules: PolicyRule[]): PolicyRule['severity'] | undefined {
    const order = { low: 1, medium: 2, high: 3, critical: 4, extreme: 4 };
    let max: PolicyRule['severity'] | undefined;
    for (const rule of rules) {
      const level = rule.severity;
      if (!level) continue;
      if (!max || (order[level] ?? 0) > (order[max] ?? 0)) {
        max = level;
      }
    }
    return max;
  }

  // 排序结果随策略加载缓存，
  // 源数组引用变化（reload）即失效重建。
  private getSortedRules(rules: PolicyRule[]): PolicyRule[] {
    if (!this.sortedRulesCache || this.sortedRulesCache.source !== rules) {
      this.sortedRulesCache = {
        source: rules,
        sorted: [...rules].sort((a, b) => (b.priority || 0) - (a.priority || 0)),
      };
    }
    return this.sortedRulesCache.sorted;
  }

  // block 是最高裁决优先级（DecisionComposer 权重 900），
  // enforce 模式命中即可停扫；audit 模式需全量收集用于事件标注。
  private isBlockRule(rule: PolicyRule): boolean {
    const action = rule.action;
    if (!action) return false;
    if (action.decision === 'block') return true;
    if (action.decisionChain?.some((item) => item.decision === 'block')) return true;
    if (action.conditionalDecisions?.some((item) => item.decision === 'block')) return true;
    return false;
  }

  private findMatches(
    ctx: InterventionContext,
    rules: PolicyRule[],
    enforceShortCircuit: boolean,
    matched: RuleHit[] = []
  ): RuleHit[] {
    for (const rule of rules) {
      // 单规则隔离——非法 / 灾难性回溯正则的规则跳过并留痕，
      // 其余规则照常评估，不再整次 fail-open 放行。
      const compiled = this.loader.getCompiledRuleRegexes(rule);
      if (compiled === null) {
        if (!this.isolatedRuleWarned.has(rule.id)) {
          this.isolatedRuleWarned.add(rule.id);
          this.options.logger?.warn?.(
            `[InterventionEngine] skipping rule ${rule.id}: invalid regex pattern (load-time audit)`
          );
          this.audit({
            eventType: 'rule_invalid_regex',
            ruleId: rule.id,
            detail: `rule ${rule.id} skipped during evaluation: invalid regex pattern`,
          });
        }
        continue;
      }
      const result = RuleMatcher.match(ctx, rule, compiled);
      if (result.matched && result.rule) {
        // 命中证据（#469-D）随命中一起带出 ⇒ 事件层能回答
        // 「这条规则凭哪一段文本命中」。
        matched.push({ rule: result.rule, evidence: result.evidence });
        if (enforceShortCircuit && this.isBlockRule(rule)) {
          break;
        }
      }
    }
    return matched;
  }

  private audit(event: Omit<PolicyAuditEvent, 'ts'>): void {
    this.options.audit?.({ ...event, ts: Date.now() });
  }

  /**
   * 当前生效的 failStrategy：策略顶层值优先，缺失/非法回退 config 默认值。
   * 每次兜底决策现场解析而非 initialize 时固化——策略文件热 reload 会整体
   * 替换策略对象，固化后改 failStrategy 不生效。
   */
  private effectiveFailStrategy(): FailStrategy {
    return this.loader.getPolicy().failStrategy ?? this.configFailStrategy;
  }

  /**
   * 策略加载状态漂移检查：策略缺失 / 加载失败 / 解析出 0 规则
   * 此前只在 initialize 留痕一次，运行期把策略文件删掉或改坏后审计里看不到。
   * 每次评估前比对状态签名，变化即补发审计事件；同一状态只发一次，
   * 恢复正常后重新武装。
   */
  private syncPolicyLoadState(): void {
    const loadError = this.loader.getLoadError();
    let eventType: PolicyAuditEventType | undefined;
    let detail = '';
    if (loadError) {
      eventType = loadError.includes('not found') ? 'policy_missing' : 'policy_load_failed';
      detail = loadError;
    } else if (this.loader.getPolicy().rules.length === 0) {
      eventType = 'policy_empty';
      detail = 'policy file parsed successfully but contains 0 rules; all actions will be allowed';
    }

    const signature = eventType ? `${eventType}:${detail}` : undefined;
    if (signature === this.auditedPolicyState) return;
    this.auditedPolicyState = signature;
    if (eventType) this.audit({ eventType, detail });
  }

  private fallbackDecision(
    ctx: InterventionContext,
    err: unknown,
    matchedRules: PolicyRule[]
  ): SecurityDecision {
    const message = err instanceof Error ? err.message : String(err);
    this.options.logger?.error?.(`[InterventionEngine] ${message}`);
    return this.applyFailStrategy(ctx, matchedRules, {
      closedReason: '干预决策组件异常，按安全策略阻断',
      closedCode: 'INTERVENTION_ERROR',
      highRiskReason: '检测到高危行为且干预决策组件异常，按策略阻断',
      highRiskCode: 'INTERVENTION_ERROR_HIGH_RISK',
      allowReason: '干预决策组件异常，按策略放行',
    });
  }

  /**
   * 策略加载失败时的兜底决策。RuleLoader 在沙箱越界 / 文件缺失 / 解析失败时会退回
   * 0 规则的 empty-policy，不在这里兜底就会静默全放行。
   */
  private policyLoadFailureDecision(ctx: InterventionContext, loadError: string): SecurityDecision {
    this.options.logger?.error?.(`[InterventionEngine] 策略未生效，按 failStrategy 兜底: ${loadError}`);
    return this.applyFailStrategy(ctx, [], {
      closedReason: '安全策略未加载成功，已按安全策略阻断',
      closedCode: 'POLICY_LOAD_FAILED',
      highRiskReason: '检测到高危行为且安全策略未加载成功，按策略阻断',
      highRiskCode: 'POLICY_LOAD_FAILED_HIGH_RISK',
      allowReason: '安全策略未加载成功，按策略放行',
    });
  }

  /** failStrategy 分支的唯一实现：异常兜底与策略加载失败共用，只有文案与 blockCode 不同。 */
  private applyFailStrategy(
    ctx: InterventionContext,
    matchedRules: PolicyRule[],
    labels: {
      closedReason: string;
      closedCode: string;
      highRiskReason: string;
      highRiskCode: string;
      allowReason: string;
    }
  ): SecurityDecision {
    const strategy = this.effectiveFailStrategy();

    if (strategy === 'fail_closed') {
      return {
        decision: 'block',
        blockReason: labels.closedReason,
        blockCode: labels.closedCode,
        failStrategy: 'fail_closed',
      };
    }

    if (strategy === 'fail_open_high_risk_only') {
      const riskLevel = this.highestRiskLevel(matchedRules);
      let isHighRisk = false;
      if (riskLevel === 'high' || riskLevel === 'critical' || riskLevel === 'extreme') {
        isHighRisk = true;
      } else if (!riskLevel) {
        // No explicit risk_level on matched rules: fall back to legacy high-risk flags.
        const flags = ctx.riskFlags || [];
        isHighRisk = (this.options.highRiskFlags || []).some((f) => flags.includes(f));
      }
      if (isHighRisk) {
        return {
          decision: 'block',
          blockReason: labels.highRiskReason,
          blockCode: labels.highRiskCode,
          failStrategy: 'fail_open_high_risk_only',
        };
      }
    }

    return {
      decision: 'allow',
      reason: labels.allowReason,
      failStrategy: strategy,
    };
  }

  private updateStats(decision: SecurityDecision, isFallback: boolean): void {
    this.stats.evaluations++;
    this.stats.latencyTotalMs = (this.stats.latencyTotalMs ?? 0) + (decision.latencyMs ?? 0);
    if (isFallback) this.stats.fallbacks++;

    if (decision.decision === 'block') this.stats.blocks++;
    if (decision.decision === 'modify') this.stats.modifies++;
    // substitute / degrade 已删除，不再自增。
    // context_adjust 删除值兜底仍可能命中（如旧 fixture），继续自增以保留
    // 事件层审计可见性。loader 不再产出。
    if (decision.decision === 'context_adjust') this.stats.guidanceAdjustments++;
    if (decision.decision === 'audit') this.stats.audits++;

    this.stats.rulesLoaded = this.loader.getPolicy().rules.length;
  }
}
