/**
 * OpenClaw Security Monitor - Guidance Engine
 *
 * Generates context_adjust guidance results from policy rules and risk signals.
 */

import type {
  InterventionContext,
  RiskSignal,
  GuidanceResult,
  GuidanceConfig,
  PolicyRule,
  PolicyRuleActionGuidance,
  PolicyResources,
} from './types.js';
import { DEFAULT_GUIDANCE_THRESHOLDS } from './types.js';
import {
  GuidanceTemplateStoreImpl,
  TemplateRenderer,
  loadBuiltinTemplates,
  normalizeTemplateRef,
  type GuidanceTemplateStore,
} from './GuidanceTemplate.js';
import { GuidanceStateMachine, type GuidanceStateMachineOptions } from './GuidanceStateMachine.js';

export interface GuidanceEngineOptions {
  config?: GuidanceConfig;
  resources?: PolicyResources;
  logger?: { warn: (msg: string) => void; error: (msg: string) => void };
}

export class GuidanceEngine {
  private store: GuidanceTemplateStore;
  private renderer: TemplateRenderer;
  private stateMachine: GuidanceStateMachine;
  private options: GuidanceEngineOptions;

  constructor(options: GuidanceEngineOptions = {}) {
    this.options = options;
    this.store = new GuidanceTemplateStoreImpl();
    this.renderer = new TemplateRenderer({ maxLength: 4000 });
    const smOptions: GuidanceStateMachineOptions = {
      defaultThreshold: options.config?.budgetThresholds?.default
        ? Number(options.config.budgetThresholds.default)
        : 3,
      stateTtlMs: options.config?.stateTtlMs,
      guidanceWindowSteps: options.config?.guidanceWindowSteps,
      budgetThresholds: options.config?.budgetThresholds || DEFAULT_GUIDANCE_THRESHOLDS,
    };
    this.stateMachine = new GuidanceStateMachine(smOptions);
    this.loadBuiltinTemplates();
    this.loadExternalTemplates();
  }

  /**
   * Generate a guidance result from a matched rule and context.
   */
  generate(
    ctx: InterventionContext,
    rule: PolicyRule,
    riskSignal?: RiskSignal,
    guidanceAction?: PolicyRuleActionGuidance
  ): GuidanceResult {
    const action = guidanceAction || rule.action.guidance || {};
    const template = this.resolveTemplate(action.templateRef);
    const variables = this.buildVariables(ctx, rule, riskSignal, action);
    const rendered = template
      ? this.renderer.render(template, variables)
      : this.renderFallback(variables);

    const state = this.stateMachine.record(ctx, rule.id, rendered);
    const threshold = this.resolveThreshold(action, riskSignal);
    const attemptsRemaining = threshold - state.attempts;

    return {
      adjustmentId: this.generateAdjustmentId(),
      policyId: rule.id,
      policyVersion: rule.action?.guidance?.templateParams?.version as string | undefined,
      riskSignal,
      rendered,
      allowedScope: this.resolveAllowedScope(action, variables),
      alternatives: this.resolveAlternatives(action, variables),
      attemptsRemaining,
      nonOverridable: action.nonOverridable ?? false,
      templateId: template?.id || action.templateRef?.toString(),
      templateVersion: template?.version,
    };
  }

  /**
   * Check whether the guidance attempt budget is exhausted for this rule
   * (the next matching attempt upgrades to a block decision).
   */
  isBudgetExhausted(ctx: InterventionContext, rule: PolicyRule, riskSignal?: RiskSignal): boolean {
    const action = rule.action.guidance || {};
    const threshold = action.maxAttempts ?? action.budgetThreshold ?? undefined;
    return this.stateMachine.isBudgetExhausted(ctx, rule.id, riskSignal, threshold);
  }

  /**
   * Mark a state's guidance budget as exhausted.
   */
  markBudgetExhausted(ctx: InterventionContext, rule: PolicyRule): void {
    this.stateMachine.markBudgetExhausted(ctx, rule.id);
  }

  /**
   * Get current guidance state for a context.
   */
  getState(ctx: InterventionContext, rule: PolicyRule) {
    return this.stateMachine.getState(ctx, rule.id);
  }

  /**
   * Cleanup expired states.
   */
  cleanup(): number {
    return this.stateMachine.cleanup();
  }

  /**
   * Reset guidance state.
   */
  reset(): void {
    this.stateMachine.reset();
  }

  private resolveTemplate(ref?: string | { id?: string; path?: string }) {
    const normalized = normalizeTemplateRef(ref || this.options.config?.defaultTemplateId || 'guidance.default');
    if (normalized.id) {
      return this.store.get(normalized.id);
    }
    if (normalized.path) {
      return this.store.loadFromFile(normalized.path);
    }
    return undefined;
  }

  private resolveAllowedScope(
    action: PolicyRuleActionGuidance,
    variables: Record<string, unknown>
  ): string | undefined {
    if (action.templateParams?.allowedScope) {
      return String(action.templateParams.allowedScope);
    }
    return variables.allowedScope as string | undefined;
  }

  private resolveAlternatives(
    action: PolicyRuleActionGuidance,
    variables: Record<string, unknown>
  ): string[] | undefined {
    if (action.templateParams?.alternatives) {
      return Array.isArray(action.templateParams.alternatives)
        ? action.templateParams.alternatives.map((a) => String(a))
        : [String(action.templateParams.alternatives)];
    }
    return variables.alternatives as string[] | undefined;
  }

  private buildVariables(
    ctx: InterventionContext,
    rule: PolicyRule,
    riskSignal: RiskSignal | undefined,
    action: PolicyRuleActionGuidance
  ): Record<string, unknown> {
    const params = ctx.params || {};
    const templateParams = action.templateParams || {};

    return {
      ...templateParams,
      policy_id: rule.id,
      policy_name: rule.name || rule.id,
      policy_version: rule.action?.guidance?.templateParams?.version,
      tool_name: ctx.toolName,
      action_type: ctx.actionType,
      risk_level: riskSignal?.riskLevel,
      risk_score: riskSignal?.riskScore,
      reg_level: riskSignal?.regLevel,
      reg_clause: riskSignal?.regClause?.join(', '),
      risk_flags: ctx.riskFlags?.join(', '),
      user_prompt: ctx.userPrompt,
      agent_plan: ctx.agentPlan?.join('\n'),
      allowed_scope: templateParams.allowedScope || action.templateParams?.allowedScope,
      alternatives: templateParams.alternatives || action.templateParams?.alternatives,
      target_host: this.extractHost(params),
      session_id: ctx.sessionId,
      agent_id: ctx.agentId,
      run_id: ctx.runId,
    };
  }

  private extractHost(params: Record<string, unknown>): string | undefined {
    const url = params.url || params.path || params.host || params.target;
    if (typeof url === 'string') {
      try {
        return new URL(url).hostname;
      } catch {
        return url;
      }
    }
    return undefined;
  }

  private renderFallback(variables: Record<string, unknown>): string {
    const riskLevel = variables.risk_level || '中风险';
    const policyName = variables.policy_name || '安全策略';
    const allowedScope = variables.allowed_scope || '请保持安全合规。';
    return `检测到风险（${riskLevel}），规则：${policyName}。\n${allowedScope}`;
  }

  private generateAdjustmentId(): string {
    return `adj_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  }

  private resolveThreshold(action: PolicyRuleActionGuidance, riskSignal?: RiskSignal): number {
    if (action.budgetThreshold !== undefined) {
      return action.budgetThreshold;
    }
    if (action.maxAttempts !== undefined) {
      return action.maxAttempts;
    }
    const level = riskSignal?.riskLevel || 'medium';
    return (
      this.stateMachine.thresholds[level] ||
      DEFAULT_GUIDANCE_THRESHOLDS[level] ||
      3
    );
  }

  private loadBuiltinTemplates(): void {
    for (const template of loadBuiltinTemplates()) {
      this.store.set(template);
    }
  }

  private loadExternalTemplates(): void {
    const paths = this.options.config?.templatePaths || [];
    for (const p of paths) {
      try {
        this.store.loadFromDirectory(p);
      } catch (err) {
        this.options.logger?.warn?.(`[GuidanceEngine] failed to load templates from ${p}: ${err}`);
      }
    }
  }
}
