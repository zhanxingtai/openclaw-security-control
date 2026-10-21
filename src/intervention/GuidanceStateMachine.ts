/**
 * OpenClaw Security Monitor - Guidance State Machine
 *
 * Tracks per-session and per-action guidance counts to decide when the
 * guidance attempt budget is exhausted and the action upgrades to a block.
 */

import type { InterventionContext, RiskSignal } from './types.js';

export interface GuidanceState {
  /** Number of guidance attempts already issued. */
  attempts: number;
  /** Last guidance timestamp (ms). */
  lastGuidanceAt: number;
  /** Whether the guidance attempt budget for this policy is exhausted. */
  budgetExhausted: boolean;
  /** Last rendered guidance text. */
  lastRendered?: string;
  /** Last policy id that triggered guidance. */
  lastPolicyId?: string;
}

export interface GuidanceStateMachineOptions {
  /** Max attempts before the block upgrade. */
  defaultThreshold?: number;
  /** State TTL in milliseconds. */
  stateTtlMs?: number;
  /** Steps window to consider guidance effective. */
  guidanceWindowSteps?: number;
  /** Guidance attempt thresholds per risk level. */
  budgetThresholds?: Record<string, number>;
}

export class GuidanceStateMachine {
  private states = new Map<string, GuidanceState>();
  private options: Required<GuidanceStateMachineOptions>;

  constructor(options: GuidanceStateMachineOptions = {}) {
    this.options = {
      defaultThreshold: 3,
      stateTtlMs: 30 * 60 * 1000, // 30 minutes
      guidanceWindowSteps: 5,
      budgetThresholds: {},
      ...options,
    };
  }

  /**
   * Record that a guidance was issued for this context.
   */
  record(ctx: InterventionContext, policyId: string, rendered: string): GuidanceState {
    const key = this.makeKey(ctx, policyId);
    const now = Date.now();
    const existing = this.states.get(key);
    const state: GuidanceState = {
      attempts: (existing?.attempts || 0) + 1,
      lastGuidanceAt: now,
      budgetExhausted: existing?.budgetExhausted || false,
      lastRendered: rendered,
      lastPolicyId: policyId,
    };
    this.states.set(key, state);
    return state;
  }

  /**
   * Determine if the guidance attempt budget is exhausted for this context
   * (i.e. attempts have reached the threshold). If thresholdOverride is
   * provided, it takes precedence over risk-level thresholds.
   */
  isBudgetExhausted(
    ctx: InterventionContext,
    policyId: string,
    riskSignal?: RiskSignal,
    thresholdOverride?: number
  ): boolean {
    const key = this.makeKey(ctx, policyId);
    const state = this.states.get(key);
    if (!state) return false;

    const threshold = thresholdOverride ?? this.resolveThreshold(riskSignal);
    return state.attempts >= threshold;
  }

  /**
   * Mark a state's guidance budget as exhausted.
   */
  markBudgetExhausted(ctx: InterventionContext, policyId: string): void {
    const key = this.makeKey(ctx, policyId);
    const state = this.states.get(key);
    if (state) {
      state.budgetExhausted = true;
    }
  }

  /**
   * Get the current state for a context.
   */
  getState(ctx: InterventionContext, policyId: string): GuidanceState | undefined {
    const key = this.makeKey(ctx, policyId);
    return this.states.get(key);
  }

  /**
   * Clean up expired states.
   */
  cleanup(): number {
    const now = Date.now();
    let removed = 0;
    for (const [key, state] of this.states.entries()) {
      if (now - state.lastGuidanceAt > this.options.stateTtlMs) {
        this.states.delete(key);
        removed++;
      }
    }
    return removed;
  }

  /**
   * Reset all states.
   */
  reset(): void {
    this.states.clear();
  }

  /**
   * Number of tracked states.
   */
  size(): number {
    return this.states.size;
  }

  /**
   * Effective thresholds.
   */
  get thresholds(): Record<string, number> {
    return this.options.budgetThresholds;
  }

  private makeKey(ctx: InterventionContext, policyId: string): string {
    // Avoid collapsing every 'unknown' session into a shared 'global' key, which
    // causes unrelated sessions to share guidance counts and exhaust the budget too fast.
    // Fall back to runId/agentId so that each distinct run/agent gets its own
    // counter; only use the literal 'unknown' label when nothing else is available.
    const sessionId =
      ctx.sessionId && ctx.sessionId !== 'unknown'
        ? ctx.sessionId
        : ctx.runId || ctx.agentId || 'unknown';
    const actionType = ctx.actionType || 'any';
    const actionName = ctx.toolName || ctx.actionType || 'any';
    return `${sessionId}::${actionType}::${actionName}::${policyId}`;
  }

  private resolveThreshold(riskSignal?: RiskSignal): number {
    const level = riskSignal?.riskLevel || 'medium';
    if (this.options.budgetThresholds[level] !== undefined) {
      return this.options.budgetThresholds[level];
    }
    return this.options.defaultThreshold;
  }
}
