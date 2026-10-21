import { describe, it, expect } from 'vitest';
import { GuidanceEngine } from '../../src/intervention/GuidanceEngine.js';
import type { InterventionContext, PolicyRule } from '../../src/intervention/types.js';

describe('GuidanceEngine', () => {
  const baseRule: PolicyRule = {
    id: 'path-boundary',
    name: 'Path Boundary Rule',
    enabled: true,
    priority: 100,
    match: { actionType: ['tool_call'], toolName: ['file_read'] },
    action: {
      decision: 'context_adjust',
      guidance: {
        templateRef: 'guidance.default',
        templateParams: { allowedScope: '仅允许读取 /home/user/data 目录' },
        maxAttempts: 2,
      },
    },
  };

  const baseCtx: InterventionContext = {
    actionType: 'tool_call',
    toolName: 'file_read',
    params: { path: '/etc/passwd' },
    sessionId: 'session-1',
    riskFlags: ['sensitive_path'],
  };

  it('renders a guidance result from a matched rule', () => {
    const engine = new GuidanceEngine();
    const result = engine.generate(baseCtx, baseRule);

    expect(result.adjustmentId).toMatch(/^adj_/);
    expect(result.policyId).toBe('path-boundary');
    expect(result.rendered).toContain('仅允许读取 /home/user/data 目录');
    expect(result.attemptsRemaining).toBe(1); // first attempt, max 2
    expect(result.templateId).toBe('guidance.default');
  });

  it('counts guidance attempts per session+action', () => {
    const engine = new GuidanceEngine();
    engine.generate(baseCtx, baseRule);
    engine.generate(baseCtx, baseRule);
    const third = engine.generate(baseCtx, baseRule);

    expect(third.attemptsRemaining).toBe(-1); // 3 attempts, max 2
    expect(engine.isBudgetExhausted(baseCtx, baseRule)).toBe(true);
  });

  it('uses fallback rendering when template is missing', () => {
    const engine = new GuidanceEngine();
    const rule: PolicyRule = {
      ...baseRule,
      action: {
        decision: 'context_adjust',
        guidance: { templateRef: 'missing.template' },
      },
    };
    const result = engine.generate(baseCtx, rule);
    expect(result.rendered).toContain('Path Boundary Rule');
  });

  it('applies per-risk-level thresholds', () => {
    const engine = new GuidanceEngine({
      config: { budgetThresholds: { high: 1 } },
    });
    const rule: PolicyRule = {
      ...baseRule,
      action: {
        decision: 'context_adjust',
        guidance: { templateRef: 'guidance.default' },
      },
    };
    engine.generate(baseCtx, rule, { riskScore: 75, riskLevel: 'high' });
    expect(engine.isBudgetExhausted(baseCtx, rule, { riskScore: 75, riskLevel: 'high' })).toBe(true);
  });
});
