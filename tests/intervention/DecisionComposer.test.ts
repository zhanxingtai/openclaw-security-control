import { describe, it, expect } from 'vitest';
import { DecisionComposer } from '../../src/intervention/DecisionComposer.js';
import type { InterventionContext, PolicyRule } from '../../src/intervention/types.js';

describe('DecisionComposer', () => {
  it('returns allow when no rules match', () => {
    const composer = new DecisionComposer({ defaultAction: 'allow' });
    const ctx: InterventionContext = { actionType: 'tool_call', toolName: 'file_read' };
    const decision = composer.compose(ctx, []);
    expect(decision.decision).toBe('allow');
  });

  it('returns block decision from matched rule', () => {
    const composer = new DecisionComposer({ defaultAction: 'allow' });
    const rule: PolicyRule = {
      id: 'block-rule',
      name: 'Block Rule',
      enabled: true,
      priority: 100,
      match: { actionType: ['tool_call'] },
      action: {
        decision: 'block',
        block: { blockReason: 'blocked by rule', blockCode: 'RULE_001' },
      },
    };
    const ctx: InterventionContext = { actionType: 'tool_call', toolName: 'file_read' };
    const decision = composer.compose(ctx, [rule]);
    expect(decision.decision).toBe('block');
    expect(decision.blockReason).toBe('blocked by rule');
    expect(decision.blockCode).toBe('RULE_001');
    expect(decision.policyId).toBe('block-rule');
  });

  it('redacts fields for modify decision', () => {
    const composer = new DecisionComposer({ defaultAction: 'allow' });
    const rule: PolicyRule = {
      id: 'redact-rule',
      name: 'Redact Rule',
      enabled: true,
      priority: 100,
      match: { actionType: ['http_request'] },
      action: {
        decision: 'modify',
        modify: { redactFields: ['password', 'token'] },
      },
    };
    const ctx: InterventionContext = {
      actionType: 'http_request',
      params: { password: 'secret', token: 'abc', user: 'alice' },
    };
    const decision = composer.compose(ctx, [rule]);
    expect(decision.decision).toBe('modify');
    expect(decision.modifiedParams).toEqual({
      password: '***',
      token: '***',
      user: 'alice',
    });
  });

  // substitute 决策已删除（loader 抛错 + 单规则隔离）。
  // DecisionComposer 不实现 buildSubstituteDecision；历史 fixture 仍以
  // substitute 字面量写入时，switch default 兜底为 allow + audit 留痕。
  it('downgrades substitute decision to allow (removed per spec )', () => {
    const composer = new DecisionComposer({ defaultAction: 'allow' });
    const rule = {
      id: 'substitute-rule',
      name: 'Substitute Rule',
      enabled: true,
      priority: 100,
      match: { actionType: ['tool_call'] },
      action: {
        decision: 'substitute' as const,
        substitute: {
          toolName: 'safe_file_read',
          paramMapping: { path: 'file_path' },
        },
      },
    } as unknown as PolicyRule;
    const ctx: InterventionContext = {
      actionType: 'tool_call',
      toolName: 'file_read',
      params: { path: '/etc/passwd' },
    };
    const decision = composer.compose(ctx, [rule]);
    expect(decision.decision).toBe('allow');
    expect(decision.substitutedToolName).toBeUndefined();
    expect(decision.modifiedParams).toBeUndefined();
  });

  it('applies first matched rule only', () => {
    const composer = new DecisionComposer({ defaultAction: 'allow' });
    const rules: PolicyRule[] = [
      {
        id: 'first',
        name: 'First',
        enabled: true,
        priority: 100,
        match: { actionType: ['tool_call'] },
        action: { decision: 'block', block: { blockReason: 'first' } },
      },
      {
        id: 'second',
        name: 'Second',
        enabled: true,
        priority: 100,
        match: { actionType: ['tool_call'] },
        action: { decision: 'allow' },
      },
    ];
    const ctx: InterventionContext = { actionType: 'tool_call' };
    const decision = composer.compose(ctx, rules);
    expect(decision.decision).toBe('block');
    expect(decision.policyId).toBe('first');
  });

  // appealable 降级为展示字段（方案 B，无在线申诉链路）。
  it('fills default remediationHint with policyId when appealable and no hint configured', () => {
    const composer = new DecisionComposer({ defaultAction: 'allow' });
    const rule: PolicyRule = {
      id: 'appeal-rule',
      name: 'Appeal Rule',
      enabled: true,
      priority: 100,
      match: { actionType: ['tool_call'] },
      action: {
        decision: 'block',
        block: { blockReason: 'blocked', appealable: true },
      },
    };
    const ctx: InterventionContext = { actionType: 'tool_call', toolName: 'exec' };
    const decision = composer.compose(ctx, [rule]);
    expect(decision.decision).toBe('block');
    expect(decision.appealable).toBe(true);
    // 缺省文案必须含 policyId 并指明联系管理员复核 / 调整策略路径。
    expect(decision.remediationHint).toContain('appeal-rule');
    expect(decision.remediationHint).toContain('管理员');
    expect(decision.remediationHint).toContain('策略');
  });

  it('keeps explicit remediationHint over the appealable default', () => {
    const composer = new DecisionComposer({ defaultAction: 'allow' });
    const rule: PolicyRule = {
      id: 'explicit-hint-rule',
      enabled: true,
      priority: 100,
      match: { actionType: ['tool_call'] },
      action: {
        decision: 'block',
        block: { blockReason: 'blocked', appealable: true, remediationHint: '自定义修复指引' },
      },
    };
    const ctx: InterventionContext = { actionType: 'tool_call' };
    const decision = composer.compose(ctx, [rule]);
    expect(decision.remediationHint).toBe('自定义修复指引');
  });

  it('leaves remediationHint undefined when appealable is false', () => {
    const composer = new DecisionComposer({ defaultAction: 'allow' });
    const rule: PolicyRule = {
      id: 'hard-block-rule',
      enabled: true,
      priority: 100,
      match: { actionType: ['tool_call'] },
      action: {
        decision: 'block',
        block: { blockReason: 'blocked', appealable: false },
      },
    };
    const ctx: InterventionContext = { actionType: 'tool_call' };
    const decision = composer.compose(ctx, [rule]);
    expect(decision.appealable).toBe(false);
    expect(decision.remediationHint).toBeUndefined();
  });

  // 多规则命中时 composeDetailed 返回完整命中标注。
  it('composeDetailed returns full matched-rule annotations alongside the decision', () => {
    const composer = new DecisionComposer({ defaultAction: 'allow' });
    const warnRule: PolicyRule = {
      id: 'warn-rule',
      name: 'Warn Rule',
      enabled: true,
      priority: 100,
      category: 'data_leak_monitoring',
      match: { actionType: ['tool_call'] },
      action: { decision: 'warn' },
    };
    const blockRule: PolicyRule = {
      id: 'block-rule',
      name: 'Block Rule',
      enabled: true,
      priority: 90,
      severity: 'high',
      match: { actionType: ['tool_call'] },
      action: { decision: 'block', block: { blockReason: 'blocked' } },
    };
    const ctx: InterventionContext = { actionType: 'tool_call' };
    const { decision, matched } = composer.composeDetailed(ctx, [warnRule, blockRule]);
    // 最终决策仍是最高优先级的 block。
    expect(decision.decision).toBe('block');
    expect(decision.policyId).toBe('block-rule');
    // 被掩盖的 warn 规则也完整保留在命中标注里。
    expect(matched.length).toBe(2);
    expect(matched[0]).toMatchObject({
      policyId: 'warn-rule',
      policyName: 'Warn Rule',
      decision: 'warn',
      category: 'data_leak_monitoring',
    });
    expect(matched[1]).toMatchObject({
      policyId: 'block-rule',
      decision: 'block',
      priority: 90,
      riskLevel: 'high',
    });
  });

  it('composeDetailed returns empty matched list when no rule matches', () => {
    const composer = new DecisionComposer({ defaultAction: 'allow' });
    const { decision, matched } = composer.composeDetailed({ actionType: 'tool_call' }, []);
    expect(decision.decision).toBe('allow');
    expect(matched).toEqual([]);
  });

  // context_adjust 已删除。DecisionComposer 仍允许历史 fixture /
  // 第三方策略以字符串字面量写入 context_adjust 字段，落到 switch 兜底为
  // block + GUIDANCE_REMOVED。
  it('downgrades context_adjust to block with GUIDANCE_REMOVED code', () => {
    const composer = new DecisionComposer({ defaultAction: 'allow' });
    const rule = {
      id: 'guide-rule',
      name: 'Guide Rule',
      enabled: true,
      priority: 100,
      match: { actionType: ['tool_call'] },
      action: { decision: 'context_adjust' as const, guidance: { templateRef: 'guidance.default' } },
    } as unknown as PolicyRule;
    const ctx: InterventionContext = { actionType: 'tool_call', toolName: 'exec' };
    const decision = composer.compose(ctx, [rule]);
    expect(decision.decision).toBe('block');
    expect(decision.blockCode).toBe('GUIDANCE_REMOVED');
    expect(decision.policyId).toBe('guide-rule');
  });

  // decisionChain 中的 context_adjust 项在引导关闭时直接落为 block。
  it('downgrades decision-chain context_adjust to block when guidanceEnabled is false', () => {
    const composer = new DecisionComposer({ defaultAction: 'allow', guidanceEnabled: false });
    const rule = {
      id: 'chain-rule',
      name: 'Chain Rule',
      enabled: true,
      priority: 100,
      match: { actionType: ['tool_call'] },
      action: {
        decisionChain: [
          { decision: 'context_adjust' as const, guidance: { templateRef: 'guidance.default' } },
          { decision: 'warn' as const },
        ],
      },
    } as unknown as PolicyRule;
    const ctx: InterventionContext = { actionType: 'tool_call', toolName: 'exec' };
    const decision = composer.compose(ctx, [rule]);
    expect(decision.decision).toBe('block');
    expect(decision.blockCode).toBe('GUIDANCE_REMOVED');
  });

  // degrade 已删除，degradeEnabled 开关保留为 schema 兼容位，
  // 实际行为一律为 allow + audit 留痕（兜底分支）。
  it('downgrades degrade decision to allow regardless of degradeEnabled', () => {
    const composer = new DecisionComposer({ defaultAction: 'allow', degradeEnabled: false });
    const rule = {
      id: 'degrade-rule',
      name: 'Degrade Rule',
      enabled: true,
      priority: 100,
      match: { actionType: ['tool_call'] },
      action: { decision: 'degrade' as const, degrade: { mode: 'restricted', removedTools: ['exec'] } },
    } as unknown as PolicyRule;
    const ctx: InterventionContext = { actionType: 'tool_call', toolName: 'exec' };
    const decision = composer.compose(ctx, [rule]);
    expect(decision.decision).toBe('allow');
    expect(decision.degradeMode).toBeUndefined();
  });

  // 对照：degrade 字面量在默认配置下同样兜底为 allow（删除值）。
  it('downgrades degrade decision to allow when switches are unset', () => {
    const composer = new DecisionComposer({ defaultAction: 'allow' });
    const degradeRule = {
      id: 'degrade-rule',
      name: 'Degrade Rule',
      enabled: true,
      priority: 100,
      match: { actionType: ['tool_call'] },
      action: { decision: 'degrade' as const, degrade: { mode: 'restricted' } },
    } as unknown as PolicyRule;
    const ctx: InterventionContext = { actionType: 'tool_call', toolName: 'exec' };
    const decision = composer.compose(ctx, [degradeRule]);
    expect(decision.decision).toBe('allow');
    expect(decision.degradeMode).toBeUndefined();
  });
});
