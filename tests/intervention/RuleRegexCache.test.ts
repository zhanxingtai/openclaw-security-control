import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, resolve } from 'path';
import { load as loadYaml } from 'js-yaml';
import { RuleLoader } from '../../src/intervention/RuleLoader.js';
import { RuleMatcher } from '../../src/intervention/RuleMatcher.js';
import { InterventionEngineImpl } from '../../src/intervention/InterventionEngine.js';
import { compileRuleRegexes, collectRulePatterns, isCatastrophicallyUnsafePattern, isSuspiciousNestedQuantifier } from '../../src/intervention/RuleRegexCache.js';
import { parseSPLPolicy } from '../../src/intervention/SPLRuleLoader.js';
import type { InterventionContext } from '../../src/intervention/types.js';

// 正则预编译旁路结构、排序缓存与 enforce 命中短路的行为测试。

describe('RuleRegexCache', () => {
  it('compiles all regex dimensions into RegExp at load time', () => {
    const rule = {
      id: 'r1', severity: 'medium',
      match: {
        sessionRegex: ['^sess-'],
        bodyRegex: ['danger'],
        paramsRegex: { path: ['^/etc/'], cmd: ['rm\\s'] },
        paramsNotRegex: { path: ['^/tmp/'] },
        chain: {
          withinSteps: 2,
          prior: [{ action: 'bash', pathRegex: ['^/opt/'], urlRegex: ['https?://'], bodyRegex: ['token'] }],
        },
      },
      action: { decision: 'block' as const },
    };
    const result = compileRuleRegexes(rule as never);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.sessionRegex![0]).toBeInstanceOf(RegExp);
    expect(result.value.bodyRegex![0]).toBeInstanceOf(RegExp);
    expect(result.value.paramsRegex!.path[0]).toBeInstanceOf(RegExp);
    expect(result.value.paramsNotRegex!.path[0]).toBeInstanceOf(RegExp);
    expect(result.value.chain!.prior[0].pathRegex![0]).toBeInstanceOf(RegExp);
    expect(result.value.chain!.prior[0].urlRegex![0]).toBeInstanceOf(RegExp);
    expect(result.value.chain!.prior[0].bodyRegex![0]).toBeInstanceOf(RegExp);
  });

  it('reports the invalid pattern instead of throwing', () => {
    const rule = {
      id: 'r-bad', severity: 'medium',
      match: { paramsRegex: { path: ['^/ok/', '['] } },
      action: { decision: 'block' as const },
    };
    const result = compileRuleRegexes(rule as never);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.pattern).toBe('[');
  });

  it('matches via lazy fallback for rules constructed outside RuleLoader', () => {
    const rule = {
      id: 'direct', severity: 'medium',
      enabled: true,
      match: { actionType: ['agent_tool_call'], toolName: ['file_read'], paramsRegex: { path: ['^/etc/'] } },
      action: { decision: 'block' as const },
    } as never;
    const ctx: InterventionContext = {
      actionType: 'agent_tool_call',
      toolName: 'file_read',
      params: { path: '/etc/passwd' },
    };
    expect(RuleMatcher.match(ctx, rule).matched).toBe(true);
    expect(RuleMatcher.match(ctx, rule).matched).toBe(true);
    // 懒编译产物缓存后复用：弱引用缓存命中即可，行为上两次一致。
  });
});

// 嵌套量词观察级告警的启发式：互补字符类对（\s+\S+ 等）线性安全不打 warn，
// 其余嵌套量词（单原子 / 交替分支 / 非互补序列）仍 suspicious。
describe('isSuspiciousNestedQuantifier', () => {
  it('treats complementary character-class pairs as linear-safe', () => {
    expect(isSuspiciousNestedQuantifier('cat(?:\\s+\\S+)*\\s+/etc/passwd')).toBe(false);
    expect(isSuspiciousNestedQuantifier('(?:\\w+\\W+)+x')).toBe(false);
    expect(isSuspiciousNestedQuantifier('(?:\\s+\\S+\\w+\\W+)*')).toBe(false);
    expect(isSuspiciousNestedQuantifier('(?:\\d+\\D+)+')).toBe(false);
  });

  it('still flags non-complementary nested quantifiers', () => {
    expect(isSuspiciousNestedQuantifier('(a+)+')).toBe(true);
    expect(isSuspiciousNestedQuantifier('(ab+)+')).toBe(true);
    expect(isSuspiciousNestedQuantifier('(\\w+)+')).toBe(true);
    expect(isSuspiciousNestedQuantifier('(?:\\s+\\d+)*')).toBe(true);
    expect(isSuspiciousNestedQuantifier('(a+)*')).toBe(true);
  });

  it('shipped policy produces zero suspicious nested-quantifier warnings', () => {
    const policyPath = resolve('policies/security-policy.spl.yaml');
    const rules = parseSPLPolicy(loadYaml(readFileSync(policyPath, 'utf8'))).rules;
    const flagged = rules.flatMap((rule) =>
      collectRulePatterns(rule)
        .filter((p) => isSuspiciousNestedQuantifier(p))
        .map((p) => `${rule.id}: ${p}`)
    );
    expect(flagged).toEqual([]);
  });
});

// 灾难性回溯审计对嵌套量词的拒绝口径。旧实现组体排除 `|`，
// `((a|b)+)+` 逃逸；现口径为"带量词的组其组内仍含量词组即拒绝"（含 | 分支
// 内嵌套，逐支递归同理），是旧口径的超集。
describe('isCatastrophicallyUnsafePattern ', () => {
  it('rejects alternation-branch nested quantifiers that previously escaped', () => {
    expect(isCatastrophicallyUnsafePattern('((a|b)+)+')).toBe(true);
    expect(isCatastrophicallyUnsafePattern('((a|b)+|c)+')).toBe(true);
    expect(isCatastrophicallyUnsafePattern('((a|b|c)*)+$')).toBe(true);
  });

  it('rejects multiply-nested and class-inner quantified groups', () => {
    expect(isCatastrophicallyUnsafePattern('((a+)(b+))+')).toBe(true);
    expect(isCatastrophicallyUnsafePattern('([a-z]+)*')).toBe(true);
    expect(isCatastrophicallyUnsafePattern('(\\w+\\s?)+$')).toBe(true);
  });

  it('keeps rejecting the classic signatures', () => {
    expect(isCatastrophicallyUnsafePattern('(a+)+')).toBe(true);
    expect(isCatastrophicallyUnsafePattern('(.*)*')).toBe(true);
    expect(isCatastrophicallyUnsafePattern('(a+){1,3}')).toBe(true);
  });

  it('still allows single-level and non-quantified-inner shapes', () => {
    // 单层量词交替（无嵌套量词）：线性/多项式，不在拒绝面。
    expect(isCatastrophicallyUnsafePattern('(a|b)*c')).toBe(false);
    // 量词组内嵌未量化组：线性。
    expect(isCatastrophicallyUnsafePattern('((a)(b))+')).toBe(false);
    // 未量化组：不参与判定。
    expect(isCatastrophicallyUnsafePattern('(a+)(b+)')).toBe(false);
  });

  it('keeps exempting complementary character-class sequences', () => {
    // shipped 策略在用的线性安全形态不回归。
    expect(isCatastrophicallyUnsafePattern('cat(?:\\s+\\S+)*\\s+/etc/passwd')).toBe(false);
    expect(isCatastrophicallyUnsafePattern('(?:\\d+\\D+)+')).toBe(false);
    expect(isCatastrophicallyUnsafePattern('-[a-zA-Z]*\\s+')).toBe(false);
  });

  it('compileRuleRegexes isolates a rule carrying an escaped-shape pattern', () => {
    const rule = {
      id: 'r-redos', severity: 'medium',
      match: { paramsRegex: { command: ['((a|b)+)+'] } },
      action: { decision: 'block' as const },
    };
    const result = compileRuleRegexes(rule as never);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe('unsafe');
    expect(result.pattern).toBe('((a|b)+)+');
  });

  it('shipped policy compiles clean under the stricter audit (zero isolated rules)', () => {
    const policyPath = resolve('policies/security-policy.spl.yaml');
    const rules = parseSPLPolicy(loadYaml(readFileSync(policyPath, 'utf8'))).rules;
    const rejected = rules
      .map((rule) => ({ rule, result: compileRuleRegexes(rule) }))
      .filter((r) => !r.result.ok)
      .map((r) => `${r.rule.id}: ${r.result.ok ? '' : r.result.pattern}`);
    expect(rejected).toEqual([]);
  });
});

// JS RegExp 不支持 PCRE 内联标志组 (?i:...)，
// 含该形态的模式此前在加载期整体报 invalid 导致规则被静默隔离。
describe('inline (?i:) flag groups ', () => {
  it('compiles (?i:) patterns as case-insensitive', () => {
    const rule = {
      id: 'r-inline-i', severity: 'medium',
      match: { bodyRegex: ['(?i:bearer\\s+[a-z0-9]{8})'] },
      action: { decision: 'audit' as const },
    };
    const result = compileRuleRegexes(rule as never);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.bodyRegex![0].test('Bearer abcdef12')).toBe(true);
    expect(result.value.bodyRegex![0].test('bearer ABCDEF12')).toBe(true);
    expect(result.value.bodyRegex![0].test('BEARER abcdef12')).toBe(true);
    expect(result.value.bodyRegex![0].test('BEARER xx')).toBe(false);
  });

  it('restores the shipped rules that were silently isolated', () => {
    const policyPath = resolve('policies/security-policy.spl.yaml');
    const rules = parseSPLPolicy(loadYaml(readFileSync(policyPath, 'utf8'))).rules;
    for (const id of ['block-credential-in-command-critical', 'block-credential-in-command-warn', 'data-leak-imds-001', 'data-leak-imds-002']) {
      const rule = rules.find((r) => r.id === id)!;
      expect(compileRuleRegexes(rule).ok, id).toBe(true);
    }
  });
});

describe('InterventionEngineImpl 预编译 / 热更新', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'regex-cache-'));
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  function writePolicy(content: string) {
    const policyPath = join(tmpDir, 'policy.yaml');
    writeFileSync(policyPath, content);
    return policyPath;
  }

  function createEngine(policyPath: string, extra: Record<string, unknown> = {}) {
    return new InterventionEngineImpl({
      ruleLoader: { policyPath, reloadIntervalMs: 0 },
      decisionTimeoutMs: 50,
      failStrategy: 'fail_open',
      logger: { warn: () => {}, error: () => {} },
      ...extra,
    });
  }

  it('RuleLoader exposes compiled regexes and skips rules with invalid regex', async () => {
    const warn = vi.fn();
    const policyPath = writePolicy(`
apiVersion: security.use/v2
kind: Policy
metadata: { id: test-policy, name: Test Policy, version: "1.0.0" }
rules:
  - id: valid-rule
    severity: medium
    priority: 100
    match:
      actionType: ["tool_call"]
      toolName: ["file_read"]
      paramsRegex:
        path: ["^/etc/"]
    action:
      decision: block
      blockReason: "敏感文件"
      blockCode: "POLICY_001"
  - id: invalid-rule
    severity: medium
    priority: 90
    match:
      actionType: ["tool_call"]
      toolName: ["file_read"]
      paramsRegex:
        path: ["["]
    action:
      decision: block
      blockReason: "不该触发"
      blockCode: "SHOULD_NOT_FIRE"
`);
    const loader = new RuleLoader({ policyPath, logger: { warn, error: () => {} } });
    await loader.initialize();
    await loader.shutdown();

    const rules = loader.getPolicy().rules;
    const compiledValid = loader.getCompiledRuleRegexes(rules[0]);
    expect(compiledValid).not.toBeNull();
    expect(compiledValid!.paramsRegex!.path[0]).toBeInstanceOf(RegExp);
    // 非法正则：加载期告警 + 编译产物为 null（跳过该规则）。
    expect(loader.getCompiledRuleRegexes(rules[1])).toBeNull();
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('invalid-rule'));

    const engine = createEngine(policyPath);
    await engine.initialize();
    const ctx: InterventionContext = {
      actionType: 'tool_call',
      toolName: 'file_read',
      params: { path: '/etc/passwd' },
    };
    const decision = await engine.evaluate(ctx);
    // 单规则隔离——非法正则规则被跳过，合法规则照常拦截，
    // 不再整次评估走 failStrategy 兜底。
    expect(decision.decision).toBe('block');
    expect(decision.blockCode).toBe('POLICY_001');
    expect(decision.failStrategy).toBeUndefined();
    await engine.shutdown();
  });

  it('aggregates nested-quantifier warnings by pattern across rules', async () => {
    const warn = vi.fn();
    const policyPath = writePolicy(`
apiVersion: security.use/v2
kind: Policy
metadata: { id: test-policy, name: Test Policy, version: "1.0.0" }
rules:
  - id: rule-a
    severity: medium
    priority: 100
    match: { actionType: ["tool_call"], toolName: ["file_read"], paramsRegex: { path: ["(ab+)+"] } }
    action: { decision: block, blockReason: "a", blockCode: "A" }
  - id: rule-b
    severity: medium
    priority: 90
    match: { actionType: ["tool_call"], toolName: ["file_read"], paramsRegex: { path: ["(ab+)+"] } }
    action: { decision: block, blockReason: "b", blockCode: "B" }
`);
    const loader = new RuleLoader({ policyPath, logger: { warn, error: () => {} } });
    await loader.initialize();
    await loader.shutdown();
    // 同一可疑模式命中两条规则只打一行聚合告警（含规则清单）。
    const nestedWarns = warn.mock.calls.map((c) => String(c[0])).filter((m) => m.includes('nested quantifiers'));
    expect(nestedWarns).toHaveLength(1);
    expect(nestedWarns[0]).toContain('2 rule(s)');
    expect(nestedWarns[0]).toContain('rule-a');
    expect(nestedWarns[0]).toContain('rule-b');
  });

  it('applies new regex after hot reload', async () => {
    const policyPath = writePolicy(`
apiVersion: security.use/v2
kind: Policy
metadata: { id: test-policy, name: Test Policy, version: "1.0.0" }
rules:
  - id: block-secret
    severity: medium
    priority: 100
    match:
      actionType: ["tool_call"]
      toolName: ["file_read"]
      paramsRegex:
        path: ["^/secret/"]
    action:
      decision: block
      blockReason: "secret"
      blockCode: "SECRET"
`);
    const engine = createEngine(policyPath);
    await engine.initialize();

    const secretCtx: InterventionContext = {
      actionType: 'tool_call',
      toolName: 'file_read',
      params: { path: '/secret/key' },
    };
    expect((await engine.evaluate(secretCtx)).decision).toBe('block');

    // 热更新：把正则换成 /other/，新编译产物必须生效。
    writePolicy(`
apiVersion: security.use/v2
kind: Policy
metadata: { id: test-policy, name: Test Policy, version: "1.0.0" }
rules:
  - id: block-secret
    severity: medium
    priority: 100
    match:
      actionType: ["tool_call"]
      toolName: ["file_read"]
      paramsRegex:
        path: ["^/other/"]
    action:
      decision: block
      blockReason: "other"
      blockCode: "OTHER"
`);
    await engine.getRuleLoader().load();

    expect((await engine.evaluate(secretCtx)).decision).toBe('allow');
    const otherCtx: InterventionContext = {
      actionType: 'tool_call',
      toolName: 'file_read',
      params: { path: '/other/key' },
    };
    const decision = await engine.evaluate(otherCtx);
    expect(decision.decision).toBe('block');
    expect(decision.blockCode).toBe('OTHER');
    await engine.shutdown();
  });

  it('caches sorted rules and invalidates on reload', async () => {
    const policyPath = writePolicy(`
apiVersion: security.use/v2
kind: Policy
metadata: { id: test-policy, name: Test Policy, version: "1.0.0" }
rules:
  - id: low
    severity: medium
    priority: 1
    match: { actionType: ["tool_call"], toolName: ["file_read"] }
    action: { decision: allow }
  - id: high
    severity: medium
    priority: 100
    match: { actionType: ["tool_call"], toolName: ["file_read"] }
    action: { decision: allow }
  - id: mid
    severity: medium
    priority: 50
    match: { actionType: ["tool_call"], toolName: ["file_read"] }
    action: { decision: allow }
`);
    const engine = createEngine(policyPath);
    await engine.initialize();

    // 只统计引擎的优先级排序（composer 内部另有按键排序，需区分）。
    let prioritySortCalls = 0;
    const originalSort = Array.prototype.sort;
    vi.spyOn(Array.prototype, 'sort').mockImplementation(function (
      this: unknown[],
      cmp?: (a: unknown, b: unknown) => number
    ) {
      if (cmp && cmp({ priority: 1 }, { priority: 0 }) === -1 && cmp({ priority: 0 }, { priority: 1 }) === 1) {
        prioritySortCalls++;
      }
      return originalSort.apply(this, [cmp] as never);
    });

    const ctx: InterventionContext = { actionType: 'tool_call', toolName: 'file_read' };
    await engine.evaluate(ctx);
    expect(prioritySortCalls).toBe(1);

    // 第二次评估命中缓存，不再重排。
    prioritySortCalls = 0;
    await engine.evaluate(ctx);
    expect(prioritySortCalls).toBe(0);

    // 热更新后源数组替换，缓存失效并重建。
    writePolicy(`
apiVersion: security.use/v2
kind: Policy
metadata: { id: test-policy, name: Test Policy, version: "1.0.0" }
rules:
  - id: low
    severity: medium
    priority: 1
    match: { actionType: ["tool_call"], toolName: ["file_read"] }
    action: { decision: allow }
  - id: high
    severity: medium
    priority: 100
    match: { actionType: ["tool_call"], toolName: ["file_read"] }
    action: { decision: allow }
`);
    await engine.getRuleLoader().load();
    prioritySortCalls = 0;
    await engine.evaluate(ctx);
    expect(prioritySortCalls).toBe(1);
    await engine.shutdown();
  });

  it('stops scanning after a block match in enforce mode but collects all in audit mode', async () => {
    const policyPath = writePolicy(`
apiVersion: security.use/v2
kind: Policy
metadata: { id: test-policy, name: Test Policy, version: "1.0.0" }
mode: enforce
rules:
  - id: block-rule
    severity: medium
    priority: 100
    match: { actionType: ["tool_call"], toolName: ["file_read"] }
    action: { decision: block, blockReason: "blocked", blockCode: "B1" }
  - id: second-rule
    severity: medium
    priority: 50
    match: { actionType: ["tool_call"], toolName: ["file_read"] }
    action: { decision: block, blockReason: "blocked2", blockCode: "B2" }
`);
    const ctx: InterventionContext = { actionType: 'tool_call', toolName: 'file_read' };

    const matchSpy = vi.spyOn(RuleMatcher, 'match');

    const enforceEngine = createEngine(policyPath, { mode: 'enforce' });
    await enforceEngine.initialize();
    const enforceDecision = await enforceEngine.evaluate(ctx);
    expect(enforceDecision.decision).toBe('block');
    // block 是最高裁决优先级：命中第一条 block 后即停扫。
    expect(matchSpy).toHaveBeenCalledTimes(1);
    await enforceEngine.shutdown();

    matchSpy.mockClear();
    const auditEngine = createEngine(policyPath, { mode: 'audit' });
    await auditEngine.initialize();
    const auditDecision = await auditEngine.evaluate(ctx);
    expect(auditDecision.decision).toBe('block');
    // audit 模式保持全量收集（事件标注需要全部命中）。
    expect(matchSpy).toHaveBeenCalledTimes(2);
    await auditEngine.shutdown();
  });
});
