import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { InterventionEngineImpl } from '../../src/intervention/InterventionEngine.js';
import { DecisionComposer } from '../../src/intervention/DecisionComposer.js';
import { parseSPLPolicy } from '../../src/intervention/SPLRuleLoader.js';
import { compileRuleRegexes, isCatastrophicallyUnsafePattern, collectRulePatterns } from '../../src/intervention/RuleRegexCache.js';
import { RuleMatcher } from '../../src/intervention/RuleMatcher.js';
import { SecurityMonitorStore } from '../../src/store.js';
import type { InterventionContext, PolicyRule } from '../../src/intervention/types.js';
import type { SecurityEvent } from '../../src/types.js';

// 验收测试：fail-open 面收敛 + 单规则隔离 + 顶层 failStrategy 生效 +
// 策略缺失留痕且自保护兜底 + 未知 actionType 可观测。

describe('fail-open isolation', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'fail-open-isolation-'));
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

  it('验收1: 注入非法正则的规则被隔离，其余规则照常拦截，且产生可观测告警与留痕事件', async () => {
    const policyPath = writePolicy(`
apiVersion: security.use/v2
kind: Policy
metadata: { id: test-policy, name: Test Policy, version: "1.0.0" }
rules:
  - id: bad-regex-rule
    severity: medium
    priority: 100
    match:
      actionType: ["tool_call"]
      paramsRegex:
        path: ["["]
    action:
      decision: block
      blockReason: "不该触发"
      blockCode: "SHOULD_NOT_FIRE"
  - id: good-block-rule
    severity: medium
    priority: 90
    match:
      actionType: ["tool_call"]
      toolName: ["file_read"]
      paramsRegex:
        path: ["^/etc/"]
    action:
      decision: block
      blockReason: "敏感文件访问被阻断"
      blockCode: "POLICY_001"
`);
    const warn = vi.fn();
    const error = vi.fn();
    const audit = vi.fn();
    const engine = new InterventionEngineImpl({
      ruleLoader: { policyPath, reloadIntervalMs: 0 },
      decisionTimeoutMs: 50,
      failStrategy: 'fail_open',
      logger: { warn, error },
      audit,
    });
    await engine.initialize();

    const ctx: InterventionContext = {
      actionType: 'tool_call',
      toolName: 'file_read',
      params: { path: '/etc/passwd' },
    };
    const decision = await engine.evaluate(ctx);
    expect(decision.decision).toBe('block');
    expect(decision.blockCode).toBe('POLICY_001');
    expect(decision.failStrategy).toBeUndefined();

    // 可观测告警：加载期（RuleLoader）+ 评估期首次跳过（引擎）。
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('bad-regex-rule'));
    // 留痕事件：加载期 onRuleIssue 与评估期隔离各产生一次（均按规则去重）。
    expect(audit).toHaveBeenCalledWith(
      expect.objectContaining({ eventType: 'rule_invalid_regex', ruleId: 'bad-regex-rule' })
    );

    await engine.shutdown();
  });

  it('验收1b: 灾难性回溯正则在编译期被拒绝（单规则隔离，无新依赖）', () => {
    expect(isCatastrophicallyUnsafePattern('(a+)+$')).toBe(true);
    expect(isCatastrophicallyUnsafePattern('(.*)*$')).toBe(true);
    // shipped 策略在用的线性安全形态不被误杀。
    expect(isCatastrophicallyUnsafePattern('cat(?:\\s+\\S+)*\\s+/etc/passwd')).toBe(false);

    const rule = {
      id: 'redos-rule', severity: 'medium',
      match: { actionType: ['tool_call'], paramsRegex: { command: ['(a+)+$'] } },
      action: { decision: 'block' },
    } as unknown as PolicyRule;
    const result = compileRuleRegexes(rule);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe('unsafe');
    expect(result.pattern).toBe('(a+)+$');
  });

  it('验收2: 策略顶层 failStrategy 合法值覆盖 config 默认值', async () => {
    const policyPath = writePolicy(`
apiVersion: security.use/v2
kind: Policy
metadata: { id: spl-fail-closed, name: SPL Fail Closed, version: 1.0.0 }
failStrategy: fail_closed
rules:
  - id: block-rule
    severity: medium
    priority: 100
    match:
      actionType: ["tool_call"]
    action:
      decision: block
      blockReason: "blocked"
`);
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    const engine = new InterventionEngineImpl({
      ruleLoader: { policyPath, reloadIntervalMs: 0 },
      decisionTimeoutMs: 50,
      failStrategy: 'fail_open',
      logger: { warn: () => {}, error: () => {} },
    });
    await engine.initialize();
    expect(log).toHaveBeenCalledWith(expect.stringContaining('failStrategy=fail_closed'));
    await engine.shutdown();
  });

  it('验收2b: 非法顶层 failStrategy 记 warn 并回退 config 默认值', async () => {
    const policyPath = writePolicy(`
apiVersion: security.use/v2
kind: Policy
metadata: { id: spl-fail-invalid, name: SPL Fail Invalid, version: 1.0.0 }
failStrategy: banana
rules:
  - id: block-rule
    severity: medium
    priority: 100
    match:
      actionType: ["tool_call"]
    action:
      decision: block
`);
    const warn = vi.fn();
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    const engine = new InterventionEngineImpl({
      ruleLoader: { policyPath, reloadIntervalMs: 0 },
      decisionTimeoutMs: 50,
      failStrategy: 'fail_open',
      logger: { warn, error: () => {} },
    });
    await engine.initialize();
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('failStrategy'));
    expect(log).toHaveBeenCalledWith(expect.stringContaining('failStrategy=fail_open'));
    await engine.shutdown();

    const parsed = parseSPLPolicy({
      apiVersion: 'security.use/v2',
      kind: 'Policy',
      metadata: { id: 'p', name: 'P', version: '1.0.0' },
      failStrategy: 'fail_open_high_risk_only',
      rules: [],
    });
    expect(parsed.failStrategy).toBe('fail_open_high_risk_only');
  });

  it('验收4: 未知运行时 actionType 记 warn（每个值一次）', async () => {
    const policyPath = writePolicy(`
apiVersion: security.use/v2
kind: Policy
metadata: { id: test-policy, name: Test Policy, version: "1.0.0" }
rules:
  - id: block-rule
    severity: medium
    priority: 100
    match:
      actionType: ["tool_call"]
    action:
      decision: block
`);
    const warn = vi.fn();
    const engine = new InterventionEngineImpl({
      ruleLoader: { policyPath, reloadIntervalMs: 0 },
      decisionTimeoutMs: 50,
      failStrategy: 'fail_open',
      logger: { warn, error: () => {} },
    });
    await engine.initialize();

    const ctx: InterventionContext = { actionType: 'brand_new_host_action', toolName: 'exec' };
    await engine.evaluate(ctx);
    await engine.evaluate(ctx);
    const unknownWarns = warn.mock.calls.filter((c) => String(c[0]).includes('unknown runtime actionType'));
    expect(unknownWarns).toHaveLength(1);
    expect(String(unknownWarns[0][0])).toContain('brand_new_host_action');

    await engine.shutdown();
  });

  it('验收补充: DecisionComposer 对非法 substitutePatterns 做单条隔离，不崩溃', () => {
    const composer = new DecisionComposer({ defaultAction: 'allow' });
    const rule = {
      id: 'modify-rule', severity: 'medium',
      match: {},
      action: {
        decision: 'modify',
        modify: {
          substitutePatterns: [
            { pattern: '[', replacement: 'x' },
            { pattern: 'secret', replacement: '***' },
          ],
        },
      },
    } as unknown as PolicyRule;
    const ctx: InterventionContext = { actionType: 'tool_call', params: { body: 'secret=1' } };
    const decision = composer.compose(ctx, [rule]);
    expect(decision.decision).toBe('modify');
    // 非法模式被跳过，合法替换照常生效。
    expect(decision.modifiedParams).toEqual({ body: '***=1' });
  });

  it('验收5: params 循环引用不爆栈、不触发 fail_open，规则照常命中 ', async () => {
    // 旧实现无界递归：宿主传入自引用 live 对象 → RangeError → 被评估 catch
    // → fail_open 下整次评估全量放行。
    const policyPath = writePolicy(`
apiVersion: security.use/v2
kind: Policy
metadata: { id: test-policy, name: Test Policy, version: "1.0.0" }
rules:
  - id: cyclic-params-block
    severity: medium
    priority: 100
    match:
      actionType: ["tool_call"]
      toolName: ["file_read"]
      paramsRegex:
        payload: ["rm -rf /"]
    action:
      decision: block
      blockReason: "危险命令"
      blockCode: "POLICY_CYCLE_001"
`);
    const engine = new InterventionEngineImpl({
      ruleLoader: { policyPath, reloadIntervalMs: 0 },
      decisionTimeoutMs: 50,
      failStrategy: 'fail_open',
      logger: { warn: () => {}, error: () => {} },
    });
    await engine.initialize();

    const payload: Record<string, unknown> = { command: 'rm -rf /' };
    payload.self = payload;
    payload.list = [payload, { nested: payload }];

    // 截断告警按进程只发一次，故在本文件首个触发截断的用例断言。
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const decision = await engine.evaluate({
      actionType: 'tool_call',
      toolName: 'file_read',
      params: { payload },
    });

    expect(decision.decision).toBe('block');
    expect(decision.blockCode).toBe('POLICY_CYCLE_001');
    expect(decision.failStrategy).toBeUndefined();
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('循环引用'));

    await engine.shutdown();
  });

  it('验收6: 超深嵌套 params（10^4 层）有界截断，既不爆栈也不 fail_open ', async () => {
    const policyPath = writePolicy(`
apiVersion: security.use/v2
kind: Policy
metadata: { id: test-policy, name: Test Policy, version: "1.0.0" }
rules:
  - id: deep-nesting-block
    severity: medium
    priority: 100
    match:
      actionType: ["tool_call"]
      toolName: ["file_read"]
      paramsRegex:
        deep: ["rm -rf /"]
    action:
      decision: block
      blockReason: "不该触发：越界子树不参与匹配"
      blockCode: "SHOULD_NOT_FIRE"
`);
    const engine = new InterventionEngineImpl({
      ruleLoader: { policyPath, reloadIntervalMs: 0 },
      decisionTimeoutMs: 50,
      failStrategy: 'fail_open',
      logger: { warn: () => {}, error: () => {} },
    });
    await engine.initialize();

    // 10^4 层 JSON 是 ticket 给的阈值：旧实现对嵌套对象递归提取同样爆栈。
    let deep = JSON.parse('{"leaf":"rm -rf /"}');
    for (let i = 0; i < 10000; i++) deep = { nested: deep };

    const started = Date.now();
    const decision = await engine.evaluate({
      actionType: 'tool_call',
      toolName: 'file_read',
      params: { deep },
    });

    // 越界子树被跳过 → 该规则不命中（默认 allow），但绝不能是 failStrategy 兜底。
    expect(decision.decision).toBe('allow');
    expect(decision.failStrategy).toBeUndefined();
    expect(Date.now() - started).toBeLessThan(1000);

    await engine.shutdown();
  });

  it('验收7: 大对象 params 走节点预算有界提取，预算内仍正常命中且不超时 ', async () => {
    const policyPath = writePolicy(`
apiVersion: security.use/v2
kind: Policy
metadata: { id: test-policy, name: Test Policy, version: "1.0.0" }
rules:
  - id: wide-object-block
    severity: medium
    priority: 100
    match:
      actionType: ["tool_call"]
      toolName: ["file_read"]
      paramsRegex:
        wide: ["rm -rf /"]
    action:
      decision: block
      blockReason: "危险命令"
      blockCode: "POLICY_WIDE_001"
`);
    const engine = new InterventionEngineImpl({
      ruleLoader: { policyPath, reloadIntervalMs: 0 },
      decisionTimeoutMs: 50,
      failStrategy: 'fail_open',
      logger: { warn: () => {}, error: () => {} },
    });
    await engine.initialize();

    // 命中值放在预算内（首个 key）：证明大对象仍然被评估、匹配照常生效；
    // 超出节点预算的尾部被跳过（本用例只断言不抛错 / 不兜底 / 不超时）。
    const wide: Record<string, string> = { 'key-hit': 'rm -rf /' };
    for (let i = 0; i < 50000; i++) wide[`key-${i}`] = `value-${i}`;

    const started = Date.now();
    const decision = await engine.evaluate({
      actionType: 'tool_call',
      toolName: 'file_read',
      params: { wide },
    });

    expect(decision.decision).toBe('block');
    expect(decision.blockCode).toBe('POLICY_WIDE_001');
    expect(decision.failStrategy).toBeUndefined();
    expect(Date.now() - started).toBeLessThan(1000);

    await engine.shutdown();
  });

  it('验收8: 热 reload 修改策略顶层 failStrategy 后新值立即生效 ', async () => {
    const policyPath = writePolicy(`
apiVersion: security.use/v2
kind: Policy
metadata: { id: spl-reload-fail, name: Reload Fail, version: 1.0.0 }
failStrategy: fail_open
rules:
  - id: block-rule
    severity: medium
    priority: 100
    match:
      actionType: ["tool_call"]
    action:
      decision: block
`);
    const engine = new InterventionEngineImpl({
      ruleLoader: { policyPath, reloadIntervalMs: 0 },
      decisionTimeoutMs: 50,
      // config 默认值与策略顶层值不同：断言生效的是策略值，而非 config 值。
      failStrategy: 'fail_open_high_risk_only',
      logger: { warn: () => {}, error: () => {} },
    });
    await engine.initialize();

    // 让评估内部抛错以走兜底路径，兜底决策由 failStrategy 决定。
    const boom = vi.spyOn(RuleMatcher, 'match').mockImplementation(() => {
      throw new Error('boom');
    });
    const ctx: InterventionContext = { actionType: 'tool_call', toolName: 'file_read' };
    try {
      const before = await engine.evaluate(ctx);
      expect(before.decision).toBe('allow');
      expect(before.failStrategy).toBe('fail_open');

      // 热 reload：策略顶层 failStrategy 改为 fail_closed。
      // 旧实现在 initialize 固化该值，reload 后引擎仍按 fail_open 放行。
      writeFileSync(policyPath, `
apiVersion: security.use/v2
kind: Policy
metadata: { id: spl-reload-fail, name: Reload Fail, version: 1.0.1 }
failStrategy: fail_closed
rules:
  - id: block-rule
    severity: medium
    priority: 100
    match:
      actionType: ["tool_call"]
    action:
      decision: block
`);
      await engine.getRuleLoader().load();

      const after = await engine.evaluate(ctx);
      expect(after.decision).toBe('block');
      expect(after.blockCode).toBe('INTERVENTION_ERROR');
      expect(after.failStrategy).toBe('fail_closed');

      // 策略层撤回该键后回退 config 默认值（不能被上一次的策略值黏住）。
      writeFileSync(policyPath, `
apiVersion: security.use/v2
kind: Policy
metadata: { id: spl-reload-fail, name: Reload Fail, version: 1.0.2 }
rules:
  - id: block-rule
    severity: medium
    priority: 100
    match:
      actionType: ["tool_call"]
    action:
      decision: block
`);
      await engine.getRuleLoader().load();

      const reverted = await engine.evaluate(ctx);
      expect(reverted.decision).toBe('allow');
      expect(reverted.failStrategy).toBe('fail_open_high_risk_only');
    } finally {
      boom.mockRestore();
      await engine.shutdown();
    }
  });

  it('验收9: 运行期策略加载失败会补发 audit 事件，同一状态只发一次 ', async () => {
    const policyPath = writePolicy(`
apiVersion: security.use/v2
kind: Policy
metadata: { id: test-policy, name: Test Policy, version: "1.0.0" }
rules:
  - id: block-rule
    severity: medium
    priority: 100
    match:
      actionType: ["tool_call"]
    action:
      decision: block
`);
    const audit = vi.fn();
    const engine = new InterventionEngineImpl({
      ruleLoader: { policyPath, reloadIntervalMs: 0 },
      decisionTimeoutMs: 50,
      failStrategy: 'fail_open',
      logger: { warn: () => {}, error: () => {} },
      audit,
    });
    await engine.initialize();
    const ctx: InterventionContext = { actionType: 'tool_call', toolName: 'file_read' };

    // 正常策略：无策略级 audit 事件。
    await engine.evaluate(ctx);
    expect(audit).not.toHaveBeenCalled();

    // 运行期把策略改坏（YAML 解析失败）→ 载入失败留痕，且不再重复刷。
    writeFileSync(policyPath, 'rules: [ \n  - id: broken\n');
    await engine.getRuleLoader().load();
    await engine.evaluate(ctx);
    await engine.evaluate(ctx);
    const failed = audit.mock.calls.filter((c) => c[0].eventType === 'policy_load_failed');
    expect(failed).toHaveLength(1);
    expect(String(failed[0][0].detail)).toContain('failed to load policy file');

    // 运行期删除策略文件 → policy_missing（与 initialize 分支同一审计口径）。
    rmSync(policyPath);
    await engine.getRuleLoader().load();
    await engine.evaluate(ctx);
    const missing = audit.mock.calls.filter((c) => c[0].eventType === 'policy_missing');
    expect(missing).toHaveLength(1);
    expect(String(missing[0][0].detail)).toContain('not found');

    await engine.shutdown();
  });

  it('验收10: 含灾难性回溯 substitutePatterns 的规则在加载期被隔离并留痕 ', async () => {
    const policyPath = writePolicy(`
apiVersion: security.use/v2
kind: Policy
metadata: { id: spl-substitute-redos, name: Sub Redos, version: 1.0.0 }
rules:
  - id: modify-redos-rule
    severity: medium
    priority: 100
    match:
      actionType: ["tool_call"]
      toolName: ["file_read"]
    action:
      decision: modify
      modify:
        substitutePatterns:
          - pattern: "(a+)+$"
            replacement: "x"
`);
    const warn = vi.fn();
    const audit = vi.fn();
    const engine = new InterventionEngineImpl({
      ruleLoader: { policyPath, reloadIntervalMs: 0 },
      decisionTimeoutMs: 50,
      failStrategy: 'fail_open',
      logger: { warn, error: () => {} },
      audit,
    });
    await engine.initialize();

    // 加载期即拒绝：告警 + 留痕（unsafe），不等到评估时才在现场编译。
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('catastrophically backtracking'));
    expect(audit).toHaveBeenCalledWith(
      expect.objectContaining({ eventType: 'rule_unsafe_regex', ruleId: 'modify-redos-rule' })
    );

    // 该规则是唯一命中项：被隔离 ⇒ 无命中 ⇒ 默认放行。
    // 若未被隔离，它会产出 modify，且 (a+)+$ 在长 a 串上指数回溯卡死评估线程。
    const decision = await engine.evaluate({
      actionType: 'tool_call',
      toolName: 'file_read',
      params: { body: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!' },
    });
    expect(decision.decision).toBe('allow');
    expect(decision.failStrategy).toBeUndefined();

    await engine.shutdown();
  });

  it('验收10b: collectRulePatterns 覆盖 modify.substitutePatterns（与 match 维度同口径）', () => {
    const rule = {
      id: 'sub-redos', severity: 'medium',
      match: {},
      action: {
        decision: 'modify',
        modify: { substitutePatterns: [{ pattern: '(a+)+$', replacement: 'x' }] },
      },
    } as unknown as PolicyRule;

    expect(collectRulePatterns(rule)).toContain('(a+)+$');
    const result = compileRuleRegexes(rule);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe('unsafe');
    expect(result.pattern).toBe('(a+)+$');
  });

  it('验收3: 策略文件缺失 → NDJSON 留痕 policy_missing 事件，且自保护拦截仍生效', async () => {
    const ndjsonPath = join(tmpDir, 'events.ndjson');
    const missingPolicyPath = join(tmpDir, 'missing-policy.yaml');

    const store = new SecurityMonitorStore();
    try {
      await store.initialize({
        collector: { ndjsonPath },
        application: { enabled: true },
        intervention: { policyPath: missingPolicyPath, reloadIntervalMs: 0, mode: 'enforce' },
        system: { enabled: false },
        network: { enabled: false },
        assetMonitor: { enabled: false },
      });

      // 审计事件写入是异步 appendFile，轮询等待留痕落盘。
      let events: SecurityEvent[] = [];
      for (let i = 0; i < 40; i++) {
        if (existsSync(ndjsonPath)) {
          events = readFileSync(ndjsonPath, 'utf8')
            .split('\n')
            .filter(Boolean)
            .map((line) => JSON.parse(line) as SecurityEvent);
          if (events.some((e) => e.event_type === 'policy_missing')) break;
        }
        await new Promise((r) => setTimeout(r, 50));
      }
      const missing = events.find((e) => e.event_type === 'policy_missing');
      expect(missing).toBeDefined();
      expect(String(missing?.detail ?? '')).toContain('not found');

      // 策略缺失（0 规则）时，硬编码自保护仍然阻断卸载行为。
      const result = await store.beforeToolCall({
        toolName: 'exec',
        params: { command: 'npm uninstall sst-security-control-openclaw' },
        sessionKey: 's1',
        runId: 'r1',
        agentId: 'a1',
      } as never);
      expect(result.block).toBe(true);
    } finally {
      await store.shutdown();
    }
  });
});
