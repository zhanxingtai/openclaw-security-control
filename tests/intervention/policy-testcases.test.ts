/**
 * 声明式 testCase 运行器。shipped 策略每条规则的 testCase
 * 在这里统一执行：input 构造 InterventionContext，经 evaluateSync 全量扫描
 * + DecisionComposer 合成后，断言最终 decision 与 expectedDecision 一致。
 *
 * 与 policy-reachability.test.ts 约定一致：input.actionType 缺省视为
 * tool_call；每个用例注入独立 sessionId 避免 Guidance 预算串扰。enabled:
 * false 的规则其 testCase 由统计用例统一跳过。
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, resolve } from 'path';
import { load as loadYaml } from 'js-yaml';
import { parseSPLPolicy } from '../../src/intervention/SPLRuleLoader.js';
import { InterventionEngineImpl } from '../../src/intervention/InterventionEngine.js';
import type { InterventionContext, PolicyRule } from '../../src/intervention/types.js';

const POLICY_PATH = resolve('policies/security-policy.spl.yaml');
const policy = parseSPLPolicy(loadYaml(readFileSync(POLICY_PATH, 'utf8')));
const rules = policy.rules;

/** input → InterventionContext（字段白名单由 reachability 测试锁定）。 */
function buildContext(rule: PolicyRule, index: number, input: Record<string, unknown>): InterventionContext {
  const ctx = { ...input } as Record<string, unknown>;
  if (ctx.actionType === undefined) ctx.actionType = 'tool_call';
  if (ctx.sessionId === undefined) ctx.sessionId = `tc:${rule.id}#${index}`;
  return ctx as unknown as InterventionContext;
}

interface CaseRef {
  rule: PolicyRule;
  index: number;
  expected: string;
}

const executable: CaseRef[] = [];
const skipped: Array<{ ruleId: string; reason: string; count: number }> = [];

for (const rule of rules) {
  const cases = rule.testCases || [];
  if (cases.length === 0) continue;
  if (rule.enabled === false) {
    skipped.push({ ruleId: rule.id, reason: 'enabled: false，运行时恒不匹配', count: cases.length });
    continue;
  }
  cases.forEach((tc, index) => {
    executable.push({
      rule,
      index,
      expected: tc.expectedDecision ?? '(未声明)',
    });
  });
}

describe('policy-testcases runner', () => {
  let engine: InterventionEngineImpl;
  let policyDir: string;

  beforeAll(async () => {
    // RuleLoader 沙箱仅允许 ~/.openclaw 与 os.tmpdir()：把 shipped 策略复制到
    // 临时目录后加载，保证评估的就是文件本身。
    policyDir = mkdtempSync(join(tmpdir(), 'policy-testcases-'));
    writeFileSync(join(policyDir, 'policy.yaml'), readFileSync(POLICY_PATH, 'utf8'));
    engine = new InterventionEngineImpl({
      mode: 'audit',
      ruleLoader: { policyPath: join(policyDir, 'policy.yaml'), reloadIntervalMs: 0 },
      guidance: { enabled: true },
    });
    await engine.initialize();
  }, 30_000);

  afterAll(async () => {
    await engine?.shutdown();
    rmSync(policyDir, { recursive: true, force: true });
  });

  it('engine loaded the shipped policy', () => {
    expect(engine.getStats().rulesLoaded).toBe(rules.length);
  });

  for (const ref of executable) {
    const tc = ref.rule.testCases![ref.index];
    it(`${ref.rule.id} #${ref.index} ${tc.name} → ${ref.expected}`, () => {
      const decision = engine.evaluateSync(buildContext(ref.rule, ref.index, tc.input));
      expect(decision.decision).toBe(tc.expectedDecision);
    });
  }

  it('testCase 执行统计与跳过清单', () => {
    const summary = {
      rules: rules.length,
      executableCases: executable.length,
      skippedRules: skipped,
    };
    // 基线锚点：shipped 策略当前规模（规则/可执行用例数）变化时此处更新，
    // 防止静默丢失整组用例；跳过清单（disabled 规则的用例）在下方断言为空
    // 以外的部分由 console.log 输出供审计。
    expect(summary.rules).toBe(91); // 70 + 7（通用攻击面规则组：paste/gist 外传、远端传输、多语言反弹、capabilities、进程终止、procfs）+ 13（自保护规则组：cron 写入、防火墙清空、SELinux 降级、ptrace、审计文件篡改、插件路径、磁盘覆写）+ 1（self-protection-block-gateway-config-write：收窄 gateway config 写轴误拦时新增）
    expect(summary.executableCases).toBe(485); // 350 + 27（match 取强补充用例：imds/ssrf/rm-root/db-dump/db-live/proc-mem）+ 100（自保护规则组 + cron/firewall/SELinux/ptrace/审计/插件路径/磁盘覆写 等新增用例）+ 8（gateway config 写轴收窄：self-protection-block-gateway-action 净增 2 条 + 新规则 6 条）
    console.log(JSON.stringify(summary, null, 2));
  });

  it('block/warn 规则 testCases 覆盖校验（≥1 正例 + ≥1 负例）', () => {
    // SPL v2 spec 要求：每条 block / warn 规则必须有 ≥1 正例
    // （expectedDecision 与规则 decision 一致）+ ≥1 负例（expectedDecision 为
    // allow，证明规则不误伤）；审计类规则（audit/modify/escalate）不强制但允许。
    // 这条校验随 policy-testcases 一起进 build:ci 跑 vitest run，规则漏用例会
    // 阻断构建（不绕过 等于指定命令），用于防止静默丢失整组用例。
    const missing: Array<{ id: string; reason: string }> = [];
    for (const rule of rules) {
      if (rule.enabled === false) continue; // 示例/占位规则豁免
      const decision = rule.action.decision;
      if (decision !== 'block' && decision !== 'warn') continue; // 只盯强阻断与告警
      const cases = rule.testCases || [];
      if (cases.length === 0) {
        missing.push({ id: rule.id, reason: '无任何 testCase' });
        continue;
      }
      const positives = cases.filter((tc) => tc.expectedDecision === decision);
      const negatives = cases.filter((tc) => tc.expectedDecision === 'allow');
      if (positives.length === 0) missing.push({ id: rule.id, reason: '缺正例（expectedDecision 与规则 decision 一致）' });
      if (negatives.length === 0) missing.push({ id: rule.id, reason: '缺负例（expectedDecision=allow，证明规则不误伤）' });
    }
    expect(missing, `以下 block/warn 规则 testCases 覆盖不达标：\n${missing.map((m) => `  ${m.id}: ${m.reason}`).join('\n')}`).toEqual([]);
  });

  it('spl-policy-v2.schema.json 枚举覆盖 shipped 策略实际取值（draft 2020-12）', () => {
    const schema = JSON.parse(readFileSync(resolve('policies/spl-policy-v2.schema.json'), 'utf8')) as {
      properties: { rules: { items: { $ref?: string } } };
      $defs: Record<string, { enum?: unknown[]; properties?: Record<string, { enum?: unknown[] }> }>;
    };
    expect(schema.$schema).toBe('https://json-schema.org/draft/2020-12/schema');

    const actionTypeEnum = new Set(schema.$defs.actionTypeValue.enum as string[]);
    const decisionEnum = new Set(schema.$defs.decision.enum as string[]);
    // severity 枚举从 $defs.rule.properties.severity.enum 取（items 通过
    // $ref 指向 rule definition）。
    const severityEnum = new Set(
      (schema.$defs.rule.properties?.severity?.enum ?? []) as string[]
    );

    const usedActionTypes = new Set<string>();
    const usedDecisions = new Set<string>();
    const usedSeverities = new Set<string>();
    const collectDecision = (d: unknown) => {
      if (typeof d === 'string') usedDecisions.add(d);
    };

    for (const rule of rules) {
      for (const at of rule.match.actionType || []) usedActionTypes.add(at);
      collectDecision(rule.action.decision);
      for (const item of rule.action.decisionChain || []) collectDecision(item.decision);
      for (const item of rule.action.conditionalDecisions || []) collectDecision(item.decision);
      if (rule.severity) usedSeverities.add(rule.severity);
      for (const tc of rule.testCases || []) {
        collectDecision(tc.expectedDecision);
        if (typeof tc.input?.actionType === 'string') usedActionTypes.add(tc.input.actionType);
      }
      for (const link of rule.match.chain?.prior || []) {
        if (link.action) usedActionTypes.add(link.action);
      }
    }

    // schema 必须允许 shipped 策略用到的每一个值（防止"schema 与策略漂移"）。
    for (const at of usedActionTypes) expect(actionTypeEnum.has(at), `actionType ${at} 不在 schema 枚举`).toBe(true);
    for (const d of usedDecisions) expect(decisionEnum.has(d), `decision ${d} 不在 schema 枚举`).toBe(true);
    for (const r of usedSeverities) expect(severityEnum.has(r), `severity ${r} 不在 schema 枚举`).toBe(true);
  });
});
