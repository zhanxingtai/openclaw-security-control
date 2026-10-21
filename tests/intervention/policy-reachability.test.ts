/**
 * 策略规则运行时可达性静态校验。testCase input 直接注入 riskFlags /
 * previousActions 时，若与运行时实际回灌字段脱节，会出现"测试全绿但
 * 运行时永不命中"的假象（历史上曾有 13 条死规则由此而来）。这里在测试
 * 侧做静态可达性校验（不依赖 CI 环境）：
 *
 *   1. 规则 actionType 必须有运行时评估入口（store.ts 共 6 处）。
 *   2. riskFlagsAny/All 引用的标签必须有 runtime hook computeRiskFlags
 *      注入源，且规则至少挂在回灌 riskFlags 的入口上。
 *   3. chain 链节 actionType 必须被记入 ActionHistory（方向可达），且
 *      规则自身入口必须回灌 previousActions。
 *   4. testCase input 字段必须与 InterventionContext 一致；注解 riskFlags
 *      的用例其 actionType 必须是回灌 riskFlags 的入口。
 *
 * 注册表与生产代码的对应关系由 drift-guard 用例静态锁定（标签从
 * hooks/runtime.js flags.push 抽取；评估入口从 src/store.ts actionType
 * 接线比对）。新增标签/入口时改一处，另一侧不一致即失败。
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { load as loadYaml } from 'js-yaml';
import { parseSPLPolicy } from '../../src/intervention/SPLRuleLoader.js';
import { expandActionType } from '../../src/intervention/splActionType.js';
import type { PolicyRule, PolicyRuleTestCase } from '../../src/intervention/types.js';

const POLICY_PATH = resolve('policies/security-policy.spl.yaml');
const rules: PolicyRule[] = parseSPLPolicy(loadYaml(readFileSync(POLICY_PATH, 'utf8'))).rules;

// 生产代码源码（drift-guard 静态比对用；不执行 runtime.js，避免其
// require 即 install() 的副作用）。
const RUNTIME_HOOK_SOURCE = readFileSync(resolve('hooks/runtime.js'), 'utf8');
const STORE_SOURCE = readFileSync(resolve('src/store.ts'), 'utf8');

/**
 * 运行时风险标签注册表：与 hooks/runtime.js computeRiskFlags() 的产出严格
 * 一一对应—— 起纯正则 flag 改由构建产物 hooks/generated-patterns.json
 * 承载（动态 push），代码内只剩代码驱动 flag 的字面 push；下方 drift-guard
 * 用例因此改为「字面 push ∪ 生成产物 flag 键」比对本注册表。runtime-hook-collector 把 hook
 * 事件里的 risk_flags 原样回灌 process_start / network_http 评估上下文
 * （store.ts evaluateRuntimeEvent），因此这就是 riskFlagsAny/All 的全部
 * 合法取值来源。drift-guard 用例比对 runtime.js 源码，防止两侧漂移。
 */
const RUNTIME_RISK_FLAGS: readonly string[] = [
  'background_execution',
  'chmod_executable',
  'credential_exposure',
  'data_exfiltration',
  'db_dump',
  'download_execute',
  'file_deletion',
  'mass_deletion',
  'network_tool',
  'pipe_to_shell',
  'privilege_escalation',
  'reverse_shell',
  // ：hook 传播被显式跳过（explicit_skip）或 env 剥离后重注入
  // （env_stripped）时打标，注册表同步收录。
  'self_protection_bypass',
  'sensitive_file_access',
  'shell_involved',
  'skill_binary_execution',
  'suspicious_encoding',
  'token_in_command',
];

/**
 * store.ts 运行时评估入口登记（共 6 处，key 为 SPL 规范值）：
 * - agent_tool_call：beforeToolCall → buildInterventionContext（store.ts）
 * - agent_message：beforeMessageWrite → buildMessageInterventionContext
 * - agent_start：beforeAgentRun → OpenClawAdapter.toInterventionContext
 * - process_start / network_http：evaluateRuntimeEvent（runtime hook 事件回灌）
 * - agent_tool_result：afterToolCall → buildToolResultInterventionContext
 *   （事后评估，决策只写事件标注）
 *
 * injectsRiskFlags：该入口是否回灌 riskFlags。仅 runtime hook 事件路径携带
 * risk_flags（network.js 不产出标签，normalizeNetworkEvent 也不映射，故
 * network_http 恒为 undefined）；agent_* 入口的上下文构建回填
 * sessionRiskFlags 沉淀（recentRiskFlags），不属于 runtime 标签直灌。
 *
 * historyTool：该入口写入 ActionHistory 时 ActionRecord.tool 使用的名字
 * （chain 链节按此校验方向可达性）；agent_start / agent_message /
 * agent_tool_result 不记历史。
 */
const RUNTIME_ENTRIES: Record<string, { injectsRiskFlags: boolean; historyTool?: string }> = {
  agent_tool_call: { injectsRiskFlags: false, historyTool: 'agent_tool_call' },
  agent_message: { injectsRiskFlags: false },
  agent_start: { injectsRiskFlags: false },
  process_start: { injectsRiskFlags: true, historyTool: 'process_start' },
  network_http: { injectsRiskFlags: false, historyTool: 'network_http' },
  agent_tool_result: { injectsRiskFlags: false },
};

/** InterventionContext 实例字段全集（testCase input 注解的合法字段）。 */
const INTERVENTION_CONTEXT_FIELDS = new Set([
  'actionType',
  'toolName',
  'params',
  'body',
  'headers',
  'riskFlags',
  'previousActions',
  'sessionId',
  'runId',
  'agentId',
  'userPrompt',
  'agentPlan',
  'userAuthzState',
  'userRoles',
]);

/** 把规则/testCase 的 actionType 展开为规范值；未知值原样返回以便报错。 */
function canonicalActionTypes(value: string): string[] {
  if (value === '*') return Object.keys(RUNTIME_ENTRIES);
  const expanded = expandActionType(value);
  return expanded.length > 0 ? expanded : [value];
}

/** 校验单条规则（不含 testCase）的运行时可达性，返回可读问题列表。 */
export function ruleReachabilityProblems(rule: PolicyRule): string[] {
  const problems: string[] = [];
  const match = rule.match || {};
  const label = `rule ${rule.id}`;

  // 1. actionType 评估入口
  const actionTypes = match.actionType || [];
  if (actionTypes.length === 0) {
    problems.push(`${label}: match.actionType 为空，无任何评估入口可达`);
  }
  const reachableEntries = new Set<string>();
  for (const at of actionTypes) {
    for (const canonical of canonicalActionTypes(String(at))) {
      if (!RUNTIME_ENTRIES[canonical]) {
        problems.push(
          `${label}: actionType "${at}"（规范值 ${canonical}）没有运行时评估入口（store.ts 未接入）`
        );
      } else {
        reachableEntries.add(canonical);
      }
    }
  }

  // 2. riskFlags 注入来源
  // 生产端全集 = runtime.js computeRiskFlags（RUNTIME_RISK_FLAGS）∪ process
  // monitor 产物（monitor/generated-patterns.json 的 flag）∪ store.ts 启动期
  // 自保护事件（unpatched_engine）。其消费
  // 规则依赖后两类来源。
  const monitorGenerated = JSON.parse(
    readFileSync(resolve('monitor/generated-patterns.json'), 'utf8')
  ) as { patterns: Array<{ flag: string }> };
  const producedFlags = new Set([
    ...RUNTIME_RISK_FLAGS,
    ...monitorGenerated.patterns.map((p) => p.flag),
    'unpatched_engine',
  ]);
  const flags = [...(match.riskFlagsAny || []), ...(match.riskFlagsAll || [])];
  if (flags.length > 0) {
    for (const flag of flags) {
      if (!producedFlags.has(flag)) {
        problems.push(
          `${label}: 风险标签 "${flag}" 无运行时注入来源（runtime hook / process monitor / 启动期事件均不产出该标签）`
        );
      }
    }
    const hasFlagEntry = [...reachableEntries].some((c) => RUNTIME_ENTRIES[c].injectsRiskFlags);
    if (!hasFlagEntry) {
      problems.push(
        `${label}: riskFlagsAny/All 引用的标签无任何注入入口——` +
          `规则 actionType [${actionTypes.join(', ')}] 的评估入口均不回灌 riskFlags，运行时永不命中`
      );
    }
  }

  // 3. chain 方向可达性
  if (match.chain) {
    const prior = match.chain.prior || [];
    if (prior.length === 0) {
      problems.push(`${label}: chain 无链节，previousActions 条件永不满足`);
    }
    const hasHistoryEntry = [...reachableEntries].some((c) => RUNTIME_ENTRIES[c].historyTool);
    if (!hasHistoryEntry) {
      problems.push(
        `${label}: chain 依赖 previousActions，但规则自身 actionType [${actionTypes.join(', ')}] ` +
          `的评估入口均不回灌历史（agent_start / agent_message 不写 ActionHistory）`
      );
    }
    const recordedTools = new Set(
      Object.values(RUNTIME_ENTRIES)
        .map((e) => e.historyTool)
        .filter((t): t is string => typeof t === 'string')
    );
    for (const [index, link] of prior.entries()) {
      const linkAction = link.action || link.actionName;
      if (!linkAction) {
        problems.push(`${label}: chain 链节 #${index} 缺少 actionType，无法确认关联方向`);
        continue;
      }
      const candidates = canonicalActionTypes(linkAction);
      if (!candidates.some((c) => recordedTools.has(c))) {
        problems.push(
          `${label}: chain 链节 #${index} actionType "${linkAction}" 不会被记入 ActionHistory ` +
            `（store.ts 仅记录 agent_tool_call 与 runtime 事件），方向不可达，链式条件永不满足`
        );
      }
    }
  }

  return problems;
}

/** 校验单条 testCase input 注解与运行时上下文的一致性，返回可读问题列表。 */
export function testCaseReachabilityProblems(rule: PolicyRule, tc: PolicyRuleTestCase, index: number): string[] {
  const problems: string[] = [];
  const input = tc.input || {};
  const label = `rule ${rule.id} testCase #${index} (${tc.name})`;

  // 4a. 注解字段必须是 InterventionContext 实例字段
  for (const key of Object.keys(input)) {
    if (!INTERVENTION_CONTEXT_FIELDS.has(key)) {
      problems.push(`${label}: input 字段 "${key}" 不是 InterventionContext 字段（运行时不会被赋值）`);
    }
  }

  // 4b. input actionType（缺省 tool_call，与 policy-testcases.test.ts buildContext 一致）
  const at = String(input.actionType ?? 'tool_call');
  const canonical = canonicalActionTypes(at);
  for (const c of canonical) {
    if (!RUNTIME_ENTRIES[c]) {
      problems.push(`${label}: actionType "${at}"（规范值 ${c}）没有运行时评估入口`);
    }
  }

  // 4c. 注解 riskFlags 的用例，其 actionType 必须是回灌 riskFlags 的入口，
  //     否则该用例构造的是运行时不存在的上下文（这正是本校验要消除的假象）。
  //     可接受的 flag 集合 = runtime.js 字面 push ∪ monitor 构建产物 flag ∪
  //     store.ts 启动期自保护事件，与 rule-level 校验的 producedFlags
  //     口径一致——  覆盖率补齐后，warn-runtime-hook-inactive 用例需
  //     注解 unpatched_engine 才能命中规则。
  const annotatedFlags = Array.isArray(input.riskFlags) ? input.riskFlags.map(String) : [];
  if (annotatedFlags.length > 0) {
    const monitorGenerated = JSON.parse(
      readFileSync(resolve('monitor/generated-patterns.json'), 'utf8')
    ) as { patterns: Array<{ flag: string }> };
    const acceptedFlags = new Set([
      ...RUNTIME_RISK_FLAGS,
      ...monitorGenerated.patterns.map((p) => p.flag),
      'unpatched_engine',
    ]);
    for (const flag of annotatedFlags) {
      if (!acceptedFlags.has(flag)) {
        problems.push(`${label}: 注解风险标签 "${flag}" 无运行时注入来源`);
      }
    }
    if (!canonical.some((c) => RUNTIME_ENTRIES[c]?.injectsRiskFlags)) {
      problems.push(
        `${label}: actionType "${at}" 的运行时入口不回灌 riskFlags，该用例注入的 riskFlags ` +
          `在运行时永不出现，属于"测试全绿但运行时永不命中"场景`
      );
    }
  }

  // 4d. chain 规则的用例必须注解 previousActions，否则链式路径未被覆盖
  if (rule.match?.chain && !Array.isArray(input.previousActions)) {
    problems.push(`${label}: chain 规则用例未注解 previousActions，未覆盖链式可达路径`);
  }

  return problems;
}

describe('runtime reachability registry drift guards', () => {
  it('risk flag registry matches hooks/runtime.js computeRiskFlags production', () => {
    const literalPushes = [...RUNTIME_HOOK_SOURCE.matchAll(/flags\.push\('([^']+)'\)/g)].map(
      (m) => m[1]
    );
    const generated = JSON.parse(readFileSync(resolve('hooks/generated-patterns.json'), 'utf8')) as {
      flags: Record<string, unknown>;
    };
    const produced = new Set([...literalPushes, ...Object.keys(generated.flags)]);
    expect(new Set(RUNTIME_RISK_FLAGS)).toEqual(produced);
  });

  it('evaluation entry registry matches store.ts wiring', () => {
    for (const key of Object.keys(RUNTIME_ENTRIES)) {
      expect(STORE_SOURCE, `store.ts 缺少 ${key} 评估入口接线`).toContain(`actionType: '${key}'`);
    }
    // riskFlags 回灌只发生在 runtime hook 事件路径（evaluateRuntimeEvent）。
    for (const [key, entry] of Object.entries(RUNTIME_ENTRIES)) {
      if (entry.injectsRiskFlags) {
        expect(STORE_SOURCE, `${key} 声称回灌 riskFlags，store.ts 无对应接线`).toContain(
          'riskFlags: event.risk_flags'
        );
      }
    }
    // ActionHistory 记录：tool_call 以规范名记录，runtime 事件以 ctx.actionType 记录。
    expect(STORE_SOURCE).toContain("tool: 'agent_tool_call'");
    expect(STORE_SOURCE).toContain('tool: ctx.actionType');
  });
});

describe('security-policy.spl.yaml runtime reachability', () => {
  const enabledRules = rules.filter((r) => r.enabled !== false);

  it('every enabled rule is reachable at runtime', () => {
    const problems = enabledRules.flatMap((rule) => ruleReachabilityProblems(rule));
    expect(problems).toEqual([]);
  });

  it('every enabled rule testCase annotates runtime-consistent input', () => {
    const problems = enabledRules.flatMap((rule) =>
      (rule.testCases || []).flatMap((tc, index) => testCaseReachabilityProblems(rule, tc, index))
    );
    expect(problems).toEqual([]);
  });
});

describe('reachability validator negative cases', () => {
  // 构造临时策略对象做负向用例，不污染 shipped 策略文件。
  function makeRule(overrides: Partial<PolicyRule> & { match: PolicyRule['match'] }): PolicyRule {
    return { id: 'TEST-RULE', enabled: true, action: { decision: 'warn' }, ...overrides };
  }
  function makeTestCase(input: Record<string, unknown>): PolicyRuleTestCase {
    return { name: 'negative-fixture', input };
  }

  it('flags a riskFlagsAny tag with no runtime injection source', () => {
    const rule = makeRule({
      match: { actionType: ['process_start'], riskFlagsAny: ['no_such_runtime_flag'] },
    });
    expect(ruleReachabilityProblems(rule).join('\n')).toMatch(/no_such_runtime_flag.*无运行时注入来源/);
  });

  it('flags an actionType with no evaluation entry in store.ts', () => {
    const rule = makeRule({ match: { actionType: ['file_delete'] } });
    expect(ruleReachabilityProblems(rule).join('\n')).toMatch(/file_delete.*没有运行时评估入口/);
  });

  it('flags a riskFlags rule whose actionTypes never inject riskFlags', () => {
    const rule = makeRule({
      match: { actionType: ['tool_call'], riskFlagsAny: ['reverse_shell'] },
    });
    expect(ruleReachabilityProblems(rule).join('\n')).toMatch(/均不回灌 riskFlags/);
  });

  it('flags a chain link that is never recorded into ActionHistory', () => {
    const rule = makeRule({
      match: {
        actionType: ['process_start'],
        chain: { prior: [{ action: 'agent_start' }] },
      },
    });
    expect(ruleReachabilityProblems(rule).join('\n')).toMatch(/agent_start.*不会被记入 ActionHistory/);
  });

  it('flags a chain rule whose own entry does not backfill previousActions', () => {
    const rule = makeRule({
      match: { actionType: ['agent_start'], chain: { prior: [{ action: 'process_start' }] } },
    });
    const problems = ruleReachabilityProblems(rule).join('\n');
    expect(problems).toMatch(/均不回灌历史/);
  });

  it('flags a testCase annotating riskFlags on an entry that never injects them', () => {
    const rule = makeRule({ match: { actionType: ['tool_call', 'process_start'] } });
    const problems = testCaseReachabilityProblems(
      rule,
      makeTestCase({ actionType: 'tool_call', riskFlags: ['reverse_shell'] }),
      0
    ).join('\n');
    expect(problems).toMatch(/不回灌 riskFlags.*运行时永不出现/);
  });

  it('flags a testCase input field that is not an InterventionContext field', () => {
    const rule = makeRule({ match: { actionType: ['tool_call'] } });
    const problems = testCaseReachabilityProblems(
      rule,
      makeTestCase({ actionType: 'tool_call', madeUpField: 'x' }),
      0
    ).join('\n');
    expect(problems).toMatch(/madeUpField.*不是 InterventionContext 字段/);
  });

  it('flags a chain rule testCase missing previousActions', () => {
    const rule = makeRule({
      match: { actionType: ['process_start'], chain: { prior: [{ action: 'process_start' }] } },
    });
    const problems = testCaseReachabilityProblems(
      rule,
      makeTestCase({ actionType: 'process_start' }),
      0
    ).join('\n');
    expect(problems).toMatch(/未注解 previousActions/);
  });
});
