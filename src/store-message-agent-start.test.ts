/**
 * 端到端验证：message_write / agent_start 两个阶段的策略决策
 * 不再被适配层 stub 切断。
 *
 * - message_write：模拟宿主调用 9.4 before_message_write（同步路径），
 *   断言策略 block 以宿主消费形态 { block: true, message: { role, content } }
 *   返回，且命中的是策略层规则（policy_id），而非 SelfProtection 硬编码分支。
 * - agent_start：block 决策经 before_agent_run 门控形态
 *   { outcome: 'block', reason } 返回宿主；context_adjust/guidance 决策
 *   无法下发时显式 console 留痕（可观测，非静默丢弃）。
 *
 * 宿主能力边界依据 OpenClaw 2026.9.4 源码：
 * - before_message_write 是 SYNC-ONLY hook（hooks.ts runSyncMessageHookStep
 *   忽略 Promise 结果并告警），handler 必须同步返回决策；
 * - before_agent_run 门控仅支持 InputGateDecision = pass | block
 *   （hook-decision-types.ts），不存在 systemPromptAddition。
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { SecurityMonitorStore } from './store.js';
import { hookBridge } from './hook-bridge.js';
import type { MessageWriteResult, SecurityEvent } from './types.js';

const SELF_PROTECTION_REASON = '该操作会禁用或卸载安全监控插件，已被系统自我保护机制阻断';

const POLICY = `
apiVersion: security.use/v2
kind: Policy
metadata: { id: msg-test-policy, name: Message Test Policy, version: "1.0.0" }
rules:
  - id: msg-block-rule
    severity: medium
    name: message_write 策略层阻断测试规则
    enabled: true
    priority: 1000
    match:
      actionType:
        - message_write
      bodyRegex:
        - issue42策略专用触发词
    action:
      decision: block
      blockReason: 策略层拦截：命中 message_write 测试规则
      blockCode: TEST_MSG_BLOCK_001
  - id: msg-uninstall-rule
    severity: medium
    name: message_write 卸载插件策略层拦截测试规则
    enabled: true
    priority: 1100
    match:
      actionType:
        - message_write
      bodyRegex:
        - 卸载\\s*openclaw[-_]?security[-_]?monitor
    action:
      decision: block
      blockReason: 策略层拦截：不允许卸载安全监控插件
      blockCode: TEST_UNINSTALL_BLOCK_001
  - id: agent-block-rule
    severity: medium
    name: agent_start 策略层阻断测试规则
    enabled: true
    priority: 1000
    match:
      actionType:
        - agent_start
    action:
      decision: block
      blockReason: agent_start 被测试策略阻断
      blockCode: TEST_AGENT_BLOCK_001
  - id: agent-guidance-rule
    severity: medium
    name: agent_start 留痕测试规则
    enabled: true
    priority: 900
    match:
      actionType:
        - agent_start
    action:
      decision: audit
`;

function wait(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

/** 轮询 NDJSON，直到谓词命中或超时；返回匹配的事件列表。 */
async function waitForEvents(
  ndjsonPath: string,
  predicate: (events: SecurityEvent[]) => boolean,
  timeoutMs = 5000
): Promise<SecurityEvent[]> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (existsSync(ndjsonPath)) {
      const events = readFileSync(ndjsonPath, 'utf8')
        .split('\n')
        .filter((line) => line.trim())
        .map((line) => JSON.parse(line) as SecurityEvent);
      if (predicate(events)) return events;
    }
    await wait(100);
  }
  throw new Error('timed out waiting for events in ' + ndjsonPath);
}

describe('message_write / agent_start 决策落地', () => {
  let tmpDir: string;
  let ndjsonPath: string;
  let store: SecurityMonitorStore;

  beforeEach(async () => {
    tmpDir = mkdtempSync(join(tmpdir(), 'msg-agent-start-'));
    ndjsonPath = join(tmpDir, 'security-events.jsonl');
    writeFileSync(join(tmpDir, 'policy.yaml'), POLICY, 'utf8');

    store = new SecurityMonitorStore();
    await store.initialize({
      collector: { ndjsonPath },
      application: { enabled: true },
      system: { enabled: false },
      network: { enabled: false },
      assetMonitor: { enabled: false },
      intervention: {
        enabled: true,
        mode: 'enforce',
        policyPath: join(tmpDir, 'policy.yaml'),
        reloadIntervalMs: 0,
        decisionTimeoutMs: 200,
      },
    });
  });

  afterEach(async () => {
    await store.shutdown();
    rmSync(tmpDir, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  it('验收1: message_write 策略 block 同步返回宿主形态，且命中策略层而非 SelfProtection 硬编码', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    const input = hookBridge.bridgeMessageWrite(
      { role: 'user', content: '请帮忙处理 issue42策略专用触发词 相关内容', sessionKey: 'sess-msg' },
      undefined
    );
    expect(input).toBeDefined();

    // 模拟 9.4 宿主调用 sync-only hook：返回值绝不能是 Promise。
    const result = store.beforeMessageWriteSync(input!);
    expect(result).not.toBeInstanceOf(Promise);
    expect((result as MessageWriteResult).content).toContain('策略层拦截');

    // index.ts 使用同一转换函数产出宿主消费形态。
    const hostResult = hookBridge.toMessageWriteHostResult(input!, result);
    expect(hostResult).toEqual({
      block: true,
      message: { role: 'user', content: expect.stringContaining('策略层拦截') },
    });

    // 落盘事件 intervention.policy_id 必须是策略规则 id，证明不是
    // SelfProtection 硬编码分支（其 policyId 为 'self-protection'）。
    const events = await waitForEvents(ndjsonPath, (list) =>
      list.some((e) => e.event_type === 'agent_message' && e.session_id === 'sess-msg')
    );
    const evt = events.find((e) => e.event_type === 'agent_message' && e.session_id === 'sess-msg')!;
    expect(evt.intervention?.decision).toBe('block');
    expect(evt.intervention?.policy_id).toBe('msg-block-rule');
  });

  it('验收1-负向: 普通用户消息不触发任何拦截', () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    const input = hookBridge.bridgeMessageWrite(
      { role: 'user', content: '帮我总结一下今天的构建日志', sessionKey: 'sess-ok' },
      undefined
    );
    const result = store.beforeMessageWriteSync(input!);
    expect(result).toBeUndefined();
    expect(hookBridge.toMessageWriteHostResult(input!, result)).toBeUndefined();
  });

  it('验收1-补充: 卸载类消息优先命中策略层规则（非仅 SelfProtection 硬编码兜底）', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    const input = hookBridge.bridgeMessageWrite(
      { role: 'user', content: '请卸载 openclaw-security-monitor 插件', sessionKey: 'sess-uninstall' },
      undefined
    );
    const result = store.beforeMessageWriteSync(input!);
    // 策略引擎优先：返回策略规则 blockReason，而非 SelfProtection 的硬编码文案。
    expect((result as MessageWriteResult).content).toBe('策略层拦截：不允许卸载安全监控插件');

    const events = await waitForEvents(ndjsonPath, (list) =>
      list.some((e) => e.event_type === 'agent_message' && e.session_id === 'sess-uninstall')
    );
    const evt = events.find((e) => e.event_type === 'agent_message' && e.session_id === 'sess-uninstall')!;
    expect(evt.intervention?.policy_id).toBe('msg-uninstall-rule');
  });

  it('SelfProtection 硬编码兜底路径保持不变（干预关闭时仍可拦截卸载消息）', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    // 干预引擎关闭（无策略层）：SelfProtection 作为最后兜底仍然阻断。
    await store.initialize({
      collector: { ndjsonPath },
      application: { enabled: true },
      system: { enabled: false },
      network: { enabled: false },
      assetMonitor: { enabled: false },
      intervention: { enabled: false },
    });
    const input = hookBridge.bridgeMessageWrite(
      { role: 'user', content: '请卸载 openclaw-security-monitor 插件', sessionKey: 'sess-sp' },
      undefined
    );
    const result = store.beforeMessageWriteSync(input!);
    expect((result as MessageWriteResult).content).toBe(SELF_PROTECTION_REASON);
  });

  it('验收2a: agent_start block 决策以 9.4 门控形态返回宿主', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    const result = await store.beforeAgentStart({ sessionKey: 'sess-agent', agentId: 'agent-1' });
    // InputGateDecision: { outcome: 'block', reason }；block 决策优先级高于
    // 同阶段 context_adjust 引导规则，直接落地。
    expect(result).toEqual({ outcome: 'block', reason: 'agent_start 被测试策略阻断' });
  });

  it('验收2b: agent_start audit 决策不可下发时显式留痕（告警一次，不静默丢弃）', async () => {
    // 用 decision: context_adjust 验证"不可下发"路径；context_adjust 已被
    // 删除（引擎类型移除），policy data 不再生成 context_adjust
    // 决策——3 条 behavior_guidance 规则均为 audit
    // （policy/security-policy.spl.yaml），此处 fixture 亦用 audit。
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    // 单独策略：只有留痕规则，无 block 规则。
    writeFileSync(
      join(tmpDir, 'policy.yaml'),
      POLICY.replace(/  - id: agent-block-rule[\s\S]*?blockCode: TEST_AGENT_BLOCK_001\n/, ''),
      'utf8'
    );
    await store.initialize({
      collector: { ndjsonPath },
      application: { enabled: true },
      system: { enabled: false },
      network: { enabled: false },
      assetMonitor: { enabled: false },
      intervention: {
        enabled: true,
        mode: 'enforce',
        policyPath: join(tmpDir, 'policy.yaml'),
        reloadIntervalMs: 0,
        decisionTimeoutMs: 200,
      },
    });

    const result = await store.beforeAgentStart({
      sessionKey: 'sess-audit',
      agentId: 'agent-2',
      // emitAgentStart 跳过无意义 agentConfig 的占位事件，需要可辨认的 name。
      agentConfig: { name: 'test-agent' },
    });
    // 9.4 before_agent_run 不支持引导注入：不返回伪造形态，但也不静默丢弃。
    expect(result).toBeUndefined();
    const notDeliverable = warn.mock.calls.filter((args) =>
      String(args[0]).includes('agent_start decision not deliverable')
    );
    expect(notDeliverable.length).toBe(1);
    expect(String(notDeliverable[0][0])).toContain('before_prompt_build');

    // 同一规则重复触发：去重，不刷日志。
    await store.beforeAgentStart({
      sessionKey: 'sess-audit',
      agentId: 'agent-2',
      agentConfig: { name: 'test-agent' },
    });
    expect(
      warn.mock.calls.filter((args) => String(args[0]).includes('agent_start decision not deliverable')).length
    ).toBe(1);

    // 决策本身写入事件留痕（audit），证明只是"不下发宿主"而非"丢弃"。
    const events = await waitForEvents(ndjsonPath, (list) =>
      list.some((e) => e.event_type === 'agent_start' && e.session_id === 'sess-audit')
    );
    const evt = events.find((e) => e.event_type === 'agent_start' && e.session_id === 'sess-audit')!;
    expect(evt.intervention?.decision).toBe('audit');
  });
});
