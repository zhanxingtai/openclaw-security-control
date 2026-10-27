/**
 * 消息角色解析的回归护栏。
 *
 * 缺陷 A（实测 6/6 条 agent_message 的 role 都是 'unknown'）有三个后果，
 * 这里逐条钉住：
 *
 *   1. 角色恒为 unknown → 消息级策略与自保护兜底整条不生效
 *      （两处都 gate 在 `ctx.role === 'user'`）；
 *   2. 采集器本来有一条"丢弃空 assistant 占位消息"的规则，因为角色不是
 *      'assistant' 而整条失效 → 5 条 content="" 的噪声行落盘；
 *   3. 会话生命周期事件（agent_session_start）从来没落过盘。
 *
 * 修法是三层：
 *   - ctxExtract：显式定位角色（多个宿主形态 + 同义词 + 载荷形态推断）；
 *   - 采集器：角色仍未知时按会话生命周期推断（运行中=assistant，否则=user）；
 *   - 采集器：空消息按"有没有信息"丢弃，与角色无关。
 *
 * 角色来源（role_source）随事件落盘，下游能分辨"宿主明说的"和"我们推的"。
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

import { ApplicationCollector } from '../src/application-collector.js';
import { SecurityMonitorStore } from '../src/store.js';
import { hookBridge } from '../src/hook-bridge.js';
import {
  normalizeMessageWriteContext,
  normalizeRoleValue,
  resolveMessageRole,
} from '../src/ctxExtract.js';
import type { MessageWriteContext, SecurityEvent } from '../src/types.js';

function wait(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

async function rmTreeBestEffort(dir: string, attempts = 10, delayMs = 200) {
  for (let i = 0; i < attempts; i++) {
    try {
      rmSync(dir, { recursive: true, force: true });
      return;
    } catch {
      await wait(delayMs);
    }
  }
}

// ---------------------------------------------------------------------------
// 第一层：显式定位角色
// ---------------------------------------------------------------------------

describe('角色解析 · 宿主形态', () => {
  it('同义词收敛成规范角色', () => {
    expect(normalizeRoleValue('human')).toBe('user');
    expect(normalizeRoleValue('USER')).toBe('user');
    expect(normalizeRoleValue('ai')).toBe('assistant');
    expect(normalizeRoleValue('model')).toBe('assistant');
    expect(normalizeRoleValue('bot')).toBe('assistant');
    expect(normalizeRoleValue('tool_result')).toBe('tool');
    // 'unknown' 是"没拿到"，不是一种角色
    expect(normalizeRoleValue('unknown')).toBeUndefined();
    expect(normalizeRoleValue('')).toBeUndefined();
    expect(normalizeRoleValue(undefined)).toBeUndefined();
  });

  it('role 出现在四个不同位置都能认出来', () => {
    expect(resolveMessageRole({ role: 'user' })).toEqual({ role: 'user', source: 'explicit' });
    expect(resolveMessageRole({ context: { role: 'assistant' } })).toEqual({
      role: 'assistant',
      source: 'explicit',
    });
    expect(resolveMessageRole({ message: { role: 'ai' } })).toEqual({
      role: 'assistant',
      source: 'explicit',
    });
    expect(resolveMessageRole({ metadata: { role: 'human' } })).toEqual({
      role: 'user',
      source: 'explicit',
    });
  });

  it('作者类字段也算显式角色', () => {
    expect(resolveMessageRole({ author: 'user' }).role).toBe('user');
    expect(resolveMessageRole({ sender: 'assistant' }).role).toBe('assistant');
    expect(resolveMessageRole({ speaker: 'human' }).role).toBe('user');
  });

  it('会话数组里最后一条带 role 的消息决定角色', () => {
    const ctx = {
      messages: [
        { role: 'user', content: 'a' },
        { role: 'assistant', content: 'b' },
      ],
    };
    expect(resolveMessageRole(ctx)).toEqual({ role: 'assistant', source: 'explicit' });
  });

  it('载荷形态可推断角色：带 prompt 是用户输入，带 response 是模型输出', () => {
    expect(resolveMessageRole({ prompt: '帮我看下日志' })).toEqual({
      role: 'user',
      source: 'inferred',
    });
    expect(resolveMessageRole({ response: '好的' })).toEqual({
      role: 'assistant',
      source: 'inferred',
    });
  });

  it('什么都没有时回落到默认角色，并标成 default', () => {
    expect(resolveMessageRole({})).toEqual({ role: 'unknown', source: 'default' });
    expect(resolveMessageRole({}, 'user')).toEqual({ role: 'user', source: 'default' });
  });

  it('角色解析与内容解析互不影响：没有内容也照样能拿到角色', () => {
    // 回归：之前只有"内容没找到"时才会去会话数组里翻角色，于是顶层不带
    // role 时，真实存在的角色被一起丢掉。
    const ctx = normalizeMessageWriteContext({
      sessionKey: 'sess-1',
      context: { role: 'assistant' },
    });
    expect(ctx?.role).toBe('assistant');
    expect(ctx?.roleSource).toBe('explicit');
  });

  it('会话数组里的角色优先于载荷形态推断', () => {
    const ctx = normalizeMessageWriteContext({
      sessionKey: 'sess-1',
      prompt: '用户输入',
      messages: [{ role: 'assistant', content: '模型输出' }],
    });
    expect(ctx?.role).toBe('assistant');
    expect(ctx?.roleSource).toBe('explicit');
  });

  it('钩子语义可以兜底角色（message.received → user）', () => {
    const ctx = normalizeMessageWriteContext({ sessionKey: 'sess-1' }, 'user');
    expect(ctx?.role).toBe('user');
    expect(ctx?.roleSource).toBe('default');
  });
});

// ---------------------------------------------------------------------------
// 第二层：采集器按会话生命周期推断
// ---------------------------------------------------------------------------

describe('角色解析 · 采集器生命周期推断', () => {
  let collector: { report: (e: SecurityEvent) => Promise<void>; shutdown: () => Promise<void> };
  let appCollector: ApplicationCollector;
  let reported: SecurityEvent[];

  beforeEach(() => {
    reported = [];
    collector = {
      report: vi.fn(async (event: SecurityEvent) => {
        reported.push(event);
      }),
      shutdown: vi.fn(async () => {}),
    };
    appCollector = new ApplicationCollector(
      collector,
      { enabled: true, maxContentLength: 2000, maxResultPreviewLength: 500 },
      { hostId: 'host-test', containerId: 'container-test' }
    );
  });

  afterEach(async () => {
    await appCollector.shutdown();
    await collector.shutdown();
  });

  const unknownRoleCtx = (sessionKey: string, content: string): MessageWriteContext => ({
    sessionKey,
    role: 'unknown',
    content,
  });

  it('智能体运行之外到达的消息按用户输入处理', async () => {
    await appCollector.onMessageWrite(unknownRoleCtx('sess-user', '帮我看下网关日志'));

    const msg = reported.find((e) => e.event_type === 'agent_message');
    expect(msg?.role).toBe('user');
    expect(msg?.role_source).toBe('lifecycle');
    expect(msg?.content).toBe('帮我看下网关日志');
  });

  it('智能体运行期间到达的消息按模型输出处理', async () => {
    // 占位 agent_start 不带 agent 配置，但仍意味着"运行开始了"。
    await appCollector.onAgentStart({
      sessionKey: 'sess-run',
      agentId: 'agent-1',
    } as never);

    await appCollector.onMessageWrite(unknownRoleCtx('sess-run', '我先看一下日志'));

    const msg = reported.find((e) => e.event_type === 'agent_message');
    expect(msg?.role).toBe('assistant');
    expect(msg?.role_source).toBe('lifecycle');
  });

  it('宿主显式给的角色优先于生命周期推断', async () => {
    await appCollector.onAgentStart({
      sessionKey: 'sess-explicit',
      agentId: 'agent-1',
    } as never);

    await appCollector.onMessageWrite({
      sessionKey: 'sess-explicit',
      role: 'user',
      content: '用户在运行期间插话',
    });

    const msg = reported.find((e) => e.event_type === 'agent_message');
    expect(msg?.role).toBe('user');
    expect(msg?.role_source).toBe('explicit');
  });

  it('空消息不再落盘（回归：5 条 content="" 的噪声行）', async () => {
    await appCollector.onAgentStart({
      sessionKey: 'sess-junk',
      agentId: 'agent-1',
    } as never);

    await appCollector.onMessageWrite(unknownRoleCtx('sess-junk', ''));
    await appCollector.onMessageWrite(unknownRoleCtx('sess-junk', '   '));
    await appCollector.onMessageWrite({
      sessionKey: 'sess-junk',
      role: 'unknown',
      content: '',
      reasoning: '模型在思考',
    });

    const messages = reported.filter((e) => e.event_type === 'agent_message');
    expect(messages).toHaveLength(1);
    // 只有带 reasoning 的那条留下来
    expect(messages[0].reasoning).toBe('模型在思考');
  });

  it('带拦截决策的空消息仍然留痕', async () => {
    await appCollector.onMessageWrite(unknownRoleCtx('sess-blocked', ''), {
      decision: 'block',
      blockReason: '不该拦',
    } as never);

    const messages = reported.filter((e) => e.event_type === 'agent_message');
    expect(messages).toHaveLength(1);
    expect(messages[0].blocked).toBe(true);
  });

  it('session_start 落成 agent_session_start，不再是空消息行', async () => {
    await appCollector.onSessionStart({
      sessionKey: 'sess-session',
      role: 'unknown',
      content: '',
    });

    expect(reported.filter((e) => e.event_type === 'agent_message')).toHaveLength(0);
    const starts = reported.filter((e) => e.event_type === 'agent_session_start');
    expect(starts).toHaveLength(1);
    expect(starts[0].session_id).toBe('sess-session');
  });

  it('一个会话只落一条 agent_session_start（首条 user 消息不重复发）', async () => {
    await appCollector.onSessionStart({
      sessionKey: 'sess-once',
      role: 'unknown',
      content: '',
    });
    await appCollector.onMessageWrite(unknownRoleCtx('sess-once', '第一句'));

    expect(reported.filter((e) => e.event_type === 'agent_session_start')).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// 第三层：消息级评估真的跑起来了
// ---------------------------------------------------------------------------

describe('角色解析 · 消息级评估恢复生效', () => {
  let tmpDir: string;
  let ndjsonPath: string;
  let store: SecurityMonitorStore;

  beforeEach(async () => {
    tmpDir = mkdtempSync(join(tmpdir(), 'msg-role-'));
    ndjsonPath = join(tmpDir, 'security-events.jsonl');
    store = new SecurityMonitorStore();
    await store.initialize({
      collector: { ndjsonPath },
      application: { enabled: true },
      system: { enabled: false },
      network: { enabled: false },
      assetMonitor: { enabled: false },
      intervention: { enabled: false },
    });
  });

  afterEach(async () => {
    await store.shutdown();
    await rmTreeBestEffort(tmpDir);
    vi.restoreAllMocks();
  });

  it('宿主不带 role 时，自保护兜底照样拦得住卸载消息', () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});

    // 宿主载荷里**没有 role 字段**——这正是实测采样的形态。
    const input = hookBridge.bridgeMessageWrite(
      { content: '帮我卸载 openclaw-security-monitor 插件', sessionKey: 'sess-selfprotect' },
      undefined
    );
    expect(input).toBeDefined();
    expect(input?.role).toBe('unknown');

    // 修复前：role 是 unknown → 自保护整条不生效 → 消息直接放行。
    const result = store.beforeMessageWriteSync(input!);
    expect(result).toBeDefined();
    expect((result as { content?: string }).content).toContain('自我保护');
  });

  it('宿主不带 role 时，普通用户消息不被误拦', () => {
    const input = hookBridge.bridgeMessageWrite(
      { content: '帮我看一下网关的启动日志', sessionKey: 'sess-benign' },
      undefined
    );
    expect(store.beforeMessageWriteSync(input!)).toBeUndefined();
  });

  it('返回给宿主的拦截结果带上解析后的角色，不是 unknown', () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});

    const input = hookBridge.bridgeMessageWrite(
      { content: '帮我卸载 openclaw-security-monitor 插件', sessionKey: 'sess-hostshape' },
      undefined
    );
    const resolved = store.resolveMessageRole(input!);
    expect(resolved.role).toBe('user');

    const result = store.beforeMessageWriteSync(resolved);
    const hostResult = hookBridge.toMessageWriteHostResult(resolved, result);
    expect(hostResult).toEqual({
      block: true,
      message: { role: 'user', content: expect.stringContaining('自我保护') },
    });
  });

  it('session_start 载荷里带了内容时，按消息处理而不是丢掉', async () => {
    const input = hookBridge.bridgeMessageWrite(
      { content: '帮我重启一下网关', sessionKey: 'sess-start-content' },
      undefined
    );
    await store.onSessionStart(input!);

    // 内容没丢：作为一条 agent_message 落盘
    const deadline = Date.now() + 3000;
    let found = false;
    while (Date.now() < deadline && !found) {
      if (existsSync(ndjsonPath)) {
        const events = readFileSync(ndjsonPath, 'utf8')
          .split('\n')
          .filter((l) => l.trim())
          .map((l) => JSON.parse(l) as SecurityEvent);
        found = events.some(
          (e) => e.event_type === 'agent_message' && e.content === '帮我重启一下网关'
        );
      }
      if (!found) await wait(100);
    }
    expect(found).toBe(true);
  });
});
