/**
 * 端到端：会话标题随应用层事件落进 NDJSON。
 *
 * 标题由首条有效 user 消息派生，随该会话之后的每一条应用层事件一起落盘，
 * 消费方不必回放事件流自己重建标题。这里验证的是"字段真的落到盘上"，
 * 而不是只看内存里的事件对象。
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { readFileSync, existsSync, mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { SecurityMonitorStore } from './store.js';
import type { SecurityEvent } from './types.js';

function wait(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

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
    await wait(50);
  }
  throw new Error('timed out waiting for events in ' + ndjsonPath);
}

describe('会话标题落盘', () => {
  let tmpDir: string;
  let ndjsonPath: string;
  let store: SecurityMonitorStore;

  beforeEach(async () => {
    tmpDir = mkdtempSync(join(tmpdir(), 'store-session-title-'));
    ndjsonPath = join(tmpDir, 'security-events.jsonl');
    store = new SecurityMonitorStore();
    await store.initialize({
      collector: { ndjsonPath },
      application: { enabled: true },
      system: { enabled: false },
      network: { enabled: false },
      assetMonitor: { enabled: false },
    });
  });

  afterEach(async () => {
    await store.shutdown();
  });

  it('首条 user 消息派生的标题写进该会话的每一条应用层事件', async () => {
    await store.beforeMessageWrite({
      sessionKey: 'sess-title-e2e',
      role: 'user',
      content: '帮我修复登录接口的 500 错误',
    });

    const events = await waitForEvents(
      ndjsonPath,
      (list) => list.some((e) => e.event_type === 'agent_message' && e.session_id === 'sess-title-e2e')
    );

    const titled = events.filter((e) => e.session_id === 'sess-title-e2e');
    expect(titled.length).toBeGreaterThan(0);
    for (const e of titled) {
      expect(e.session_title).toBe('帮我修复登录接口的 500 错误');
    }
  });

  it('工具调用事件带同一个标题', async () => {
    await store.beforeMessageWrite({
      sessionKey: 'sess-title-e2e-2',
      role: 'user',
      content: '查一下配置文件',
    });
    await waitForEvents(
      ndjsonPath,
      (list) => list.some((e) => e.event_type === 'agent_message' && e.session_id === 'sess-title-e2e-2')
    );

    await store.beforeToolCall({
      sessionKey: 'sess-title-e2e-2',
      runId: 'run-1',
      agentId: 'agent-1',
      toolName: 'custom_tool',
      params: { input: 'x' },
    });

    const events = await waitForEvents(
      ndjsonPath,
      (list) => list.some((e) => e.event_type === 'agent_tool_call' && e.session_id === 'sess-title-e2e-2')
    );
    const toolEvent = events.find(
      (e) => e.event_type === 'agent_tool_call' && e.session_id === 'sess-title-e2e-2'
    )!;
    expect(toolEvent.session_title).toBe('查一下配置文件');
  });

  it('标题里不留凭据', async () => {
    const gh = 'ghp_' + 'a'.repeat(36);
    await store.beforeMessageWrite({
      sessionKey: 'sess-title-e2e-3',
      role: 'user',
      content: `用 ${gh} 登录后台`,
    });

    const events = await waitForEvents(
      ndjsonPath,
      (list) => list.some((e) => e.event_type === 'agent_message' && e.session_id === 'sess-title-e2e-3')
    );
    const raw = readFileSync(ndjsonPath, 'utf8');
    expect(raw).not.toContain('ghp_');
    const titled = events.find((e) => e.event_type === 'agent_message' && e.session_id === 'sess-title-e2e-3')!;
    expect(titled.session_title).toContain('***');
  });
});
