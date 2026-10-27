/**
 * 批次 2 字段收敛的端到端验证。
 *
 * 走真实 SecurityMonitorStore → NDJSON 落盘（不经 mock），确认：
 *   1. 一次 cron 运行（scheduled/started/finished 三元组）只落一条
 *      cron_run；一次配置变化（added）落一条 cron_changed；
 *   2. tool_call 事件不再有 params 对象，tool_params 信息完整且带
 *      raw_params_hash；
 *   3. 一条被丢弃的消息（相邻重复）不占 message_index。
 */

import { describe, it, expect, afterEach, beforeEach } from 'vitest';
import { mkdtempSync, readFileSync, rmSync, existsSync } from 'fs';
import { createHash } from 'crypto';
import { tmpdir } from 'os';
import { join } from 'path';

import { SecurityMonitorStore } from '../src/store.js';
import { stableStringify } from '../src/asset-hash.js';
import type { SecurityEvent } from '../src/types.js';

let tmpDir: string;
let ndjsonPath: string;
let store: SecurityMonitorStore;

function readEvents(): SecurityEvent[] {
  if (!existsSync(ndjsonPath)) return [];
  return readFileSync(ndjsonPath, 'utf8')
    .split('\n')
    .filter((l) => l.trim())
    .map((l) => JSON.parse(l) as SecurityEvent);
}

beforeEach(async () => {
  tmpDir = mkdtempSync(join(tmpdir(), 'batch2-e2e-'));
  ndjsonPath = join(tmpDir, 'security-events.jsonl');
  store = new SecurityMonitorStore();
  await store.initialize({
    collector: { ndjsonPath },
    application: { enabled: true },
    system: { enabled: false },
    network: { enabled: false },
    assetMonitor: { enabled: false },
    intervention: { enabled: false },
    // 平台 common-v1 把 host_id / container_id 列为公共必填：生产环境由
    // 配置注入（宿主机固定写 host），这里模拟生产口径。
    environment: { hostId: 'host-e2e', containerId: 'host' },
  });
});

afterEach(async () => {
  await store.shutdown();
  rmSync(tmpDir, { recursive: true, force: true });
});

describe('批次 2 端到端', () => {
  it('一次 cron 运行 + 一次配置变化：事件流条数与形状', async () => {
    // 运行三元组（8.2 每次触发都发这三条）
    await store.onCronEvent({
      sessionKey: 'cron:job-1:daily',
      action: 'scheduled',
      cronName: 'daily-backup',
      schedule: '0 3 * * *',
    });
    await store.onCronEvent({ sessionKey: 'cron:job-1:daily', action: 'started' });
    await new Promise((r) => setTimeout(r, 5));
    await store.onCronEvent({
      sessionKey: 'cron:job-1:daily',
      action: 'finished',
      firedResult: 'backup ok',
    });

    // 配置变化
    await store.onCronEvent({
      sessionKey: 'cron:job-2:weekly',
      action: 'added',
      cronName: 'weekly-clean',
      schedule: '0 0 * * 0',
      enabled: true,
    });

    const events = readEvents().filter((e) => e.event_type === 'cron_changed' || e.event_type === 'x_openclaw_cron_run');
    // 收敛前是 4 条（3 条 cron_changed + 1 条）；收敛后 2 条。
    expect(events).toHaveLength(2);

    const run = events.find((e) => e.event_type === 'x_openclaw_cron_run');
    expect(run?.status).toBe('success');
    expect(run?.metadata?.cron_id).toBe('cron:job-1:daily');
    // 作业名/表达式来自 scheduled（中间事件），收敛后仍保留在 cron_run 上。
    expect(run?.metadata?.cron_name).toBe('daily-backup');
    expect(run?.metadata?.schedule).toBe('0 3 * * *');
    expect(run?.started_at).toEqual(expect.any(Number));
    expect(run?.duration_ms).toEqual(expect.any(Number));
    expect(run?.fired_result).toBe('backup ok');

    const changed = events.find((e) => e.event_type === 'cron_changed');
    expect(changed?.status).toBe('modified');
    expect(changed?.metadata?.cron_id).toBe('cron:job-2:weekly');
    expect(changed?.metadata?.enabled).toBe(true);
  });

  it('tool_call 落盘：无 params、tool_params 完整、raw_params_hash 可核对', async () => {
    const rawParams = { z: 1, api_key: 'sk-live-secret', a: 'x' };
    await store.beforeToolCall({
      sessionKey: 'sess-e2e',
      runId: 'run-e2e',
      agentId: 'agent-e2e',
      toolName: 'custom_tool',
      params: rawParams,
    });

    const line = readFileSync(ndjsonPath, 'utf8');
    const event = readEvents().find((e) => e.event_type === 'agent_tool_call') as SecurityEvent &
      Record<string, unknown>;

    // 对象视图删除，字符串载荷信息完整。
    expect('params' in event).toBe(false);
    expect(JSON.parse(event.tool_params as string)).toEqual({
      z: 1,
      api_key: '***',
      a: 'x',
    });
    // 指纹 = 脱敏前规范化序列化的 sha256。
    expect(event.raw_params_hash).toBe(
      // 与落盘实现同源：stableStringify 键序规范化。
      createHash('sha256').update(stableStringify(rawParams)).digest('hex')
    );
    // 明文绝不落盘。
    expect(line).not.toContain('sk-live-secret');
    // 键序不同内容相同 → 同一指纹（规范化生效）。
    await store.beforeToolCall({
      sessionKey: 'sess-e2e-2',
      runId: 'run-e2e',
      agentId: 'agent-e2e',
      toolName: 'custom_tool',
      params: { a: 'x', api_key: 'sk-live-secret', z: 1 },
    });
    const toolCalls = readEvents().filter((e) => e.event_type === 'agent_tool_call');
    expect(toolCalls[1].raw_params_hash).toBe(toolCalls[0].raw_params_hash as string);
  });

  it('消息流：被丢弃的消息不占 message_index', async () => {
    await store.beforeMessageWrite({ sessionKey: 'sess-e2e', role: 'user', content: '第一句' });
    // 相邻重复 → 丢弃，不占号
    await store.beforeMessageWrite({ sessionKey: 'sess-e2e', role: 'user', content: '第一句' });
    // 空消息 → 丢弃，不占号
    await store.beforeMessageWrite({ sessionKey: 'sess-e2e', role: 'assistant', content: '' });
    await store.beforeMessageWrite({ sessionKey: 'sess-e2e', role: 'assistant', content: '第二句' });

    const messages = readEvents().filter((e) => e.event_type === 'agent_message');
    expect(messages.map((m) => m.message_index)).toEqual([1, 2]);
  });

  it('冒烟：x_openclaw_ 前缀 + 平台 common-v1 公共必填字段不缺', async () => {
    // cron 运行 → x_openclaw_cron_run
    await store.onCronEvent({ sessionKey: 'cron:job-x:daily', action: 'started' });
    await store.onCronEvent({ sessionKey: 'cron:job-x:daily', action: 'finished', firedResult: 'ok' });
    // 子代理生命周期
    await store.onSubagentStart({ sessionKey: 'sess-e2e', subagentId: 'sub-1' });
    // 常规工具调用
    await store.beforeToolCall({
      sessionKey: 'sess-e2e', runId: 'r', agentId: 'a', toolName: 'read', params: { path: '/tmp/x' },
    });

    const events = readEvents().filter((e) => e.event_type !== 'agent_session_start');
    expect(events.length).toBeGreaterThanOrEqual(3);
    // 平台 validate_batch：未登记的裸名 event_type 整批拒收；x_openclaw_ 前缀
    // 扩展只校验公共字段后放行。凡本插件发出的扩展类型必须带前缀。
    const extended = events.filter((e) =>
      (e.event_type as string).startsWith('x_openclaw_')
    );
    expect(extended.map((e) => e.event_type)).toContain('x_openclaw_cron_run');
    expect(extended.map((e) => e.event_type)).toContain('x_openclaw_subagent_start');
    for (const e of events) {
      // common-v1 公共必填：event_id / event_type / schema_version / ts / comm /
      // host_id / container_id / pid——缺一不可，否则平台侧校验失败。
      for (const f of ['event_id', 'event_type', 'schema_version', 'ts', 'comm', 'host_id', 'container_id', 'pid']) {
        expect(e, `事件 ${e.event_type} 缺公共必填字段 ${f}`).toHaveProperty(f);
      }
      expect(typeof e.schema_version).toBe('number');
    }
  });
});
