/**
 * 落盘幂等：同一 event_id 在 NDJSON 里只出现一次。
 *
 * 实测样本（1154 行 / 96 小时）里有 393 组**字节完全相同**的行——同一
 * 条源端事件被写了 2~3 次，占 46.6% 的行、45.5% 的字节。NDJSON 是审计
 * 契约：消费方按 event_id 关联，重复行会让"一次动作"看起来发生了多次。
 *
 * 复现路径是部署现实：插件被装了两份（或升级后旧实例没退场），两个
 * 采集器读同一份 runtime hook 日志、往同一个 NDJSON 追加。各自的内存
 * 去重表互不相识，所以幂等必须落在最终写文件的那一层。
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { readFileSync, existsSync, appendFileSync, writeFileSync, mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { SecurityMonitorStore } from './store.js';
import type { SecurityEvent } from './types.js';

function wait(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

function readEvents(ndjsonPath: string): SecurityEvent[] {
  if (!existsSync(ndjsonPath)) return [];
  return readFileSync(ndjsonPath, 'utf8')
    .split('\n')
    .filter((line) => line.trim())
    .map((line) => JSON.parse(line) as SecurityEvent);
}

async function waitForLines(ndjsonPath: string, count: number, timeoutMs = 5000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (readEvents(ndjsonPath).length >= count) return;
    await wait(50);
  }
}

describe('NDJSON 落盘幂等', () => {
  let tmpDir: string;
  let runtimeLog: string;
  let ndjsonPath: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'store-idempotency-'));
    runtimeLog = join(tmpDir, 'security-events-runtime.jsonl');
    ndjsonPath = join(tmpDir, 'security-events.jsonl');
    writeFileSync(runtimeLog, '', 'utf8');
  });

  afterEach(async () => {
    await wait(50);
  });

  function appendRuntimeEvent(eventId: string, command = 'ls -la') {
    appendFileSync(
      runtimeLog,
      JSON.stringify({
        event_type: 'process_start',
        type: 'application.process_start',
        id: eventId,
        event_id: eventId,
        ts: new Date().toISOString(),
        runtime: 'node',
        api: 'child_process.exec',
        executable: 'ls',
        process_name: 'ls',
        pid: 4321,
        ppid: 1,
        command_line: command,
        session_id: 'sess-dup',
      }) + '\n',
      'utf8'
    );
  }

  async function newStore(): Promise<SecurityMonitorStore> {
    const store = new SecurityMonitorStore();
    await store.initialize({
      collector: { ndjsonPath },
      application: { enabled: true, runtimeHooks: { enabled: true, logPath: runtimeLog } },
      system: { enabled: false },
      network: { enabled: false },
      assetMonitor: { enabled: false },
      intervention: { enabled: false },
    });
    return store;
  }

  it('两个实例读同一份 hook 日志时，同一 event_id 只落一行', async () => {
    const eventId = '11111111-2222-4333-8444-555555555555';
    const storeA = await newStore();
    const storeB = await newStore();

    try {
      appendRuntimeEvent(eventId);
      await waitForLines(ndjsonPath, 1);
      // 两个实例的轮询周期不同步，给落后的一方足够时间落第二行——
      // 修复前这里会出现两行字节相同的事件。
      await wait(800);

      const events = readEvents(ndjsonPath).filter((e) => e.event_id === eventId);
      expect(events).toHaveLength(1);
    } finally {
      await storeA.shutdown();
      await storeB.shutdown();
    }
  });

  it('不同 event_id 的事件照常全部落盘', async () => {
    const store = await newStore();
    try {
      appendRuntimeEvent('aaaaaaaa-0000-4000-8000-000000000001', 'ls -la');
      appendRuntimeEvent('aaaaaaaa-0000-4000-8000-000000000002', 'cat /etc/hosts');
      await waitForLines(ndjsonPath, 2);

      const ids = new Set(readEvents(ndjsonPath).map((e) => e.event_id));
      expect(ids.has('aaaaaaaa-0000-4000-8000-000000000001')).toBe(true);
      expect(ids.has('aaaaaaaa-0000-4000-8000-000000000002')).toBe(true);
    } finally {
      await store.shutdown();
    }
  });

  it('同一实例里重复上报同一事件也只落一行', async () => {
    const store = await newStore();
    try {
      const eventId = 'bbbbbbbb-0000-4000-8000-000000000001';
      // 绕过采集器的内存去重，直接把同一条事件报两次到落盘层。
      const sink = (store as unknown as { collector: { report: (e: SecurityEvent) => Promise<void> } })
        .collector;
      const event = {
        comm: 'openclaw',
        event_id: eventId,
        event_type: 'process_start',
        layer: 'system',
        ts: Date.now(),
        schema_version: 1,
      } as unknown as SecurityEvent;
      await sink.report(event);
      await sink.report(event);
      await wait(200);

      const events = readEvents(ndjsonPath).filter((e) => e.event_id === eventId);
      expect(events).toHaveLength(1);
    } finally {
      await store.shutdown();
    }
  });
});
