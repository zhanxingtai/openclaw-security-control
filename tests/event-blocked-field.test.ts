/**
 * `blocked` 字段恒在（schema 一致性）。「键缺失」与 `false` 在 `===` 下等价，
 * 但在 Object.keys / in / schema 校验下不等价——键缺失会让审计丢失「这条没被拦」
 * 的语义。四层门禁：类型层（必带 boolean）、出口层（report 缺省补 false，覆盖
 * 绕过类型系统的路径）、schema 层（blocked 进 required）、端到端（落盘逐行断言）。
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, readFileSync, rmSync, existsSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { SecurityMonitorStore } from '../src/store.js';
import { RuntimeHookCollector } from '../src/runtime-hook-collector.js';
import { normalizeConfig } from '../src/config.js';

interface SinkLike {
  report: (event: unknown) => Promise<void>;
  initialize: () => Promise<void>;
}

let tmpDir: string;
let ndjsonPath: string;
let store: SecurityMonitorStore;
let sink: SinkLike;

function makeEvent(eventId?: string, extra: Record<string, unknown> = {}) {
  return {
    ...(eventId ? { event_id: eventId } : {}),
    event_type: 'test_emit',
    layer: 'application',
    ts: 1_700_000_000_000,
    schema_version: 1,
    pid: process.pid,
    session_id: null,
    host_id: 'test-host',
    source: 'openclaw.v1',
    collection_method: 'test',
    collector: { hook_name: 'test', middleware_name: 'test', collector_name: 'test' },
    ...extra,
  };
}

function readLines(): Array<Record<string, unknown>> {
  if (!existsSync(ndjsonPath)) return [];
  return readFileSync(ndjsonPath, 'utf8')
    .split('\n')
    .filter((l) => l.trim())
    .map((l) => JSON.parse(l) as Record<string, unknown>);
}

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), 'event-blocked-'));
  ndjsonPath = join(tmpDir, 'security-events.jsonl');
  store = new SecurityMonitorStore(
    normalizeConfig({
      collector: { ndjsonPath },
      intervention: { enabled: false },
    })
  );
  sink = (store as unknown as { collector: SinkLike }).collector;
});

afterEach(async () => {
  await store.shutdown();
  rmSync(tmpDir, { recursive: true, force: true });
});

describe('出口层：`blocked` 恒在', () => {
  it('事件缺 `blocked` ⇒ 落盘行补上 `false`（**安静**地补，不刷屏）', async () => {
    // 模拟「绕过类型系统」的路径：hook JSON / 旧版插件 / 外部采集器。
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      await sink.report(makeEvent('evt-no-blocked'));
      const line = readLines()[0];
      expect(line).toBeDefined();
      expect(line.blocked).toBe(false);
      expect(typeof line.blocked).toBe('boolean');
      // 「缺省」是正常路径，不该告警——老生产方本就不带这个键，每次都告警
      // 等于刷屏，真正的告警会被淹掉。
      const warned = warnSpy.mock.calls.map((c) => String(c[0])).join('\n');
      expect(warned).not.toContain('blocked');
    } finally {
      warnSpy.mockRestore();
    }
  });

  it('`blocked: true` 原样保留（不被兜底覆盖）', async () => {
    await sink.report(makeEvent('evt-blocked-true', { blocked: true }));
    expect(readLines()[0].blocked).toBe(true);
  });

  it('`blocked: false` 原样保留', async () => {
    await sink.report(makeEvent('evt-blocked-false', { blocked: false }));
    expect(readLines()[0].blocked).toBe(false);
  });

  it('非布尔取值 ⇒ 归一成 false 且**告警一次**（异常不能静默）', async () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      await sink.report(makeEvent('evt-blocked-garbage', { blocked: 'yes' }));
      expect(readLines()[0].blocked).toBe(false);
      const warned = warnSpy.mock.calls.map((c) => String(c[0])).join('\n');
      expect(warned).toContain('blocked');
    } finally {
      warnSpy.mockRestore();
    }
  });

  it('兜底是**幂等**的：已带 `blocked` 的事件再走一次出口，值不变', async () => {
    await sink.report(makeEvent('evt-idem-1', { blocked: true }));
    await sink.report(makeEvent('evt-idem-2', { blocked: false }));
    const lines = readLines();
    expect(lines.find((l) => l.event_id === 'evt-idem-1')?.blocked).toBe(true);
    expect(lines.find((l) => l.event_id === 'evt-idem-2')?.blocked).toBe(false);
  });
});

describe('采集路径：每条事件都带布尔 `blocked`', () => {
  it('runtime hook 的三类事件（process_start / network_http / process_exit）都带', async () => {
    const logPath = join(tmpDir, 'runtime-hook.log');
    const lines = [
      JSON.stringify({
        id: 'hp-1',
        event_id: 'hp-1',
        event_type: 'process_start',
        type: 'application.process_start',
        timestamp: '2026-10-29T08:31:53.000Z',
        command_line: 'ls -la /tmp',
        executable: 'ls',
        pid: 4242,
        ppid: 1,
      }),
      JSON.stringify({
        id: 'hn-1',
        event_id: 'hn-1',
        event_type: 'network_http',
        type: 'network.http_request',
        timestamp: '2026-10-29T08:31:54.000Z',
        method: 'POST',
        url: 'https://api.example.invalid/v1/chat',
        host: 'api.example.invalid',
      }),
      JSON.stringify({
        id: 'hx-1',
        event_id: 'hx-1',
        event_type: 'process_exit',
        type: 'process_exit',
        timestamp: '2026-10-29T08:31:55.000Z',
        child_pid: 4242,
        exit_code: 0,
      }),
    ];
    writeFileSync(logPath, lines.join('\n') + '\n', 'utf8');

    const collector = new RuntimeHookCollector(sink as unknown as SinkLike, {
      enabled: true,
      logPath,
      replayOnFirstRun: true,
    });
    await collector.initialize();
    await waitFor(() => readLines().length >= 3, 5000);
    await collector.shutdown();

    const events = readLines();
    expect(events.length).toBe(3);
    for (const ev of events) {
      expect(typeof ev.blocked, `事件 ${String(ev.event_id)} 缺 blocked`).toBe('boolean');
    }
    // process_start / network_http 的 `blocked` 由 hook 侧如实给出（本例没带 ⇒ false）；
    // process_exit 恒 false。
    expect(events.every((e) => e.blocked === false)).toBe(true);
  });

  it('hook 侧报 `blocked: true` ⇒ 落盘事件保留 true', async () => {
    const logPath = join(tmpDir, 'runtime-hook-blocked.log');
    writeFileSync(
      logPath,
      JSON.stringify({
        id: 'hb-1',
        event_id: 'hb-1',
        event_type: 'network_http',
        type: 'network.http_request',
        timestamp: '2026-10-29T08:31:54.000Z',
        method: 'POST',
        url: 'https://api.example.invalid/v1/chat',
        host: 'api.example.invalid',
        blocked: true,
        block_reason: 'blocked by network hook',
      }) + '\n',
      'utf8',
    );

    const collector = new RuntimeHookCollector(sink as unknown as SinkLike, {
      enabled: true,
      logPath,
      replayOnFirstRun: true,
    });
    await collector.initialize();
    await waitFor(() => readLines().length >= 1, 5000);
    await collector.shutdown();

    expect(readLines()[0].blocked).toBe(true);
  });

  it('应用层事件（beforeMessageWrite）带 `blocked`', async () => {
    await store.initialize(
      normalizeConfig({
        collector: { ndjsonPath },
        intervention: { enabled: false },
        application: { enabled: true },
      }) as unknown as Record<string, unknown>,
    );
    await store.beforeMessageWrite({ sessionKey: 'sess-blocked', role: 'user', content: 'hello' });
    await waitFor(() => readLines().length >= 1, 5000);

    const events = readLines();
    expect(events.length).toBeGreaterThan(0);
    for (const ev of events) {
      expect(typeof ev.blocked, `事件 ${String(ev.event_id)} 缺 blocked`).toBe('boolean');
    }
  });
});

describe('schema 层：`blocked` 是必填', () => {
  it('schema 的 required 含 blocked', () => {
    const schema = JSON.parse(
      readFileSync(join(__dirname, '..', 'schemas', 'security-event-v1.schema.json'), 'utf8'),
    ) as { required: string[]; properties: Record<string, { type?: string }> };
    expect(schema.required).toContain('blocked');
    expect(schema.properties.blocked.type).toBe('boolean');
  });

  it('schema 的 required 与 types.ts 的非可选字段集相等（唯一事实源）', () => {
    // 生成脚本（scripts/gen-event-schema.mjs）从 types.ts 推导必填集 ⇒
    // 两侧不一致 ⇒ 说明 schema 过期 ⇒ 这里会红。
    const schema = JSON.parse(
      readFileSync(join(__dirname, '..', 'schemas', 'security-event-v1.schema.json'), 'utf8'),
    ) as { required: string[] };
    const src = readFileSync(join(__dirname, '..', 'src', 'types.ts'), 'utf8');
    const start = src.indexOf('export interface SecurityEvent {');
    expect(start).toBeGreaterThan(-1);
    let depth = 0;
    let end = -1;
    for (let j = src.indexOf('{', start); j < src.length; j++) {
      if (src[j] === '{') depth++;
      else if (src[j] === '}') {
        depth--;
        if (depth === 0) {
          end = j;
          break;
        }
      }
    }
    const body = src.slice(src.indexOf('\n', start) + 1, end);
    const required: string[] = [];
    for (const m of body.matchAll(/^  ([a-zA-Z_][a-zA-Z0-9_]*)(\??):/gm)) {
      if (m[2] !== '?') required.push(m[1]!);
    }
    expect([...schema.required].sort()).toEqual(required.sort());
  });
});

async function waitFor(predicate: () => boolean, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((r) => setTimeout(r, 25));
  }
}
