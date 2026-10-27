import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { ControlUiService } from './control-ui-service.js';

let seq = 0;
function hit(decision: string, ts: number, extra: Record<string, unknown> = {}) {
  return JSON.stringify({
    // Read-side schema validation requires event_id / whitelisted
    // event_type / numeric ts; intervention blocks only from engine sources.
    event_id: `evt-hit-${++seq}`,
    event_type: 'agent_tool_result',
    layer: 'application',
    ts,
    source: 'openclaw.v1',
    tool_name: 'exec',
    blocked: decision === 'block',
    intervention: { decision, policy_id: `p-${decision}` },
    ...extra,
  });
}

function bareEvent(eventType: string, ts: number, extra: Record<string, unknown> = {}) {
  return JSON.stringify({
    event_id: `evt-${eventType}-${++seq}`,
    event_type: eventType,
    layer: 'system',
    ts,
    ...extra,
  });
}

describe('ControlUiService', () => {
  let dir: string;
  let file: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'control-ui-'));
    file = join(dir, 'events.jsonl');
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  function write(lines: string[]) {
    writeFileSync(file, lines.join('\n') + '\n');
  }

  describe('metrics threats', () => {
    it('counts every non-allow decision as a threat event', async () => {
      const now = Date.now();
      write([
        hit('block', now - 1000),
        hit('degrade', now - 900),
        hit('warn', now - 800),
        hit('audit', now - 700),
        hit('modify', now - 600),
        // allow 与无干预事件不是威胁事件
        hit('allow', now - 500),
        bareEvent('process_start', now - 400),
      ]);
      const svc = new ControlUiService(file);
      const m = await svc.metrics();
      expect(m.threats).toBe(5);
      expect(m.blocks).toBe(1);
      expect(m.total).toBe(7);
    });

    it('returns zero threats for an empty source', async () => {
      const svc = new ControlUiService(join(dir, 'missing.jsonl'));
      const m = await svc.metrics();
      expect(m.threats).toBe(0);
      expect(m.blocks).toBe(0);
    });

    // metrics 不再透出 policyIssues 字段（Policy Issues 告警磁贴已移除）；
    // policy 审计事件仍留在事件流里可查询。
    it('no longer exposes policyIssues on metrics (tile removed)', async () => {
      const now = Date.now();
      write([
        bareEvent('policy_missing', now - 3000, { layer: 'application', detail: 'policy file not found' }),
        hit('block', now - 500),
      ]);
      const svc = new ControlUiService(file);
      const m = await svc.metrics();
      expect('policyIssues' in m).toBe(false);
    });
  });

  describe('policyHits offset paging', () => {
    it('pages without overlap, newest first', async () => {
      const now = Date.now();
      // 5 条命中，ts 递增写入（时间顺序），返回应最新在前。
      write([
        hit('block', now - 5000),
        hit('warn', now - 4000),
        hit('audit', now - 3000),
        hit('degrade', now - 2000),
        hit('modify', now - 1000),
      ]);
      const svc = new ControlUiService(file);

      const page1 = await svc.policyHits({ limit: 2, offset: 0 });
      expect(page1.hits.map((h) => h.intervention?.decision)).toEqual(['modify', 'degrade']);
      expect(page1.total).toBe(5);

      const page2 = await svc.policyHits({ limit: 2, offset: 2 });
      expect(page2.hits.map((h) => h.intervention?.decision)).toEqual(['audit', 'warn']);

      const page3 = await svc.policyHits({ limit: 2, offset: 4 });
      expect(page3.hits.map((h) => h.intervention?.decision)).toEqual(['block']);

      // 各页无交集
      const ids = [...page1.hits, ...page2.hits, ...page3.hits].map((h) => h.ts);
      expect(new Set(ids).size).toBe(5);
    });

    it('combines decision filter with offset', async () => {
      const now = Date.now();
      write([
        hit('warn', now - 3000),
        hit('block', now - 2000),
        hit('warn', now - 1000),
      ]);
      const svc = new ControlUiService(file);
      const first = await svc.policyHits({ decision: 'warn', limit: 1, offset: 0 });
      const second = await svc.policyHits({ decision: 'warn', limit: 1, offset: 1 });
      expect(first.hits).toHaveLength(1);
      expect(second.hits).toHaveLength(1);
      expect(first.hits[0].ts).toBe(now - 1000);
      expect(second.hits[0].ts).toBe(now - 3000);
      expect(first.total).toBe(2);
    });
  });
});


describe('ControlUiService listEvents paging', () => {
  let dir: string;
  let file: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'control-ui-events-'));
    file = join(dir, 'events.jsonl');
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  function write(lines: string[]) {
    writeFileSync(file, lines.join('\n') + '\n');
  }

  function event(ts: number) {
    return bareEvent('agent_tool_call', ts, { layer: 'application', tool_name: 'exec' });
  }

  it('reports the full match count as total even beyond the first page', async () => {
    const now = Date.now();
    write(Array.from({ length: 120 }, (_, i) => event(now - (120 - i) * 1000)));
    const svc = new ControlUiService(file);

    const page1 = await svc.listEvents({ limit: 50, offset: 0 });
    expect(page1.events).toHaveLength(50);
    expect(page1.total).toBe(120);

    // 最后一页可翻到底：newest-first，offset 100 剩 20 条。
    const page3 = await svc.listEvents({ limit: 50, offset: 100 });
    expect(page3.events).toHaveLength(20);
    expect(page3.total).toBe(120);
    // newest-first：offset k 对应第 k+1 新的事件。
    expect(page3.events[0].ts).toBe(now - 101 * 1000);
  });

  it('keeps total consistent when a filter shrinks the match set', async () => {
    const now = Date.now();
    write([
      ...Array.from({ length: 10 }, (_, i) => event(now - (10 - i) * 1000)),
      bareEvent('process_start', now - 500),
    ]);
    const svc = new ControlUiService(file);

    const page = await svc.listEvents({ limit: 50, offset: 0, eventType: 'agent_tool_call' });
    expect(page.events).toHaveLength(10);
    expect(page.total).toBe(10);
  });
});

// 读路径事件 schema 校验。NDJSON 由本插件独占写入，任何不满足
// schema 的行（坏 JSON、缺 event_id/event_type/ts、event_type 不在白名单、
// 非引擎 source 带 intervention 块）都按注入/损坏处理：跳过并计数留痕。
describe('ControlUiService read-side schema validation', () => {
  let dir: string;
  let file: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'control-ui-schema-'));
    file = join(dir, 'events.jsonl');
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  function write(lines: string[]) {
    writeFileSync(file, lines.join('\n') + '\n');
  }

  function validEvent(ts: number, extra: Record<string, unknown> = {}) {
    return JSON.stringify({
      event_id: `evt-${ts}`,
      event_type: 'agent_tool_call',
      layer: 'application',
      ts,
      source: 'openclaw.v1',
      ...extra,
    });
  }

  it('skips and counts lines failing the schema (bad json / missing fields / unknown type)', async () => {
    const now = Date.now();
    write([
      validEvent(now - 300),
      'not-json-at-all',
      JSON.stringify({ event_id: 'x', event_type: 'agent_tool_call', ts: 'yesterday' }),
      JSON.stringify({ event_id: 'x', ts: now - 250 }),
      JSON.stringify({ event_id: 'x', event_type: 'totally_fake_event', ts: now - 200 }),
      JSON.stringify(['array', 'not', 'object']),
      validEvent(now - 100),
    ]);
    const svc = new ControlUiService(file);
    const m = await svc.metrics();
    expect(m.total).toBe(2);
    expect(svc.getInvalidLineCount()).toBe(5);
  });

  it('accepts intervention blocks only from engine sources', async () => {
    const now = Date.now();
    write([
      validEvent(now - 300, {
        source: 'openclaw.v1',
        intervention: { decision: 'block', policy_id: 'p1' },
      }),
      validEvent(now - 200, {
        source: 'openclaw.runtime-hooks.v1',
        intervention: { decision: 'block', policy_id: 'p2' },
      }),
      // 伪造：未知 source 带 intervention 块 → 整行丢弃。
      validEvent(now - 100, {
        source: 'evil.inject.v9',
        intervention: { decision: 'block', policy_id: 'forged' },
      }),
      validEvent(now - 50, { source: 'untrusted-but-no-intervention' }),
    ]);
    const svc = new ControlUiService(file);
    const m = await svc.metrics();
    expect(m.total).toBe(3);
    expect(m.blocks).toBe(2);
    expect(svc.getInvalidLineCount()).toBe(1);
  });

  it('counts x_openclaw_tamper_detected and policy audit event types as valid', async () => {
    const now = Date.now();
    write([
      JSON.stringify({ event_id: 't1', event_type: 'x_openclaw_tamper_detected', layer: 'asset', ts: now - 200, kind: 'forged_lock' }),
      JSON.stringify({ event_id: 't2', event_type: 'rule_invalid_regex', layer: 'application', ts: now - 100 }),
      JSON.stringify({ event_id: 't3', event_type: 'network_http', layer: 'system', ts: now - 50 }),
      JSON.stringify({ event_id: 't4', event_type: 'asset_add', layer: 'asset', ts: now - 25 }),
      JSON.stringify({ event_id: 't5', event_type: 'command_execution', layer: 'system', ts: now - 10 }),
    ]);
    const svc = new ControlUiService(file);
    const m = await svc.metrics();
    expect(m.total).toBe(5);
    expect(svc.getInvalidLineCount()).toBe(0);
  });
});
