/**
 * ControlUiService bySeverity / severity 过滤 / resolveEventSeverity 单元测试。
 *
 * 覆盖：
 *  - resolveEventSeverity 解析优先级（matched_rules → intervention.risk_level → 顶层 risk_level → severity → null）
 *  - Aggregate.bySeverity 增量聚合（含 unknown 桶）
 *  - MetricsResult 同时返回 bySeverity + byDecision
 *  - EventQuery.severity 过滤（按 resolveEventSeverity 口径）
 *  - PolicyHitsQuery.severity 过滤 + bySeverity 返回 + total 双过滤交集
 *
 * 与 src/control-ui-service.test.ts 互补（后者覆盖 schema 校验 + 顶层 counts；
 * 本文件专测 severity 维度）。
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import {
  ControlUiService,
  incrementAggregate,
  resolveEventSeverity,
  type Aggregate,
} from '../src/control-ui-service.js';

let seq = 0;
function mkEvent(opts: {
  decision?: string;
  riskLevel?: string;
  matchedRules?: Array<{ policy_id?: string; risk_level?: string }>;
  ts?: number;
  extra?: Record<string, unknown>;
}): string {
  seq += 1;
  const ts = opts.ts ?? Date.now();
  const intervention: Record<string, unknown> = {};
  if (opts.decision !== undefined) intervention.decision = opts.decision;
  if (opts.riskLevel !== undefined) intervention.risk_level = opts.riskLevel;
  if (opts.matchedRules !== undefined) intervention.matched_rules = opts.matchedRules;
  return JSON.stringify({
    event_id: `evt-${seq}`,
    event_type: 'agent_tool_result',
    layer: 'application',
    ts,
    source: 'openclaw.v1',
    tool_name: 'exec',
    intervention,
    ...opts.extra,
  });
}

describe('ControlUiService .D severity dimension', () => {
  let dir: string;
  let file: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'control-ui-sev-'));
    file = join(dir, 'events.jsonl');
  });
  afterEach(() => {
    // Windows CI（GitHub Actions）偶发 ENOTEMPTY，症状是本文件最后两条用例
    // 在 afterEach 里删不掉自己的临时目录。
    //
    // 排查结论：不是 Node 自己留了句柄——libuv 打开文件带 FILE_SHARE_DELETE，
    // 本地实测"句柄不放开也删得掉"（脚本 /tmp/enotempty-proof.mjs 第 1 段）。
    // 阻塞只可能来自外部进程：Windows 上以限制性共享模式短暂打开 %TEMP% 新建
    // 文件的扫描器（Defender 实时保护是典型）。这解释了三个现象：
    //   · Linux/macOS 免疫——POSIX unlink 语义允许删掉已打开的文件；
    //   · 只在负载高的 CI 上现形，本地跑 3 次全过；
    //   · 失败的是本文件最后两条用例，与它们上面两条结构完全相同的用例同批
    //     通过——不是这两条用例的代码路径有问题。
    //
    // fs.rmSync 的 maxRetries/retryDelay 正是为 EBUSY/EMFILE/ENFILE/
    // ENOTEMPTY/EPERM 这组 errno 设计的，而**默认是 0 次重试**：一次瞬时占用
    // 就足以让整条用例判失败。删不掉是清理噪音，不是被测行为出错，所以在这里
    // 重试，而不是去改断言或跳过用例。
    rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 50 });
  });
  function write(lines: string[]) {
    writeFileSync(file, lines.join('\n') + '\n');
  }

  describe('resolveEventSeverity (pure helper)', () => {
    it('returns the highest risk_level from matched_rules', () => {
      const ev = {
        intervention: {
          decision: 'block',
          matched_rules: [
            { policy_id: 'a', risk_level: 'medium' },
            { policy_id: 'b', risk_level: 'critical' },
            { policy_id: 'c', risk_level: 'high' },
          ],
        },
      };
      expect(resolveEventSeverity(ev)).toBe('critical');
    });

    it('falls back to intervention.risk_level when matched_rules is empty', () => {
      const ev = {
        intervention: { decision: 'warn', risk_level: 'high' },
      };
      expect(resolveEventSeverity(ev)).toBe('high');
    });

    it('falls back to top-level risk_level', () => {
      const ev = {
        intervention: { decision: 'warn' },
        risk_level: 'medium',
      };
      expect(resolveEventSeverity(ev)).toBe('medium');
    });

    it('falls back to top-level severity (cgroup_anomaly path)', () => {
      const ev = {
        intervention: { decision: 'warn' },
        severity: 'high',
      };
      expect(resolveEventSeverity(ev)).toBe('high');
    });

    it('returns null when no severity field is present', () => {
      expect(resolveEventSeverity({ intervention: { decision: 'block' } })).toBeNull();
      expect(resolveEventSeverity({ event_type: 'process_start' })).toBeNull();
    });

    it('ignores invalid risk_level values (not in {low,medium,high,critical,extreme})', () => {
      const ev = {
        intervention: {
          decision: 'block',
          matched_rules: [{ policy_id: 'a', risk_level: 'foo' }],
          risk_level: 'low',
        },
      };
      expect(resolveEventSeverity(ev)).toBe('low');
    });
  });

  describe('incrementAggregate bySeverity', () => {
    it('aggregates by risk_level from matched_rules with unknown bucket fallback', () => {
      const agg: Aggregate = {
        total: 0,
        byType: {},
        byLayer: {},
        last24h: 0,
        blocks: 0,
        threats: 0,
        modifies: 0,
        audits: 0,
        byDecision: {},
        bySeverity: {},
      };
      const now = Date.now();
      incrementAggregate(agg, JSON.parse(mkEvent({
        decision: 'block',
        matchedRules: [{ policy_id: 'a', risk_level: 'critical' }],
        ts: now,
      })), now);
      incrementAggregate(agg, JSON.parse(mkEvent({
        decision: 'warn',
        matchedRules: [{ policy_id: 'b', risk_level: 'medium' }],
        ts: now,
      })), now);
      // 无 severity 字段 → unknown 桶
      incrementAggregate(agg, JSON.parse(mkEvent({
        decision: 'allow',
        ts: now,
      })), now);
      incrementAggregate(agg, JSON.parse(mkEvent({
        decision: 'block',
        riskLevel: 'high',
        ts: now,
      })), now);

      expect(agg.bySeverity).toEqual({
        critical: 1,
        medium: 1,
        high: 1,
        unknown: 1,
      });
    });
  });

  describe('metrics() exposes bySeverity + byDecision', () => {
    it('returns both dimensions on MetricsResult', async () => {
      const now = Date.now();
      write([
        mkEvent({ decision: 'block', matchedRules: [{ risk_level: 'critical' }], ts: now - 100 }),
        mkEvent({ decision: 'block', matchedRules: [{ risk_level: 'high' }], ts: now - 90 }),
        mkEvent({ decision: 'warn', matchedRules: [{ risk_level: 'medium' }], ts: now - 80 }),
        mkEvent({ decision: 'modify', matchedRules: [{ risk_level: 'low' }], ts: now - 70 }),
        mkEvent({ decision: 'audit', ts: now - 60 }), // no severity → unknown
        mkEvent({ decision: 'allow', ts: now - 50 }), // no severity → unknown（顶层粒度）
      ]);
      const svc = new ControlUiService(file);
      const m = await svc.metrics();
      expect(m.bySeverity).toEqual({
        critical: 1, high: 1, medium: 1, low: 1, unknown: 2,
      });
      expect(m.byDecision).toEqual({
        block: 2, warn: 1, modify: 1, audit: 1,
      });
      // 顶层 counts 与 byDecision 仍保持原口径
      expect(m.blocks).toBe(2);
      expect(m.threats).toBe(5);
    });
  });

  describe('listEvents severity filter', () => {
    it('filters events by severity (matched_rules path)', async () => {
      const now = Date.now();
      write([
        mkEvent({ decision: 'block', matchedRules: [{ risk_level: 'critical' }], ts: now - 100 }),
        mkEvent({ decision: 'block', matchedRules: [{ risk_level: 'high' }], ts: now - 90 }),
        mkEvent({ decision: 'warn', matchedRules: [{ risk_level: 'medium' }], ts: now - 80 }),
      ]);
      const svc = new ControlUiService(file);
      const out = await svc.listEvents({ severity: 'critical', limit: 100 });
      expect(out.events.length).toBe(1);
      expect(out.events[0].intervention.matched_rules[0].risk_level).toBe('critical');
      expect(out.total).toBe(1);
    });

    it('falls back to intervention.risk_level when matched_rules is absent', async () => {
      const now = Date.now();
      write([
        mkEvent({ decision: 'warn', riskLevel: 'low', ts: now - 100 }),
        mkEvent({ decision: 'warn', riskLevel: 'high', ts: now - 90 }),
      ]);
      const svc = new ControlUiService(file);
      const out = await svc.listEvents({ severity: 'low', limit: 100 });
      expect(out.events.length).toBe(1);
      expect(out.total).toBe(1);
    });

    it('filters out events without any severity field (no silent allow)', async () => {
      const now = Date.now();
      write([
        mkEvent({ decision: 'block', ts: now - 100 }), // 无 severity
        mkEvent({ decision: 'block', matchedRules: [{ risk_level: 'critical' }], ts: now - 90 }),
      ]);
      const svc = new ControlUiService(file);
      const out = await svc.listEvents({ severity: 'critical', limit: 100 });
      expect(out.events.length).toBe(1);
      expect(out.total).toBe(1);
    });
  });

  describe('policyHits severity filter + bySeverity + total intersection', () => {
    it('returns bySeverity aggregate alongside byDecision', async () => {
      const now = Date.now();
      write([
        mkEvent({ decision: 'block', matchedRules: [{ risk_level: 'critical' }], ts: now - 100 }),
        mkEvent({ decision: 'block', matchedRules: [{ risk_level: 'high' }], ts: now - 90 }),
        mkEvent({ decision: 'warn', matchedRules: [{ risk_level: 'medium' }], ts: now - 80 }),
        mkEvent({ decision: 'allow', ts: now - 70 }), // 无 severity → unknown
      ]);
      const svc = new ControlUiService(file);
      const out = await svc.policyHits();
      // bySeverity 是顶层聚合（含 allow 无 severity 的 unknown 桶）；
      // byDecision 仅非 allow 决策。两条维度口径独立，前端按需展示。
      expect(out.bySeverity).toEqual({ critical: 1, high: 1, medium: 1, unknown: 1 });
      expect(out.byDecision).toEqual({ block: 2, warn: 1 });
      expect(out.total).toBe(3); // 排除 allow（byDecision 口径）
    });

    it('filters by severity alone (no decision filter)', async () => {
      const now = Date.now();
      write([
        mkEvent({ decision: 'block', matchedRules: [{ risk_level: 'critical' }], ts: now - 100 }),
        mkEvent({ decision: 'block', matchedRules: [{ risk_level: 'high' }], ts: now - 90 }),
        mkEvent({ decision: 'warn', matchedRules: [{ risk_level: 'critical' }], ts: now - 80 }),
      ]);
      const svc = new ControlUiService(file);
      const out = await svc.policyHits({ severity: 'critical' });
      expect(out.hits.length).toBe(2);
      // total 用全决策命中聚合（无 decision 过滤时）；sev 过滤仅为 hits 列表过滤
      expect(out.total).toBe(3);
    });

    it('dual-filter (decision + severity) computes total as intersection length', async () => {
      const now = Date.now();
      write([
        mkEvent({ decision: 'block', matchedRules: [{ risk_level: 'critical' }], ts: now - 100 }),
        mkEvent({ decision: 'block', matchedRules: [{ risk_level: 'high' }], ts: now - 90 }),
        mkEvent({ decision: 'warn', matchedRules: [{ risk_level: 'critical' }], ts: now - 80 }),
      ]);
      const svc = new ControlUiService(file);
      const out = await svc.policyHits({ decision: 'block', severity: 'critical' });
      expect(out.hits.length).toBe(1);
      // total 是精确交集（双过滤时）；hits 长度与 total 一致
      expect(out.total).toBe(1);
    });

    it('decision-only filter (legacy path)', async () => {
      const now = Date.now();
      write([
        mkEvent({ decision: 'block', matchedRules: [{ risk_level: 'critical' }], ts: now - 100 }),
        mkEvent({ decision: 'warn', matchedRules: [{ risk_level: 'high' }], ts: now - 90 }),
      ]);
      const svc = new ControlUiService(file);
      const out = await svc.policyHits({ decision: 'block' });
      expect(out.hits.length).toBe(1);
      expect(out.total).toBe(1);
    });
  });
});
