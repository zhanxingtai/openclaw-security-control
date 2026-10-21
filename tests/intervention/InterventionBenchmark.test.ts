import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { InterventionEngineImpl } from '../../src/intervention/InterventionEngine.js';
import type { InterventionContext } from '../../src/intervention/types.js';

/**
 * 2026-09-12 P3 (#1): CI 性能回归哨兵（标准 2.4）。
 * 覆盖 N=100/1000/5000 三档含 paramsRegex 规则的评估延迟。
 *
 * 注意：这是回归哨兵而非精确基准——阈值留足共享 CI 环境余量；
 * 对客性能声明以发布前实测数据为准。
 */

function buildPolicy(n: number): string {
  const rules = Array.from({ length: n }, (_, i) => ({
    id: `rule-${i}`,
    priority: i,
    match: {
      actionType: ['tool_call'],
      toolName: ['file_read'],
      paramsRegex: { path: [`^/sensitive/dir-${i}/`] },
    },
    action: { decision: 'allow' },
  }));
  return JSON.stringify({ version: '1.0.0', rules });
}

function percentile(sorted: number[], p: number): number {
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return sorted[idx];
}

const CASES = [
  { n: 100, iterations: 300, p95BudgetMs: 10 },
  { n: 1000, iterations: 300, p95BudgetMs: 30 },
  // N=5000 档预算 80-100ms：共享 runner 上 50ms 余量仅
  // 2.2x，有 flaky 风险；放宽到 100ms 后余量约 4x。
  { n: 5000, iterations: 200, p95BudgetMs: 100 },
];

describe.each(CASES)('intervention benchmark N=$n', ({ n, iterations, p95BudgetMs }) => {
  let tmpDir: string;
  let engine: InterventionEngineImpl;

  // 不匹配任何规则的上下文：每轮评估都走完全量 N 条规则的维度扫描
  // （actionType/actionName 命中后由 paramsRegex 否决），即最坏线性扫描。
  const ctx: InterventionContext = {
    actionType: 'tool_call',
    toolName: 'file_read',
    params: { path: '/tmp/benign' },
  };

  beforeEach(async () => {
    tmpDir = mkdtempSync(join(tmpdir(), `intervention-bench-${n}-`));
    const policyPath = join(tmpDir, 'policy.json');
    writeFileSync(policyPath, buildPolicy(n));
    engine = new InterventionEngineImpl({
      ruleLoader: { policyPath, reloadIntervalMs: 0 },
      // 0 = 关闭评估超时包装，基准测量的是纯评估延迟。
      decisionTimeoutMs: 0,
      failStrategy: 'fail_open',
    });
    await engine.initialize();
  });

  afterEach(async () => {
    await engine.shutdown();
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it(`full scan of ${n} paramsRegex rules keeps p95 < ${p95BudgetMs}ms`, async () => {
    const latencies: number[] = [];
    for (let i = 0; i < iterations; i++) {
      const start = performance.now();
      const decision = await engine.evaluate(ctx);
      latencies.push(performance.now() - start);
      expect(decision.decision).toBe('allow');
    }

    const sorted = [...latencies].sort((a, b) => a - b);
    const avg = latencies.reduce((sum, v) => sum + v, 0) / latencies.length;
    const p95 = percentile(sorted, 95);
    const p99 = percentile(sorted, 99);
    console.log(`N=${n} iterations=${iterations} avg=${avg.toFixed(2)}ms p95=${p95.toFixed(2)}ms p99=${p99.toFixed(2)}ms`);

    expect(p95).toBeLessThan(p95BudgetMs);

    const stats = engine.getStats();
    expect(stats.evaluations).toBe(iterations);
    // 兜底（超时/异常）不得混入基准采样，否则延迟与决策语义均被污染。
    expect(stats.fallbacks).toBe(0);
  });
});
