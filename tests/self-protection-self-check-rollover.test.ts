/**
 * 自保护自检：插件自身的体积轮转不得报成"受保护文件被删"。
 *
 * 场景：EventBridgeCollector 按 maxFileSizeBytes 把事件文件改名成
 * `<path>.rotated` 后重建。改名与重建之间规范路径短暂不存在；若重建
 * 失败（append 报错/进程先退），文件还会一直空着。下一次自检拿旧基线
 * （比如 6.3MB）比对"文件不存在"，就会误报 x_openclaw_tamper_detected
 * "protected file deleted" —— 告警是插件自己造成的。
 *
 * 判据：旁挂的 `<path>.rotated` 存在、装得下上一份基线、且是上次观测
 * 之后才挪走的 → 判为自伤轮转，只重置基线不报篡改。没有旁挂文件
 * （真删除）仍然照报。
 *
 * 自检本身由 60s 定时器驱动（实现细节，不是不变式）；这里直接驱动自检
 * 入口，避免把断言绑在定时器节奏上。
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { existsSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { SecurityMonitorStore } from '../src/store.js';
import type { SecurityEvent } from '../src/types.js';

function readEvents(ndjsonPath: string): SecurityEvent[] {
  if (!existsSync(ndjsonPath)) return [];
  return readFileSync(ndjsonPath, 'utf8')
    .split('\n')
    .filter((line) => line.trim())
    .map((line) => JSON.parse(line) as SecurityEvent);
}

describe('自保护自检：自身轮转不误报篡改', () => {
  let tmpDir: string;
  let ndjsonPath: string;
  let store: SecurityMonitorStore | undefined;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'selfcheck-rollover-'));
    ndjsonPath = join(tmpDir, 'security-events.jsonl');
  });

  afterEach(async () => {
    await store?.shutdown();
    store = undefined;
    rmSync(tmpDir, { recursive: true, force: true });
  });

  async function startStore(): Promise<void> {
    store = new SecurityMonitorStore();
    await store.initialize({
      collector: { ndjsonPath },
      application: { enabled: true, runtimeHooks: { enabled: false } },
      system: { enabled: false },
      network: { enabled: false },
      assetMonitor: { enabled: false },
      intervention: { enabled: false },
    });
  }

  async function runSelfCheck(): Promise<void> {
    await (
      store as unknown as { runSelfProtectionSelfCheck(): Promise<void> }
    ).runSelfProtectionSelfCheck();
  }

  it('插件自己把事件文件轮转走 → 不产生 tamper_detected', async () => {
    writeFileSync(ndjsonPath, 'x'.repeat(4096));
    await startStore();

    // 第一拍：记录基线（文件在，4096 字节）
    await runSelfCheck();

    // 模拟插件自身的体积轮转：改名成 .rotated，规范路径此刻不存在
    renameSync(ndjsonPath, `${ndjsonPath}.rotated`);

    // 第二拍：规范路径仍不存在（未修复时这里会误报"被删"）
    await runSelfCheck();

    const tamper = readEvents(ndjsonPath).filter((e) => e.event_type === 'x_openclaw_tamper_detected');
    expect(tamper).toHaveLength(0);
  });

  it('真删除（无旁挂文件）仍然报 tamper_detected', async () => {
    writeFileSync(ndjsonPath, 'x'.repeat(4096));
    await startStore();

    await runSelfCheck();

    // 规范路径与旁挂文件都不在 → 真删除
    rmSync(ndjsonPath);

    await runSelfCheck();

    const tamper = readEvents(ndjsonPath).filter((e) => e.event_type === 'x_openclaw_tamper_detected');
    expect(tamper).toHaveLength(1);
    expect((tamper[0] as SecurityEvent & { detail?: string }).detail).toBe('protected file deleted');
  });

  it('旁挂文件装不下上一份基线 → 仍按真删除报（不给自己开免罪金牌）', async () => {
    writeFileSync(ndjsonPath, 'x'.repeat(4096));
    await startStore();

    await runSelfCheck();

    // 旁挂文件比基线小 → 不是被挪走的那份文件，是外部伪造
    writeFileSync(`${ndjsonPath}.rotated`, 'x'.repeat(16));
    rmSync(ndjsonPath);

    await runSelfCheck();

    const tamper = readEvents(ndjsonPath).filter((e) => e.event_type === 'x_openclaw_tamper_detected');
    expect(tamper).toHaveLength(1);
  });
});
