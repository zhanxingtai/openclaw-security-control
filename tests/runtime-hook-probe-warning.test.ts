/**
 * 决策 1：bootstrap 探测 runtime hook 未加载且用户未主动关闭
 * runtimeHooks 时，store 初始化完成后向事件流补写一条 WARN 级
 * unpatched_engine 事件；security.status 携带 runtimeHookLoaded /
 * runtimeHooksEnabled 供面板持久状态条使用。用户主动关闭 → 不告警。
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { readFileSync, existsSync, mkdtempSync, rmSync } from 'fs';
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

describe('runtime hook 探测失败告警', () => {
  let tmpDir: string;
  let ndjsonPath: string;
  let store: SecurityMonitorStore;

  beforeEach(async () => {
    tmpDir = mkdtempSync(join(tmpdir(), 'hook-probe-warn-'));
    ndjsonPath = join(tmpDir, 'security-events.jsonl');
    store = new SecurityMonitorStore();
    await store.initialize({
      collector: { ndjsonPath },
      application: { enabled: true, runtimeHooks: { enabled: false } },
      system: { enabled: false },
      network: { enabled: false },
      assetMonitor: { enabled: false },
      intervention: { enabled: false },
    });
  });

  afterEach(async () => {
    await store.shutdown();
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('探测失败 + 用户未关闭 → WARN 事件携带 unpatched_engine，status 透出探测状态', async () => {
    // register() 顺序：initializePlugin 后同步记录状态，initialize 完成后补写事件。
    store.setRuntimeHookProbeState(false, true);
    await store.emitRuntimeHookProbeWarningIfNeeded();

    const events = readEvents(ndjsonPath);
    const warn = events.find((e) => e.event_type === 'x_openclaw_runtime_hook_unloaded') as
      | (SecurityEvent & { severity?: string; risk_flags?: string[] })
      | undefined;
    expect(warn).toBeDefined();
    expect(warn?.severity).toBe('warn');
    expect(warn?.risk_flags).toContain('unpatched_engine');

    const status = store.getStatus();
    expect(status.runtimeHookLoaded).toBe(false);
    expect(status.runtimeHooksEnabled).toBe(true);
  });

  it('用户主动关闭 runtimeHooks → 不写告警事件', async () => {
    store.setRuntimeHookProbeState(false, false);
    await store.emitRuntimeHookProbeWarningIfNeeded();
    const events = readEvents(ndjsonPath);
    expect(events.some((e) => e.event_type === 'x_openclaw_runtime_hook_unloaded')).toBe(false);

    const status = store.getStatus();
    expect(status.runtimeHookLoaded).toBe(false);
    expect(status.runtimeHooksEnabled).toBe(false);
  });

  it('探测通过 → 不写告警事件', async () => {
    store.setRuntimeHookProbeState(true, true);
    await store.emitRuntimeHookProbeWarningIfNeeded();
    const events = readEvents(ndjsonPath);
    expect(events.some((e) => e.event_type === 'x_openclaw_runtime_hook_unloaded')).toBe(false);
    expect(store.getStatus().runtimeHookLoaded).toBe(true);
  });

  it('bootstrap 未上报（legacy 路径）→ status 字段为 null，不告警', async () => {
    await store.emitRuntimeHookProbeWarningIfNeeded();
    const status = store.getStatus();
    expect(status.runtimeHookLoaded).toBeNull();
    // 未上报时回退到生效配置里的开关值
    expect(status.runtimeHooksEnabled).toBe(false);
    const events = readEvents(ndjsonPath);
    expect(events.some((e) => e.event_type === 'x_openclaw_runtime_hook_unloaded')).toBe(false);
  });
});
