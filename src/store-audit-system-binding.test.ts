/**
 * audit 模式下 beforeToolCall 会提前 return，但 burst/bind 块在 audit
 * 早退之前执行，保证 enterBurstScan / bindProcessContext 与 afterToolCall
 * 的 exitBurstScan 成对——audit 模式下短生命周期命令也能触发 burst
 * 高频扫描，process_start 事件具备 session 归因；audit 不拦截语义不变。
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { SecurityMonitorStore } from './store.js';
import { SystemCollector } from './system-collector.js';
import { normalizeConfig } from './config.js';
import type { MiddlewareContext } from './types.js';

describe('audit 模式 tool call 的 system 层 burst/bind', () => {
  let tmpDir: string;
  let store: SecurityMonitorStore;
  let enterSpy: ReturnType<typeof vi.spyOn>;
  let exitSpy: ReturnType<typeof vi.spyOn>;
  let bindSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'store-audit-system-'));
    const config = normalizeConfig({
      collector: { ndjsonPath: join(tmpDir, 'events.jsonl') },
      application: { enabled: true },
      intervention: { enabled: false, mode: 'audit' },
      system: { enabled: true, procfs: { enabled: true } },
    });
    store = new SecurityMonitorStore(config);
    enterSpy = vi.spyOn(SystemCollector.prototype, 'enterBurstScan');
    exitSpy = vi.spyOn(SystemCollector.prototype, 'exitBurstScan');
    bindSpy = vi.spyOn(SystemCollector.prototype, 'bindProcessContext');
  });

  afterEach(() => {
    enterSpy.mockRestore();
    exitSpy.mockRestore();
    bindSpy.mockRestore();
    rmSync(tmpDir, { recursive: true, force: true });
  });

  function toolCtx(): MiddlewareContext {
    return {
      sessionKey: 'sess-audit-1',
      agentId: 'agent-1',
      runId: 'run-1',
      toolName: 'exec',
      params: { command: 'ls /tmp' },
    };
  }

  it('audit 模式 beforeToolCall 进入 burst 扫描并绑定进程上下文', async () => {
    const ctx = toolCtx();
    const result = await store.beforeToolCall(ctx);

    expect(result.block).toBe(false);
    expect(enterSpy).toHaveBeenCalledTimes(1);
    expect(bindSpy).toHaveBeenCalledTimes(1);
    const bound = bindSpy.mock.calls[0][0] as { sessionId?: string; runId?: string; toolName?: string };
    expect(bound.sessionId).toBe('sess-audit-1');
    expect(bound.runId).toBe('run-1');
    expect(bound.toolName).toBe('exec');
  });

  it('audit 模式 enter/exit burst 成对，tool call 结束后退出 burst', async () => {
    const ctx = toolCtx();
    await store.beforeToolCall(ctx);
    await store.afterToolCall(ctx, { ok: true });

    expect(exitSpy).toHaveBeenCalledTimes(1);
    expect(enterSpy).toHaveBeenCalledTimes(1);
  });

  it('audit 模式带循环引用 params 的 tool call 不抛 RangeError（SelfProtection）', async () => {
    const ctx = toolCtx();
    const cyclic: Record<string, unknown> = { command: 'ls /tmp' };
    cyclic.self = cyclic;
    ctx.params = cyclic;

    await expect(store.beforeToolCall(ctx)).resolves.toEqual({ block: false });
    await expect(store.afterToolCall(ctx, undefined)).resolves.toBeUndefined();
  });
});
