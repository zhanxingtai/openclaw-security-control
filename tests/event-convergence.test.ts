import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { ApplicationCollector } from '../src/application-collector.js';
import { RuntimeHookCollector } from '../src/runtime-hook-collector.js';
import { normalizeCronEventContext } from '../src/ctxExtract.js';
import { canonicalizePathParams } from '../src/utils/path-params.js';
import type { MiddlewareContext, SecurityEvent } from '../src/types.js';

/**
 * 1.1.0 收敛项的回归护栏。
 *
 * 这些用例守的是"改动之前真实存在过的错误"，每一条都对应一次实际
 * 观测到的现象，不是凭空捏造的断言。
 */

function wait(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForReported(reported: SecurityEvent[], expected: number, timeoutMs = 2000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (reported.length >= expected) return;
    await wait(50);
  }
}

describe('1.1.0 收敛 · 工具调用关联键', () => {
  let collector: { report: (e: SecurityEvent) => Promise<void>; shutdown: () => Promise<void> };
  let appCollector: ApplicationCollector;
  let reported: SecurityEvent[];

  beforeEach(() => {
    reported = [];
    collector = {
      report: vi.fn(async (event: SecurityEvent) => {
        reported.push(event);
      }),
      shutdown: vi.fn(async () => {}),
    };
    appCollector = new ApplicationCollector(
      collector,
      { enabled: true, maxContentLength: 2000, maxResultPreviewLength: 500 },
      { hostId: 'host-test', containerId: 'container-test' }
    );
  });

  afterEach(async () => {
    await appCollector.shutdown();
    await collector.shutdown();
  });

  it('乱序返回的结果不会串到别的工具名下（回归：exec 结果曾被记到 ls 名下）', async () => {
    const execCtx: MiddlewareContext = {
      sessionKey: 'sess-concurrent',
      runId: 'run-001',
      agentId: 'agent-001',
      toolName: 'exec',
      params: { code: 'read({path:"/tmp/x"})' },
    };
    const lsCtx: MiddlewareContext = {
      sessionKey: 'sess-concurrent',
      runId: 'run-001',
      agentId: 'agent-001',
      toolName: 'ls',
      params: { path: '/tmp' },
    };

    // 两个调用几乎同时开始（code-mode 的 exec 是异步的），随后结果乱序返回，
    // 且框架给 after hook 传的是**另一个 ctx 对象**。
    await appCollector.onBeforeToolCall(execCtx);
    await appCollector.onBeforeToolCall(lsCtx);
    await appCollector.onAfterToolCall({ ...execCtx }, { ok: true });
    await appCollector.onAfterToolCall({ ...lsCtx }, { ok: true });

    const results = reported.filter((e) => e.event_type === 'agent_tool_result');
    expect(results).toHaveLength(2);

    const execResult = results.find((e) => e.tool_name === 'exec');
    const lsResult = results.find((e) => e.tool_name === 'ls');
    expect(execResult).toBeDefined();
    expect(lsResult).toBeDefined();

    // 关联键必须各归各位——这是 1.1.0 之前最严重的一条：exec 的结果被
    // 记到 ls 的 tool_call_id 上。
    expect(execResult?.tool_call_id).toContain(':exec:');
    expect(lsResult?.tool_call_id).toContain(':ls:');
    expect(execResult?.tool_call_id).not.toBe(lsResult?.tool_call_id);
  });

  it('结果事件的耗时不再因为别人的开始时间被弹出而丢失', async () => {
    const execCtx: MiddlewareContext = {
      sessionKey: 'sess-duration',
      runId: 'run-001',
      agentId: 'agent-001',
      toolName: 'exec',
      params: {},
    };
    const lsCtx: MiddlewareContext = {
      sessionKey: 'sess-duration',
      runId: 'run-001',
      agentId: 'agent-001',
      toolName: 'ls',
      params: {},
    };

    await appCollector.onBeforeToolCall(execCtx);
    await appCollector.onBeforeToolCall(lsCtx);
    await appCollector.onAfterToolCall({ ...lsCtx }, { ok: true });
    await appCollector.onAfterToolCall({ ...execCtx }, { ok: true });

    const results = reported.filter((e) => e.event_type === 'agent_tool_result');
    for (const r of results) {
      expect(typeof r.duration, `${r.tool_name} 的 duration 丢了`).toBe('number');
    }
  });

  it('blocked 恒为布尔值：未拦截的事件也带 blocked=false', async () => {
    const ctx: MiddlewareContext = {
      sessionKey: 'sess-blocked-flag',
      runId: 'run-001',
      agentId: 'agent-001',
      toolName: 'custom_tool',
      params: {},
    };
    await appCollector.onBeforeToolCall(ctx);
    await appCollector.onAfterToolCall(ctx, { ok: true });

    for (const e of reported) {
      expect(e.blocked, `${e.event_type} 缺少 blocked 键`).toBe(false);
    }
  });

  it('收敛掉的同义字段不再出现', async () => {
    const ctx: MiddlewareContext = {
      sessionKey: 'sess-schema',
      runId: 'run-001',
      agentId: 'agent-001',
      toolName: 'custom_tool',
      params: { path: '/tmp/a.txt' },
    };
    await appCollector.onBeforeToolCall(ctx);
    await appCollector.onAfterToolCall(ctx, { ok: true });

    for (const e of reported) {
      expect(e).not.toHaveProperty('raw_params');
      expect(e).not.toHaveProperty('result');
      expect(e).not.toHaveProperty('execution_status');
      expect(e).not.toHaveProperty('execution_duration_ms');
      expect(e).not.toHaveProperty('result_preview_length');
    }
    const toolCall = reported.find((e) => e.event_type === 'agent_tool_call');
    expect(toolCall?.tool_params).toBe('{"path":"/tmp/a.txt"}');
    expect(toolCall?.tool_params_length).toBe('{"path":"/tmp/a.txt"}'.length);
  });
});

describe('1.1.0 收敛 · 路径别名落盘', () => {
  it('同值别名收敛成单个规范名 path', () => {
    const expanded = {
      path: '/home/node/.openclaw/logs/gateway-restart.log',
      optional: true,
      file_path: '/home/node/.openclaw/logs/gateway-restart.log',
      filepath: '/home/node/.openclaw/logs/gateway-restart.log',
      filePath: '/home/node/.openclaw/logs/gateway-restart.log',
      file: '/home/node/.openclaw/logs/gateway-restart.log',
      src: '/home/node/.openclaw/logs/gateway-restart.log',
      source: '/home/node/.openclaw/logs/gateway-restart.log',
      target: '/home/node/.openclaw/logs/gateway-restart.log',
      destination: '/home/node/.openclaw/logs/gateway-restart.log',
    };
    const out = canonicalizePathParams(expanded);
    expect(Object.keys(out).sort()).toEqual(['optional', 'path']);
    expect(out.path).toBe('/home/node/.openclaw/logs/gateway-restart.log');
  });

  it('多路径语义（src 与 destination 不同）原样保留，不做收敛', () => {
    const multi = { src: '/a.txt', destination: '/b.txt' };
    const out = canonicalizePathParams(multi);
    expect(out.src).toBe('/a.txt');
    expect(out.destination).toBe('/b.txt');
    expect(out).not.toHaveProperty('path');
  });

  it('没有路径参数时原样返回', () => {
    expect(canonicalizePathParams({ command: 'ls' })).toEqual({ command: 'ls' });
  });
});

describe('1.1.0 收敛 · 工具调用参数落盘', () => {
  let collector: { report: (e: SecurityEvent) => Promise<void>; shutdown: () => Promise<void> };
  let appCollector: ApplicationCollector;
  let reported: SecurityEvent[];

  beforeEach(() => {
    reported = [];
    collector = {
      report: vi.fn(async (event: SecurityEvent) => {
        reported.push(event);
      }),
      shutdown: vi.fn(async () => {}),
    };
    appCollector = new ApplicationCollector(
      collector,
      { enabled: true, maxContentLength: 2000, maxResultPreviewLength: 500 },
      { hostId: 'host-test', containerId: 'container-test' }
    );
  });

  afterEach(async () => {
    await appCollector.shutdown();
    await collector.shutdown();
  });

  it('宿主展开的 9 个路径别名在 params / tool_params 上收敛成唯一 path', async () => {
    const p = '/home/node/.openclaw/logs/gateway-restart.log';
    const ctx: MiddlewareContext = {
      sessionKey: 'sess-alias',
      runId: 'run-001',
      agentId: 'agent-001',
      toolName: 'read',
      params: {
        path: p,
        optional: true,
        file_path: p,
        filepath: p,
        filePath: p,
        file: p,
        src: p,
        source: p,
        target: p,
        destination: p,
      },
    };

    await appCollector.onBeforeToolCall(ctx);

    // `read` 是文件类工具，事件类型归一为 file_read。
    const event = reported.find((e) => e.tool_name === 'read');
    expect(event?.event_type).toBe('file_read');
    // params 对象视图已删除（agent.json 1.1.0）：tool_params 是唯一载荷。
    const toolParams = JSON.parse(event?.tool_params ?? '{}') as Record<string, unknown>;
    expect(Object.keys(toolParams).sort()).toEqual(['optional', 'path']);
    expect(toolParams.path).toBe(p);
    expect('params' in (event as Record<string, unknown>)).toBe(false);
  });

  it('多路径工具的别名保持原样，不被合并成一个 path', async () => {
    const ctx: MiddlewareContext = {
      sessionKey: 'sess-multi',
      runId: 'run-001',
      agentId: 'agent-001',
      toolName: 'copy',
      params: { src: '/a.txt', destination: '/b.txt' },
    };

    await appCollector.onBeforeToolCall(ctx);

    const event = reported.find((e) => e.event_type === 'agent_tool_call');
    const toolParams = JSON.parse(event?.tool_params ?? '{}') as Record<string, unknown>;
    expect(toolParams.src).toBe('/a.txt');
    expect(toolParams.destination).toBe('/b.txt');
    expect(toolParams).not.toHaveProperty('path');
  });
});

describe('1.1.0 收敛 · cron 作业身份', () => {
  it('ctx.cron 是字符串时不会短路掉 ctx.cronTask（回归：作业身份整个丢失）', () => {
    const ctx = normalizeCronEventContext({
      context: {
        action: 'started',
        cron: '0 4 * * *',
        cronTask: { id: 'job-42', name: 'daily-dump', schedule: '0 4 * * *' },
      },
    });
    expect(ctx?.cronId).toBe('job-42');
    expect(ctx?.cronName).toBe('daily-dump');
    expect(ctx?.schedule).toBe('0 4 * * *');
    expect(ctx?.action).toBe('started');
  });

  it('ctx.cron 是 cron 表达式字符串时被当作 schedule 收下', () => {
    const ctx = normalizeCronEventContext({
      context: { action: 'scheduled', cron: '*/5 * * * *' },
    });
    expect(ctx?.schedule).toBe('*/5 * * * *');
  });

  it('宿主直接给 cronId/cronName 时照单全收', () => {
    const ctx = normalizeCronEventContext({
      context: { action: 'finished', cronId: 'c-1', cronName: 'nightly' },
    });
    expect(ctx?.cronId).toBe('c-1');
    expect(ctx?.cronName).toBe('nightly');
  });

  it('只有 runId 时 sessionKey 不再回退成 runId（规范：session 未知写 null）', () => {
    const ctx = normalizeCronEventContext({
      context: { action: 'started', runId: 'run-9' },
    });
    // 1.1.0 之前这里是 'run-9'：session_id 被填成 run_id，不同会话的事件被
    // 假性关联成同一会话。现在拿不到 session 就是 undefined → 事件落 null。
    expect(ctx?.sessionKey).toBeUndefined();
    expect(ctx?.runId).toBe('run-9');
  });
});

describe('1.1.0 收敛 · runtime 采集', () => {
  let logFile: string;
  let collector: { report: (e: SecurityEvent) => Promise<void>; shutdown: () => Promise<void> };
  let runtimeCollector: RuntimeHookCollector;
  let reported: SecurityEvent[];

  beforeEach(() => {
    reported = [];
    logFile = path.join(os.tmpdir(), `openclaw-convergence-${Date.now()}.jsonl`);
    fs.writeFileSync(logFile, '', 'utf8');
    collector = {
      report: async (event: SecurityEvent) => {
        reported.push(event);
      },
      shutdown: async () => {},
    };
  });

  afterEach(async () => {
    await runtimeCollector.shutdown();
    for (const f of [logFile, `${logFile}.offset`]) {
      try {
        fs.unlinkSync(f);
      } catch {
        /* ignore */
      }
    }
  });

  it('content 按 maxContentLength 截断，content_length 保持原始长度', async () => {
    runtimeCollector = new RuntimeHookCollector(collector, {
      enabled: true,
      logPath: logFile,
      maxContentLength: 100,
    });
    await runtimeCollector.initialize();

    const body = 'x'.repeat(5000);
    fs.appendFileSync(
      logFile,
      JSON.stringify({
        event_type: 'network_http',
        timestamp: new Date().toISOString(),
        method: 'GET',
        url: '/api/v1/plugins/overview',
        request_url: 'https://clawhub.ai/api/v1/plugins/overview',
        host: 'clawhub.ai',
        code: 200,
        content: body,
      }) + '\n',
      'utf8'
    );

    await waitForReported(reported, 1);
    expect(reported).toHaveLength(1);
    expect(reported[0].content?.length).toBe(100);
    expect(reported[0].content_length).toBe(5000);
    expect(reported[0].content_truncated).toBe(true);
  });

  it('宿主自有内部 worker 的子进程默认不再落盘', async () => {
    runtimeCollector = new RuntimeHookCollector(collector, {
      enabled: true,
      logPath: logFile,
    });
    await runtimeCollector.initialize();

    fs.appendFileSync(
      logFile,
      JSON.stringify({
        event_type: 'command_execution',
        timestamp: new Date().toISOString(),
        command_line:
          '/usr/local/bin/node /app/dist/infra/sqlite-readonly-location.worker.js --openclaw-sqlite-readonly-child session',
        executable: '/usr/local/bin/node',
      }) + '\n',
      'utf8'
    );
    fs.appendFileSync(
      logFile,
      JSON.stringify({
        event_type: 'command_execution',
        timestamp: new Date().toISOString(),
        command_line: 'cat /etc/passwd',
        executable: 'cat',
      }) + '\n',
      'utf8'
    );

    await waitForReported(reported, 1);
    await wait(300);
    expect(reported).toHaveLength(1);
    expect(reported[0].cmdline).toBe('cat /etc/passwd');
  });

  it('关掉内置排除后宿主内部 worker 重新落盘', async () => {
    runtimeCollector = new RuntimeHookCollector(collector, {
      enabled: true,
      logPath: logFile,
      excludeHostInternalProcesses: false,
    });
    await runtimeCollector.initialize();

    fs.appendFileSync(
      logFile,
      JSON.stringify({
        event_type: 'command_execution',
        timestamp: new Date().toISOString(),
        command_line:
          '/usr/local/bin/node /app/dist/infra/sqlite-readonly-location.worker.js --openclaw-sqlite-readonly-child session',
        executable: '/usr/local/bin/node',
      }) + '\n',
      'utf8'
    );

    await waitForReported(reported, 1);
    expect(reported).toHaveLength(1);
    expect(reported[0].cmdline).toContain('--openclaw-sqlite-readonly-child');
  });
});
