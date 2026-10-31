import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { createHash } from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { RuntimeHookCollector } from './runtime-hook-collector.js';
import type { SecurityEvent } from './types.js';

function wait(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

const WAIT_TIME = 1000;

async function waitForReported(reported: SecurityEvent[], expectedLength: number, timeoutMs = 2000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (reported.length >= expectedLength) return;
    await wait(50);
  }
}

describe('RuntimeHookCollector', () => {
  let logFile: string;
  let collector: { report: (event: SecurityEvent) => Promise<void>; shutdown: () => Promise<void> };
  let runtimeCollector: RuntimeHookCollector;
  let reported: SecurityEvent[];

  beforeEach(() => {
    reported = [];

    logFile = path.join(os.tmpdir(), `openclaw-runtime-collector-test-${Date.now()}.jsonl`);
    fs.writeFileSync(logFile, '', 'utf8');

    collector = {
      report: async (event: SecurityEvent) => {
        reported.push(event);
      },
      shutdown: async () => {},
    };

    runtimeCollector = new RuntimeHookCollector(collector, {
      enabled: true,
      logPath: logFile,
    });
  });

  afterEach(async () => {
    await runtimeCollector.shutdown();
    try {
      fs.unlinkSync(logFile);
    } catch {
      // ignore
    }
    try {
      fs.unlinkSync(`${logFile}.offset`);
    } catch {
      // ignore
    }
  });

  it('ignores unrelated JSON lines', async () => {
    await runtimeCollector.initialize();
    fs.appendFileSync(logFile, '{"type":"noise"}\n', 'utf8');
    await wait(300);
    expect(reported).toHaveLength(0);
  });

  it('forwards legacy command_execution events as process_start', async () => {
    await runtimeCollector.initialize();
    const event = {
      type: 'application.command_execution',
      event_type: 'command_execution',
      id: 'evt-1',
      timestamp: new Date().toISOString(),
      runtime: 'node',
      api: 'child_process.exec',
      command_line: 'ls -la',
      executable: 'ls',
      shell_involved: false,
      cwd: '/tmp',
      pid: 1234,
      ppid: 1,
      session_id: 'sess-1',
      run_id: 'run-1',
      tool_call_id: 'call-1',
    };
    fs.appendFileSync(logFile, JSON.stringify(event) + '\n', 'utf8');

    await waitForReported(reported, 1);

    expect(reported).toHaveLength(1);
    expect(reported[0].event_type).toBe('process_start');
    expect(reported[0].layer).toBe('system');
    expect(reported[0].cmdline).toBe('ls -la');
    expect(reported[0].exe).toBe('ls');
    expect(reported[0].comm).toBe('openclaw');
    expect(reported[0].session_id).toBe('sess-1');
    expect(reported[0].tool_call_id).toBe('call-1');
  });

  it('keeps the source event id and source timestamp instead of regenerating them', async () => {
    await runtimeCollector.initialize();
    const sourceTs = '2026-10-20T08:00:00.000Z';
    fs.appendFileSync(
      logFile,
      JSON.stringify({
        event_type: 'process_start',
        type: 'application.process_start',
        id: 'src-uuid-1',
        event_id: 'src-uuid-1',
        ts: sourceTs,
        runtime: 'node',
        api: 'child_process.spawn',
        command_line: 'ls -la',
        executable: 'ls',
        pid: 4321,
        ppid: 1,
      }) + '\n',
      'utf8'
    );

    await waitForReported(reported, 1);

    expect(reported).toHaveLength(1);
    // The source id is the event's stable identity: it is what makes a
    // replayed sidecar line de-duplicable, and what lets an auditor trace
    // the event back to the runtime hook that produced it.
    expect(reported[0].event_id).toBe('src-uuid-1');
    // The source timestamp is when the command actually ran — falling back
    // to "now" would silently rewrite the audit timeline.
    expect(reported[0].ts).toBe(Date.parse(sourceTs));
  });

  it('drops a replayed source event instead of writing it once per replay', async () => {
    await runtimeCollector.initialize();
    const line =
      JSON.stringify({
        event_type: 'process_start',
        type: 'application.process_start',
        id: 'src-uuid-replay',
        event_id: 'src-uuid-replay',
        ts: '2026-10-20T08:00:00.000Z',
        runtime: 'node',
        api: 'child_process.spawn',
        command_line: '/usr/bin/lsof -nP -iTCP:18789',
        executable: '/usr/bin/lsof',
        pid: 368,
        ppid: 8,
      }) + '\n';
    fs.appendFileSync(logFile, line, 'utf8');
    fs.appendFileSync(logFile, line, 'utf8');
    fs.appendFileSync(logFile, line, 'utf8');

    await waitForReported(reported, 1);
    await wait(400);

    expect(reported).toHaveLength(1);
    expect(runtimeCollector.getStats().eventsDeduplicated).toBe(2);
  });

  it('drops the same command repeated by the same call site inside the dedup window', async () => {
    await runtimeCollector.initialize();
    const base = {
      event_type: 'process_start',
      type: 'application.process_start',
      ts: '2026-10-20T08:00:00.000Z',
      runtime: 'node',
      api: 'child_process.spawn',
      command_line: '/usr/bin/lsof -nP -iTCP:18789',
      executable: '/usr/bin/lsof',
      pid: 368,
      ppid: 8,
      caller: { function: 'spawn', file: '/app/dist/spawn.js', line: 42, column: 7 },
    };
    // Distinct ids: only the command-window fingerprint can catch these.
    fs.appendFileSync(logFile, JSON.stringify({ ...base, id: 'a', event_id: 'a' }) + '\n', 'utf8');
    fs.appendFileSync(logFile, JSON.stringify({ ...base, id: 'b', event_id: 'b' }) + '\n', 'utf8');

    await waitForReported(reported, 1);
    await wait(400);

    expect(reported).toHaveLength(1);
  });

  it('keeps the same command when the call site differs', async () => {
    await runtimeCollector.initialize();
    const base = {
      event_type: 'process_start',
      type: 'application.process_start',
      ts: '2026-10-20T08:00:00.000Z',
      runtime: 'node',
      api: 'child_process.spawn',
      command_line: 'ls -la',
      executable: 'ls',
      pid: 368,
      ppid: 8,
    };
    fs.appendFileSync(
      logFile,
      JSON.stringify({
        ...base,
        id: 'c',
        event_id: 'c',
        caller: { function: 'spawn', file: '/app/dist/a.js', line: 1, column: 1 },
      }) + '\n',
      'utf8'
    );
    fs.appendFileSync(
      logFile,
      JSON.stringify({
        ...base,
        id: 'd',
        event_id: 'd',
        caller: { function: 'spawn', file: '/app/dist/b.js', line: 2, column: 2 },
      }) + '\n',
      'utf8'
    );

    await waitForReported(reported, 2);
    await wait(400);

    // Two different call sites are two different actions, not a duplicate.
    expect(reported).toHaveLength(2);
  });

  it('normalizes empty-string context fields to null', async () => {
    await runtimeCollector.initialize();
    fs.appendFileSync(
      logFile,
      JSON.stringify({
        event_type: 'process_start',
        type: 'application.process_start',
        id: 'src-empty-ctx',
        ts: '2026-10-20T08:00:00.000Z',
        runtime: 'node',
        api: 'child_process.spawn',
        command_line: 'ls -la',
        executable: 'ls',
        pid: 4321,
        ppid: 1,
        session_id: '',
        run_id: '',
        agent_id: '',
        tool_call_id: '',
        tool_name: '',
      }) + '\n',
      'utf8'
    );

    await waitForReported(reported, 1);

    expect(reported).toHaveLength(1);
    // "absent" must not be spelled three different ways ("", null, missing).
    expect(reported[0].agent_id).toBeNull();
    expect(reported[0].session_id).toBeNull();
    expect(reported[0].run_id).toBeNull();
    expect(reported[0].tool_call_id).toBeNull();
    expect(reported[0].tool_name).toBeNull();
  });

  it('filters command_execution events matching excludeCommandLines patterns', async () => {
    runtimeCollector = new RuntimeHookCollector(collector, {
      enabled: true,
      logPath: logFile,
      excludeCommandLines: ['^ip neigh show$', 'PUBLIC_SHARED_PATH'],
    });
    await runtimeCollector.initialize();

    const noiseEvents = [
      {
        event_type: 'command_execution',
        timestamp: new Date().toISOString(),
        command_line: 'ip neigh show',
        executable: 'ip',
      },
      {
        event_type: 'command_execution',
        timestamp: new Date().toISOString(),
        command_line: 'sh -c echo "=== Expired dirs ===" && find "$PUBLIC_SHARED_PATH" -mtime +7',
        executable: 'sh',
      },
    ];
    const realEvent = {
      event_type: 'command_execution',
      timestamp: new Date().toISOString(),
      command_line: 'cat /etc/passwd',
      executable: 'cat',
    };

    for (const event of noiseEvents) {
      fs.appendFileSync(logFile, JSON.stringify(event) + '\n', 'utf8');
    }
    fs.appendFileSync(logFile, JSON.stringify(realEvent) + '\n', 'utf8');

    await waitForReported(reported, 1);

    expect(reported).toHaveLength(1);
    expect(reported[0].cmdline).toBe('cat /etc/passwd');
  });

  it('skips pre-existing log content by default to avoid replay noise', async () => {
    // Simulate a log file that already contains historical events from a
    // previous run. With the default settings (replayOnFirstRun=false) the
    // collector must NOT replay these — otherwise a restart would inject
    // hundreds of MB of stale network_http traffic into the collector.
    const event = {
      event_type: 'command_execution',
      id: 'evt-existing',
      timestamp: new Date().toISOString(),
      runtime: 'node',
      api: 'child_process.exec',
      command_line: 'ls -la',
      executable: 'ls',
      shell_involved: false,
      cwd: '/tmp',
      pid: 1234,
      ppid: 1,
    };
    fs.appendFileSync(logFile, JSON.stringify(event) + '\n', 'utf8');

    await runtimeCollector.initialize();
    await waitForReported(reported, 0);

    expect(reported).toHaveLength(0);

    // After init the cursor sidecar should mark EOF so a subsequent restart
    // also skips the historical content.
    expect(fs.existsSync(`${logFile}.offset`)).toBe(true);
    const persisted = Number(fs.readFileSync(`${logFile}.offset`, 'utf8').trim());
    expect(persisted).toBeGreaterThan(0);
  });

  it('replays pre-existing content when replayOnFirstRun is explicitly enabled', async () => {
    runtimeCollector = new RuntimeHookCollector(collector, {
      enabled: true,
      logPath: logFile,
      replayOnFirstRun: true,
    });

    const event = {
      event_type: 'command_execution',
      id: 'evt-existing',
      timestamp: new Date().toISOString(),
      runtime: 'node',
      api: 'child_process.exec',
      command_line: 'ls -la',
      executable: 'ls',
      shell_involved: false,
      cwd: '/tmp',
      pid: 1234,
      ppid: 1,
    };
    fs.appendFileSync(logFile, JSON.stringify(event) + '\n', 'utf8');

    await runtimeCollector.initialize();
    await waitForReported(reported, 1);

    expect(reported).toHaveLength(1);
    expect(reported[0].event_type).toBe('process_start');
    expect(reported[0].cmdline).toBe('ls -la');
  });

  it('rotates the runtime log when it exceeds maxLogSizeBytes', async () => {
    runtimeCollector = new RuntimeHookCollector(collector, {
      enabled: true,
      logPath: logFile,
      maxLogSizeBytes: 100,
    });

    await runtimeCollector.initialize();
    await wait(300);

    const event = {
      event_type: 'command_execution',
      timestamp: new Date().toISOString(),
      command_line: 'python -c "print(' + '"x"'.repeat(200) + ')"',
      executable: 'python',
    };
    fs.appendFileSync(logFile, JSON.stringify(event) + '\n', 'utf8');

    await wait(600);

    expect(reported).toHaveLength(1);
    expect(reported[0].event_type).toBe('process_start');

    // Rotated file should be cleaned up after draining.
    expect(fs.existsSync(`${logFile}.rotated`)).toBe(false);
    // Active log path should be empty or not yet recreated by the hook.
    if (fs.existsSync(logFile)) {
      expect(fs.statSync(logFile).size).toBeLessThanOrEqual(100);
    }
  });

  it('resumes from persisted cursor across restart instead of replaying', async () => {
    // Phase 1: write an event, init with replay enabled so we drain it,
    // then shut down. This leaves a sidecar cursor at EOF.
    const e1 = {
      event_type: 'command_execution',
      timestamp: new Date().toISOString(),
      command_line: 'ls -la',
      executable: 'ls',
    };
    const e2 = {
      event_type: 'command_execution',
      timestamp: new Date().toISOString(),
      command_line: 'cat /etc/hosts',
      executable: 'cat',
    };
    fs.appendFileSync(logFile, JSON.stringify(e1) + '\n', 'utf8');

    runtimeCollector = new RuntimeHookCollector(collector, {
      enabled: true,
      logPath: logFile,
      replayOnFirstRun: true,
    });
    await runtimeCollector.initialize();
    await wait(400);
    expect(reported.map((r) => r.cmdline)).toEqual(['ls -la']);

    // Simulate gateway restart. A fresh collector with default
    // settings should resume from the persisted cursor and ONLY see new
    // traffic — not the already-drained `ls -la`.
    await runtimeCollector.shutdown();
    reported.length = 0;
    fs.appendFileSync(logFile, JSON.stringify(e2) + '\n', 'utf8');

    runtimeCollector = new RuntimeHookCollector(collector, {
      enabled: true,
      logPath: logFile,
    });
    await runtimeCollector.initialize();
    await wait(400);

    expect(reported.map((r) => r.cmdline)).toEqual(['cat /etc/hosts']);
  });

  it('recovers early events via firstRunLookbackBytes when no cursor exists', async () => {
    const early = {
      event_type: 'command_execution',
      timestamp: new Date().toISOString(),
      command_line: 'echo early',
      executable: 'echo',
    };
    fs.appendFileSync(logFile, JSON.stringify(early) + '\n', 'utf8');

    runtimeCollector = new RuntimeHookCollector(collector, {
      enabled: true,
      logPath: logFile,
      // Only recover the last ~1 KB so we don't pull the whole historical file.
      firstRunLookbackBytes: 1024,
    });
    await runtimeCollector.initialize();
    await wait(400);

    expect(reported.map((r) => r.cmdline)).toEqual(['echo early']);
  });

  it('forwards legacy command_execution events using event_type only', async () => {
    await runtimeCollector.initialize();
    const event = {
      event_type: 'command_execution',
      id: 'evt-1b',
      timestamp: new Date().toISOString(),
      runtime: 'node',
      api: 'child_process.exec',
      command_line: 'curl https://example.com',
      executable: 'curl',
      shell_involved: false,
      cwd: '/tmp',
      pid: 1235,
      ppid: 1,
    };
    fs.appendFileSync(logFile, JSON.stringify(event) + '\n', 'utf8');

    await waitForReported(reported, 1);

    expect(reported).toHaveLength(1);
    expect(reported[0].event_type).toBe('process_start');
    expect(reported[0].layer).toBe('system');
    expect(reported[0].cmdline).toBe('curl https://example.com');
  });

  it('forwards new-format process_start events as process_start', async () => {
    await runtimeCollector.initialize();
    const event = {
      type: 'application.process_start',
      event_type: 'process_start',
      id: 'evt-ps-1',
      timestamp: new Date().toISOString(),
      runtime: 'node',
      api: 'child_process.spawn',
      command_line: 'sh -c echo hi',
      executable: 'sh',
      shell_involved: true,
      cwd: '/root',
      pid: 1236,
      ppid: 1,
    };
    fs.appendFileSync(logFile, JSON.stringify(event) + '\n', 'utf8');

    await waitForReported(reported, 1);

    expect(reported).toHaveLength(1);
    expect(reported[0].event_type).toBe('process_start');
    expect(reported[0].layer).toBe('system');
    expect(reported[0].exe).toBe('sh');
    expect(reported[0].cmdline).toBe('sh -c echo hi');
  });

  it('does nothing when disabled', async () => {
    runtimeCollector = new RuntimeHookCollector(collector, { enabled: false });
    await runtimeCollector.initialize();
    const event = { type: 'application.command_execution', id: 'evt-2' };
    fs.appendFileSync(logFile, JSON.stringify(event) + '\n', 'utf8');
    await wait(300);
    expect(reported).toHaveLength(0);
  });

  it('forwards network.http_request events as network_http', async () => {
    await runtimeCollector.initialize();
    const event = {
      type: 'network.http_request',
      event_id: '34ac8d9a-89ae-4555-9eb5-9b06b33298c8',
      event_type: 'network_http',
      ts: 1784277722604,
      host_id: 'coze-studio-node-1',
      container_id: '219f6417a478',
      pid: 1,
      run_id: 'run-20260717084202-q0gt7ky9',
      content: '{"node_types":["1"]}',
      content_length: 18,
      service: 'http',
      direction: 'send',
      latency_ms: 21,
      source: {
        hook_name: 'network_http_req',
        middleware_name: 'coze-security-monitor',
        collector_name: 'security-http-middleware',
      },
      method: 'POST',
      url: '/api/workflow_api/node_template_list',
      host: '127.0.0.1:8989',
      code: 200,
      header: 'Host: 127.0.0.1:8989\r\nContent-Type: application/json',
      body: '{"node_types":["1"]}',
      session_id: 'sess-network',
      agent_id: 'agent-network',
      tool_call_id: 'call-network',
    };
    fs.appendFileSync(logFile, JSON.stringify(event) + '\n', 'utf8');

    await waitForReported(reported, 1);

    expect(reported).toHaveLength(1);
    expect(reported[0].event_type).toBe('network_http');
    expect(reported[0].layer).toBe('system');
    expect(reported[0].event_id).toBe('34ac8d9a-89ae-4555-9eb5-9b06b33298c8');
    expect(reported[0].comm).toBe('openclaw');
    expect(reported[0].method).toBe('POST');
    expect(reported[0].url).toBe('/api/workflow_api/node_template_list');
    expect(reported[0].host).toBe('127.0.0.1:8989');
    expect(reported[0].code).toBe(200);
    expect(reported[0].body).toBe('{"node_types":["1"]}');
    expect(reported[0].session_id).toBe('sess-network');
    expect(reported[0].tool_call_id).toBe('call-network');
    expect(reported[0].collector?.collector_name).toBe('runtime-hook-collector');
  });

  it('does not store the response body twice when it equals the canonical content', async () => {
    await runtimeCollector.initialize();
    const body = '{"version":"2026.10.7"}';
    fs.appendFileSync(
      logFile,
      JSON.stringify({
        event_type: 'network_http',
        event_id: 'net-dup-1',
        ts: 1784277722604,
        method: 'GET',
        url: '/api/latest-version',
        host: 'telemetry.openclaw.ai',
        content: body,
        content_length: body.length,
        body: '',
        response_body: body,
      }) + '\n',
      'utf8'
    );

    await waitForReported(reported, 1);

    expect(reported).toHaveLength(1);
    // The response body is already the canonical content — carrying it in a
    // second field doubles the payload for no information.
    expect(reported[0].content).toBe(body);
    expect(reported[0].response_body).toBeUndefined();
  });

  it('forwards network_http events without legacy type field', async () => {    await runtimeCollector.initialize();
    const event = {
      event_id: '34ac8d9a-89ae-4555-9eb5-9b06b33298c8',
      event_type: 'network_http',
      ts: 1784277722604,
      host_id: 'coze-studio-node-1',
      container_id: '219f6417a478',
      pid: 1,
      method: 'GET',
      url: 'https://www.baidu.com',
      host: 'www.baidu.com',
      code: 200,
      header: 'Host: www.baidu.com',
      body: '',
    };
    fs.appendFileSync(logFile, JSON.stringify(event) + '\n', 'utf8');

    await waitForReported(reported, 1);

    expect(reported).toHaveLength(1);
    expect(reported[0].event_type).toBe('network_http');
    expect(reported[0].layer).toBe('system');
    expect(reported[0].url).toBe('https://www.baidu.com');
  });

  it('adds intervention field when process_start event is blocked', async () => {
    await runtimeCollector.initialize();
    const event = {
      event_type: 'process_start',
      timestamp: new Date().toISOString(),
      runtime: 'node',
      api: 'child_process.exec',
      command_line: 'cat /etc/passwd',
      executable: 'cat',
      shell_involved: true,
      cwd: '/tmp',
      pid: 1234,
      ppid: 1,
      blocked: true,
      block_reason: '命令被 OpenClaw runtime hook 拦截',
      block_code: 'RUNTIME_HOOK_BLOCK',
      risk_flags: ['shell_involved', 'sensitive_file_access'],
    };
    fs.appendFileSync(logFile, JSON.stringify(event) + '\n', 'utf8');

    await waitForReported(reported, 1);

    expect(reported).toHaveLength(1);
    expect(reported[0].blocked).toBe(true);
    expect(reported[0].intervention).toBeDefined();
    expect(reported[0].intervention?.decision).toBe('block');
    expect(reported[0].intervention?.block_reason).toContain('runtime hook');
  });

  it('adds intervention field when network_http event is blocked', async () => {
    await runtimeCollector.initialize();
    const event = {
      event_id: '34ac8d9a-89ae-4555-9eb5-9b06b33298d9',
      event_type: 'network_http',
      ts: 1784277722604,
      pid: 1,
      method: 'GET',
      url: '/notify',
      host: 'malicious-c2-1.com',
      domain_name: 'malicious-c2-1.com',
      code: 0,
      header: 'Host: malicious-c2-1.com',
      body: '',
      blocked: true,
      block_reason: '请求被 OpenClaw network hook 拦截',
      block_code: 'NETWORK_HOOK_BLOCK',
    };
    fs.appendFileSync(logFile, JSON.stringify(event) + '\n', 'utf8');

    await waitForReported(reported, 1);

    expect(reported).toHaveLength(1);
    expect(reported[0].blocked).toBe(true);
    expect(reported[0].intervention).toBeDefined();
    expect(reported[0].intervention?.decision).toBe('block');
    expect(reported[0].intervention?.block_reason).toContain('network hook');
  });

  it('filters network_http events matching excludeNetworkUrls patterns', async () => {
    runtimeCollector = new RuntimeHookCollector(collector, {
      enabled: true,
      logPath: logFile,
      excludeNetworkUrls: ['^192\\.0\\.2\\.1/api/v1/events$'],
    });
    await runtimeCollector.initialize();

    const noiseEvent = {
      event_id: 'noise-1',
      event_type: 'network_http',
      ts: Date.now(),
      method: 'POST',
      url: '/api/v1/events',
      host: '192.0.2.1',
      code: 400,
    };
    const realEvent = {
      event_id: 'real-1',
      event_type: 'network_http',
      ts: Date.now(),
      method: 'POST',
      url: '/anthropic/v1/messages',
      host: 'api.minimaxi.com',
      code: 200,
    };

    fs.appendFileSync(logFile, JSON.stringify(noiseEvent) + '\n', 'utf8');
    fs.appendFileSync(logFile, JSON.stringify(realEvent) + '\n', 'utf8');

    await waitForReported(reported, 1);

    expect(reported).toHaveLength(1);
    expect(reported[0].host).toBe('api.minimaxi.com');
    expect(reported[0].url).toBe('/anthropic/v1/messages');
  });

  // SDK decoupling removed `collector.endpoint` and the `excludedEndpoints`
  // argument; operators now suppress noise via `application.runtimeHooks.excludeNetworkUrls`.
  // The remaining `excludeNetworkUrls` test above is the surviving surface.
});

// 评估队列无界 → 积压达到上限后跳过评估、仅落盘。
describe('RuntimeHookCollector 评估队列背压', () => {
  let logFile: string;
  let collectors: RuntimeHookCollector[];

  function processLine(i: number): string {
    return JSON.stringify({
      type: 'application.process_start',
      event_type: 'process_start',
      id: `evt-${i}`,
      timestamp: new Date().toISOString(),
      runtime: 'node',
      api: 'child_process.exec',
      command_line: `sh -c echo ${i}`,
      executable: 'sh',
      pid: 4000 + i,
      ppid: 1,
    });
  }

  // 每个 collector 自带落点数组：上一个用例的在途事件即便晚到，也只会写进
  // 自己的数组，不会污染下一个用例的断言。
  function makeCollector(backlogLimit: number, evaluationDelayMs: number) {
    const reported: SecurityEvent[] = [];
    const evaluated: string[] = [];
    const collector = new RuntimeHookCollector(
      {
        report: async (event: SecurityEvent) => {
          reported.push(event);
        },
        shutdown: async () => {},
      },
      { enabled: true, logPath: logFile, maxEvaluationBacklog: backlogLimit },
      undefined,
      {
        onEvent: async (event: SecurityEvent) => {
          evaluated.push(event.event_id);
          if (evaluationDelayMs > 0) await wait(evaluationDelayMs);
        },
      }
    );
    collectors.push(collector);
    return { collector, reported, evaluated };
  }

  async function waitFor(cond: () => boolean, timeoutMs = 5000): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (cond()) return;
      await wait(10);
    }
  }

  beforeEach(() => {
    collectors = [];
    logFile = path.join(os.tmpdir(), `openclaw-runtime-backlog-test-${Date.now()}.jsonl`);
    fs.writeFileSync(logFile, '', 'utf8');
  });

  afterEach(async () => {
    for (const c of collectors) await c.shutdown();
    for (const p of [logFile, `${logFile}.offset`]) {
      try {
        fs.unlinkSync(p);
      } catch {
        // ignore
      }
    }
  });

  it('积压达到上限后跳过评估、仅落盘：事件不丢、积压有界、跳过有留痕且可恢复', async () => {
    const { collector, reported, evaluated } = makeCollector(4, 30);
    await collector.initialize();

    // 单批写入 200 行 → 读取循环同步派发，队列瞬间打满。
    const lines: string[] = [];
    for (let i = 0; i < 200; i++) lines.push(processLine(i));
    fs.appendFileSync(logFile, lines.join('\n') + '\n', 'utf8');

    // 采样队列长度：拒绝入队的上限是硬约束，任何时刻都不应超过它。
    let maxObservedBacklog = 0;
    const sampler = setInterval(() => {
      const backlog = collector.getStats().dispatchBacklog as number;
      if (backlog > maxObservedBacklog) maxObservedBacklog = backlog;
    }, 5);

    await waitFor(() => reported.length >= 200);
    clearInterval(sampler);

    // 落盘不丢：200 条全部到达 NDJSON 出口。
    expect(reported).toHaveLength(200);
    // 评估有界：只有上限内的事件进入评估，其余全部走溢出路径。
    expect(evaluated).toHaveLength(4);
    expect(maxObservedBacklog).toBeLessThanOrEqual(4);

    // 留痕：每条溢出事件带跳过原因与当时的积压长度。
    const skipped = reported.filter((e) => e.evaluation_skipped);
    expect(skipped).toHaveLength(196);
    expect(skipped.every((e) => e.evaluation_skipped?.reason === 'runtime_dispatch_backlog')).toBe(true);
    expect(skipped.every((e) => (e.evaluation_skipped?.backlog ?? 0) >= 4)).toBe(true);
    // 溢出事件没有干预决策（不是 allow——评估根本没跑）。
    expect(skipped.every((e) => e.intervention === undefined)).toBe(true);

    const stats = collector.getStats();
    expect(stats.eventsEvaluationSkipped).toBe(196);
    expect(stats.eventsReported).toBe(200);
    // 排空后队列归零，内存不随事件流增长。
    await waitFor(() => collector.getStats().dispatchBacklog === 0);
    expect(collector.getStats().dispatchBacklog).toBe(0);

    // 恢复：空闲后新事件重新走评估路径。
    fs.appendFileSync(logFile, processLine(999) + '\n', 'utf8');
    await waitFor(() => reported.some((e) => e.pid === 4999));
    const recovered = reported.find((e) => e.pid === 4999)!;
    expect(recovered.evaluation_skipped).toBeUndefined();
    expect(evaluated).toHaveLength(5);
    expect(evaluated).toContain(recovered.event_id);
  });

  it('无积压时（评估跟得上）不触发跳过：上限是上限而非配额', async () => {
    const { collector, reported, evaluated } = makeCollector(10, 0);
    await collector.initialize();

    // 逐条写入并等落盘，队列始终为空。
    for (let i = 0; i < 20; i++) {
      fs.appendFileSync(logFile, processLine(i) + '\n', 'utf8');
      await waitFor(() => reported.length === i + 1);
    }

    expect(reported).toHaveLength(20);
    expect(evaluated).toHaveLength(20);
    expect(reported.every((e) => e.evaluation_skipped === undefined)).toBe(true);
    expect(collector.getStats().eventsEvaluationSkipped).toBe(0);
  });

  it('maxEvaluationBacklog=0 关闭限制：行为与修复前一致（全部评估）', async () => {
    const { collector, reported, evaluated } = makeCollector(0, 0);
    await collector.initialize();

    const lines: string[] = [];
    for (let i = 0; i < 50; i++) lines.push(processLine(i));
    fs.appendFileSync(logFile, lines.join('\n') + '\n', 'utf8');

    await waitFor(() => reported.length >= 50);
    await waitFor(() => evaluated.length >= 50);

    expect(reported).toHaveLength(50);
    expect(evaluated).toHaveLength(50);
    expect(reported.every((e) => e.evaluation_skipped === undefined)).toBe(true);
  });
});

/**
 * 宿主内部只读探针的排除（1.1.0）。
 *
 * 两道闸门同时成立才排除：事件没有任何 agent 归属（调用方层）+ 命令行
 * 逐字命中一条已知只读探针形态（命令模式层）。任一不成立都保留。
 */
describe('RuntimeHookCollector 宿主内部探针排除', () => {
  let logFile: string;
  let collector: { report: (event: SecurityEvent) => Promise<void>; shutdown: () => Promise<void> };
  let runtimeCollector: RuntimeHookCollector;
  let reported: SecurityEvent[];

  function probeLine(overrides: Record<string, unknown> = {}): string {
    return (
      JSON.stringify({
        event_type: 'process_start',
        type: 'application.process_start',
        id: `probe-${Math.random().toString(36).slice(2)}`,
        ts: new Date().toISOString(),
        runtime: 'node',
        api: 'child_process.spawn',
        command_line: '/usr/bin/lsof -nP -iTCP:18789 -sTCP:LISTEN -FpFcn',
        executable: '/usr/bin/lsof',
        pid: 2544,
        ppid: 2209,
        ...overrides,
      }) + '\n'
    );
  }

  function makeCollector(options: Record<string, unknown>) {
    const sink: SecurityEvent[] = [];
    const instance = new RuntimeHookCollector(
      {
        report: async (event: SecurityEvent) => {
          sink.push(event);
        },
        shutdown: async () => {},
      },
      { enabled: true, logPath: logFile, ...options } as never
    );
    return { instance, sink };
  }

  beforeEach(() => {
    reported = [];
    logFile = path.join(os.tmpdir(), `openclaw-host-probe-test-${Date.now()}-${Math.random().toString(36).slice(2)}.jsonl`);
    fs.writeFileSync(logFile, '', 'utf8');
    collector = {
      report: async (event: SecurityEvent) => {
        reported.push(event);
      },
      shutdown: async () => {},
    };
    runtimeCollector = new RuntimeHookCollector(collector, {
      enabled: true,
      logPath: logFile,
    } as never);
  });

  afterEach(async () => {
    await runtimeCollector.shutdown();
    for (const p of [logFile, `${logFile}.offset`]) {
      try {
        fs.unlinkSync(p);
      } catch {
        // ignore
      }
    }
  });

  it('无 agent 归属的宿主探针被排除，且计数留痕', async () => {
    await runtimeCollector.initialize();
    fs.appendFileSync(logFile, probeLine(), 'utf8');
    await wait(500);

    expect(reported).toHaveLength(0);
    const stats = runtimeCollector.getStats();
    expect(stats.eventsExcludedHostProbes).toBe(1);
    expect(stats.hostInternalProbes).toEqual({ lsof_port_probe: 1 });
  });

  it('带 session 归属的同一命令保留（agent 动作的产物永不排除）', async () => {
    await runtimeCollector.initialize();
    fs.appendFileSync(logFile, probeLine({ session_id: 'sess-1' }), 'utf8');
    await waitForReported(reported, 1);

    expect(reported).toHaveLength(1);
    expect(reported[0].cmdline).toBe('/usr/bin/lsof -nP -iTCP:18789 -sTCP:LISTEN -FpFcn');
    expect(runtimeCollector.getStats().eventsExcludedHostProbes).toBe(0);
  });

  it('带 tool_call 归属的同一命令保留', async () => {
    await runtimeCollector.initialize();
    fs.appendFileSync(logFile, probeLine({ tool_call_id: 'call-1', tool_name: 'exec' }), 'utf8');
    await waitForReported(reported, 1);

    expect(reported).toHaveLength(1);
    expect(runtimeCollector.getStats().eventsExcludedHostProbes).toBe(0);
  });

  it('带凭据的命令即使没有归属也保留', async () => {
    await runtimeCollector.initialize();
    fs.appendFileSync(
      logFile,
      probeLine({ command_line: 'gh auth token --hostname github.com', executable: 'gh' }),
      'utf8'
    );
    await waitForReported(reported, 1);

    expect(reported).toHaveLength(1);
    expect(runtimeCollector.getStats().eventsExcludedHostProbes).toBe(0);
  });

  it('配置关掉时宿主探针照常采集（可回到完整审计）', async () => {
    const { instance, sink } = makeCollector({ excludeHostInternalProbeCommands: false });
    await instance.initialize();
    fs.appendFileSync(logFile, probeLine(), 'utf8');
    await wait(500);

    expect(sink).toHaveLength(1);
    expect(instance.getStats().eventsExcludedHostProbes).toBe(0);
    await instance.shutdown();
  });
});

/**
 * 子进程退出事件（1.1.0）。
 *
 * 运行时层此前只记录 process_start：审计链上只有"发起了"，没有"跑完了、
 * 结果如何"（采样里 process_exit 为 0 条）。
 */
describe('RuntimeHookCollector 子进程退出事件', () => {
  let logFile: string;
  let reported: SecurityEvent[];
  let runtimeCollector: RuntimeHookCollector;

  beforeEach(() => {
    reported = [];
    logFile = path.join(
      os.tmpdir(),
      `openclaw-process-exit-test-${Date.now()}-${Math.random().toString(36).slice(2)}.jsonl`
    );
    fs.writeFileSync(logFile, '', 'utf8');
    runtimeCollector = new RuntimeHookCollector(
      {
        report: async (event: SecurityEvent) => {
          reported.push(event);
        },
        shutdown: async () => {},
      },
      { enabled: true, logPath: logFile } as never
    );
  });

  afterEach(async () => {
    await runtimeCollector.shutdown();
    for (const p of [logFile, `${logFile}.offset`]) {
      try {
        fs.unlinkSync(p);
      } catch {
        // ignore
      }
    }
  });

  it('把 process_exit 落成事件，并保留子进程 pid 与退出码', async () => {
    await runtimeCollector.initialize();
    fs.appendFileSync(
      logFile,
      JSON.stringify({
        event_type: 'process_exit',
        type: 'application.process_exit',
        id: 'exit-1',
        event_id: 'exit-1',
        ts: '2026-10-20T08:00:00.000Z',
        runtime: 'node',
        api: 'child_process.spawn',
        command_line: 'npm pack ./plugin.tgz',
        executable: 'npm',
        process_name: 'npm',
        pid: 4242,
        spawner_pid: 4242,
        child_pid: 5151,
        exit_code: 0,
        exit_signal: null,
        session_id: 'sess-1',
        run_id: 'run-1',
        tool_call_id: 'call-1',
      }) + '\n',
      'utf8'
    );

    await waitForReported(reported, 1);

    expect(reported).toHaveLength(1);
    const event = reported[0];
    expect(event.event_type).toBe('process_exit');
    expect(event.child_pid).toBe(5151);
    expect(event.spawner_pid).toBe(4242);
    // pid 保持"发起方"语义（与 process_start 一致）。
    expect(event.pid).toBe(4242);
    expect(event.exit_code).toBe(0);
    expect(event.cmdline).toBe('npm pack ./plugin.tgz');
    expect(event.session_id).toBe('sess-1');
    expect(event.tool_call_id).toBe('call-1');
  });

  it('起点事件带出子进程 pid', async () => {
    await runtimeCollector.initialize();
    fs.appendFileSync(
      logFile,
      JSON.stringify({
        event_type: 'process_start',
        type: 'application.process_start',
        id: 'start-1',
        event_id: 'start-1',
        ts: '2026-10-20T08:00:00.000Z',
        runtime: 'node',
        api: 'child_process.spawn',
        command_line: 'npm pack ./plugin.tgz',
        executable: 'npm',
        pid: 4242,
        spawner_pid: 4242,
        child_pid: 5151,
      }) + '\n',
      'utf8'
    );

    await waitForReported(reported, 1);

    expect(reported[0].event_type).toBe('process_start');
    expect(reported[0].child_pid).toBe(5151);
    expect(reported[0].spawner_pid).toBe(4242);
  });

  it('宿主探针的退出事件与起点事件一起被排除（不留孤儿退出）', async () => {
    await runtimeCollector.initialize();
    fs.appendFileSync(
      logFile,
      JSON.stringify({
        event_type: 'process_exit',
        type: 'application.process_exit',
        id: 'exit-probe',
        event_id: 'exit-probe',
        ts: '2026-10-20T08:00:00.000Z',
        runtime: 'node',
        api: 'child_process.spawn',
        command_line: '/usr/bin/lsof -nP -iTCP:18789 -sTCP:LISTEN -FpFcn',
        executable: '/usr/bin/lsof',
        pid: 4242,
        child_pid: 5151,
        exit_code: 0,
      }) + '\n',
      'utf8'
    );

    await wait(500);

    expect(reported).toHaveLength(0);
  });

  it('同一命令的多个子进程退出事件互不去重', async () => {
    await runtimeCollector.initialize();
    for (const childPid of [5151, 5152, 5153]) {
      fs.appendFileSync(
        logFile,
        JSON.stringify({
          event_type: 'process_exit',
          type: 'application.process_exit',
          id: `exit-${childPid}`,
          event_id: `exit-${childPid}`,
          ts: '2026-10-20T08:00:00.000Z',
          runtime: 'node',
          api: 'child_process.spawn',
          command_line: 'npm pack ./plugin.tgz',
          executable: 'npm',
          pid: 4242,
          child_pid: childPid,
          exit_code: 0,
        }) + '\n',
        'utf8'
      );
    }

    await waitForReported(reported, 3);
    await wait(300);

    expect(reported).toHaveLength(3);
    expect(reported.map((e) => e.child_pid).sort()).toEqual([5151, 5152, 5153]);
  });
});


// ⭐ 事件降噪 —— 宿主自检聚合与网关 LLM 自有流量采样。
describe('RuntimeHookCollector 降噪聚合', () => {
  let logFile: string;
  let collector: { report: (event: SecurityEvent) => Promise<void>; shutdown: () => Promise<void> };
  let reported: SecurityEvent[];
  let runtimeCollector: RuntimeHookCollector;

  /** 分钟/5 分钟窗口都对齐的起点（1793326200000 同时是 60s 与 300s 的整数倍）。 */
  const WINDOW_BASE = 1793326200000;

  beforeEach(() => {
    reported = [];
    logFile = path.join(os.tmpdir(), `openclaw-runtime-collector-agg-test-${Date.now()}-${Math.random().toString(36).slice(2)}.jsonl`);
    fs.writeFileSync(logFile, '', 'utf8');
    collector = {
      report: async (event: SecurityEvent) => {
        reported.push(event);
      },
      shutdown: async () => {},
    };
  });

  afterEach(async () => {
    await runtimeCollector?.shutdown();
    for (const suffix of ['', '.offset', '.rotated', '.rotated.offset']) {
      try {
        fs.unlinkSync(logFile + suffix);
      } catch {
        // ignore
      }
    }
  });

  function selfCheckEvent(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return {
      event_type: 'process_start',
      event_id: `evt-${Math.random().toString(36).slice(2)}`,
      ts: WINDOW_BASE,
      command_line: 'gh auth token --hostname github.com',
      executable: 'gh',
      pid: 133,
      ppid: 1,
      ...overrides,
    };
  }

  function llmEvent(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return {
      event_type: 'network_http',
      event_id: `net-${Math.random().toString(36).slice(2)}`,
      ts: WINDOW_BASE,
      pid: 1,
      comm: 'openclaw',
      method: 'POST',
      url: '/anthropic/v1/messages',
      host: 'api.minimaxi.com',
      code: 200,
      content: '{"response":1}',
      content_length: 14,
      body: '{"prompt":1}',
      ...overrides,
    };
  }

  it('4.1 同分钟重复命中：首个实例即时落盘，其余折叠进聚合计数事件', async () => {
    runtimeCollector = new RuntimeHookCollector(collector, { enabled: true, logPath: logFile });
    await runtimeCollector.initialize();

    // 同一分钟窗口内、不同 pid（真实重 spawn）的三次自检。
    fs.appendFileSync(logFile, JSON.stringify(selfCheckEvent({ pid: 133 })) + '\n', 'utf8');
    fs.appendFileSync(logFile, JSON.stringify(selfCheckEvent({ pid: 134, ts: WINDOW_BASE + 1000 })) + '\n', 'utf8');
    fs.appendFileSync(logFile, JSON.stringify(selfCheckEvent({ pid: 135, ts: WINDOW_BASE + 2000 })) + '\n', 'utf8');

    await waitForReported(reported, 1);
    // 首个实例即时可见。
    expect(reported).toHaveLength(1);
    expect(reported[0].event_type).toBe('process_start');
    expect(reported[0].cmdline).toBe('gh auth token --hostname github.com');

    // 关停冲刷聚合计数。
    await runtimeCollector.shutdown();
    await waitForReported(reported, 2);

    expect(reported).toHaveLength(2);
    const aggregate = reported[1];
    expect(aggregate.event_type).toBe('x_openclaw_self_traffic_aggregate');
    expect(aggregate.aggregate?.category).toBe('host_self_check');
    expect(aggregate.aggregate?.pattern).toBe('gh_auth_token');
    expect(aggregate.aggregate?.source_event_type).toBe('process_start');
    expect(aggregate.aggregate?.count).toBe(3);
    expect(aggregate.aggregate?.first_ts).toBe(WINDOW_BASE);
    expect(aggregate.aggregate?.last_ts).toBe(WINDOW_BASE + 2000);
    expect(aggregate.aggregate?.window_ms).toBe(60000);
    expect(aggregate.cmdline).toBe('gh auth token --hostname github.com');
    expect(aggregate.blocked).toBe(false);
  });

  it('4.1 跨分钟命中不折叠：各自即时落盘且不产聚合计数事件', async () => {
    runtimeCollector = new RuntimeHookCollector(collector, { enabled: true, logPath: logFile });
    await runtimeCollector.initialize();

    fs.appendFileSync(logFile, JSON.stringify(selfCheckEvent({ pid: 133 })) + '\n', 'utf8');
    fs.appendFileSync(
      logFile,
      JSON.stringify(selfCheckEvent({ pid: 134, ts: WINDOW_BASE + 60000 })) + '\n',
      'utf8'
    );

    await waitForReported(reported, 2);
    await runtimeCollector.shutdown();
    await wait(200);

    expect(reported).toHaveLength(2);
    expect(reported.every((e) => e.event_type === 'process_start')).toBe(true);
  });

  it('4.1 blocked / 带 risk_flags / 有 agent 归属的自检事件永不聚合', async () => {
    runtimeCollector = new RuntimeHookCollector(collector, { enabled: true, logPath: logFile });
    await runtimeCollector.initialize();

    fs.appendFileSync(
      logFile,
      JSON.stringify(
        selfCheckEvent({ pid: 133, blocked: true, block_reason: 'blocked by runtime hook' })
      ) + '\n',
      'utf8'
    );
    fs.appendFileSync(
      logFile,
      JSON.stringify(selfCheckEvent({ pid: 134, risk_flags: ['hook_env_reinjected'] })) + '\n',
      'utf8'
    );
    fs.appendFileSync(
      logFile,
      JSON.stringify(selfCheckEvent({ pid: 135, tool_call_id: 'call-1', session_id: 'sess-1' })) + '\n',
      'utf8'
    );

    await waitForReported(reported, 3);
    await runtimeCollector.shutdown();
    await wait(200);

    expect(reported).toHaveLength(3);
    expect(reported.every((e) => e.event_type === 'process_start')).toBe(true);
    expect(reported.find((e) => e.tool_call_id === 'call-1')).toBeDefined();
  });

  it('4.1 宿主 worker 的 process_exit 同样按分钟聚合（source_event_type=process_exit）', async () => {
    runtimeCollector = new RuntimeHookCollector(collector, { enabled: true, logPath: logFile });
    await runtimeCollector.initialize();

    const exit = (pid: number, ts: number) =>
      selfCheckEvent({
        event_type: 'process_exit',
        pid: 1,
        child_pid: pid,
        exit_code: 0,
        command_line: '/usr/local/bin/node /app/dist/process/spawn-broker/worker.js',
        ts,
      });
    fs.appendFileSync(logFile, JSON.stringify(exit(3001, WINDOW_BASE)) + '\n', 'utf8');
    fs.appendFileSync(logFile, JSON.stringify(exit(3002, WINDOW_BASE + 1000)) + '\n', 'utf8');

    await waitForReported(reported, 1);
    await runtimeCollector.shutdown();
    await waitForReported(reported, 2);

    expect(reported).toHaveLength(2);
    expect(reported[1].event_type).toBe('x_openclaw_self_traffic_aggregate');
    expect(reported[1].aggregate?.pattern).toBe('spawn_broker_worker');
    expect(reported[1].aggregate?.source_event_type).toBe('process_exit');
    expect(reported[1].aggregate?.count).toBe(2);
  });

  it('4.1 aggregateHostSelfChecks=false 时全部即时落盘', async () => {
    runtimeCollector = new RuntimeHookCollector(collector, {
      enabled: true,
      logPath: logFile,
      aggregateHostSelfChecks: false,
    });
    await runtimeCollector.initialize();

    fs.appendFileSync(logFile, JSON.stringify(selfCheckEvent({ pid: 133 })) + '\n', 'utf8');
    fs.appendFileSync(logFile, JSON.stringify(selfCheckEvent({ pid: 134 })) + '\n', 'utf8');

    await waitForReported(reported, 2);
    await runtimeCollector.shutdown();
    await wait(200);

    expect(reported).toHaveLength(2);
    expect(reported.every((e) => e.event_type === 'process_start')).toBe(true);
  });

  it('4.2 LLM 自有流量：首个实例即时落盘且 body/content 降级为 SHA-256，其余折叠进计数', async () => {
    runtimeCollector = new RuntimeHookCollector(collector, {
      enabled: true,
      logPath: logFile,
      llmSelfTrafficHosts: ['minimaxi.com'],
    });
    await runtimeCollector.initialize();

    fs.appendFileSync(logFile, JSON.stringify(llmEvent({ body: 'body-1' })) + '\n', 'utf8');
    fs.appendFileSync(logFile, JSON.stringify(llmEvent({ ts: WINDOW_BASE + 1000, body: 'body-2' })) + '\n', 'utf8');
    fs.appendFileSync(logFile, JSON.stringify(llmEvent({ ts: WINDOW_BASE + 2000, body: 'body-3' })) + '\n', 'utf8');

    await waitForReported(reported, 1);
    const first = reported[0];
    expect(first.event_type).toBe('network_http');
    // 载荷降级：原文不留存，只留指纹。
    expect(first.body).toBeUndefined();
    expect(first.content).toBeUndefined();
    expect(first.body_sha256).toBe(createHash('sha256').update('body-1').digest('hex'));
    expect(first.content_sha256).toBe(createHash('sha256').update('{"response":1}').digest('hex'));
    // 体积信号保留。
    expect(first.content_length).toBe(14);

    await runtimeCollector.shutdown();
    await waitForReported(reported, 2);

    expect(reported).toHaveLength(2);
    const aggregate = reported[1];
    expect(aggregate.event_type).toBe('x_openclaw_self_traffic_aggregate');
    expect(aggregate.aggregate?.category).toBe('llm_self_traffic');
    expect(aggregate.aggregate?.pattern).toBe('api.minimaxi.com POST /anthropic/v1/messages');
    expect(aggregate.aggregate?.count).toBe(3);
    expect(aggregate.aggregate?.window_ms).toBe(300000);
    expect(aggregate.aggregate?.body_sha256).toBe(first.body_sha256);
    expect(aggregate.aggregate?.content_length_total).toBe(42);
  });

  it('4.2 blocked / 带 risk_flags 的 LLM 自流量不采样、不降级', async () => {
    runtimeCollector = new RuntimeHookCollector(collector, {
      enabled: true,
      logPath: logFile,
      llmSelfTrafficHosts: ['minimaxi.com'],
    });
    await runtimeCollector.initialize();

    fs.appendFileSync(
      logFile,
      JSON.stringify(
        llmEvent({ blocked: true, block_reason: 'blocked by network hook', body: 'secret-body-1' })
      ) + '\n',
      'utf8'
    );
    fs.appendFileSync(
      logFile,
      JSON.stringify(llmEvent({ risk_flags: ['internal_host'], body: 'secret-body-2' })) + '\n',
      'utf8'
    );

    await waitForReported(reported, 2);
    await runtimeCollector.shutdown();
    await wait(200);

    expect(reported).toHaveLength(2);
    for (const event of reported) {
      expect(event.event_type).toBe('network_http');
      expect(typeof event.body).toBe('string');
      expect(event.body_sha256).toBeUndefined();
    }
  });

  it('4.2 llmSelfTrafficSampleRate=2 时每窗口即时落两条，其余折叠', async () => {
    runtimeCollector = new RuntimeHookCollector(collector, {
      enabled: true,
      logPath: logFile,
      llmSelfTrafficHosts: ['minimaxi.com'],
      llmSelfTrafficSampleRate: 2,
    });
    await runtimeCollector.initialize();

    fs.appendFileSync(logFile, JSON.stringify(llmEvent({ body: 'b1' })) + '\n', 'utf8');
    fs.appendFileSync(logFile, JSON.stringify(llmEvent({ ts: WINDOW_BASE + 1000, body: 'b2' })) + '\n', 'utf8');
    fs.appendFileSync(logFile, JSON.stringify(llmEvent({ ts: WINDOW_BASE + 2000, body: 'b3' })) + '\n', 'utf8');

    await waitForReported(reported, 2);
    await runtimeCollector.shutdown();
    await waitForReported(reported, 3);

    expect(reported).toHaveLength(3);
    expect(reported[0].event_type).toBe('network_http');
    expect(reported[1].event_type).toBe('network_http');
    expect(reported[2].event_type).toBe('x_openclaw_self_traffic_aggregate');
    expect(reported[2].aggregate?.count).toBe(3);
  });

  it('4.2 llmSelfTrafficHosts 未配置时特征关闭（既有测试语义的守卫）', async () => {
    runtimeCollector = new RuntimeHookCollector(collector, { enabled: true, logPath: logFile });
    await runtimeCollector.initialize();

    fs.appendFileSync(logFile, JSON.stringify(llmEvent({ pid: 1, body: 'plain-body' })) + '\n', 'utf8');

    await waitForReported(reported, 1);
    await runtimeCollector.shutdown();
    await wait(200);

    expect(reported).toHaveLength(1);
    expect(reported[0].body).toBe('plain-body');
    expect(reported[0].body_sha256).toBeUndefined();
  });

  it('4.2 非清单 host 的网关流量不受影响', async () => {
    runtimeCollector = new RuntimeHookCollector(collector, {
      enabled: true,
      logPath: logFile,
      llmSelfTrafficHosts: ['minimaxi.com'],
    });
    await runtimeCollector.initialize();

    fs.appendFileSync(
      logFile,
      JSON.stringify(llmEvent({ host: 'clawhub.ai', url: '/v1/feeds/plugins', body: 'feed-body' })) + '\n',
      'utf8'
    );

    await waitForReported(reported, 1);
    await runtimeCollector.shutdown();
    await wait(200);

    expect(reported).toHaveLength(1);
    expect(reported[0].body).toBe('feed-body');
    expect(reported[0].body_sha256).toBeUndefined();
  });
});
