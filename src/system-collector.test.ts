import { describe, it, expect, vi, beforeEach } from 'vitest';
import { EventEmitter } from 'events';
import { spawn } from 'child_process';
import type { ChildProcess } from 'child_process';
import { SystemCollector } from './system-collector.js';
import type { EventCollector, SecurityEvent, SystemLayerConfig } from './types.js';

vi.mock('child_process', () => ({
  spawn: vi.fn(),
}));

class MockCollector implements EventCollector {
  events: SecurityEvent[] = [];
  initialized = false;

  async initialize(): Promise<void> {
    this.initialized = true;
  }

  async report(event: SecurityEvent): Promise<void> {
    this.events.push(event);
  }

  async flush(): Promise<void> {}

  getStats() {
    return { totalReported: this.events.length, totalFailed: 0, queueSize: 0 };
  }

  async shutdown(): Promise<void> {}
}

class MockReadable extends EventEmitter {
  resume() {
    return this;
  }
  pause() {
    return this;
  }
  setEncoding(_encoding: string) {
    return this;
  }
  isPaused() {
    return false;
  }
}

class MockChildProcess extends EventEmitter {
  pid = 9999;
  killed = false;
  stdin = Object.assign(new EventEmitter(), { write: vi.fn(), end: vi.fn() });
  stdout = new MockReadable();
  stderr = new MockReadable();

  kill(signal?: string): boolean {
    this.killed = true;
    this.emit('exit', 0, signal);
    return true;
  }
}

function createSystemConfig(overrides: Partial<SystemLayerConfig['procfs']> = {}): SystemLayerConfig {
  return {
    enabled: true,
    procfs: {
      enabled: true,
      pythonPath: 'python3',
      scanIntervalMs: 5000,
      processNames: ['openclaw', 'node'],
      collectOpenFiles: false,
      collectConnections: false,
      collectChildren: true,
      collectCpuPercent: false,
      ...overrides,
    },
  };
}

describe('SystemCollector', () => {
  const mockSpawn = spawn as unknown as ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('does not start monitor when system layer is disabled', async () => {
    const collector = new MockCollector();
    const systemCollector = new SystemCollector(collector, { enabled: false });
    await systemCollector.initialize();
    expect(mockSpawn).not.toHaveBeenCalled();
    expect(systemCollector.getStats().started).toBe(false);
  });

  it('does not start monitor when procfs is disabled', async () => {
    const collector = new MockCollector();
    const systemCollector = new SystemCollector(collector, {
      enabled: true,
      procfs: { enabled: false },
    });
    await systemCollector.initialize();
    expect(mockSpawn).not.toHaveBeenCalled();
  });

  it('starts monitor and sends config when enabled', async () => {
    const child = new MockChildProcess();
    mockSpawn.mockReturnValue(child as unknown as ChildProcess);

    const collector = new MockCollector();
    const systemCollector = new SystemCollector(collector, createSystemConfig());
    await systemCollector.initialize();

    expect(mockSpawn).toHaveBeenCalledTimes(1);
    const [cmd, args, options] = mockSpawn.mock.calls[0] as [string, string[], Record<string, unknown>];
    expect(cmd).toBe('python3');
    expect(args).toEqual(expect.arrayContaining([expect.stringMatching(/process_monitor\.py$/)]));
    expect(options).toEqual(expect.objectContaining({ stdio: ['pipe', 'pipe', 'pipe'] }));

    // Config command should have been written to stdin.
    const writes = child.stdin.write.mock.calls as string[][];
    const configCommand = writes.find((call) => call[0].includes('"type":"config"'));
    expect(configCommand).toBeDefined();
    const parsed = JSON.parse(configCommand![0]);
    expect(parsed.data.scanIntervalMs).toBe(5000);
  });

  it('binds process context when monitor is ready', async () => {
    const child = new MockChildProcess();
    mockSpawn.mockReturnValue(child as unknown as ChildProcess);

    const collector = new MockCollector();
    const systemCollector = new SystemCollector(collector, createSystemConfig());
    await systemCollector.initialize();

    systemCollector.bindProcessContext({
      rootPid: 1234,
      sessionId: 'sess-1',
      runId: 'run-1',
      agentId: 'agent-1',
      toolName: 'file_read',
    });

    const writes = child.stdin.write.mock.calls as string[][];
    const bindCommand = writes.find((call) => call[0].includes('"type":"bind_context"'));
    expect(bindCommand).toBeDefined();
    const parsed = JSON.parse(bindCommand![0]);
    expect(parsed.data.root_pid).toBe(1234);
    expect(parsed.data.session_id).toBe('sess-1');
    expect(parsed.data.tool_name).toBe('file_read');
  });

  it('queues bind commands before monitor is ready', async () => {
    const child = new MockChildProcess();
    mockSpawn.mockReturnValue(child as unknown as ChildProcess);

    const collector = new MockCollector();
    const systemCollector = new SystemCollector(collector, createSystemConfig());

    // Bind before initialize.
    systemCollector.bindProcessContext({ rootPid: 1234, sessionId: 'sess-1' });
    expect(child.stdin.write).not.toHaveBeenCalled();

    await systemCollector.initialize();

    const writes = child.stdin.write.mock.calls as string[][];
    const bindCommand = writes.find((call) => call[0].includes('"type":"bind_context"'));
    expect(bindCommand).toBeDefined();
  });

  it('receives events from monitor stdout and reports them', async () => {
    const child = new MockChildProcess();
    mockSpawn.mockReturnValue(child as unknown as ChildProcess);

    const collector = new MockCollector();
    const systemCollector = new SystemCollector(collector, createSystemConfig());
    await systemCollector.initialize();

    const event: SecurityEvent = {
      event_id: 'sys-123',
      event_type: 'process_start',
      layer: 'system',
      ts: Date.now(),
      pid: 5678,
      process_name: 'curl',
      comm: 'curl',
    };
    child.stdout.emit('data', JSON.stringify(event) + '\n');

    // Give the readline interface a tick to process.
    await new Promise((resolve) => setTimeout(resolve, 50));

    expect(collector.events.length).toBe(1);
    expect(collector.events[0].event_type).toBe('process_start');
    expect(collector.events[0].collector?.collector_name).toBe('system-collector');
  });

  it('enriches events with environment metadata', async () => {
    const child = new MockChildProcess();
    mockSpawn.mockReturnValue(child as unknown as ChildProcess);

    const collector = new MockCollector();
    const systemCollector = new SystemCollector(
      collector,
      createSystemConfig(),
      { hostId: 'host-001', containerId: 'abc123', podName: 'agent-pod', namespace: 'default' }
    );
    await systemCollector.initialize();

    const event: SecurityEvent = {
      event_id: 'sys-123',
      event_type: 'process_start',
      layer: 'system',
      ts: Date.now(),
      pid: 5678,
      comm: 'test',
    };
    child.stdout.emit('data', JSON.stringify(event) + '\n');

    await new Promise((resolve) => setTimeout(resolve, 50));

    const reported = collector.events[0];
    expect(reported.host_id).toBe('host-001');
    expect(reported.container_id).toBe('abc123');
    expect(reported.pod_name).toBe('agent-pod');
    expect(reported.namespace).toBe('default');
  });

  it('sends shutdown command on shutdown', async () => {
    const child = new MockChildProcess();
    mockSpawn.mockReturnValue(child as unknown as ChildProcess);

    const collector = new MockCollector();
    const systemCollector = new SystemCollector(collector, createSystemConfig());
    await systemCollector.initialize();

    await systemCollector.shutdown();

    const writes = child.stdin.write.mock.calls as string[][];
    const shutdownCommand = writes.find((call) => call[0].includes('"type":"shutdown"'));
    expect(shutdownCommand).toBeDefined();
    expect(child.killed).toBe(true);
  });

  it('enters burst scan mode on enterBurstScan and sends high-frequency config', async () => {
    const child = new MockChildProcess();
    mockSpawn.mockReturnValue(child as unknown as ChildProcess);

    const collector = new MockCollector();
    const systemCollector = new SystemCollector(
      collector,
      createSystemConfig({ burstScanEnabled: true, burstScanIntervalMs: 100, burstScanDurationMs: 1000 })
    );
    await systemCollector.initialize();

    systemCollector.enterBurstScan();

    const writes = child.stdin.write.mock.calls as string[][];
    const burstConfig = writes
      .map((call) => JSON.parse(call[0]))
      .filter((cmd) => cmd.type === 'config')
      .pop();
    expect(burstConfig.data.scanIntervalMs).toBe(100);
    expect(systemCollector.getStats().burstMode).toBe(true);
    expect(systemCollector.getStats().burstActiveCalls).toBe(1);
  });

  it('exits burst scan mode after cooldown and restores normal interval', async () => {
    vi.useFakeTimers();
    try {
      const child = new MockChildProcess();
      mockSpawn.mockReturnValue(child as unknown as ChildProcess);

      const collector = new MockCollector();
      const systemCollector = new SystemCollector(
        collector,
        createSystemConfig({ burstScanEnabled: true, burstScanIntervalMs: 100, burstScanDurationMs: 500 })
      );
      await systemCollector.initialize();

      systemCollector.enterBurstScan();
      systemCollector.exitBurstScan();

      // Before cooldown, still in burst.
      expect(systemCollector.getStats().burstMode).toBe(true);

      vi.advanceTimersByTime(600);

      // After cooldown, restored.
      expect(systemCollector.getStats().burstMode).toBe(false);
      const writes = child.stdin.write.mock.calls as string[][];
      const lastConfig = writes
        .map((call) => JSON.parse(call[0]))
        .filter((cmd) => cmd.type === 'config')
        .pop();
      expect(lastConfig.data.scanIntervalMs).toBe(5000);
    } finally {
      vi.useRealTimers();
    }
  });

  it('keeps burst mode active while overlapping tool calls exist', async () => {
    vi.useFakeTimers();
    try {
      const child = new MockChildProcess();
      mockSpawn.mockReturnValue(child as unknown as ChildProcess);

      const collector = new MockCollector();
      const systemCollector = new SystemCollector(
        collector,
        createSystemConfig({ burstScanEnabled: true, burstScanIntervalMs: 100, burstScanDurationMs: 500 })
      );
      await systemCollector.initialize();

      systemCollector.enterBurstScan(); // call 1
      systemCollector.enterBurstScan(); // call 2
      systemCollector.exitBurstScan();  // call 1 ends

      vi.advanceTimersByTime(600);

      // Still active because call 2 never exited.
      expect(systemCollector.getStats().burstMode).toBe(true);
      expect(systemCollector.getStats().burstActiveCalls).toBe(1);

      systemCollector.exitBurstScan(); // call 2 ends
      vi.advanceTimersByTime(600);

      expect(systemCollector.getStats().burstMode).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  });
});


describe('SystemCollector cgroups support', () => {
  const mockSpawn = spawn as unknown as ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('starts monitor when only cgroups is enabled', async () => {
    const child = new MockChildProcess();
    mockSpawn.mockReturnValue(child as unknown as ChildProcess);

    const collector = new MockCollector();
    const systemCollector = new SystemCollector(collector, {
      enabled: true,
      procfs: { enabled: false },
      cgroups: { enabled: true },
    });
    await systemCollector.initialize();

    expect(mockSpawn).toHaveBeenCalledTimes(1);
    const writes = child.stdin.write.mock.calls as string[][];
    const configCommand = writes.find((call) => call[0].includes('"type":"config"'));
    expect(configCommand).toBeDefined();
    const parsed = JSON.parse(configCommand![0]);
    expect(parsed.data.cgroupsEnabled).toBe(true);
  });

  it('binds process context with tool_call_id', async () => {
    const child = new MockChildProcess();
    mockSpawn.mockReturnValue(child as unknown as ChildProcess);

    const collector = new MockCollector();
    const systemCollector = new SystemCollector(collector, {
      enabled: true,
      procfs: { enabled: true },
      cgroups: { enabled: true },
    });
    await systemCollector.initialize();

    systemCollector.bindProcessContext({
      rootPid: 1234,
      sessionId: 'sess-1',
      runId: 'run-1',
      agentId: 'agent-1',
      toolName: 'file_read',
      toolCallId: 'tc-001',
    });

    const writes = child.stdin.write.mock.calls as string[][];
    const bindCommand = writes.find((call) => call[0].includes('"type":"bind_context"'));
    expect(bindCommand).toBeDefined();
    const parsed = JSON.parse(bindCommand![0]);
    expect(parsed.data.tool_call_id).toBe('tc-001');
  });

  it('forwards cgroup_snapshot events to collector', async () => {
    const child = new MockChildProcess();
    mockSpawn.mockReturnValue(child as unknown as ChildProcess);

    const collector = new MockCollector();
    const systemCollector = new SystemCollector(collector, {
      enabled: true,
      cgroups: { enabled: true },
    });
    await systemCollector.initialize();

    const event: SecurityEvent = {
      event_id: 'sys-123',
      event_type: 'cgroup_snapshot',
      layer: 'system',
      ts: Date.now(),
      pid: 1,
      comm: 'openclaw-process-monitor',
      cgroup_path: '/system.slice/docker-abc.scope',
      cpu: { usage_percent: 45.2 },
    };
    child.stdout.emit('data', JSON.stringify(event) + '\n');

    await new Promise((resolve) => setTimeout(resolve, 50));

    expect(collector.events.length).toBe(1);
    expect(collector.events[0].event_type).toBe('cgroup_snapshot');
    expect(collector.events[0].collector?.collector_name).toBe('system-collector');
  });

  it('forwards cgroup_anomaly events to collector', async () => {
    const child = new MockChildProcess();
    mockSpawn.mockReturnValue(child as unknown as ChildProcess);

    const collector = new MockCollector();
    const systemCollector = new SystemCollector(collector, {
      enabled: true,
      cgroups: { enabled: true },
    });
    await systemCollector.initialize();

    const event: SecurityEvent = {
      event_id: 'sys-123',
      event_type: 'cgroup_anomaly',
      layer: 'system',
      ts: Date.now(),
      pid: 1,
      comm: 'openclaw-process-monitor',
      anomaly_type: 'cpu_spike',
      severity: 'high',
    };
    child.stdout.emit('data', JSON.stringify(event) + '\n');

    await new Promise((resolve) => setTimeout(resolve, 50));

    expect(collector.events.length).toBe(1);
    expect(collector.events[0].event_type).toBe('cgroup_anomaly');
  });
});


describe('SystemCollector kill channel', () => {
  const mockSpawn = spawn as unknown as ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('sends kill_pid command when killProcess is called', async () => {
    const child = new MockChildProcess();
    mockSpawn.mockReturnValue(child as unknown as ChildProcess);

    const collector = new MockCollector();
    const systemCollector = new SystemCollector(collector, createSystemConfig());
    await systemCollector.initialize();

    systemCollector.killProcess(12345, 'SIGKILL');

    const writes = child.stdin.write.mock.calls as string[][];
    const killCommand = writes
      .map((call) => JSON.parse(call[0]))
      .find((cmd) => cmd.type === 'kill_pid');
    expect(killCommand).toBeDefined();
    expect(killCommand.data.pid).toBe(12345);
    expect(killCommand.data.signal).toBe('SIGKILL');
  });

  it('sends kill_pid command with default signal when signal is omitted', async () => {
    const child = new MockChildProcess();
    mockSpawn.mockReturnValue(child as unknown as ChildProcess);

    const collector = new MockCollector();
    const systemCollector = new SystemCollector(collector, createSystemConfig());
    await systemCollector.initialize();

    systemCollector.killProcess(12345);

    const writes = child.stdin.write.mock.calls as string[][];
    const killCommand = writes
      .map((call) => JSON.parse(call[0]))
      .find((cmd) => cmd.type === 'kill_pid');
    expect(killCommand).toBeDefined();
    expect(killCommand.data.pid).toBe(12345);
    expect(killCommand.data.signal).toBeUndefined();
  });
});

describe('SystemCollector auto-kill config forwarding', () => {
  const mockSpawn = spawn as unknown as ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('forwards autoKill, riskFlags, riskThreshold, protectedPids and killSignal', async () => {
    const child = new MockChildProcess();
    mockSpawn.mockReturnValue(child as unknown as ChildProcess);

    const collector = new MockCollector();
    const systemCollector = new SystemCollector(
      collector,
      createSystemConfig({
        autoKill: true,
        riskFlags: ['reverse_shell', 'download_execute'],
        riskThreshold: 2,
        protectedPids: [1, 42],
        killSignal: 'SIGKILL',
      })
    );
    await systemCollector.initialize();

    const writes = child.stdin.write.mock.calls as string[][];
    const configCommand = writes
      .map((call) => JSON.parse(call[0]))
      .find((cmd) => cmd.type === 'config');
    expect(configCommand).toBeDefined();
    expect(configCommand.data.autoKill).toBe(true);
    expect(configCommand.data.riskFlags).toEqual(['reverse_shell', 'download_execute']);
    expect(configCommand.data.riskThreshold).toBe(2);
    expect(configCommand.data.protectedPids).toEqual([1, 42]);
    expect(configCommand.data.killSignal).toBe('SIGKILL');
  });
});


describe('SystemCollector monitor crash resilience', () => {
  const mockSpawn = spawn as unknown as ReturnType<typeof vi.fn>;

  beforeEach(() => {
    // mockReset also drains one-shot mockReturnValueOnce queues so a value
    // queued by a previous crash-resilience test can never leak into the
    // next test's initialize() spawn.
    mockSpawn.mockReset();
    vi.clearAllMocks();
  });

  it('stops writing to the monitor after an unexpected exit instead of throwing EPIPE', async () => {
    const child = new MockChildProcess();
    mockSpawn.mockReturnValue(child as unknown as ChildProcess);

    const collector = new MockCollector();
    const systemCollector = new SystemCollector(collector, createSystemConfig());
    await systemCollector.initialize();

    const writesBefore = child.stdin.write.mock.calls.length;
    // Simulate the Python monitor dying on its own (kill -9, crash, ...):
    // `killed` stays false on the JS side, so the old code kept writing.
    child.emit('exit', 1, 'SIGKILL');

    expect(systemCollector.getStats().monitorReady).toBe(false);
    expect(() => {
      systemCollector.enterBurstScan();
      systemCollector.bindProcessContext({ rootPid: 1, sessionId: 's' });
      systemCollector.killProcess(4321);
    }).not.toThrow();
    expect(child.stdin.write.mock.calls.length).toBe(writesBefore);

    // Cancels the pending auto-restart timer.
    await systemCollector.shutdown();
  });

  it('restarts the monitor after a crash and counts monitorRestarts', async () => {
    vi.useFakeTimers();
    try {
      const first = new MockChildProcess();
      const second = new MockChildProcess();
      const third = new MockChildProcess();
      mockSpawn
        .mockReturnValueOnce(first as unknown as ChildProcess)
        .mockReturnValueOnce(second as unknown as ChildProcess)
        .mockReturnValueOnce(third as unknown as ChildProcess);

      const collector = new MockCollector();
      const systemCollector = new SystemCollector(collector, createSystemConfig());
      await systemCollector.initialize();
      expect(mockSpawn).toHaveBeenCalledTimes(1);

      first.emit('exit', 1, null);
      expect(systemCollector.getStats().monitorRestarts).toBe(1);

      // Restart after the 1s base delay; the replacement monitor gets a
      // fresh config command and the backoff counter resets on success.
      await vi.advanceTimersByTimeAsync(1000);
      expect(mockSpawn).toHaveBeenCalledTimes(2);
      const configWrites = second.stdin.write.mock.calls.filter((call) =>
        (call[0] as string).includes('"type":"config"')
      );
      expect(configWrites.length).toBeGreaterThan(0);

      second.emit('exit', 1, null);
      expect(systemCollector.getStats().monitorRestarts).toBe(2);
      await vi.advanceTimersByTimeAsync(1000);
      expect(mockSpawn).toHaveBeenCalledTimes(3);
    } finally {
      vi.useRealTimers();
    }
  });

  it('backs off exponentially when the restart itself fails to spawn', async () => {
    vi.useFakeTimers();
    try {
      const first = new MockChildProcess();
      const second = new MockChildProcess();
      mockSpawn
        .mockReturnValueOnce(first as unknown as ChildProcess)
        .mockImplementationOnce(() => {
          throw new Error('spawn python3 ENOENT');
        })
        .mockReturnValueOnce(second as unknown as ChildProcess);

      const collector = new MockCollector();
      const systemCollector = new SystemCollector(collector, createSystemConfig());
      await systemCollector.initialize();

      first.emit('exit', 1, null);
      await vi.advanceTimersByTimeAsync(1000); // restart attempt fails to spawn
      expect(systemCollector.getStats().monitorRestarts).toBe(2);

      // Backoff doubled: 2s before the next attempt.
      await vi.advanceTimersByTimeAsync(1999);
      expect(mockSpawn).toHaveBeenCalledTimes(2);
      await vi.advanceTimersByTimeAsync(1);
      expect(mockSpawn).toHaveBeenCalledTimes(3);
      const configWrites = second.stdin.write.mock.calls.filter((call) =>
        (call[0] as string).includes('"type":"config"')
      );
      expect(configWrites.length).toBeGreaterThan(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it('does not schedule a restart after an orderly shutdown', async () => {
    vi.useFakeTimers();
    try {
      const child = new MockChildProcess();
      mockSpawn.mockReturnValue(child as unknown as ChildProcess);

      const collector = new MockCollector();
      const systemCollector = new SystemCollector(collector, createSystemConfig());
      await systemCollector.initialize();

      const shutdownPromise = systemCollector.shutdown();
      // The mock monitor exits cleanly in response to the shutdown command.
      child.emit('exit', 0, null);
      await shutdownPromise;

      vi.advanceTimersByTime(60000);
      expect(mockSpawn).toHaveBeenCalledTimes(1);
      expect(systemCollector.getStats().monitorRestarts).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it('swallows async EPIPE on monitor stdin without crashing the gateway', async () => {
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    try {
      const child = new MockChildProcess();
      mockSpawn.mockReturnValue(child as unknown as ChildProcess);

      const collector = new MockCollector();
      const systemCollector = new SystemCollector(collector, createSystemConfig());
      await systemCollector.initialize();

      // A write racing the monitor's death surfaces as an async EPIPE 'error'.
      expect(() =>
        child.stdin.emit('error', Object.assign(new Error('write EPIPE'), { code: 'EPIPE' }))
      ).not.toThrow();
      expect(errSpy).not.toHaveBeenCalled();
    } finally {
      errSpy.mockRestore();
    }
  });

  it('drops non-finite numeric config fields instead of sending NaN/null to the monitor', async () => {
    const child = new MockChildProcess();
    mockSpawn.mockReturnValue(child as unknown as ChildProcess);

    const collector = new MockCollector();
    const config = createSystemConfig({ scanIntervalMs: NaN as unknown as number });
    const systemCollector = new SystemCollector(collector, config);
    await systemCollector.initialize();

    const writes = child.stdin.write.mock.calls as string[][];
    const configCommand = writes
      .map((call) => JSON.parse(call[0]))
      .find((cmd) => cmd.type === 'config');
    expect(configCommand).toBeDefined();
    // The poisoned key is omitted entirely — never NaN or null — so the
    // monitor keeps its default scanIntervalMs.
    expect(configCommand.data.scanIntervalMs).toBeUndefined();
    expect(JSON.stringify(configCommand.data)).not.toContain('null');
  });
});
