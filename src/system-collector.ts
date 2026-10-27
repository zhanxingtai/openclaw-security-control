import { spawn, type ChildProcess } from 'child_process';
import { createInterface } from 'readline';
import type {
  EventCollector,
  ILayerCollector,
  SecurityEvent,
  SystemLayerConfig,
  EnvironmentConfig,
} from "./types.js";
import { getProcessMonitorPath } from './process-monitor-path.js';
import { isSafePythonPath } from './initialize.js';

export interface ProcessContext {
  rootPid: number;
  sessionId?: string;
  runId?: string;
  agentId?: string;
  toolName?: string;
  toolCallId?: string;
}

/**
 * System layer collector - procfs process monitoring via the embedded Python monitor.
 *
 * Responsibilities:
 * - Spawn an embedded Python monitor process that scans /proc via psutil.
 * - Send configuration and process-context bindings to the monitor.
 * - Receive NDJSON events from the monitor and forward them to EventCollector.
 * - Gracefully shut down the monitor on plugin shutdown.
 *
 * Other system-layer subsystems (cgroups, fileMonitor, auditd, containerEvents)
 * remain as future extension points.
 */
export class SystemCollector implements ILayerCollector {
  readonly name = 'system-collector';

  private collector: EventCollector;
  private config: SystemLayerConfig;
  private environment: EnvironmentConfig;
  private started = false;
  private monitor?: ChildProcess;
  private monitorPath?: string;
  private monitorReady = false;
  private pendingBinds: ProcessContext[] = [];
  private burstState = {
    activeCalls: 0,
    inBurst: false,
    restoreTimer: undefined as ReturnType<typeof setTimeout> | undefined,
  };
  private stats = {
    eventsReceived: 0,
    eventsReported: 0,
    monitorRestarts: 0,
    bindCommandsSent: 0,
    burstModeEntered: 0,
    burstModeExited: 0,
  };
  private restartTimer?: ReturnType<typeof setTimeout>;
  private restartAttempts = 0;
  private static readonly RESTART_BASE_DELAY_MS = 1000;
  private static readonly RESTART_MAX_DELAY_MS = 60000;

  constructor(
    collector: EventCollector,
    config: SystemLayerConfig,
    environment?: EnvironmentConfig
  ) {
    this.collector = collector;
    this.config = config;
    this.environment = environment || {};
  }

  async initialize(): Promise<void> {
    if (!this.config.enabled) {
      return;
    }

    if (this.config.procfs?.enabled || this.config.cgroups?.enabled) {
      await this.startProcessMonitor();
    }

    this.started = true;
  }

  async report(event: SecurityEvent): Promise<void> {
    if (!this.config.enabled) {
      return;
    }
    await this.collector.report(event);
  }

  async shutdown(): Promise<void> {
    if (!this.started) {
      return;
    }

    this.started = false;
    this.clearBurstRestoreTimer();
    this.clearRestartTimer();

    if (this.monitor && !this.monitor.killed) {
      this.sendCommand({ type: 'shutdown' });

      // Give the monitor a short window to exit cleanly.
      await new Promise<void>((resolve) => {
        const timer = setTimeout(() => {
          if (this.monitor && !this.monitor.killed) {
            this.monitor.kill('SIGTERM');
          }
          resolve();
        }, 1500);

        this.monitor?.on('exit', () => {
          clearTimeout(timer);
          resolve();
        });
      });
    }

    this.monitor = undefined;
    this.monitorReady = false;
  }

  getStats(): Record<string, unknown> {
    return {
      started: this.started,
      procfsEnabled: this.config.procfs?.enabled,
      cgroupsEnabled: this.config.cgroups?.enabled,
      monitorReady: this.monitorReady,
      monitorPath: this.monitorPath,
      burstMode: this.burstState.inBurst,
      burstActiveCalls: this.burstState.activeCalls,
      ...this.stats,
    };
  }

  /**
   * Enter high-frequency burst scan mode.
   *
   * Called by the middleware when a tool call starts. The monitor scan interval
   * is temporarily reduced so short-lived child processes (e.g. exec commands)
   * have a much higher chance of being observed.
   */
  enterBurstScan(): void {
    if (!this.config.enabled) {
      return;
    }
    if (!this.config.procfs?.enabled && !this.config.cgroups?.enabled) {
      return;
    }
    if (this.config.procfs?.enabled && !this.config.procfs.burstScanEnabled) {
      return;
    }

    this.burstState.activeCalls += 1;
    this.stats.burstModeEntered += 1;

    if (!this.burstState.inBurst) {
      this.burstState.inBurst = true;
      this.clearBurstRestoreTimer();
      this.sendDynamicConfig({ scanIntervalMs: this.config.procfs?.burstScanIntervalMs ?? 100, burstMode: true });
    }
  }

  /**
   * Exit high-frequency burst scan mode.
   *
   * Burst mode is kept active for a cooldown period after the last active tool
   * call ends, so any trailing child processes are still captured.
   */
  exitBurstScan(): void {
    if (!this.config.enabled) {
      return;
    }
    if (!this.config.procfs?.enabled && !this.config.cgroups?.enabled) {
      return;
    }
    if (this.config.procfs?.enabled && !this.config.procfs.burstScanEnabled) {
      return;
    }

    this.burstState.activeCalls = Math.max(0, this.burstState.activeCalls - 1);
    this.stats.burstModeExited += 1;

    if (this.burstState.activeCalls === 0) {
      this.scheduleBurstRestore();
    }
  }

  /**
   * Bind an OpenClaw tool-call context to the current Agent process tree.
   * The monitor will scan processes rooted at `rootPid` and tag events with
   * the supplied session/run/agent/tool metadata.
   */
  bindProcessContext(context: ProcessContext): void {
    if (!this.config.enabled || (!this.config.procfs?.enabled && !this.config.cgroups?.enabled)) {
      return;
    }

    if (!this.monitorReady || !this.monitor) {
      // Queue binds that arrive before the monitor finishes initialization.
      this.pendingBinds.push(context);
      return;
    }

    this.sendBindCommand(context);
  }

  /**
   * Request that the embedded process monitor terminate a specific PID.
   * The monitor enforces its own safety rules (never kills PID 0/1, its own
   * PID, or protected PIDs).
   */
  killProcess(pid: number, signal?: string | number): void {
    if (!this.config.enabled || !this.monitor || this.monitor.killed || !this.monitor.stdin) {
      return;
    }
    this.sendCommand({
      type: 'kill_pid',
      data: {
        pid,
        signal,
      },
    });
  }

  // ---------------------------------------------------------------------------
  // Monitor process management
  // ---------------------------------------------------------------------------

  private async startProcessMonitor(): Promise<void> {
    try {
      this.monitorPath = getProcessMonitorPath();
    } catch (err) {
      console.warn(
        '[SystemCollector] process_monitor.py not found, procfs monitoring disabled:',
        (err as Error).message
      );
      return;
    }

    const pythonPath = this.config.procfs?.pythonPath || 'python3';
    if (!isSafePythonPath(pythonPath)) {
      // pythonPath is an RCE sink — refuse to spawn anything that
      // is not a python3-named binary (see isSafePythonPath).
      console.warn(
        `[SystemCollector] 非法 pythonPath "${pythonPath}"（须为 python3/python3.x 或绝对路径且 basename 匹配 python3(\\.\\d+)?）— 不启动进程监控`
      );
      return;
    }

    this.monitor = spawn(pythonPath, [this.monitorPath], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: {
        ...process.env,
        HOSTNAME: this.environment.hostId || process.env.HOSTNAME || process.env.HOST || '',
      },
    });

    this.monitor.on('error', (err) => {
      console.error('[SystemCollector] Monitor process error:', err.message);
      this.monitorReady = false;
      if (this.started) {
        this.scheduleMonitorRestart();
      }
    });

    this.monitor.on('exit', (code, signal) => {
      this.monitorReady = false;
      this.monitor = undefined;
      if (!this.started) {
        return; // expected during shutdown
      }
      console.warn(
        `[SystemCollector] Monitor exited with code=${code} signal=${signal}. ` +
          'Process monitoring is no longer active.'
      );
      this.scheduleMonitorRestart();
    });

    // Writes to a dead monitor surface as an async EPIPE 'error' on stdin,
    // which crashes the gateway when nobody listens for it.
    if (this.monitor.stdin && typeof this.monitor.stdin.on === 'function') {
      this.monitor.stdin.on('error', (err: NodeJS.ErrnoException) => {
        if (err.code === 'EPIPE') {
          return; // monitor is gone; the exit handler logs and restarts
        }
        console.error('[SystemCollector] Monitor stdin error:', err.message);
      });
    }

    // Stderr lines are treated as monitor logs.
    if (this.monitor.stderr) {
      const stderrReader = createInterface({ input: this.monitor.stderr });
      stderrReader.on('line', (line) => {
        this.handleMonitorStderr(line);
      });
    }

    // Stdout lines are NDJSON events.
    if (this.monitor.stdout) {
      const stdoutReader = createInterface({ input: this.monitor.stdout });
      stdoutReader.on('line', (line) => {
        this.handleMonitorStdout(line);
      });
    }

    // Send configuration and drain any pending context bindings.
    this.sendConfig();
    this.monitorReady = true;
    this.restartAttempts = 0;
    this.drainPendingBinds();
  }

  /**
   * Restart the monitor after an unexpected exit, with exponential
   * backoff (1s base, doubling up to 60s) so a crashing monitor cannot
   * hot-loop. Each attempt counts towards `monitorRestarts`.
   */
  private scheduleMonitorRestart(): void {
    if (this.restartTimer) {
      return;
    }
    const delayMs = Math.min(
      SystemCollector.RESTART_MAX_DELAY_MS,
      SystemCollector.RESTART_BASE_DELAY_MS * 2 ** this.restartAttempts
    );
    this.restartAttempts += 1;
    this.stats.monitorRestarts += 1;
    console.warn(
      `[SystemCollector] Restarting process monitor in ${delayMs}ms ` +
        `(attempt ${this.restartAttempts}).`
    );
    this.restartTimer = setTimeout(() => {
      this.restartTimer = undefined;
      if (!this.started) {
        return; // shutdown won the race
      }
      void this.startProcessMonitor().catch((err) => {
        console.error('[SystemCollector] Failed to restart process monitor:', err);
        this.scheduleMonitorRestart();
      });
    }, delayMs);
  }

  private clearRestartTimer(): void {
    if (this.restartTimer) {
      clearTimeout(this.restartTimer);
      this.restartTimer = undefined;
    }
  }

  private sendConfig(): void {
    this.sendDynamicConfig({});
  }

  private sendDynamicConfig(overrides: { scanIntervalMs?: number; burstMode?: boolean }): void {
    const procfs = this.config.procfs || {};
    const cgroups = this.config.cgroups || {};
    const data: Record<string, unknown> = {
      scanIntervalMs: overrides.scanIntervalMs ?? procfs.scanIntervalMs,
      snapshotIntervalMs: procfs.snapshotIntervalMs,
      burstMode: overrides.burstMode ?? this.burstState.inBurst,
      burstScanGlobal: procfs.burstScanGlobal,
      processNames: procfs.processNames,
      excludeCommandLines: procfs.excludeCommandLines,
      collectOpenFiles: procfs.collectOpenFiles,
      collectConnections: procfs.collectConnections,
      collectChildren: procfs.collectChildren,
      collectCpuPercent: procfs.collectCpuPercent,
      changeDetectionFields: procfs.changeDetectionFields,
      memoryRssChangeThresholdBytes: procfs.memoryRssChangeThresholdBytes,
      autoKill: procfs.autoKill,
      riskFlags: procfs.riskFlags,
      riskThreshold: procfs.riskThreshold,
      protectedPids: procfs.protectedPids,
      killSignal: procfs.killSignal,
      cgroupsEnabled: cgroups.enabled,
      cgroupsScanIntervalMs: cgroups.scanIntervalMs,
      cgroupsBurstScanIntervalMs: cgroups.burstScanIntervalMs,
      cgroupsCpuChangeThresholdPercent: cgroups.cpuChangeThresholdPercent,
      cgroupsMemoryChangeThresholdPercent: cgroups.memoryChangeThresholdPercent,
      cgroupsIoChangeThresholdBytes: cgroups.ioChangeThresholdBytes,
      cgroupsAnomalyCpuSpikeThresholdPercent: cgroups.anomalyCpuSpikeThresholdPercent,
      cgroupsAnomalyMemoryThresholdPercent: cgroups.anomalyMemoryThresholdPercent,
      cgroupsFullFieldsInBurstOnly: cgroups.fullFieldsInBurstOnly,
      cgroupsHeartbeatEnabled: cgroups.heartbeatEnabled,
      cgroupsAggregateWindowSeconds: cgroups.aggregateWindowSeconds,
    };
    // NaN would serialize to null and crash the monitor's int() parsing;
    // drop the key so the monitor keeps its current (default) value.
    for (const [key, value] of Object.entries(data)) {
      if (typeof value === 'number' && !Number.isFinite(value)) {
        console.warn(`[SystemCollector] Dropping non-finite numeric config "${key}" (${value})`);
        delete data[key];
      }
    }
    this.sendCommand({ type: 'config', data });
  }

  private scheduleBurstRestore(): void {
    this.clearBurstRestoreTimer();
    const cooldownMs = this.config.procfs?.burstScanDurationMs ?? 3000;
    this.burstState.restoreTimer = setTimeout(() => {
      this.burstState.restoreTimer = undefined;
      if (this.burstState.activeCalls > 0) {
        return; // another tool call started in the meantime
      }
      this.burstState.inBurst = false;
      this.sendDynamicConfig({ scanIntervalMs: this.config.procfs?.scanIntervalMs, burstMode: false });
    }, cooldownMs);
  }

  private clearBurstRestoreTimer(): void {
    if (this.burstState.restoreTimer) {
      clearTimeout(this.burstState.restoreTimer);
      this.burstState.restoreTimer = undefined;
    }
  }

  private drainPendingBinds(): void {
    while (this.pendingBinds.length > 0) {
      const context = this.pendingBinds.shift();
      if (context) {
        this.sendBindCommand(context);
      }
    }
  }

  private sendBindCommand(context: ProcessContext): void {
    this.sendCommand({
      type: 'bind_context',
      data: {
        root_pid: context.rootPid,
        session_id: context.sessionId,
        run_id: context.runId,
        agent_id: context.agentId,
        tool_name: context.toolName,
        tool_call_id: context.toolCallId,
      },
    });
    this.stats.bindCommandsSent += 1;
  }

  private sendCommand(command: Record<string, unknown>): void {
    if (!this.monitor || this.monitor.killed || !this.monitor.stdin) {
      return;
    }

    try {
      this.monitor.stdin.write(JSON.stringify(command) + '\n');
    } catch (err) {
      console.error('[SystemCollector] Failed to send command to monitor:', err);
    }
  }

  // ---------------------------------------------------------------------------
  // Event handling
  // ---------------------------------------------------------------------------

  private handleMonitorStdout(line: string): void {
    if (!line.trim()) {
      return;
    }

    let event: SecurityEvent;
    try {
      event = JSON.parse(line) as SecurityEvent;
    } catch (err) {
      console.warn('[SystemCollector] Invalid NDJSON event from monitor:', line);
      return;
    }

    this.stats.eventsReceived += 1;

    // Enrich with environment metadata if the monitor did not set it.
    if (!event.host_id && this.environment.hostId) {
      event.host_id = this.environment.hostId;
    }
    if (!event.container_id && this.environment.containerId) {
      event.container_id = this.environment.containerId;
    }
    if (!event.pod_name && this.environment.podName) {
      event.pod_name = this.environment.podName;
    }
    if (!event.namespace && this.environment.namespace) {
      event.namespace = this.environment.namespace;
    }

    event.source = 'openclaw.v1';
    if (!event.collection_method) event.collection_method = 'procfs';
    event.schema_version = 1;
    if (event.session_id === undefined) event.session_id = null;
    if (event.run_id === undefined) event.run_id = null;
    if (event.task_id === undefined) event.task_id = null;
    if (event.turn_id === undefined) event.turn_id = null;
    event.collector = {
      ...(event.collector || {}),
      collector_name: this.name,
    };

    this.collector.report(event).catch((err) => {
      console.error('[SystemCollector] Failed to report event:', err);
    });

    this.stats.eventsReported += 1;
  }

  private handleMonitorStderr(line: string): void {
    if (!line.trim()) {
      return;
    }

    try {
      const log = JSON.parse(line) as { type?: string; level?: string; message?: string };
      if (log.type === 'log') {
        const message = `[process-monitor] ${log.message || ''}`;
        if (log.level === 'error') {
          console.error(message);
        } else if (log.level === 'warn') {
          console.warn(message);
        } else {
          console.log(message);
        }
        return;
      }
      if (log.type === 'error') {
        console.error(`[process-monitor] ${log.message || ''}`);
        return;
      }
    } catch {
      // Not JSON, forward raw.
    }

    console.error(`[process-monitor] ${line}`);
  }
}
