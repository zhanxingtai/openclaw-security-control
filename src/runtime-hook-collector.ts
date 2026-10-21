import { openSync, closeSync, fstatSync, readSync, stat, statSync } from 'fs';
import { watchFile, unwatchFile, type Stats } from 'fs';
import { existsSync, readFileSync, writeFileSync, mkdirSync, renameSync, unlinkSync, lstatSync } from 'fs';
import { dirname } from 'path';
import type {
  ILayerCollector,
  SecurityEvent,
  RuntimeHooksConfig,
  EnvironmentConfig,
} from "./types.js";
import { generateUUID } from './uuid.js';
import { pidBindingStore } from './utils/pid-binding-store.js';

// Keep an inline minimal interface so the test mock and the real
// implementation share the same surface.
type EventCollectorLike = { report: (event: SecurityEvent) => Promise<void> };

/**
 * 归一化后、落盘前的评估回调。宿主（SecurityMonitorStore）用它把
 * process_start / network_http 事件回灌干预引擎，决策写回事件的
 * intervention 字段后随 NDJSON 一起落盘留痕。
 */
export interface RuntimeHookEventHooks {
  onEvent?: (event: SecurityEvent) => Promise<void> | void;
}

interface ParsedRuntimeEvent {
  type?: string;
  id?: string;
  // Legacy timestamp field accepted for backward compatibility.
  timestamp?: string;
  runtime?: string;
  api?: string;
  command_line?: string;
  command_line_raw?: string;
  executable?: string;
  process_name?: string;
  arguments?: string[];
  shell_involved?: boolean;
  shell?: string;
  cwd?: string;
  pid?: number;
  ppid?: number;
  target_pid?: number;
  caller?: SecurityEvent['caller'];
  session_id?: string;
  run_id?: string;
  agent_id?: string;
  tool_call_id?: string;
  tool_name?: string;
  risk_flags?: string[];
  blocked?: boolean;
  block_reason?: string;
  block_code?: string;
  // Network HTTP event fields
  event_type?: string;
  event_id?: string;
  comm?: string;
  ts?: number;
  host_id?: string;
  container_id?: string;
  pod_name?: string;
  namespace?: string;
  source?: string | SecurityEvent['collector'];
  content?: string;
  content_length?: number;
  service?: string;
  direction?: 'send' | 'recv' | string;
  latency_ms?: number;
  method?: string;
  url?: string;
  host?: string;
  code?: number;
  header?: string;
  body?: string;
  response_body?: string;
  status_message?: string;
  request_url?: string;
  domain_name?: string;
  /** Local side (socket local address). Mapped to local_ip on emit. */
  local_ip?: string;
  local_port?: number;
  /** Remote side. Mapped to remote_ip on emit. */
  remote_ip?: string;
  remote_port?: number;
  /** Legacy local/remote aliases. Mapped to local_ip/local_port. */
  src_ip?: string;
  dst_ip?: string;
  src_port?: number;
  dst_port?: number;
}

/**
 * Runtime hook collector.
 *
 * Reads JSON Lines events produced by language-specific runtime hooks (e.g.
 * the Node.js child_process hook) and forwards them to the EventCollector as
 * application-layer `process_start` events.
 */
export class RuntimeHookCollector implements ILayerCollector {
  readonly name = 'runtime-hook-collector';

  private collector: EventCollectorLike;
  private config: RuntimeHooksConfig;
  private environment: EnvironmentConfig;
  private started = false;
  private lastSize = 0;
  private watchListener?: (curr: Stats, prev: Stats) => void;
  private pollingTimer?: NodeJS.Timeout;
  private logPath?: string;
  private stats = {
    eventsReceived: 0,
    eventsReported: 0,
    parseErrors: 0,
    /** 因队列积压跳过评估的事件数。 */
    eventsEvaluationSkipped: 0,
  };
  private hooks: RuntimeHookEventHooks;
  // 事件评估→落盘串行队列：chain 规则依赖事件顺序（先脱库后外传），
  // 并发评估会让后一个事件读不到前一个事件的 action 记录。
  private dispatchQueue: Promise<void> = Promise.resolve();
  // 队列当前积压长度（已入队、尚未执行完的事件数）。
  private dispatchBacklog = 0;
  /** 积压告警每次积压只打一次；排空后重新武装。 */
  private backlogWarned = false;

  constructor(
    collector: EventCollectorLike,
    config: RuntimeHooksConfig,
    environment?: EnvironmentConfig,
    hooks?: RuntimeHookEventHooks
  ) {
    this.collector = collector;
    this.config = config || { enabled: false };
    this.environment = environment || {};
    this.hooks = hooks || {};
  }

  async initialize(): Promise<void> {
    if (!this.config.enabled || !this.config.logPath) {
      return;
    }

    // Ensure the runtime hook log exists on first boot. The preload hook
    // (runtime.js) writes to this path the first time a child_process API
    // is invoked; without it the first stat/openSync call below would
    // print a noisy ENOENT before the hook has had a chance to create
    // the file. Touch the file (and its parent dir) only when missing —
    // never overwrite existing content.
    try {
      if (!existsSync(this.config.logPath)) {
        mkdirSync(dirname(this.config.logPath), { recursive: true });
        writeFileSync(this.config.logPath, '');
      }
    } catch (err) {
      console.warn(
        `[RuntimeHookCollector] failed to ensure log file at ${this.config.logPath}: ${err instanceof Error ? err.message : String(err)}`
      );
    }

    this.started = true;
    this.logPath = this.config.logPath;

    // Resume from persisted cursor when possible. This is what stops the
    // collector from replaying the entire historical log (often hundreds of
    // MB of accumulated network_http traffic) on every restart.
    const cursor = this.loadCursor();
    const fileSize = await this.getFileSize(this.logPath);

    if (cursor !== undefined && cursor <= fileSize) {
      // Happy path: resume exactly where we left off last time.
      this.lastSize = cursor;
    } else if (cursor !== undefined && cursor > fileSize) {
      // Cursor points past the current EOF → log file was rotated/replaced.
      // Restart from the beginning so we don't lose anything.
      this.lastSize = 0;
    } else {
      // First run, or the cursor file was wiped alongside the log file.
      // Default: skip the entire pre-existing file to avoid replaying
      // historical noise. Honor firstRunLookbackBytes to recover any events
      // written in the small race window between hook load and collector init.
      const lookback = Math.max(0, this.config.firstRunLookbackBytes ?? 0);
      if (this.config.replayOnFirstRun) {
        this.lastSize = 0;
      } else if (lookback > 0) {
        this.lastSize = Math.max(0, fileSize - lookback);
      } else {
        // Truly start at EOF: skip pre-existing content entirely.
        this.lastSize = fileSize;
      }
    }

    // Always go through readNewLines so the cursor is persisted (even when
    // there is nothing to read, it records EOF for the next restart).
    this.readNewLines(this.lastSize);

    this.watchListener = (curr: Stats) => {
      // File was truncated or replaced (e.g., log rotation). Re-read from
      // start so we don't lose the new content.
      if (curr.size < this.lastSize) {
        this.lastSize = 0;
        this.readNewLines(0);
        this.saveCursor(0);
        return;
      }
      if (curr.size > this.lastSize) {
        this.readNewLines(this.lastSize);
      }
    };
    watchFile(this.logPath, { interval: 50 }, this.watchListener);

    // fs.watchFile is stat-based and can miss rapid appends or fail on some
    // filesystems (e.g. overlayfs in containers). Add a lightweight polling
    // fallback so we still observe new log data within ~100 ms.
    const pollIntervalMs = this.config.pollIntervalMs ?? 100;
    this.pollingTimer = setInterval(() => {
      if (!this.logPath) return;
      try {
        const size = statSync(this.logPath).size;
        if (size < this.lastSize) {
          this.lastSize = 0;
          this.readNewLines(0);
          this.saveCursor(0);
        } else if (size > this.lastSize) {
          this.readNewLines(this.lastSize);
        }
      } catch {
        // Log file may have been rotated away; ignore and wait for next poll.
      }
    }, pollIntervalMs);
  }

  async report(event: SecurityEvent): Promise<void> {
    await this.collector.report(event);
  }

  async shutdown(): Promise<void> {
    this.started = false;
    if (this.pollingTimer) {
      clearInterval(this.pollingTimer);
      this.pollingTimer = undefined;
    }
    if (this.logPath && this.watchListener) {
      unwatchFile(this.logPath, this.watchListener);
      this.watchListener = undefined;
    }
  }

  getStats(): Record<string, unknown> {
    return {
      started: this.started,
      logPath: this.config.logPath,
      lastSize: this.lastSize,
      cursorPath: this.cursorPath(),
      replayOnFirstRun: this.config.replayOnFirstRun ?? false,
      firstRunLookbackBytes: this.config.firstRunLookbackBytes ?? 0,
      maxLogSizeBytes: this.config.maxLogSizeBytes ?? 0,
      maxEvaluationBacklog: this.config.maxEvaluationBacklog ?? 0,
      dispatchBacklog: this.dispatchBacklog,
      ...this.stats,
    };
  }

  private getFileSize(filePath: string): Promise<number> {
    return new Promise((resolve) => {
      stat(filePath, (err, stats) => {
        resolve(err ? 0 : stats.size);
      });
    });
  }

  private readNewLines(startPosition: number): void {
    if (!this.config.logPath) return;

    try {
      const fd = openSync(this.config.logPath, 'r');
      try {
        const size = fstatSync(fd).size;
        if (size <= startPosition) {
          this.lastSize = size;
          this.saveCursor(size);
          return;
        }
        const bytesToRead = size - startPosition;
        const buffer = Buffer.alloc(bytesToRead);
        const bytesRead = readSync(fd, buffer, 0, bytesToRead, startPosition);
        const content = buffer.toString('utf8', 0, bytesRead);
        const lines = content.split('\n');
        for (const line of lines) {
          this.handleLine(line);
        }
        this.lastSize = startPosition + bytesRead;
        // Persist the cursor after each successful batch so the next restart
        // resumes from exactly here.
        this.saveCursor(this.lastSize);
        // Bound the transient runtime log so it does not grow without limit
        // alongside the canonical security-events.jsonl.
        this.maybeRotateLog();
      } finally {
        closeSync(fd);
      }
    } catch (err) {
      console.error(`[RuntimeHookCollector] read error: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  /**
   * Sidecar cursor file: `${logPath}.offset`. We persist the byte offset
   * we've successfully consumed so the next startup can resume from there
   * without replaying the entire log.
   */
  private cursorPath(): string | undefined {
    return this.config.logPath ? `${this.config.logPath}.offset` : undefined;
  }

  private loadCursor(): number | undefined {
    const p = this.cursorPath();
    if (!p || !existsSync(p)) return undefined;
    try {
      const raw = readFileSync(p, 'utf8').trim();
      if (!raw) return undefined;
      const n = Number(raw);
      return Number.isFinite(n) && n >= 0 ? n : undefined;
    } catch (err) {
      console.warn(
        `[RuntimeHookCollector] failed to read cursor at ${p}: ${err instanceof Error ? err.message : String(err)}`
      );
      return undefined;
    }
  }

  private saveCursor(offset: number): void {
    const p = this.cursorPath();
    if (!p) return;
    try {
      mkdirSync(dirname(p), { recursive: true });
      writeFileSync(p, `${offset}\n`, 'utf8');
    } catch (err) {
      // Cursor persistence is best-effort: if it fails, we fall back to the
      // next-startup behavior (resume from EOF by default). Log and move on.
      console.warn(
        `[RuntimeHookCollector] failed to persist cursor at ${p}: ${err instanceof Error ? err.message : String(err)}`
      );
    }
  }

  /**
   * Keep the transient runtime hook log bounded. After the collector has read
   * up to the current EOF, if the file is larger than maxLogSizeBytes we
   * rotate it: the old file is moved aside, a fresh file is created at the same
   * path, and any events written during the rotation window are drained from
   * the rotated file before it is deleted. This prevents the raw runtime log
   * from growing without limit while the canonical events are already written
   * to security-events.jsonl.
   */
  private maybeRotateLog(): void {
    const maxSize = this.config.maxLogSizeBytes ?? 0;
    if (!this.logPath || maxSize <= 0) return;

    let currentSize: number;
    try {
      currentSize = statSync(this.logPath).size;
    } catch {
      return;
    }
    if (currentSize <= maxSize) return;

    // Symlink guard: if the configured log path is a symlink, refuse to
    // rename (it would move the symlink itself, not the target). Operators
    // must point at a regular file; warn loudly so the misconfiguration
    // surfaces instead of silently breaking rotation.
    try {
      const lst = lstatSync(this.logPath);
      if (lst.isSymbolicLink()) {
        console.warn(
          `[RuntimeHookCollector] log path ${this.logPath} is a symlink; refusing to rotate to avoid following the link`
        );
        return;
      }
    } catch {
      // lstat failed (file may have been rotated by another process); fall
      // through to the rename, which will surface a real error below.
    }

    const rotatedPath = `${this.logPath}.rotated`;
    try {
      // Stop watching the current path so we can rename it safely.
      if (this.watchListener) {
        unwatchFile(this.logPath, this.watchListener);
      }

      const resumeOffset = this.lastSize;

      // Move the oversized file aside. New hook writes will go to a fresh file.
      renameSync(this.logPath, rotatedPath);
      this.lastSize = 0;
      this.saveCursor(0);

      // Drain any events written between the last read and the rename.
      this.readNewLinesFrom(rotatedPath, resumeOffset);

      // Remove the rotated file; the canonical events are already persisted.
      try {
        unlinkSync(rotatedPath);
      } catch (err) {
        console.warn(
          `[RuntimeHookCollector] failed to delete rotated log ${rotatedPath}: ${err instanceof Error ? err.message : String(err)}`
        );
      }

      // Resume watching the fresh log file at the original path.
      if (this.watchListener) {
        watchFile(this.logPath, { interval: 50 }, this.watchListener);
      }

      console.error(
        `[RuntimeHookCollector] rotated runtime log at ${this.logPath} (size ${currentSize} > ${maxSize})`
      );
    } catch (err) {
      console.error(
        `[RuntimeHookCollector] failed to rotate runtime log ${this.logPath}: ${err instanceof Error ? err.message : String(err)}`
      );
      // Try to resume watching if it was stopped.
      if (this.watchListener && this.logPath) {
        watchFile(this.logPath, { interval: 50 }, this.watchListener);
      }
    }
  }

  private readNewLinesFrom(filePath: string, startPosition: number): void {
    try {
      const fd = openSync(filePath, 'r');
      try {
        const size = fstatSync(fd).size;
        if (size <= startPosition) {
          return;
        }
        const bytesToRead = size - startPosition;
        const buffer = Buffer.alloc(bytesToRead);
        const bytesRead = readSync(fd, buffer, 0, bytesToRead, startPosition);
        const content = buffer.toString('utf8', 0, bytesRead);
        const lines = content.split('\n');
        for (const line of lines) {
          this.handleLine(line);
        }
      } finally {
        closeSync(fd);
      }
    } catch (err) {
      console.error(`[RuntimeHookCollector] read error on ${filePath}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  private handleLine(line: string): void {
    if (!line.trim()) return;

    let parsed: ParsedRuntimeEvent;
    try {
      parsed = JSON.parse(line) as ParsedRuntimeEvent;
    } catch {
      this.stats.parseErrors += 1;
      console.warn('[RuntimeHookCollector] Invalid JSON line:', line);
      return;
    }

    if (parsed.event_type !== 'network_http' && !this.isCommandEvent(parsed)) {
      // Ignore unrelated runtime log lines.
      return;
    }

    // Skip periodic/internal noise matched by configured regex patterns.
    if (this.isCommandEvent(parsed)) {
      const cmd = parsed.command_line || parsed.command_line_raw || '';
      if (this.shouldExcludeCommand(cmd)) {
        return;
      }
    }

    // Skip network traffic generated by the collector itself (e.g. the
    // HTTP endpoint that receives this monitor's events) so the event stream
    // does not recursively report its own upload requests.
    if (this.isNetworkEvent(parsed) && this.shouldExcludeNetworkEvent(parsed)) {
      return;
    }

    this.stats.eventsReceived += 1;

    const event = this.normalizeEvent(parsed);
    this.dispatchEvent(event);
  }

  /**
   * 评估（如已接线）在前、落盘在后，两者串行：评估回调可能改写事件
   * （写 intervention 决策字段），必须发生在 NDJSON 序列化之前。
   *
   * 队列有界：评估是纯同步 CPU 工作、decisionTimeoutMs 无法
   * 抢占，事件速率超过评估吞吐时无序排队会让 Promise 链与内存无界增长，
   * 且落盘被评估一并拖住（审计延迟随积压扩大）。积压达到
   * maxEvaluationBacklog 后，新事件跳过评估、只落盘：审计不丢、内存有界，
   * 代价是该事件的 intervention 决策缺失、chain 时序弱化——两者都在事件的
   * evaluation_skipped 字段留痕。评估空闲后自动恢复正常路径。
   */
  private dispatchEvent(event: SecurityEvent): void {
    const maxBacklog = this.config.maxEvaluationBacklog ?? 0;
    if (maxBacklog > 0 && this.dispatchBacklog >= maxBacklog) {
      this.stats.eventsEvaluationSkipped += 1;
      event.evaluation_skipped = {
        reason: 'runtime_dispatch_backlog',
        backlog: this.dispatchBacklog,
      };
      if (!this.backlogWarned) {
        this.backlogWarned = true;
        console.warn(
          `[RuntimeHookCollector] 评估队列积压达到上限 ${maxBacklog}，溢出事件跳过干预评估、仅落盘留痕`
            + '（决策字段缺失、chain 时序不再保证）；积压排空后自动恢复。'
            + '可用 application.runtimeHooks.maxEvaluationBacklog 调整上限（0 = 不限制）。'
        );
      }
      // 溢出路径与串行链解耦：落盘不必等前面的评估跑完。
      this.collector
        .report(event)
        .then(() => {
          this.stats.eventsReported += 1;
        })
        .catch((err) => {
          console.error('[RuntimeHookCollector] Failed to report event:', err);
        });
      return;
    }

    this.dispatchBacklog += 1;
    this.dispatchQueue = this.dispatchQueue
      .catch(() => {})
      .then(async () => {
        if (this.hooks.onEvent) {
          try {
            await this.hooks.onEvent(event);
          } catch (err) {
            console.error('[RuntimeHookCollector] onEvent hook failed:', err);
          }
        }
        try {
          await this.collector.report(event);
          this.stats.eventsReported += 1;
        } catch (err) {
          console.error('[RuntimeHookCollector] Failed to report event:', err);
        }
      })
      .finally(() => {
        this.dispatchBacklog -= 1;
        // 排空后重新武装积压告警，下一次积压是新的独立事件。
        if (this.dispatchBacklog === 0) this.backlogWarned = false;
      });
  }

  /**
   * Command-execution events were renamed to process_start to match the
   * event data standard. Accept the legacy command_execution names as well
   * so older runtime hook scripts still deployed in the field keep flowing
   * through the rename transition.
   */
  private isCommandEvent(parsed: ParsedRuntimeEvent): boolean {
    return (
      parsed.event_type === 'process_start' ||
      parsed.event_type === 'command_execution' ||
      parsed.type === 'application.process_start' ||
      parsed.type === 'application.command_execution' ||
      parsed.type === 'process_start' ||
      parsed.type === 'command_execution'
    );
  }

  private isNetworkEvent(parsed: ParsedRuntimeEvent): boolean {
    return parsed.event_type === 'network_http' || parsed.type === 'network.http_request';
  }

  /**
   * Determine whether a network_http event should be dropped because it matches
   * a user-supplied regex pattern. This prevents the monitor from
   * recursively capturing its own traffic.
   */
  private shouldExcludeNetworkEvent(parsed: ParsedRuntimeEvent): boolean {
    const patterns = this.config.excludeNetworkUrls || [];
    if (patterns.length === 0 || (!parsed.host && !parsed.url)) {
      return false;
    }

    const target = `${parsed.host || ''}${parsed.url || ''}`;
    return patterns.some((pattern) => {
      try {
        return new RegExp(pattern, 'i').test(target);
      } catch {
        console.warn(`[RuntimeHookCollector] invalid excludeNetworkUrls pattern: ${pattern}`);
        return false;
      }
    });
  }

  private normalizeEvent(parsed: ParsedRuntimeEvent): SecurityEvent {
    if (parsed.event_type === 'network_http' || parsed.type === 'network.http_request') {
      return this.normalizeNetworkEvent(parsed);
    }
    return this.normalizeCommandEvent(parsed);
  }

  private normalizeNetworkEvent(parsed: ParsedRuntimeEvent): SecurityEvent {
    const ts = parsed.ts || Date.now();
    const comm = parsed.comm || 'openclaw';
    const eventId = parsed.event_id || generateUUID();
    const blocked = parsed.blocked === true;
    // The hook's `source` is a string after the spec migration. Older payloads
    // may still send an object — pull hook_name from it for the collector block.
    const legacyHookName =
      typeof parsed.source === 'object' && parsed.source !== null
        ? (parsed.source as { hook_name?: string }).hook_name
        : undefined;

    const localIp = parsed.local_ip ?? parsed.src_ip;
    const localPort = parsed.local_port ?? parsed.src_port;
    const remoteIp = parsed.remote_ip ?? parsed.dst_ip;
    const remotePort = parsed.remote_port ?? parsed.dst_port;

    const event: SecurityEvent = {
      comm,
      event_id: eventId,
      event_type: parsed.event_type || 'network_http',
      layer: 'system',
      ts,
      schema_version: '1.0.0',
      pid: parsed.pid ?? process.pid,
      session_id: parsed.session_id ?? null,
      run_id: parsed.run_id ?? null,
      task_id: null,
      turn_id: null,
      agent_id: parsed.agent_id ?? null,
      host_id: parsed.host_id || this.environment.hostId,
      container_id: parsed.container_id || this.environment.containerId,
      pod_name: parsed.pod_name || this.environment.podName,
      namespace: parsed.namespace || this.environment.namespace,
      source: 'openclaw.runtime-hooks.v1',
      collection_method: 'runtime',
      collector: {
        hook_name: legacyHookName || 'network_http_req',
        middleware_name: 'sst-security-control-openclaw',
        collector_name: this.name,
      },
      content: parsed.content,
      content_length: parsed.content_length,
      service: parsed.service || 'http',
      direction: parsed.direction || 'send',
      latency_ms: parsed.latency_ms,
      method: parsed.method,
      url: parsed.url,
      host: parsed.host,
      code: parsed.code,
      header: parsed.header,
      body: parsed.body,
      request_url: parsed.request_url,
      domain_name: parsed.domain_name,
      // Five-tuple per network.json.
      local_ip: localIp,
      local_port: localPort,
      remote_ip: remoteIp,
      remote_port: remotePort,
      blocked,
      block_reason: parsed.block_reason,
      tool_call_id: parsed.tool_call_id,
      tool_name: parsed.tool_name,
    };

    // Attach response body if it differs from the canonical content.
    if (parsed.response_body && parsed.response_body !== parsed.body) {
      event.response_body = parsed.response_body;
    }

    if (blocked) {
      event.intervention = {
        decision: 'block',
        policy_id: parsed.block_code || 'network-hook-enforce',
        policy_name: 'network hook enforcement',
        block_reason: parsed.block_reason || 'blocked by network hook',
        block_code: parsed.block_code || 'NETWORK_HOOK_BLOCK',
        mode: 'enforce',
      };
    }

    return event;
  }

  private normalizeCommandEvent(parsed: ParsedRuntimeEvent): SecurityEvent {
    const ts = parsed.timestamp ? new Date(parsed.timestamp).getTime() : Date.now();
    const comm = 'openclaw';
    const blocked = parsed.blocked === true;
    // process_name (spec) is prefered over deriving from cmdline; the runtime
    // hook supplies `executable` (now renamed `exe`) and optionally `process_name`.
    const exe = parsed.executable;
    const processName =
      parsed.process_name ||
      (exe ? exe.split(/[\\/]/).pop() : undefined) ||
      (parsed.command_line ? parsed.command_line.split(/\s+/, 1)[0] : undefined);

    const event: SecurityEvent = {
      comm,
      event_id: generateUUID(),
      // Emitted as process_start per the event data standard; legacy
      // command_execution inputs are normalized here as well.
      event_type: 'process_start',
      layer: 'system',
      ts,
      schema_version: '1.0.0',
      pid: parsed.pid ?? process.pid,
      session_id: parsed.session_id ?? null,
      run_id: parsed.run_id ?? null,
      task_id: null,
      turn_id: null,
      agent_id: parsed.agent_id ?? null,
      host_id: this.environment.hostId,
      container_id: this.environment.containerId,
      pod_name: this.environment.podName,
      namespace: this.environment.namespace,
      source: 'openclaw.runtime-hooks.v1',
      collection_method: 'runtime',
      collector: {
        hook_name: 'process_start',
        middleware_name: 'sst-security-control-openclaw',
        collector_name: this.name,
      },
      runtime: parsed.runtime,
      api: parsed.api,
      cmdline: parsed.command_line,
      exe,
      process_name: processName,
      shell_involved: parsed.shell_involved,
      shell: parsed.shell,
      cwd: parsed.cwd,
      ppid: parsed.ppid,
      target_pid: parsed.target_pid,
      caller: parsed.caller,
      risk_flags: parsed.risk_flags,
      blocked,
      block_reason: parsed.block_reason,
      tool_call_id: parsed.tool_call_id,
      tool_name: parsed.tool_name,
    };

    // Bind 派生子进程 PID → 父 agent session, 供后续 network/file event lookup。
    if (parsed.pid && parsed.session_id && parsed.run_id) {
      pidBindingStore.bind(parsed.pid, {
        sessionId: parsed.session_id,
        runId: parsed.run_id,
        agentId: parsed.agent_id ?? '',
      });
    }

    if (blocked) {
      event.intervention = {
        decision: 'block',
        policy_id: parsed.block_code || 'runtime-hook-enforce',
        policy_name: 'runtime hook enforcement',
        block_reason: parsed.block_reason || 'blocked by runtime hook',
        block_code: parsed.block_code || 'RUNTIME_HOOK_BLOCK',
        mode: 'enforce',
      };
    }

    return event;
  }

  private shouldExcludeCommand(command: string): boolean {
    const patterns = this.config.excludeCommandLines || [];
    if (patterns.length === 0 || !command) {
      return false;
    }
    return patterns.some((pattern) => {
      try {
        return new RegExp(pattern, 'i').test(command);
      } catch {
        console.warn(`[RuntimeHookCollector] invalid excludeCommandLines pattern: ${pattern}`);
        return false;
      }
    });
  }
}
