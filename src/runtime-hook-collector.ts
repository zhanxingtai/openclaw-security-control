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
import { hasAgentAttribution, matchHostInternalProbe } from './host-internal-probe.js';

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
  // Source timestamp: hook writes an ISO string for command events, epoch
  // milliseconds for network events. Both are accepted.
  ts?: number | string;
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
  /** 发起方 pid（谁调用了 spawn）。 */
  spawner_pid?: number;
  /** 被拉起的子进程 pid。 */
  child_pid?: number;
  /** 子进程退出码（process_exit）。 */
  exit_code?: number | null;
  /** 子进程被信号终止时的信号名（process_exit）。 */
  exit_signal?: string | null;
  ppid?: number;
  target_pid?: number;
  caller?: SecurityEvent['caller'];
  session_id?: string;
  run_id?: string;
  agent_id?: string;
  tool_call_id?: string;
  tool_name?: string;
  risk_flags?: string[];
  /** hook 传播被绕过的具体原因：'explicit_skip' | 'env_stripped'。 */
  bypass_reason?: string;
  blocked?: boolean;
  block_reason?: string;
  block_code?: string;
  // Network HTTP event fields
  event_type?: string;
  event_id?: string;
  comm?: string;
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
    /** 读侧幂等去重丢弃的重复事件数。 */
    eventsDeduplicated: 0,
    /** 被判定为宿主内部只读探针而排除的事件数。 */
    eventsExcludedHostProbes: 0,
    /** 各探针类别的排除计数（探针名 → 条数）。 */
    hostInternalProbes: {} as Record<string, number>,
  };
  private hooks: RuntimeHookEventHooks;
  // 事件评估→落盘串行队列：chain 规则依赖事件顺序（先脱库后外传），
  // 并发评估会让后一个事件读不到前一个事件的 action 记录。
  private dispatchQueue: Promise<void> = Promise.resolve();
  // 队列当前积压长度（已入队、尚未执行完的事件数）。
  private dispatchBacklog = 0;
  /** 积压告警每次积压只打一次；排空后重新武装。 */
  private backlogWarned = false;

  /**
   * 读侧幂等：已落盘事件的身份指纹（键 → 最近一次出现的毫秒时间戳）。
   *
   * runtime hook 侧自带 300ms 的进程内去重窗口（hooks/runtime.js），但那层
   * 只在**写侧**、只在**单个进程内**生效。collector 重启后回放 sidecar、
   * sidecar 被重复读取、或同一条命令被多个进程各写一次时，规范落盘里仍会
   * 出现成百上千条逐字节相同的事件：实测 8044 条 process_start 只对应 861
   * 个不同进程，85% 的事件是重复，重复事件把评估队列顶到上限，44% 的事件
   * 因此丢失了 intervention 决策。
   *
   * 这里按"源端事件身份"在**读侧**再做一层幂等：同一条源端事件只落盘一次。
   * 两把钥匙：
   *   - 源端 id（hook 的 `id`/`event_id`）：唯一标识，回放场景精确命中；
   *   - 命令窗口指纹（命令行 + pid + ppid + 调用点）：短窗口内同一进程从
   *     同一调用点发出的同一条命令视为重复，与 hook 侧的窗口语义对齐，覆
   *     盖"hook 逐条写、id 各不相同"的场景。
   */
  private seenEventIds = new Map<string, number>();
  private seenCommandWindows = new Map<string, number>();
  /** 源端 id 指纹保留时长（毫秒）。 */
  private static readonly EVENT_ID_TTL_MS = 10 * 60 * 1000;
  /** 命令窗口指纹保留时长（毫秒），与 hook 侧 DEDUP_WINDOW_MS 对齐。 */
  private static readonly COMMAND_WINDOW_TTL_MS = 300;
  /** 指纹表上限，保证内存有界。 */
  private static readonly MAX_FINGERPRINTS = 50_000;

  /**
   * 宿主自有内部 worker 的命令行标记（1.1.0 起）。
   *
   * 宿主网关在空闲期周期性拉起自己的只读子进程。实测一份 105 分钟的
   * 采样里，43 条 process_start 有 26 条属于这一类（占文件体积 17%），
   * 其中 20 条命令行逐字节相同、只差 pid 与时间戳。
   *
   * 这里只列宿主派生子进程时带的**语义标记**，不列宿主内部模块路径：
   * 标记是宿主与自己的 worker 之间的契约，比 `dist/…/xxx.worker.js`
   * 这类内部实现路径稳定得多。
   */
  private static readonly HOST_INTERNAL_COMMAND_MARKERS = [
    '--openclaw-sqlite-readonly-child',
    '--openclaw-database-verify-child',
  ];

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

  /**
   * 判断这条源端事件是否已经落盘过。
   *
   * 指纹取不到（源端既没有 id 也没有时间戳）时返回 false——宁可重复也不
   * 误杀，审计事件不允许被静默丢弃。
   */
  private isDuplicateEvent(parsed: ParsedRuntimeEvent): boolean {
    const sourceId = parsed.event_id || parsed.id;
    if (sourceId) {
      const key = `id:${sourceId}`;
      if (this.seenWithin(this.seenEventIds, key, RuntimeHookCollector.EVENT_ID_TTL_MS)) {
        return true;
      }
    }

    if (!this.isCommandEvent(parsed) && !this.isProcessExitEvent(parsed)) {
      return false;
    }

    // 命令窗口指纹：同一进程在短窗口内发出的同一条命令。键里带调用点，
    // 与 hook 侧 isRecentDuplicate 的语义保持一致——同一个调用点上的
    // 同一条命令是重复，换个调用点则是另一次动作，不能混为一谈。
    const cmd = parsed.command_line || parsed.command_line_raw || '';
    if (!cmd) return false;
    const caller = parsed.caller;
    const callerKey = caller
      ? `${caller.file || ''}:${caller.line || ''}:${caller.column || ''}`
      : '';
    // 退出事件按子进程 pid 区分：同一条命令可能被连续 spawn 多次，每个
    // 子进程都有自己的退出事件，不能互相去重。
    const scope = this.isProcessExitEvent(parsed) ? `|${parsed.child_pid ?? ''}` : '';
    const windowKey = `w:${parsed.pid ?? ''}|${parsed.ppid ?? ''}|${callerKey}|${cmd}${scope}`;
    if (this.seenWithin(this.seenCommandWindows, windowKey, RuntimeHookCollector.COMMAND_WINDOW_TTL_MS)) {
      return true;
    }
    return false;
  }

  /**
   * 指纹命中即视为重复；未命中则登记并返回 false。
   * 过期条目按 TTL 惰性淘汰，表满时先清过期项再丢最早的一条。
   */
  private seenWithin(store: Map<string, number>, key: string, ttlMs: number): boolean {
    const now = Date.now();
    const seenAt = store.get(key);
    if (seenAt !== undefined && now - seenAt < ttlMs) {
      return true;
    }
    store.set(key, now);
    if (store.size > RuntimeHookCollector.MAX_FINGERPRINTS) {
      for (const [k, ts] of store) {
        if (now - ts >= ttlMs) store.delete(k);
      }
      while (store.size > RuntimeHookCollector.MAX_FINGERPRINTS) {
        const oldest = store.keys().next();
        if (oldest.done) break;
        store.delete(oldest.value);
      }
    }
    return false;
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

    if (
      parsed.event_type !== 'network_http' &&
      !this.isCommandEvent(parsed) &&
      !this.isProcessExitEvent(parsed)
    ) {
      // Ignore unrelated runtime log lines.
      return;
    }

    // Skip periodic/internal noise matched by configured regex patterns.
    // process_exit 也带命令行：它的起点事件被排除时，退出事件同样排除，
    // 否则事件流里会留下一串没有起点的孤儿退出。
    if (this.isCommandEvent(parsed) || this.isProcessExitEvent(parsed)) {
      const cmd = parsed.command_line || parsed.command_line_raw || '';
      if (this.shouldExcludeCommand(cmd, parsed)) {
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

    // 读侧幂等：同一条源端事件只落盘一次。
    if (this.isDuplicateEvent(parsed)) {
      this.stats.eventsDeduplicated += 1;
      return;
    }

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
   * 子进程退出事件（runtime hook 侧补的进程生命周期尾巴）。
   *
   * 此前运行时层只记录 process_start：审计链上只有"发起了"，没有"跑完了、
   * 结果如何"（采样里 process_exit 为 0 条）。
   */
  private isProcessExitEvent(parsed: ParsedRuntimeEvent): boolean {
    return (
      parsed.event_type === 'process_exit' ||
      parsed.type === 'application.process_exit' ||
      parsed.type === 'process_exit'
    );
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

  /**
   * 空串与 null 在事件流里必须统一：hook 侧 `ctx.xxx || ''` 会把"没有"
   * 写成空串，collector 侧原样透传后，下游看到的是 `""` / `null` / 字段
   * 缺失三种语义。统一成 null，缺失的键保持缺失。
   */
  private normalizeOptionalString(value: string | undefined): string | null {
    if (value === undefined || value === null) return null;
    return value.length > 0 ? value : null;
  }

  /**
   * 解析源端时间戳。hook 写的是 ISO 串（`ts`），网络事件写的是 epoch 毫秒
   * （`ts`），老版本命令事件写的是 ISO 串（`timestamp`）。全部认。
   */
  private resolveSourceTimestamp(parsed: ParsedRuntimeEvent): number {
    const raw = parsed.ts ?? parsed.timestamp;
    if (typeof raw === 'number' && Number.isFinite(raw)) {
      return raw;
    }
    if (typeof raw === 'string' && raw.length > 0) {
      const parsedMs = Date.parse(raw);
      if (Number.isFinite(parsedMs)) return parsedMs;
    }
    return Date.now();
  }

  private normalizeEvent(parsed: ParsedRuntimeEvent): SecurityEvent {
    if (parsed.event_type === 'network_http' || parsed.type === 'network.http_request') {
      return this.normalizeNetworkEvent(parsed);
    }
    if (this.isProcessExitEvent(parsed)) {
      return this.normalizeProcessExitEvent(parsed);
    }
    return this.normalizeCommandEvent(parsed);
  }

  /**
   * 子进程退出事件。
   *
   * 字段与 process_start 对齐（同一套归属信息：会话 / run / agent / 工具
   * 调用），另加退出码与信号、以及被终止的子进程 pid。`pid` 仍然是发起方
   * （兼容旧语义），`spawner_pid` 显式表达同一件事，`child_pid` 指向真正
   * 跑起来又跑完的那个进程。
   */
  private normalizeProcessExitEvent(parsed: ParsedRuntimeEvent): SecurityEvent {
    const ts = this.resolveSourceTimestamp(parsed);
    const comm = parsed.comm || 'openclaw';
    const eventId = parsed.event_id || parsed.id || generateUUID();
    const exe = parsed.executable;
    const processName =
      parsed.process_name ||
      (exe ? exe.split(/[\\/]/).pop() : undefined) ||
      (parsed.command_line ? parsed.command_line.split(/\s+/, 1)[0] : undefined);

    return {
      comm,
      event_id: eventId,
      event_type: 'process_exit',
      layer: 'system',
      ts,
      schema_version: 1,
      // pid 保持"发起方"语义（与 process_start 一致），spawner_pid 显式
      // 表达同一件事，child_pid 才是被终止的子进程。
      pid: parsed.pid ?? process.pid,
      spawner_pid: parsed.spawner_pid ?? parsed.pid ?? process.pid,
      child_pid: parsed.child_pid,
      exit_code: typeof parsed.exit_code === 'number' ? parsed.exit_code : undefined,
      exit_signal: parsed.exit_signal ?? undefined,
      session_id: this.normalizeOptionalString(parsed.session_id),
      run_id: this.normalizeOptionalString(parsed.run_id),
      task_id: null,
      turn_id: null,
      agent_id: this.normalizeOptionalString(parsed.agent_id),
      host_id: this.environment.hostId,
      container_id: this.environment.containerId,
      pod_name: this.environment.podName,
      namespace: this.environment.namespace,
      source: 'openclaw.runtime-hooks.v1',
      collection_method: 'runtime',
      collector: {
        hook_name: 'process_exit',
        middleware_name: 'sst-security-control-openclaw',
        collector_name: this.name,
      },
      // `blocked` 恒在：进程退出没有「被拦」语义（拦的是启动那条）⇒ 恒为 false。
      blocked: false,
      runtime: parsed.runtime,
      api: parsed.api,
      cmdline: parsed.command_line,
      exe,
      process_name: processName,
      shell_involved: parsed.shell_involved,
      shell: parsed.shell,
      cwd: parsed.cwd,
      ppid: parsed.ppid,
      caller: parsed.caller,
      tool_call_id: this.normalizeOptionalString(parsed.tool_call_id),
      tool_name: this.normalizeOptionalString(parsed.tool_name),
    };
  }

  private normalizeNetworkEvent(parsed: ParsedRuntimeEvent): SecurityEvent {
    const ts = this.resolveSourceTimestamp(parsed);
    const comm = parsed.comm || 'openclaw';
    const eventId = parsed.event_id || parsed.id || generateUUID();
    const blocked = parsed.blocked === true;
    // The hook's `source` is a string after the spec migration. Older payloads
    // may still send an object — pull hook_name from it for the collector block.
    const legacyHookName =
      typeof parsed.source === 'object' && parsed.source !== null
        ? (parsed.source as { hook_name?: string }).hook_name
        : undefined;

    const localIp = parsed.local_ip ?? parsed.src_ip;
    const localPort = parsed.local_port ?? parsed.src_port;
    // 载荷截断：1.1.0 之前 content 由 runtime hook 原样透传，不受
    // application.maxContentLength 约束（实测落盘 4099 字符，而配置
    // 声明 2000），且 content_length 照抄 hook 值，无法区分"完整响应"
    // 与"被截断的响应"。现在 content 按配置截断，content_length 恒为
    // 原始长度，截断与否由 content_truncated 表达。
    const maxContentLen = this.config.maxContentLength ?? 2000;
    const rawContent = typeof parsed.content === 'string' ? parsed.content : undefined;
    const contentTruncated = rawContent !== undefined && rawContent.length > maxContentLen;
    const content = rawContent !== undefined
      ? (contentTruncated ? rawContent.slice(0, maxContentLen) : rawContent)
      : undefined;
    const remoteIp = parsed.remote_ip ?? parsed.dst_ip;
    const remotePort = parsed.remote_port ?? parsed.dst_port;

    const event: SecurityEvent = {
      comm,
      event_id: eventId,
      event_type: parsed.event_type || 'network_http',
      layer: 'system',
      ts,
      schema_version: 1,
      pid: parsed.pid ?? process.pid,
      session_id: this.normalizeOptionalString(parsed.session_id),
      run_id: this.normalizeOptionalString(parsed.run_id),
      task_id: null,
      turn_id: null,
      agent_id: this.normalizeOptionalString(parsed.agent_id),
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
      content,
      content_length: rawContent?.length ?? parsed.content_length,
      content_truncated: contentTruncated || undefined,
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
      tool_call_id: this.normalizeOptionalString(parsed.tool_call_id),
      tool_name: this.normalizeOptionalString(parsed.tool_name),
    };

    // Attach response body only when it carries something the canonical
    // content field does not already have — otherwise the same payload is
    // written twice and the event stream doubles in size for no gain.
    if (
      parsed.response_body &&
      parsed.response_body !== parsed.body &&
      parsed.response_body !== parsed.content
    ) {
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
    // 源端时间戳优先：hook 写的是 `ts`（ISO 串），老版本写的是 `timestamp`。
    // 两者都取不到才回落到本地时间——回落意味着时间戳不再代表"事件何时
    // 发生"，审计回溯会失真，所以必须尽量保住源端值。
    const ts = this.resolveSourceTimestamp(parsed);
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
      // 源端 id 优先：它是这条命令的稳定身份，回放/重传时据此幂等去重，
      // 同时让审计链能追溯到 runtime hook 写出的那一条。
      event_id: parsed.event_id || parsed.id || generateUUID(),
      // Emitted as process_start per the event data standard; legacy
      // command_execution inputs are normalized here as well.
      event_type: 'process_start',
      layer: 'system',
      ts,
      schema_version: 1,
      pid: parsed.pid ?? process.pid,
      // 发起方 pid（谁调用了 spawn）。子进程 pid 只有 spawn 返回后才知道，
      // hook 侧会把它回填到 child_pid——此前它从来没被采集过，审计链上
      // 只有"谁发起的"，没有"哪个进程真的跑起来了"。
      spawner_pid: parsed.spawner_pid ?? parsed.pid ?? process.pid,
      child_pid: parsed.child_pid,
      session_id: this.normalizeOptionalString(parsed.session_id),
      run_id: this.normalizeOptionalString(parsed.run_id),
      task_id: null,
      turn_id: null,
      agent_id: this.normalizeOptionalString(parsed.agent_id),
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
      // 绕过/补注入的具体原因。hook 侧区分 'explicit_skip'（子进程真的
      // 裸跑）与 'env_stripped'（hook 已补回 NODE_OPTIONS，覆盖没丢），
      // 不带原因的话下游只能看到一个笼统的 flag。
      bypass_reason: parsed.bypass_reason,
      blocked,
      block_reason: parsed.block_reason,
      tool_call_id: this.normalizeOptionalString(parsed.tool_call_id),
      tool_name: this.normalizeOptionalString(parsed.tool_name),
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

  private shouldExcludeCommand(command: string, parsed?: ParsedRuntimeEvent): boolean {
    if (!command) {
      return false;
    }
    // 内置规则：宿主自己派生的内部 worker（默认开启）。
    //
    // 判据刻意只匹配宿主派生子进程时带的**标记参数**，不匹配宿主内部的
    // 模块路径：宿主改版换掉 `dist/infra/xxx.worker.js` 这类文件名时，
    // 内置规则会失配——表现是噪声回来，而不是误杀别的进程。失配方向是
    // 安全的一侧（少采而不是多删）。
    if (this.config.excludeHostInternalProcesses !== false) {
      if (RuntimeHookCollector.HOST_INTERNAL_COMMAND_MARKERS.some((marker) =>
        command.includes(marker)
      )) {
        return true;
      }
    }
    // 内置规则：宿主自身的只读维护探针（默认开启）。
    //
    // 两道闸门同时成立才排除：**调用方**（事件没有任何 agent 归属，说明
    // 它不是某个 agent 动作的产物）+ **命令模式**（命令行逐字命中一条
    // 已知的只读探针形态）。详见 src/host-internal-probe.ts。
    //
    // 排除发生在策略评估之前，所以这些事件不会再触发
    // `warn-hook-bypass-attempt` 之类的规则——宿主自己的探活进程本来就不
    // 该被 hook 覆盖，被判成"自保护被绕过"是误报。
    if (this.config.excludeHostInternalProbeCommands !== false) {
      if (parsed && !hasAgentAttribution(parsed)) {
        const probe = matchHostInternalProbe(command);
        if (probe) {
          this.stats.eventsExcludedHostProbes += 1;
          this.stats.hostInternalProbes[probe] =
            (this.stats.hostInternalProbes[probe] || 0) + 1;
          return true;
        }
      }
    }
    const patterns = this.config.excludeCommandLines || [];
    if (patterns.length === 0) {
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
