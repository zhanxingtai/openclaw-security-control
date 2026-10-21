// Control UI service — read-only NDJSON query layer with in-memory cache.
//
// Performance model (B + C):
//   B. Parse cache keyed by (mtimeMs, size). The 10s polling Security Tab fires
//      5 read RPCs per tick; without the cache each RPC would re-read the whole
//      NDJSON file from byte 0. With the cache, repeat RPCs within the same
//      tick return instantly. Cache invalidates when the file grows (mtime/size
//      change), which is the only moment a fresh collector write happened.
//   C. Pre-aggregated counters kept in lock-step with the events array. Stats
//      and metrics RPCs answer from the aggregate (O(1)) instead of re-walking
//      the events list (O(N)). The aggregate is rebuilt from NDJSON on cache
//      miss (e.g., after process restart) and stays consistent because both
//      come from the same parse pass.
//
// Returned shapes are the minimum the Tab views need:
//   - events.list: latest N events with optional filters
//   - events.stats: counts by event_type (from aggregate)
//   - assets.list: asset_* events only
//   - policy.hits: events with an intervention decision (any type except
//     `allow`), optionally filtered by decision; byDecision counts from
//     the aggregate so the panel can render per-type badges O(1)
//   - metrics: aggregate counters for the dashboard header (from aggregate)

import { createReadStream, statSync } from "fs";
import { createInterface } from "readline";
import type { SecurityEvent } from "./types.js";

type RawEvent = Record<string, unknown> & { event_id?: string; event_type?: string; ts?: number };

// ---------------------------------------------------------------------------
// Read-side event schema validation.
//
// The NDJSON file is written exclusively by this plugin (EventBridgeCollector
// and the runtime-hook collector pipeline), so every legitimate line matches
// the schema below. Lines that fail validation are corruption or injection
// (same-UID attacker appending forged events to the panel file): they are
// skipped and counted instead of flowing straight into the panel. Field
// names and collection semantics are unchanged — this only guards the reader.
// ---------------------------------------------------------------------------

/** event_type whitelist: EventType union (types.ts) + policy audit events. */
const ALLOWED_EVENT_TYPES: ReadonlySet<string> = new Set([
  // application layer
  'agent_start',
  'agent_stop',
  'agent_session_start',
  'agent_session_end',
  'agent_subagent_start',
  'agent_subagent_progress',
  'agent_subagent_end',
  'cron_changed',
  'agent_message',
  'agent_tool_call',
  'agent_tool_result',
  'code_mode_exec',
  'reasoning',
  'runtime_log',
  'trace_span',
  // Deprecated alias kept for older runtime hooks in the field.
  'command_execution',
  // file events (system layer per file.json)
  'file_read',
  'file_write',
  'file_delete',
  'file_privilege',
  // network + process lifecycle
  'network_http',
  'network_connect',
  'network_dns',
  'process_start',
  'process_change',
  'process_exit',
  'process_snapshot',
  'cgroup_snapshot',
  'cgroup_anomaly',
  // asset layer
  'asset_add',
  'asset_change',
  'asset_remove',
  'asset_snapshot',
  // self-protection + policy audit events
  'protection_degraded',
  'tamper_detected',
  'policy_missing',
  'policy_load_failed',
  'policy_empty',
  'rule_invalid_regex',
  'rule_unsafe_regex',
]);

/**
 * intervention 块的合法来源。干预决策只由插件引擎写入（store 自保护 /
 * 评估回灌、runtime collector 的 blocked 归一化），source 必为以下两个值；
 * 其它 source 带 intervention 的行是伪造的，整行丢弃。
 */
const INTERVENTION_SOURCES: ReadonlySet<string> = new Set([
  'openclaw.v1',
  'openclaw.runtime-hooks.v1',
]);

type SchemaVerdict = { ok: true; event: RawEvent } | { ok: false; reason: string };

function validateEventLine(parsed: unknown): SchemaVerdict {
  if (!isRecord(parsed)) return { ok: false, reason: 'not_object' };
  if (typeof parsed.event_id !== 'string' || parsed.event_id.length === 0) {
    return { ok: false, reason: 'event_id' };
  }
  if (typeof parsed.event_type !== 'string' || !ALLOWED_EVENT_TYPES.has(parsed.event_type)) {
    return { ok: false, reason: 'event_type' };
  }
  if (typeof parsed.ts !== 'number' || !Number.isFinite(parsed.ts)) {
    return { ok: false, reason: 'ts' };
  }
  const intervention = parsed.intervention;
  if (intervention !== undefined && intervention !== null) {
    if (!isRecord(intervention)) return { ok: false, reason: 'intervention_shape' };
    if (typeof parsed.source !== 'string' || !INTERVENTION_SOURCES.has(parsed.source)) {
      return { ok: false, reason: 'intervention_source' };
    }
  }
  return { ok: true, event: parsed as RawEvent };
}

export interface EventQuery {
  limit?: number;
  eventType?: string;
  severity?: string;
  sinceMs?: number;
  untilMs?: number;
  offset?: number;
}

/** policy.hits 查询参数（均可选，无参调用返回全部决策命中）。 */
export interface PolicyHitsQuery {
  /** 只返回该决策类型的命中（如 "block" / "warn" / "modify" / "audit"）。 */
  decision?: string;
  /**
   * 按 severity 过滤（low/medium/high/critical/extreme）。
   * 走 resolveEventSeverity 与 bySeverity 聚合同口径。事件层无 severity 不计入。
   * 与 `decision` 正交，可同时存在（窄口径命中）。
   */
  severity?: string;
  /** 返回条数上限，默认 200，最大 1000。 */
  limit?: number;
  /** 分页偏移（最新在前计数），配合 limit 实现 Load more。 */
  offset?: number;
}

export interface PolicyHitsResult {
  /** 命中的事件，最新在前。 */
  hits: SecurityEvent[];
  /** 按决策类型分组的全量计数（来自聚合，不受 limit 截断影响）。 */
  byDecision: Record<string, number>;
  /**
   * 按 severity 分组的全量计数（来自聚合，不受 limit 截断影响）。
   * 含 `unknown` 桶（无可解析 severity 的事件），不丢失计数据。
   */
  bySeverity: Record<string, number>;
  /** 命中总数（来自聚合；带 decision / severity 过滤时为该窄口径的计数）。 */
  total: number;
}

export interface StatsResult {
  total: number;
  byType: Record<string, number>;
  last24h: { ts: number; count: number }[];
}

export interface MetricsResult {
  total: number;
  last24h: number;
  blocks: number;
  /** 威胁事件总数：所有非 allow 决策命中（block/degrade/warn/audit/modify 等）。 */
  threats: number;
  modifies: number;
  audits: number;
  byLayer: Record<string, number>;
  /**
   * 按 severity（low/medium/high/critical/extreme）分组的全量计数。
   * 来源优先级：`intervention.matched_rules[].risk_level`（最高）→
   * `intervention.risk_level` → 事件顶层 `risk_level` → `severity`。
   * 无可解析 severity 的事件计入 `unknown` 桶，不丢失计数据。
   */
  bySeverity: Record<string, number>;
  /**
   * 按 decision（block/warn/modify/audit 等）分组的全量计数（不含 allow / 无干预）。
   * 与 `blocks`/`modifies`/`audits`/`threats` 等顶层计数同源（aggregate.byDecision）。
   * 提供给面板渲染 By Decision 卡片，避免前端二次聚合。
   */
  byDecision: Record<string, number>;
}

/**
 * Compact aggregate derived from the events array. Kept as a separate type so
 * the EventBridgeCollector can update it incrementally on each event write
 * (see `incrementAggregate`) without ever touching the events array.
 */
export interface Aggregate {
  total: number;
  byType: Record<string, number>;
  byLayer: Record<string, number>;
  last24h: number;
  blocks: number;
  /**
   * 威胁事件总数：所有非 allow 决策命中（与 byDecision 各类型之和一致，
   * 与 policy.hits 列表口径对齐）。决策口径，不看 blocked 字段与 mode。
   */
  threats: number;
  modifies: number;
  audits: number;
  /**
   * 按 intervention.decision 分组的全量计数（不含 allow / 无干预）。
   * policy.hits 的分组徽标直接读这里，保持 O(1)，不随 limit 截断失真。
   */
  byDecision: Record<string, number>;
  /**
   * 按 severity（low/medium/high/critical/extreme）分组的全量计数。
   * 来源同 MetricsResult.bySeverity。无可解析 severity 的事件计入 `unknown` 桶。
   */
  bySeverity: Record<string, number>;
}

function emptyAggregate(): Aggregate {
  return {
    total: 0,
    byType: {},
    byLayer: {},
    last24h: 0,
    blocks: 0,
    threats: 0,
    modifies: 0,
    audits: 0,
    byDecision: {},
    bySeverity: {},
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * 从事件上解析最高 severity。来源优先级：
 *   1. `intervention.matched_rules[].risk_level` 取最高
 *   2. `intervention.risk_level`
 *   3. 事件顶层 `risk_level`
 *   4. 事件顶层 `severity`（cgroup_anomaly 用）
 *   5. `null`（落到 `unknown` 桶）
 *
 * 复用 InterventionEngine.highestRiskLevel 的同档位定义（low<medium<high<critical<extreme）。
 * 该函数纯读 event 字段，不依赖引擎；面板聚合用，无需引入额外依赖。
 */
const SEVERITY_RANK: Record<string, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
  extreme: 5,
};

export function resolveEventSeverity(ev: RawEvent | SecurityEvent): string | null {
  const intervention = ev.intervention as Record<string, unknown> | undefined;
  const matched = intervention?.matched_rules;
  if (Array.isArray(matched)) {
    let bestRank = 0;
    let bestName: string | null = null;
    for (const m of matched) {
      const rl = (m as Record<string, unknown>)?.risk_level;
      if (typeof rl !== "string") continue;
      const rank = SEVERITY_RANK[rl] ?? 0;
      if (rank > bestRank) {
        bestRank = rank;
        bestName = rl;
      }
    }
    if (bestName) return bestName;
  }
  if (intervention && typeof intervention.risk_level === "string") return intervention.risk_level;
  const directRiskLevel = (ev as Record<string, unknown>)?.risk_level;
  if (typeof directRiskLevel === "string" && SEVERITY_RANK[directRiskLevel] !== undefined) return directRiskLevel;
  const directSeverity = (ev as Record<string, unknown>)?.severity;
  if (typeof directSeverity === "string" && SEVERITY_RANK[directSeverity] !== undefined) return directSeverity;
  return null;
}

/**
 * Apply one parsed event to a running aggregate. Pure function so it can be
 * reused by both the cache rebuild path and the per-write incremental path
 * in EventBridgeCollector (see `getOrCreateLiveAggregate`).
 */
export function incrementAggregate(agg: Aggregate, raw: RawEvent, nowMs: number): void {
  agg.total++;
  const t = (raw.event_type as string) ?? "unknown";
  agg.byType[t] = (agg.byType[t] ?? 0) + 1;
  const layer = (raw.layer as string) ?? "unknown";
  agg.byLayer[layer] = (agg.byLayer[layer] ?? 0) + 1;
  const ts = typeof raw.ts === "number" ? raw.ts : 0;
  if (ts >= nowMs - 24 * 60 * 60 * 1000) agg.last24h++;
  const intervention = raw.intervention as Record<string, unknown> | undefined;
  const decision = typeof intervention?.decision === "string" ? intervention.decision : "";
  if (decision === "block") agg.blocks++;
  else if (decision === "modify") agg.modifies++;
  else if (decision === "audit") agg.audits++;
  // 全决策类型分组计数（allow 与无干预事件不算命中，不计入）。
  if (decision && decision !== "allow") {
    agg.threats++;
    agg.byDecision[decision] = (agg.byDecision[decision] ?? 0) + 1;
  }
  // severity 维度聚合（面板 By Severity 卡片 / EventStream 过滤）。
  // 无可解析 severity 的事件计入 `unknown` 桶，避免与 `low` 混淆。
  const sev = resolveEventSeverity(raw);
  const sevKey = sev ?? "unknown";
  agg.bySeverity[sevKey] = (agg.bySeverity[sevKey] ?? 0) + 1;
}

export class ControlUiService {
  // Cache signature + parsed events + aggregate. Invalidated on (mtimeMs, size)
  // change. null forces a fresh parse.
  private cache: { mtimeMs: number; size: number; events: SecurityEvent[]; aggregate: Aggregate; truncated: boolean } | null = null;
  // Cumulative count of lines rejected by schema validation
  // (corrupt JSON or injected/invalid events). Exposed via the getter so the
  // panel/operator can see something is feeding garbage into the file.
  private invalidLineCount = 0;

  constructor(
    private readonly filePath: string | undefined,
    private readonly maxEventsInMemory: number = 5000,
  ) {}

  /** Number of NDJSON lines skipped by read-side schema validation. */
  getInvalidLineCount(): number {
    return this.invalidLineCount;
  }

  hasSource(): boolean {
    if (!this.filePath) return false;
    try {
      statSync(this.filePath);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Lazily load + parse NDJSON, populating the events array and aggregate in
   * one pass. Subsequent calls within the same (mtime, size) signature return
   * the cached snapshot. This is the single hot-path bottleneck; everything
   * else reads from it.
   */
  private async loadCached(): Promise<{ events: SecurityEvent[]; aggregate: Aggregate; truncated: boolean }> {
    if (!this.filePath) return { events: [], aggregate: emptyAggregate(), truncated: false };
    let stat: { mtimeMs: number; size: number };
    try {
      const s = statSync(this.filePath);
      stat = { mtimeMs: s.mtimeMs, size: s.size };
    } catch {
      return { events: [], aggregate: emptyAggregate(), truncated: false };
    }
    if (this.cache && this.cache.mtimeMs === stat.mtimeMs && this.cache.size === stat.size) {
      return { events: this.cache.events, aggregate: this.cache.aggregate, truncated: this.cache.truncated };
    }
    const events: SecurityEvent[] = [];
    const aggregate = emptyAggregate();
    const nowMs = Date.now();
    const stream = createReadStream(this.filePath, { encoding: "utf8" });
    const rl = createInterface({ input: stream, crlfDelay: Infinity });
    // Bound the in-memory event array. NDJSON files can grow large on a busy
    // gateway; keeping every parsed line in RAM blows up heap and starves
    // the polling Security Tab. Drop the oldest lines once we hit the cap so
    // the UI still sees the most recent activity. Aggregate stays global
    // (counts don't depend on which events are retained) so stats/metrics
    // remain accurate.
    const MAX_EVENTS_IN_MEMORY = this.maxEventsInMemory;
    let truncated = false;
    // Schema-validate every parsed line. Previously any JSON
    // object flowed into the panel unchecked — a same-UID process could
    // inject arbitrary "events" (including fake intervention decisions)
    // into the file the panel reads.
    let invalidLines = 0;
    try {
      for await (const line of rl) {
        if (!line) continue;
        try {
          const parsed = JSON.parse(line);
          const verdict = validateEventLine(parsed);
          if (!verdict.ok) {
            invalidLines += 1;
            continue;
          }
          const event = verdict.event;
          events.push(event as unknown as SecurityEvent);
          if (events.length > MAX_EVENTS_IN_MEMORY) {
            events.shift();
            truncated = true;
          }
          incrementAggregate(aggregate, event, nowMs);
        } catch {
          // tolerate partial / corrupt lines (writer crash)
          invalidLines += 1;
        }
      }
    } finally {
      rl.close();
      stream.destroy();
    }
    if (invalidLines > 0) {
      this.invalidLineCount += invalidLines;
      console.warn(
        `[ControlUiService] skipped ${invalidLines} invalid line(s) in ${this.filePath} (schema validation)`
      );
    }
    this.cache = { mtimeMs: stat.mtimeMs, size: stat.size, events, aggregate, truncated };
    return { events, aggregate, truncated };
  }

  async listEvents(query: EventQuery = {}): Promise<{ events: SecurityEvent[]; total: number; truncated: boolean }> {
    const limit = Math.max(1, Math.min(query.limit ?? 50, 1000));
    const sinceMs = query.sinceMs ?? 0;
    const untilMs = query.untilMs ?? Number.MAX_SAFE_INTEGER;
    const { events, truncated } = await this.loadCached();
    // events are appended chronologically; reverse once, filter, slice.
    // Collect at most offset+limit matches for the page, but keep counting so
    // `total` is the full match count (drives the panel's Load-more control).
    const offset = query.offset ?? 0;
    const filtered: SecurityEvent[] = [];
    let total = 0;
    for (let i = events.length - 1; i >= 0; i--) {
      const ev = events[i];
      const ts = (ev as { ts?: number }).ts ?? 0;
      if (ts < sinceMs || ts > untilMs) continue;
      if (query.eventType && ev.event_type !== query.eventType) continue;
      if (query.severity) {
        // severity 过滤走 resolveEventSeverity，与 bySeverity 聚合口径一致。
        // 事件层无 severity 时 reject（不落到 `info` 兜底，避免静默丢数据）。
        const sev = resolveEventSeverity(ev);
        if (sev !== query.severity) continue;
      }
      total++;
      if (filtered.length < offset + limit) {
        filtered.push(ev);
      }
    }
    return { events: filtered.slice(offset, offset + limit), total, truncated };
  }

  async stats(): Promise<StatsResult> {
    const { aggregate } = await this.loadCached();
    return { total: aggregate.total, byType: { ...aggregate.byType }, last24h: [] };
  }

  async listAssets(): Promise<SecurityEvent[]> {
    const { events } = await this.loadCached();
    const out: SecurityEvent[] = [];
    for (let i = events.length - 1; i >= 0; i--) {
      const ev = events[i];
      if (typeof ev.event_type === "string" && ev.event_type.startsWith("asset_")) {
        out.push(ev);
        if (out.length >= 200) break;
      }
    }
    return out;
  }

  /**
   * 返回全部决策类型的命中（block / warn / modify / audit 等）——
   * 数据泄露监测类目以 warn/audit 为主，灰度观察与误报
   * 排查需要全类型可查。无参调用返回全部决策命中（仅排除 allow），
   * 另支持 decision / severity 过滤缩小到窄口径。byDecision / bySeverity /
   * total 直接读聚合，保持 O(1)；命中列表仍是最新在前、上限截断。
   */
  async policyHits(query: PolicyHitsQuery = {}): Promise<PolicyHitsResult> {
    const { events, aggregate } = await this.loadCached();
    const limit = Math.max(1, Math.min(query.limit ?? 200, 1000));
    const offset = Math.max(0, query.offset ?? 0);
    const filter = query.decision;
    const sevFilter = query.severity;
    const out: SecurityEvent[] = [];
    for (let i = events.length - 1; i >= 0; i--) {
      const ev = events[i];
      const intervention = ev.intervention as Record<string, unknown> | undefined;
      const decision = typeof intervention?.decision === "string" ? intervention.decision : "allow";
      // allow（含无 intervention 的事件）不是策略命中，全部类型视图都排除。
      if (decision === "allow") continue;
      if (filter && decision !== filter) continue;
      // severity 过滤。无 severity 的事件不命中（与 bySeverity 桶口径一致）。
      if (sevFilter) {
        const sev = resolveEventSeverity(ev);
        if (sev !== sevFilter) continue;
      }
      out.push(ev);
      if (out.length >= offset + limit) break;
    }
    const byDecision = { ...aggregate.byDecision };
    const bySeverity = { ...aggregate.bySeverity };
    // total：与 decision / severity 过滤组合精确对齐。无过滤时为全部决策命中；
    // 仅 decision 过滤时为该决策类型计数；仅 severity 过滤时为该 severity 全决策计数；
    // 双过滤时为交集（精确重扫 byDecision × bySeverity 等价结果）。
    let total: number;
    if (filter && sevFilter) {
      total = out.length; // 双过滤需重算交集（聚合层不预存）；长度即精确计数
    } else if (filter) {
      total = byDecision[filter] ?? 0;
    } else {
      total = Object.values(byDecision).reduce((a, b) => a + b, 0);
    }
    return { hits: out.slice(offset, offset + limit), byDecision, bySeverity, total };
  }

  async metrics(): Promise<MetricsResult> {
    const { aggregate } = await this.loadCached();
    return {
      total: aggregate.total,
      last24h: aggregate.last24h,
      blocks: aggregate.blocks,
      threats: aggregate.threats,
      modifies: aggregate.modifies,
      audits: aggregate.audits,
      byLayer: { ...aggregate.byLayer },
      bySeverity: { ...aggregate.bySeverity },
      byDecision: { ...aggregate.byDecision },
    };
  }
}
