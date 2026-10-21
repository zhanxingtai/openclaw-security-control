/**
 * AssetCollector — periodic collection of agent configuration assets:
 * agent config files, skills (SKILL.md frontmatter), and MCP server configs
 * (including obfuscated credentials).
 *
 * Design contract:
 * - Scans run on a timer, but reporting is event-driven: an event is only
 *   emitted when an asset's normalized content hash actually changes
 *   (added / changed / removed). Unchanged scans emit nothing.
 * - mtime+size signatures are used to skip re-reading unchanged sources;
 *   the content hash is the final arbiter of "changed".
 * - A persisted state file survives restarts so the plugin does not
 *   re-baseline on every start.
 * - A low-frequency full snapshot (default 24h, 0 disables) lets the
 *   reconcile drift; snapshot events carry prev_hash context.
 * - Sensitive values (token/key/secret/...) are obfuscated with obf:v1;
 *   content_hash is always computed on plaintext before obfuscation.
 */

import type {
  AssetMonitorConfig,
  AssetPackageInfo,
  EnvironmentConfig,
  EventCollector as IEventCollector,
  SecurityEvent,
} from "./types.js";
import { generateUUID } from './uuid.js';
import { contentHash, sha256Hex, stableStringify } from './asset-hash.js';
import { buildZip } from './zip-pack.js';
import {
  isSensitiveKey,
  obfEncode,
  obfuscateDeep,
  obfuscateSensitiveValues,
} from './sensitive-obfuscate.js';
import { homedir } from 'os';
import path from 'path';
import { randomBytes } from 'crypto';
import { mkdir, readdir, readFile, rename, rm, stat, writeFile } from 'fs/promises';
import { open as openAsync } from 'fs/promises';

type AssetType = 'agent_config' | 'skill' | 'mcp_server';
type ChangeType = 'added' | 'changed' | 'removed' | 'snapshot';

interface ScannedAsset {
  assetId: string;
  assetType: AssetType;
  assetPath: string;
  contentHash: string;
  fileSize?: number;
  fileMtime?: number;
  parsed?: Record<string, unknown>;
  assetPackage?: AssetPackageInfo;
}

interface AssetStateRecord {
  contentHash: string;
  assetType: string;
  assetPath: string;
  firstSeen: number;
  lastReported: number;
}

interface AssetStateFile {
  version: 1;
  /** Fingerprint of payload-shaping settings; mismatch → full re-baseline. */
  fingerprint?: string;
  assets: Record<string, AssetStateRecord>;
}

/** On-disk shape of `${statePath}.lock`. */
interface AssetLockFile {
  pid?: number;
  acquiredAt?: number;
  /** Random per-acquisition nonce; refresh keeps it stable. */
  nonce?: string;
}

interface SourceCacheEntry {
  sig: string;
  assets: ScannedAsset[];
}

/** Test/discovery hook: overrides the built-in default locations. */
export interface AssetDiscoveryOverrides {
  configPaths?: string[];
  skillDirs?: string[];
  mcpPaths?: string[];
  configRoots?: string[];
}

const CONFIG_FILE_PATTERN = /\.(json|ya?ml|md|toml)$/i;
const AUTH_KEY_PATTERN = /authorization|api[-_]?key|token|secret|credential/i;
// Directories skipped during recursive config discovery: dependency/VCS dirs
// and volatile runtime state (sessions/history/logs) that would otherwise
// produce constant change noise.
const CONFIG_IGNORED_DIRS = new Set([
  'node_modules',
  '.git',
  'sessions',
  'session',
  'history',
  'memory',
  'logs',
  'log',
  'tmp',
  'temp',
  'cache',
  'runs',
]);
const MAX_CONFIG_SEARCH_DEPTH = 3;
const MAX_SKILL_FILES = 200;
// Minimum interval between tamper_detected emissions for lock forgery, so a
// persistent forger cannot flood the event sink (one alert per window is
// enough for the panel; the lock is reclaimed every tick regardless).
const LOCK_TAMPER_EMIT_INTERVAL_MS = 60_000;
const MAX_SKILL_WALK_DEPTH = 5;
const SKILL_IGNORED_DIRS = new Set(['node_modules', '.git', '__pycache__']);
// Skill search: how deep below a skill root to look for SKILL.md (covers flat
// layouts like skills/<name>/ and nested ones like plugins/<pkg>/skills/<name>/).
const MAX_SKILL_SEARCH_DEPTH = 4;
const MAX_SKILL_DIRS = 100;
// Config section summary bounds (agent_config parsed.sections).
const SUMMARY_MAX_DEPTH = 3;
const SUMMARY_MAX_STRING = 200;
const SUMMARY_MAX_ARRAY = 20;
// Placeholder buffer for over-cap files: buildFileAssets only derives the
// truncated marker from it, no byte of the real file is ever loaded.
const EMPTY_BUFFER = Buffer.alloc(0);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function pruneUndefined(obj: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(obj)) {
    if (v !== undefined) out[k] = v;
  }
  return out;
}

// Bumped when the event payload shape changes in code (new fields, different
// parsing); combined with the payload-shaping config flags into the state
// fingerprint so capability upgrades trigger exactly one re-baseline.
// 2 = packages; 3 = lean parsed for agent_config; 4 = lean parsed for skill;
// 5 = entry-level exclusion in skill packages;
// 6 = flat event_type (asset_add/change/remove/snapshot), change_type dropped.
const STATE_FORMAT_VERSION = 6;

/** Flat event_type per change action — the data standard encodes the action
 * in event_type itself (like file_read/write/delete, process_start/exit), so
 * there is no separate change_type field on the event. */
const EVENT_TYPE_BY_CHANGE: Record<ChangeType, SecurityEvent['event_type']> = {
  added: 'asset_add',
  changed: 'asset_change',
  removed: 'asset_remove',
  snapshot: 'asset_snapshot',
};

export class AssetCollector {
  readonly name = 'asset-collector';

  private collector: IEventCollector;
  private environment: EnvironmentConfig;
  private enabled: boolean;
  private scanIntervalMs: number;
  private fullSnapshotIntervalMs: number;
  private watchPaths: string[];
  private collectContent: boolean;
  private maxFileSizeBytes: number;
  private statePath: string;
  private lockPath: string;
  private lockStaleMs: number;
  private lockHeld = false;
  // Random nonce written into the lock we hold. Refresh keeps the
  // nonce, so a same-UID attacker who rewrites the lock file (dead pid +
  // fresh timestamp, or our own pid with a forged body) is detectable: the
  // nonce no longer matches what we wrote.
  private lockNonce: string | undefined;
  // Rate limit for tamper_detected emissions (one per window is enough to
  // alert the panel; a persistent forger must not spam the event sink).
  private lastLockTamperAt = 0;
  private sensitiveKeyPatterns: string[];
  private collectSkillPackage: boolean;
  private collectConfigPackage: boolean;
  private maxPackageBytes: number;
  private maxPackageEntryBytes: number;
  private packageEncoding: 'base64' | 'hex';
  private hostPrefix: string;

  private configPaths: string[];
  private skillRoots: string[];
  private mcpPaths: string[];
  private configRoots: string[];

  private state: Record<string, AssetStateRecord> = {};
  private sourceCache = new Map<string, SourceCacheEntry>();
  private dirty = false;
  private scanning = false;
  private scanTimer?: ReturnType<typeof setInterval>;
  private lastScanAt?: number;
  private lastSnapshotAt = 0;
  private totalScans = 0;
  private totalEmitted = 0;
  private fingerprint: string;
  // js-yaml is loaded lazily (same pattern as RuleLoader): the install bundle
  // does not ship node_modules, so a static import would crash the whole
  // plugin at load time when the deployment lacks the package.
  private yaml?: typeof import('js-yaml');

  constructor(
    collector: IEventCollector,
    config: AssetMonitorConfig,
    environment: EnvironmentConfig = {},
    discovery?: AssetDiscoveryOverrides
  ) {
    this.collector = collector;
    this.environment = environment;
    this.enabled = config.enabled === true;
    this.scanIntervalMs = config.scanIntervalMs ?? 300000;
    this.fullSnapshotIntervalMs = config.fullSnapshotIntervalMs ?? 86400000;
    this.watchPaths = config.watchPaths ?? [];
    this.collectContent = config.collectContent === true;
    this.maxFileSizeBytes = config.maxFileSizeBytes ?? 1024 * 1024;
    this.statePath =
      config.statePersistencePath || path.join(homedir(), '.openclaw', 'asset-state.json');
    this.lockPath = this.statePath + '.lock';
    // Lock becomes stale if the leader has not refreshed it for two scan intervals
    // (plus a small grace), so a crashed leader does not block scans forever.
    this.lockStaleMs = Math.max(2 * this.scanIntervalMs + 10000, 60000);
    this.sensitiveKeyPatterns =
      config.sensitiveKeyPatterns && config.sensitiveKeyPatterns.length > 0
        ? config.sensitiveKeyPatterns
        : ['token', 'key', 'secret', 'password', 'credential'];
    this.collectSkillPackage = config.collectSkillPackage === true;
    this.collectConfigPackage = config.collectConfigPackage === true;
    this.maxPackageBytes = config.maxPackageBytes ?? 1024 * 1024;
    this.maxPackageEntryBytes = config.maxPackageEntryBytes ?? 2 * 1024 * 1024;
    this.packageEncoding = config.packageEncoding === 'hex' ? 'hex' : 'base64';
    this.hostPrefix = environment.hostId || 'local';

    // Fingerprint of everything that shapes the event payload. Stored in the
    // state file; when it changes (e.g. packaging switched on, caps raised,
    // code upgraded), previously-reported assets are re-baselined once so the
    // consumer receives the new payload shape instead of staying silent.
    this.fingerprint = sha256Hex(
      JSON.stringify({
        v: STATE_FORMAT_VERSION,
        collectContent: this.collectContent,
        collectSkillPackage: this.collectSkillPackage,
        collectConfigPackage: this.collectConfigPackage,
        packageEncoding: this.packageEncoding,
        maxPackageBytes: this.maxPackageBytes,
        maxPackageEntryBytes: this.maxPackageEntryBytes,
        maxFileSizeBytes: this.maxFileSizeBytes,
        sensitiveKeyPatterns: this.sensitiveKeyPatterns,
      })
    );

    const openclawDir = path.join(homedir(), '.openclaw');
    this.configPaths = discovery?.configPaths ?? [path.join(openclawDir, 'openclaw.json')];
    // Skills can live in a flat user directory, nested inside installed
    // plugins/extensions (e.g. plugins/<pkg>/skills/<name>/SKILL.md), in
    // per-project workspace dirs (workspace/<project>/skills/<name>/), or in
    // inbound media uploads (media/inbound/<name>/). Depth ≤ 4 covers these
    // layouts while excluding deep audit/temp copies.
    this.skillRoots = discovery?.skillDirs ?? [
      path.join(openclawDir, 'skills'),
      path.join(openclawDir, 'plugins'),
      path.join(openclawDir, 'extensions'),
      path.join(openclawDir, 'workspace'),
      path.join(openclawDir, 'media'),
      ...(config.skillPaths ?? []),
    ];
    this.mcpPaths = discovery?.mcpPaths ?? [
      path.join(openclawDir, 'mcp.json'),
      ...(config.mcpPaths ?? []),
    ];
    // Per-agent directories (~/.openclaw/agents/<id>/agent/) hold agent-level
    // configs, sometimes including mcpServers — scanned recursively with
    // volatile dirs (sessions/history/...) excluded. Tests pass discovery
    // overrides to stay hermetic, so the built-in root applies only when no
    // overrides are given at all.
    this.configRoots = discovery ? (discovery.configRoots ?? []) : [path.join(openclawDir, 'agents')];
  }

  async initialize(): Promise<void> {
    if (!this.enabled) {
      return;
    }
    try {
      this.yaml = await import('js-yaml');
    } catch {
      console.warn(
        '[AssetCollector] js-yaml not available; SKILL frontmatter and YAML config parsing degraded (assets are still collected via hashes).'
      );
    }
    await this.loadState();
    // First scan doubles as the baseline. Only the leader runs it; the lock is
    // released afterwards so the long-running process's timer can take over.
    if (await this.isLeader()) {
      try {
        await this.scanNow();
      } finally {
        await this.releaseLock();
      }
    }
    this.lastSnapshotAt = Date.now();
    this.scanTimer = setInterval(() => {
      this.tick().catch((err) => {
        console.error('[AssetCollector] scheduled scan failed:', err);
      });
    }, this.scanIntervalMs);
    // Do not keep the host process alive just for asset scans.
    this.scanTimer.unref?.();
  }

  /**
   * Leader election across multiple OpenClaw worker processes. Only the process
   * that holds the lock runs periodic scans; the lock file is refreshed by every
   * scan and becomes stale after `lockStaleMs` so a crashed leader does not
   * block the next process forever.
   *
   * The lock file cannot be trusted on `{pid, acquiredAt}` alone: any
   * same-UID process could suppress all asset scans by writing someone
   * else's pid with a fresh timestamp, and a corrupted lock file made
   * JSON.parse throw → `return false` silently disabled scanning forever.
   * The lock therefore carries a random nonce and the holder pid is
   * verified to be a live process: a fresh lock held by a dead pid is
   * treated as forgery (reclaimed + tamper_detected event), and corrupted
   * JSON is treated as stale (reclaimed + warning) instead of a silent
   * opt-out.
   */
  private async isLeader(): Promise<boolean> {
    // a custom statePersistencePath whose parent dir does
    // not exist would fail lock creation with ENOENT on every tick and
    // silently disable all scans; mkdir first (idempotent, recursive).
    await mkdir(path.dirname(this.statePath), { recursive: true }).catch(() => {});

    let raw: string;
    try {
      raw = await readFile(this.lockPath, 'utf8');
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
        return this.createLock();
      }
      console.error('[AssetCollector] failed to check lock:', err);
      return false;
    }

    let data: AssetLockFile;
    try {
      data = JSON.parse(raw) as AssetLockFile;
      if (!isRecord(data)) throw new Error('lock file is not an object');
    } catch (parseErr) {
      // Corrupted lock (crash-torn write or tampering). Previously this fell
      // into the generic error path and silently returned false — scans died
      // until manual cleanup. Treat it as stale instead: warn + reclaim.
      console.warn(
        `[AssetCollector] lock file ${this.lockPath} is corrupted; treating as stale and reclaiming:`,
        parseErr
      );
      return this.reclaimLock();
    }

    if (data.pid === process.pid) {
      if (this.lockHeld) {
        if (data.nonce !== this.lockNonce) {
          // The file claims our pid but no longer carries our nonce: someone
          // same-UID replaced the lock under us. Re-assert ownership (the
          // old code blindly refreshed, which already won this fight) and
          // leave a tamper trace.
          await this.emitLockTamperEvent('lock_replaced', {
            lock_pid: data.pid,
            lock_nonce: typeof data.nonce === 'string' ? data.nonce : null,
            expected_nonce: this.lockNonce ?? null,
          });
        }
        // Our lock: refresh the timestamp, keep the nonce stable.
        await writeFile(
          this.lockPath,
          JSON.stringify({ pid: process.pid, acquiredAt: Date.now(), nonce: this.lockNonce }, null, 2)
        ).catch(() => {
          /* refresh is best-effort; losing the write means the lock goes stale */
        });
        return true;
      }
      // The file names our pid but this instance never acquired it (leftover
      // from a recycled pid). Adopt it like the earlier code did.
      this.lockNonce = this.generateLockNonce();
      await writeFile(
        this.lockPath,
        JSON.stringify({ pid: process.pid, acquiredAt: Date.now(), nonce: this.lockNonce }, null, 2)
      ).catch(() => {});
      this.lockHeld = true;
      return true;
    }

    const holderAlive = isPidAlive(data.pid);
    const fresh =
      typeof data.acquiredAt === 'number' && Date.now() - data.acquiredAt < this.lockStaleMs;

    if (!holderAlive) {
      // Fresh lock + dead holder pid is the forgery signature:
      // a same-UID writer parked a non-existent pid with a fresh timestamp
      // to suppress scans indefinitely. A stale lock left by a crashed
      // leader also lands here — reclaim either way, but only the fresh
      // variant alerts (a crash is routine, not tampering).
      if (fresh) {
        await this.emitLockTamperEvent('forged_lock', {
          lock_pid: typeof data.pid === 'number' ? data.pid : null,
          lock_acquiredAt: typeof data.acquiredAt === 'number' ? data.acquiredAt : null,
          lock_nonce: typeof data.nonce === 'string' ? data.nonce : null,
        });
      }
      return this.reclaimLock();
    }

    if (fresh) {
      // Live holder refreshing on schedule: stand down.
      return false;
    }

    // Holder process exists but stopped refreshing (hung leader). Reclaim
    // after the stale window, same as the earlier behavior.
    return this.reclaimLock();
  }

  /**
   * Atomic lock creation (O_CREAT|O_EXCL). The payload is written through the
   * same handle, so the lock file never appears empty; losers get EEXIST.
   */
  private async createLock(): Promise<boolean> {
    try {
      const handle = await openAsync(this.lockPath, 'wx');
      try {
        this.lockNonce = this.generateLockNonce();
        await handle.writeFile(
          JSON.stringify({ pid: process.pid, acquiredAt: Date.now(), nonce: this.lockNonce }, null, 2)
        );
      } finally {
        await handle.close();
      }
      this.lockHeld = true;
      return true;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'EEXIST') {
        return false;
      }
      // A torn create (e.g. write failed after open) must not leave an empty
      // lock behind for the next reader to mis-read as corruption.
      await rm(this.lockPath).catch(() => {});
      console.error('[AssetCollector] failed to acquire lock:', err);
      return false;
    }
  }

  /**
   * Reclaim a stale / corrupted / forged lock. The removal widens no race
   * the design did not already have: two racers can both unlink (ENOENT is
   * ignored), then fight for the O_EXCL create, and exactly one wins. A
   * third process creating a fresh lock in between simply wins the create.
   */
  private async reclaimLock(): Promise<boolean> {
    await rm(this.lockPath).catch(() => {
      /* already gone — treat as a won race and fall through to the create */
    });
    return this.createLock();
  }

  private generateLockNonce(): string {
    return randomBytes(16).toString('hex');
  }

  /** Best-effort tamper_detected event (rate-limited; never blocks isLeader). */
  private async emitLockTamperEvent(kind: string, detail: Record<string, unknown>): Promise<void> {
    const now = Date.now();
    if (now - this.lastLockTamperAt < LOCK_TAMPER_EMIT_INTERVAL_MS) {
      return;
    }
    this.lastLockTamperAt = now;
    // Same construction as store.emitSelfProtectionEvent: base fields plus a
    // spread detail payload, cast to SecurityEvent.
    const event = {
      comm: 'openclaw',
      event_id: generateUUID(),
      event_type: 'tamper_detected',
      layer: 'asset',
      ts: now,
      schema_version: '1.0.0',
      pid: process.pid,
      session_id: null,
      run_id: null,
      task_id: null,
      turn_id: null,
      host_id: this.environment.hostId,
      container_id: this.environment.containerId,
      pod_name: this.environment.podName,
      namespace: this.environment.namespace,
      source: 'openclaw.v1',
      collection_method: 'agent_api',
      collector: {
        hook_name: 'tamper_detected',
        middleware_name: 'sst-security-control-openclaw',
        collector_name: this.name,
      },
      kind,
      ...detail,
    } as SecurityEvent;
    try {
      await this.collector.report(event);
    } catch (err) {
      console.error('[AssetCollector] failed to report lock tamper event:', err);
    }
  }

  private async releaseLock(): Promise<void> {
    if (!this.lockHeld) return;
    try {
      await rm(this.lockPath).catch(() => {
        /* ignore */
      });
    } finally {
      this.lockHeld = false;
      this.lockNonce = undefined;
    }
  }

  private async tick(): Promise<void> {
    if (!(await this.isLeader())) {
      return;
    }
    if (
      this.fullSnapshotIntervalMs > 0 &&
      Date.now() - this.lastSnapshotAt >= this.fullSnapshotIntervalMs
    ) {
      await this.snapshotNow();
    } else {
      await this.scanNow();
    }
  }

  /**
   * Run one incremental scan: emit added/changed/removed events only.
   * Public so tests (and future manual triggers) can drive scans directly.
   */
  async scanNow(): Promise<void> {
    if (!this.enabled || this.scanning) {
      return;
    }
    this.scanning = true;
    try {
      const assets = await this.collectAssets();
      await this.diffAndReport(assets, false);
      this.totalScans += 1;
      this.lastScanAt = Date.now();
    } finally {
      this.scanning = false;
    }
  }

  /**
   * Run a full reconciliation snapshot: every present asset is reported as
   * asset_snapshot (carrying prev_hash), vanished assets as asset_remove.
   */
  async snapshotNow(): Promise<void> {
    if (!this.enabled || this.scanning) {
      return;
    }
    this.scanning = true;
    try {
      const assets = await this.collectAssets();
      await this.diffAndReport(assets, true);
      this.totalScans += 1;
      this.lastScanAt = Date.now();
      this.lastSnapshotAt = Date.now();
    } finally {
      this.scanning = false;
    }
  }

  // ---------------------------------------------------------------------------
  // Diff & reporting
  // ---------------------------------------------------------------------------

  private async diffAndReport(assets: ScannedAsset[], snapshotMode: boolean): Promise<void> {
    const now = Date.now();
    const current = new Map<string, ScannedAsset>();
    for (const asset of assets) {
      // Defensive dedupe: the same assetId can be discovered twice (e.g. an
      // MCP file listed both as a default and inside a watchPath directory).
      if (!current.has(asset.assetId)) {
        current.set(asset.assetId, asset);
      }
    }

    // Removed: in state but no longer discovered.
    for (const [assetId, record] of Object.entries(this.state)) {
      if (!current.has(assetId)) {
        delete this.state[assetId];
        this.dirty = true;
        // Persist the new state before emitting so short-lived processes do not
        // leave a stale state file behind for the next leader.
        await this.saveState();
        await this.emit(
          {
            assetId,
            assetType: record.assetType as AssetType,
            assetPath: record.assetPath,
            contentHash: record.contentHash,
          },
          'removed',
          record.contentHash
        );
      }
    }

    for (const asset of current.values()) {
      const prev = this.state[asset.assetId];
      if (snapshotMode) {
        await this.emit(asset, 'snapshot', prev?.contentHash);
        this.state[asset.assetId] = this.toRecord(asset, prev?.firstSeen ?? now, now);
        this.dirty = true;
      } else if (!prev) {
        this.state[asset.assetId] = this.toRecord(asset, now, now);
        this.dirty = true;
        await this.saveState();
        await this.emit(asset, 'added');
      } else if (prev.contentHash !== asset.contentHash) {
        this.state[asset.assetId] = this.toRecord(asset, prev.firstSeen, now);
        this.dirty = true;
        await this.saveState();
        await this.emit(asset, 'changed', prev.contentHash);
      }
      // Unchanged in scan mode: no event — this is the core anti-redundancy rule.
    }

    if (this.dirty) {
      await this.saveState();
    }
  }

  private toRecord(asset: ScannedAsset, firstSeen: number, lastReported: number): AssetStateRecord {
    return {
      contentHash: asset.contentHash,
      assetType: asset.assetType,
      assetPath: asset.assetPath,
      firstSeen,
      lastReported,
    };
  }

  private async emit(asset: ScannedAsset, changeType: ChangeType, prevHash?: string): Promise<void> {
    const now = Date.now();
    const event: SecurityEvent = {
      comm: 'openclaw',
      event_id: generateUUID(),
      event_type: EVENT_TYPE_BY_CHANGE[changeType],
      layer: 'asset',
      ts: now,
      schema_version: '1.0.0',
      pid: process.pid,
      session_id: null,
      run_id: null,
      task_id: null,
      turn_id: null,
      host_id: this.environment.hostId,
      container_id: this.environment.containerId,
      pod_name: this.environment.podName,
      namespace: this.environment.namespace,
      source: 'openclaw.v1',
      collection_method: 'skill_sync',
      collector: { collector_name: this.name },
      asset_id: asset.assetId,
      asset_type: asset.assetType,
      asset_path: asset.assetPath,
      // asset_remove only announces that the asset is gone; the data standard
      // forbids content_hash on it — the last known hash rides in prev_hash.
      content_hash: changeType === 'removed' ? undefined : asset.contentHash,
      prev_hash: prevHash,
      parsed: asset.parsed,
      asset_package: asset.assetPackage,
      file_size: asset.fileSize,
      file_mtime: asset.fileMtime,
    };
    try {
      await this.collector.report(event);
      this.totalEmitted += 1;
    } catch (err) {
      console.error('[AssetCollector] failed to report asset event:', err);
    }
  }

  // ---------------------------------------------------------------------------
  // Asset collection
  // ---------------------------------------------------------------------------

  private async collectAssets(): Promise<ScannedAsset[]> {
    const out: ScannedAsset[] = [];
    const seenSources = new Set<string>();

    for (const filePath of await this.discoverConfigFiles()) {
      const key = `file:${filePath}`;
      seenSources.add(key);
      out.push(...(await this.collectFromFile(filePath, key, 'config')));
    }

    for (const filePath of this.mcpPaths) {
      const key = `file:${filePath}`;
      seenSources.add(key);
      out.push(...(await this.collectFromFile(filePath, key, 'mcp')));
    }

    for (const root of this.skillRoots) {
      for (const skillDir of await this.listSkillDirs(root)) {
        const key = `skill:${skillDir}`;
        seenSources.add(key);
        out.push(...(await this.collectFromSkillDir(skillDir, key)));
      }
    }

    // Prune cache entries whose source vanished so their assets leave the scan.
    for (const key of [...this.sourceCache.keys()]) {
      if (!seenSources.has(key)) {
        this.sourceCache.delete(key);
      }
    }

    return out;
  }

  private async discoverConfigFiles(): Promise<string[]> {
    const files = new Set<string>(this.configPaths);
    for (const watchPath of this.watchPaths) {
      try {
        const st = await stat(watchPath);
        if (st.isDirectory()) {
          const entries = await readdir(watchPath);
          for (const entry of entries.sort()) {
            if (CONFIG_FILE_PATTERN.test(entry)) {
              files.add(path.join(watchPath, entry));
            }
          }
        } else if (st.isFile()) {
          files.add(watchPath);
        }
      } catch {
        // Missing watch path — ignore; it simply yields no assets.
      }
    }
    for (const root of this.configRoots) {
      for (const file of await this.walkConfigFiles(root, 1)) {
        files.add(file);
      }
    }
    return [...files];
  }

  /**
   * Recursively collect config files under a root (per-agent dirs), skipping
   * dependency/VCS dirs and volatile runtime state dirs.
   */
  private async walkConfigFiles(dir: string, depth: number): Promise<string[]> {
    if (depth > MAX_CONFIG_SEARCH_DEPTH) return [];
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return [];
    }
    const out: string[] = [];
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!CONFIG_IGNORED_DIRS.has(entry.name) && !entry.name.startsWith('.')) {
          out.push(...(await this.walkConfigFiles(full, depth + 1)));
        }
      } else if (entry.isFile() && CONFIG_FILE_PATTERN.test(entry.name)) {
        out.push(full);
      }
    }
    return out.sort();
  }

  /**
   * Collect assets from one source file with mtime/size fast-skip. `kind`
   * controls what the file yields: 'config' yields an agent_config asset (and
   * any embedded mcpServers), 'mcp' yields only mcp_server assets.
   */
  private async collectFromFile(
    filePath: string,
    cacheKey: string,
    kind: 'config' | 'mcp'
  ): Promise<ScannedAsset[]> {
    try {
      const st = await stat(filePath);
      if (!st.isFile()) {
        this.sourceCache.delete(cacheKey);
        return [];
      }
      const sig = `${st.mtimeMs}:${st.size}`;
      const cached = this.sourceCache.get(cacheKey);
      if (cached && cached.sig === sig) {
        return cached.assets;
      }

      // over-cap files are never read into memory (same
      // cap as the skill scanner below) — the asset degrades to the
      // metadata-only truncated marker.
      const truncated = st.size > this.maxFileSizeBytes;
      if (truncated) {
        console.warn(
          `[AssetCollector] skipping oversized config file ${filePath} (${st.size} > ${this.maxFileSizeBytes} bytes)`
        );
        const assets = this.buildFileAssets(filePath, EMPTY_BUFFER, st.mtimeMs, st.size, true, kind);
        this.sourceCache.set(cacheKey, { sig, assets });
        return assets;
      }
      const buf = await readFile(filePath);
      const assets = this.buildFileAssets(filePath, buf, st.mtimeMs, st.size, false, kind);
      this.sourceCache.set(cacheKey, { sig, assets });
      return assets;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
        console.error(`[AssetCollector] failed to collect from ${filePath}:`, err);
      }
      this.sourceCache.delete(cacheKey);
      return [];
    }
  }

  private buildFileAssets(
    filePath: string,
    buf: Buffer,
    mtimeMs: number,
    size: number,
    truncated: boolean,
    kind: 'config' | 'mcp'
  ): ScannedAsset[] {
    const assets: ScannedAsset[] = [];
    const raw = buf.toString('utf8');
    const json = truncated ? undefined : tryParseJson(raw);

    if (kind === 'config') {
      const parsed = this.summarizeConfigFile(filePath, raw, json, truncated);
      let assetPackage: AssetPackageInfo | undefined;
      if (this.collectConfigPackage && !truncated) {
        // Single-file ZIP of the raw config for downstream audit scanning.
        // Intentionally NOT obfuscated (same rationale as skill packages);
        // the archive is what the scanner needs, sections/content stay obf'd.
        const zip = buildZip([{ name: path.basename(filePath), data: buf, mtime: mtimeMs }]);
        if (zip.length <= this.maxPackageBytes) {
          assetPackage = {
            format: 'zip',
            encoding: this.packageEncoding,
            data: zip.toString(this.packageEncoding),
            original_bytes: buf.length,
            compressed_bytes: zip.length,
            file_count: 1,
          };
        } else {
          parsed.package_omitted = 'too_large';
          parsed.package_bytes = zip.length;
        }
      }
      if (assetPackage) {
        // The package is the single carrier of the full config content. Keep
        // parsed as a lean description (file_name/format/keys/plugins/
        // mcp_servers lists) — drop sections and content (and the new
        // hash/preview fallback) to avoid storing the same configuration
        // twice. When the package was omitted (too_large), sections/content
        // stay as the fallback visibility.
        delete parsed.content;
        delete parsed.content_hash;
        delete parsed.content_preview;
        delete parsed.sections;
      }
      assets.push({
        assetId: `${this.hostPrefix}:agent_config:${filePath}`,
        assetType: 'agent_config',
        assetPath: filePath,
        contentHash: contentHash(raw),
        fileSize: size,
        fileMtime: mtimeMs,
        parsed,
        assetPackage,
      });
    }

    // MCP servers can live in a standalone mcp.json or embedded in any JSON
    // config file under the conventional `mcpServers` key.
    if (json) {
      for (const [name, def] of extractMcpServers(json)) {
        assets.push(this.buildMcpAsset(filePath, name, def));
      }
    }

    return assets;
  }

  private summarizeConfigFile(
    filePath: string,
    raw: string,
    json: unknown,
    truncated: boolean
  ): Record<string, unknown> {
    const ext = path.extname(filePath).replace(/^\./, '').toLowerCase() || 'txt';
    if (truncated) {
      return { file_name: path.basename(filePath), format: ext, truncated: true };
    }

    let doc = json;
    if (!doc && (ext === 'yaml' || ext === 'yml')) {
      doc = this.tryParseYaml(raw);
    }

    const parsed: Record<string, unknown> = { file_name: path.basename(filePath), format: ext };
    if (isRecord(doc)) {
      parsed.keys = Object.keys(doc).sort();
      if (isRecord(doc.plugins)) {
        parsed.plugins = Object.keys(doc.plugins).sort();
      }
      if (isRecord(doc.mcpServers)) {
        parsed.mcp_servers = Object.keys(doc.mcpServers).sort();
      }
      // Structured, depth-capped summary of every top-level section so the
      // consumer can see the real configuration (agents/models/channels/...)
      // without shipping full content. Sensitive leaves are obf:v1 envelopes.
      const sections: Record<string, unknown> = {};
      for (const [key, value] of Object.entries(doc)) {
        sections[key] = this.summarizeValue(value, key, 1);
      }
      parsed.sections = sections;
    }
    if (this.collectContent) {
      // 内容落盘收紧：不再保留明文/反混淆原文，改存 sha256 + 前 256 字节
      // 脱敏预览。审计 H8：toml/md/ini 等非结构化文件此前直落原文，伪造
      // 配置随 NDJSON 外送即明文广播。结构化 JSON/YAML 仍走 obfuscateDeep
      // —— 其反序列化产物是结构化对象，可逐键脱敏。
      if (doc) {
        const obf = obfuscateDeep(doc, this.sensitiveKeyPatterns);
        const obfText = stableStringify(obf);
        parsed.content_hash = sha256Hex(obfText);
        parsed.content_preview = obfText.length > 256 ? obfText.slice(0, 256) + '…' : obfText;
      } else {
        // 非结构化：原文也不入盘，仅留 hash + 头 256 字节
        parsed.content_hash = sha256Hex(raw);
        parsed.content_preview = raw.length > 256 ? raw.slice(0, 256) + '…' : raw;
      }
    }
    return parsed;
  }

  /**
   * Bounded structural summary of a config value: objects/arrays are recursed
   * up to SUMMARY_MAX_DEPTH, long strings and large arrays are truncated, and
   * string values under sensitive keys become obf:v1 envelopes.
   */
  private summarizeValue(value: unknown, key: string | undefined, depth: number): unknown {
    const sensitive = key !== undefined && isSensitiveKey(key, this.sensitiveKeyPatterns);
    if (typeof value === 'string') {
      if (sensitive) return obfEncode(value);
      return value.length > SUMMARY_MAX_STRING
        ? `${value.slice(0, SUMMARY_MAX_STRING)}…(${value.length} chars)`
        : value;
    }
    if (value === null || typeof value !== 'object') {
      return value;
    }
    if (Array.isArray(value)) {
      if (value.length > SUMMARY_MAX_ARRAY) return `[array:${value.length}]`;
      if (sensitive) {
        return value.map((item) => (typeof item === 'string' ? obfEncode(item) : this.summarizeValue(item, undefined, depth + 1)));
      }
      return depth >= SUMMARY_MAX_DEPTH
        ? `[array:${value.length}]`
        : value.map((item) => this.summarizeValue(item, undefined, depth + 1));
    }
    if (depth >= SUMMARY_MAX_DEPTH) {
      return '[object]';
    }
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = this.summarizeValue(v, k, depth + 1);
    }
    return out;
  }

  private buildMcpAsset(sourcePath: string, name: string, def: Record<string, unknown>): ScannedAsset {
    const env = isRecord(def.env) ? def.env : undefined;
    const headers = isRecord(def.headers) ? def.headers : undefined;
    const transport =
      typeof def.transport === 'string'
        ? def.transport
        : typeof def.type === 'string'
          ? def.type
          : def.command
            ? 'stdio'
            : def.url
              ? 'http'
              : 'unknown';

    return {
      assetId: `${this.hostPrefix}:mcp_server:${sourcePath}#${name}`,
      assetType: 'mcp_server',
      assetPath: sourcePath,
      // Hash the plaintext definition (before any obfuscation) so change
      // detection is unaffected by the deterministic-but-opaque envelope.
      contentHash: sha256Hex(stableStringify(def)),
      parsed: pruneUndefined({
        name,
        transport,
        command: typeof def.command === 'string' ? def.command : undefined,
        args: Array.isArray(def.args) ? def.args : undefined,
        url: typeof def.url === 'string' ? def.url : undefined,
        env: obfuscateSensitiveValues(env, this.sensitiveKeyPatterns),
        headers: obfuscateSensitiveValues(headers, this.sensitiveKeyPatterns),
        auth: this.extractAuth(env, headers),
      }),
    };
  }

  private extractAuth(
    env: Record<string, unknown> | undefined,
    headers: Record<string, unknown> | undefined
  ): Record<string, unknown> {
    const sources: Array<['env' | 'headers', Record<string, unknown> | undefined]> = [
      ['env', env],
      ['headers', headers],
    ];
    for (const [sourceName, obj] of sources) {
      if (!obj) continue;
      for (const [key, value] of Object.entries(obj)) {
        if (typeof value === 'string' && AUTH_KEY_PATTERN.test(key)) {
          return {
            present: true,
            key,
            source: sourceName,
            type: /authorization/i.test(key) ? 'bearer' : 'key',
            value: obfEncode(value),
          };
        }
      }
    }
    return { present: false };
  }

  // ---------------------------------------------------------------------------
  // Skills
  // ---------------------------------------------------------------------------

  /**
   * Find skill directories (dirs containing SKILL.md) under a root, searching
   * up to MAX_SKILL_SEARCH_DEPTH levels so both flat and plugin-nested layouts
   * are discovered. Dot-directories (staging dirs, .git) are skipped.
   */
  private async listSkillDirs(root: string): Promise<string[]> {
    const found: string[] = [];
    const walk = async (dir: string, depth: number): Promise<void> => {
      if (depth > MAX_SKILL_SEARCH_DEPTH || found.length >= MAX_SKILL_DIRS) return;
      let entries;
      try {
        entries = await readdir(dir, { withFileTypes: true });
      } catch {
        return; // missing/unreadable root — simply no skills
      }
      if (entries.some((e) => e.isFile() && e.name === 'SKILL.md')) {
        found.push(dir);
        return;
      }
      for (const entry of entries) {
        if (entry.isDirectory() && !SKILL_IGNORED_DIRS.has(entry.name) && !entry.name.startsWith('.')) {
          await walk(path.join(dir, entry.name), depth + 1);
        }
      }
    };
    await walk(root, 1);
    return found.sort();
  }

  private async collectFromSkillDir(skillDir: string, cacheKey: string): Promise<ScannedAsset[]> {
    try {
      const files = await this.walkSkillFiles(skillDir);
      const sigParts: string[] = [];
      for (const filePath of files) {
        const st = await stat(filePath);
        sigParts.push(`${path.relative(skillDir, filePath)}:${st.mtimeMs}:${st.size}`);
      }
      const sig = sigParts.join('|');
      const cached = this.sourceCache.get(cacheKey);
      if (cached && cached.sig === sig) {
        return cached.assets;
      }

      // Per-file size cap: a skill directory containing a 500 MB
      // blob would otherwise load all of it into memory and balloon the
      // ZIP. Drop over-cap files from both the signature and the buffer
      // loop so they neither affect the cache key nor get read into RAM.
      const maxBytes = this.maxFileSizeBytes ?? 1024 * 1024;
      const bounded: string[] = [];
      for (const filePath of files) {
        const st = await stat(filePath);
        if (st.size > maxBytes) {
          console.warn(
            `[AssetCollector] skipping oversized skill file ${filePath} (${st.size} > ${maxBytes} bytes)`
          );
          continue;
        }
        bounded.push(filePath);
      }

      // Read every file exactly once into memory: the per-file manifest, the
      // aggregate fingerprint, the frontmatter and the ZIP package are all
      // derived from the same buffers, so the hash always matches the package.
      const entries: Array<{ rel: string; buf: Buffer; mtimeMs: number }> = [];
      for (const filePath of bounded) {
        const st = await stat(filePath);
        const rel = path.relative(skillDir, filePath).replace(/\\/g, '/');
        entries.push({ rel, buf: await readFile(filePath), mtimeMs: st.mtimeMs });
      }

      // Aggregate fingerprint over every file in the skill directory: any
      // added/modified/removed file changes the asset hash.
      const manifest = entries.map((e) => ({
        path: e.rel,
        size: e.buf.length,
        sha256: sha256Hex(e.buf),
      }));
      const aggregateHash = sha256Hex(manifest.map((m) => `${m.path}:${m.sha256}`).join('\n'));

      const skillMd = entries.find((e) => e.rel === 'SKILL.md');
      const skillMdRaw = skillMd ? skillMd.buf.toString('utf8') : '';
      const frontmatter = this.parseFrontmatter(skillMdRaw);

      const parsed: Record<string, unknown> = {
        ...frontmatter,
        name: typeof frontmatter.name === 'string' ? frontmatter.name : path.basename(skillDir),
        file_count: entries.length,
        files_truncated: files.length >= MAX_SKILL_FILES || undefined,
        // Per-file manifest: the consumer can inventory and diff versions
        // without unpacking the archive.
        files: manifest,
      };
      if (this.collectContent) {
        parsed.content = skillMdRaw;
      }

      let assetPackage: AssetPackageInfo | undefined;
      if (this.collectSkillPackage) {
        // Entry-level guard: single files larger than maxPackageEntryBytes
        // (typically big binaries) are excluded from the ZIP so the package
        // stays small; they remain in the manifest with hash + excluded flag.
        const included = entries.filter((e) => e.buf.length <= this.maxPackageEntryBytes);
        const excludedRels = new Set(
          entries.filter((e) => e.buf.length > this.maxPackageEntryBytes).map((e) => e.rel)
        );
        for (const item of manifest) {
          if (excludedRels.has(item.path)) {
            (item as Record<string, unknown>).excluded = 'too_large';
          }
        }

        if (included.length === 0) {
          parsed.package_omitted = 'entries_too_large';
        } else {
          const zip = buildZip(included.map((e) => ({ name: e.rel, data: e.buf, mtime: e.mtimeMs })));
          if (zip.length <= this.maxPackageBytes) {
            assetPackage = {
              format: 'zip',
              encoding: this.packageEncoding,
              data: zip.toString(this.packageEncoding),
              original_bytes: included.reduce((sum, e) => sum + e.buf.length, 0),
              compressed_bytes: zip.length,
              file_count: included.length,
            };
            if (excludedRels.size > 0) {
              parsed.package_excluded_files = excludedRels.size;
            }
          } else {
            // Too large to ship inline: manifest still goes out so the consumer
            // has per-file hashes and can request the package out-of-band.
            parsed.package_omitted = 'too_large';
            parsed.package_bytes = zip.length;
          }
        }
      }
      if (assetPackage) {
        // SKILL.md content already lives inside the package — same lean rule
        // as agent_config: never store the raw file twice.
        delete parsed.content;
      }

      const assets: ScannedAsset[] = [
        {
          assetId: `${this.hostPrefix}:skill:${skillDir}`,
          assetType: 'skill',
          assetPath: skillDir,
          contentHash: aggregateHash,
          fileSize: skillMd?.buf.length,
          fileMtime: skillMd?.mtimeMs,
          parsed: pruneUndefined(parsed),
          assetPackage,
        },
      ];
      this.sourceCache.set(cacheKey, { sig, assets });
      return assets;
    } catch (err) {
      console.error(`[AssetCollector] failed to collect skill ${skillDir}:`, err);
      this.sourceCache.delete(cacheKey);
      return [];
    }
  }

  private async walkSkillFiles(dir: string, depth = 0): Promise<string[]> {
    if (depth > MAX_SKILL_WALK_DEPTH) return [];
    const out: string[] = [];
    const entries = await readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (out.length >= MAX_SKILL_FILES) break;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!SKILL_IGNORED_DIRS.has(entry.name)) {
          out.push(...(await this.walkSkillFiles(full, depth + 1)));
        }
      } else if (entry.isFile()) {
        if (path.extname(entry.name).toLowerCase() === '.pyc') continue;
        out.push(full);
      }
    }
    return out.sort();
  }

  // ---------------------------------------------------------------------------
  // State persistence
  // ---------------------------------------------------------------------------

  private async loadState(): Promise<void> {
    try {
      const raw = await readFile(this.statePath, 'utf8');
      const data = JSON.parse(raw) as AssetStateFile;
      if (data && typeof data === 'object' && isRecord(data.assets)) {
        if (data.fingerprint !== this.fingerprint) {
          // Payload shape changed since the state was written (new flags or
          // upgraded code): re-baseline so the consumer gets the new shape.
          console.log(
            '[AssetCollector] state fingerprint mismatch (payload shape changed); re-baselining all assets'
          );
          this.state = {};
          this.dirty = true;
          return;
        }
        this.state = data.assets;
      }
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
        // Preserve the corrupt file for forensics, then fall back to an
        // empty baseline. Quarantining instead of deleting gives operators a
        // chance to inspect / replay; the next saveState will replace the
        // broken file with a fresh one.
        const backupPath = `${this.statePath}.bak.${Date.now()}`;
        try {
          await rename(this.statePath, backupPath);
          console.error(
            `[AssetCollector] tamper_detected state file moved to ${backupPath}; starting with empty baseline:`,
            err
          );
        } catch (renameErr) {
          console.error(
            `[AssetCollector] tamper_detected state file unreadable and backup failed; starting with empty baseline:`,
            err,
            '| renameErr:',
            renameErr
          );
        }
      }
    }
  }

  private async saveState(): Promise<void> {
    try {
      await mkdir(path.dirname(this.statePath), { recursive: true });
      const tmpPath = this.statePath + '.tmp';
      const payload: AssetStateFile = { version: 1, fingerprint: this.fingerprint, assets: this.state };
      await writeFile(tmpPath, JSON.stringify(payload, null, 2), 'utf8');
      await rename(tmpPath, this.statePath);
      this.dirty = false;
    } catch (err) {
      console.error('[AssetCollector] failed to persist state:', err);
    }
  }

  private tryParseYaml(raw: string): unknown {
    if (!this.yaml) return undefined;
    try {
      return this.yaml.load(raw);
    } catch {
      return undefined;
    }
  }

  private parseFrontmatter(raw: string): Record<string, unknown> {
    const match = /^---\r?\n([\s\S]*?)\r?\n---/.exec(raw);
    if (!match || !this.yaml) {
      return {};
    }
    try {
      const doc = this.yaml.load(match[1]);
      return isRecord(doc) ? doc : {};
    } catch {
      return {};
    }
  }

  // ---------------------------------------------------------------------------
  // Lifecycle
  // ---------------------------------------------------------------------------

  getStats(): Record<string, unknown> {
    return {
      enabled: this.enabled,
      statePath: this.statePath,
      lastScanAt: this.lastScanAt,
      lastSnapshotAt: this.lastSnapshotAt || undefined,
      totalScans: this.totalScans,
      totalEmitted: this.totalEmitted,
      trackedAssets: Object.keys(this.state).length,
      cachedSources: this.sourceCache.size,
    };
  }

  async shutdown(): Promise<void> {
    if (this.scanTimer) {
      clearInterval(this.scanTimer);
      this.scanTimer = undefined;
    }
    if (this.dirty) {
      await this.saveState();
    }
    await this.releaseLock();
  }
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

function tryParseJson(raw: string): unknown {
  try {
    return JSON.parse(raw);
  } catch {
    return undefined;
  }
}

/**
 * Verify that the lock holder pid refers to a live process.
 * `kill(pid, 0)` probes existence without signalling: ESRCH means the
 * process is gone, EPERM means it exists but is not ours to signal (still
 * alive — count it). Pids that cannot exist (missing / non-positive) are
 * treated as dead so their locks get reclaimed.
 */
function isPidAlive(pid: unknown): boolean {
  if (typeof pid !== 'number' || !Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === 'EPERM';
  }
}

function extractMcpServers(json: unknown): Array<[string, Record<string, unknown>]> {
  if (!isRecord(json) || !isRecord(json.mcpServers)) {
    return [];
  }
  return Object.entries(json.mcpServers).filter(([, def]) => isRecord(def)) as Array<
    [string, Record<string, unknown>]
  >;
}

// Re-export for convenience so AssetCollector consumers can check sensitivity
// without importing the obfuscation module directly.
export { isSensitiveKey };
