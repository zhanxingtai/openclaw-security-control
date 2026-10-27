import type {
  SecurityMonitorConfig,
  NetworkLayerConfig,
  SystemLayerConfig,
  AssetMonitorConfig,
} from './types.js';
import type { InterventionConfig, FailStrategy } from './intervention/types.js';
import { getHostId, getContainerId, getPodName, getNamespace } from './environment.js';
import { GENERATED_HOOK_BLOCKED_FLAGS } from './intervention/generated-flag-defaults.js';
import { homedir } from 'os';
import path from 'path';

/**
 * Expand a leading `~` or `~/` in a path to the current user's home directory.
 * Leaves other paths (including absolute paths and `~user`) unchanged.
 */
function expandPath(value: string | undefined): string | undefined {
  if (!value || typeof value !== 'string') return value;
  if (value === '~') return homedir();
  if (value.startsWith('~/') || value.startsWith('~\\')) {
    return path.join(homedir(), value.slice(2));
  }
  return value;
}

// Tiny declarative config merger: each rule describes how to merge one field.
// Rules keep defaults unless the input explicitly provides a value (presence
// check, not truthiness — `false`, `0`, and `""` all override the default).
type Rule = (value: unknown, defaultValue: unknown) => unknown;
const bool: Rule = (v, d) => (v !== undefined ? Boolean(v) : d);
const num: Rule = (v, d) => {
  if (v === undefined) return d;
  const n = Number(v);
  return Number.isFinite(n) ? n : d;
};
const str: Rule = (v, d) => (v !== undefined ? String(v) : d);
const pth: Rule = (v, d) => (v !== undefined ? expandPath(String(v)) : d);
// Arrays only override defaults when the caller actually supplied entries;
// empty arrays are treated as "use default" so a stray `[]` never disables
// the configured deny-list.
const arr: Rule = (v, d) => (Array.isArray(v) && v.length > 0 ? v : d);
const passthrough: Rule = (v, d) => (v !== undefined ? v : d);
const en = (values: readonly string[]): Rule => (v, d) =>
  typeof v === 'string' && values.includes(v) ? v : d;

function pick(
  input: Record<string, unknown> | undefined,
  defaults: Record<string, unknown>,
  schema: Record<string, Rule>
): Record<string, unknown> {
  const src = input || {};
  const out: Record<string, unknown> = {};
  for (const [key, rule] of Object.entries(schema)) {
    out[key] = rule(src[key], defaults[key]);
  }
  return out;
}

export const DEFAULT_CONFIG: SecurityMonitorConfig = {
  collector: {
    // Local NDJSON sink. The plugin only writes here; the sidecar SDK tails
    // the file and owns transport, batching, retry, and encoding. Avoiding
    // an `endpoint` field here is intentional — it keeps the plugin surface
    // strictly OpenClaw-spec and prevents accidental wiring against an
    // internal collector URL.
    ndjsonPath: path.join(homedir(), '.openclaw', 'security-events.jsonl'),
    // Rotate the sink once it exceeds this size in bytes. Renamed to
    // `<ndjsonPath>.rotated` (single backup) on rollover. 0 disables.
    maxFileSizeBytes: 100 * 1024 * 1024, // 100 MB
    // Cap on the panel's in-memory event cache. Older events are dropped
    // when the NDJSON grows past this; aggregate counters are global and
    // unaffected.
    maxEventsInMemory: 5000,
  },
  application: {
    enabled: true,
    captureUserPrompt: true,
    captureSystemPrompt: true,
    captureAgentPlan: true,
    captureCodeMode: true,
    captureUserId: true,
    captureReasoning: true,
    userIdField: 'userId',
    maxContentLength: 2000,
    maxResultPreviewLength: 500,
    maxRawParamsLength: 10000,
    maxCodeContentLength: 5000,
    sessionTtlMs: 30 * 60 * 1000, // 30 minutes
    maxPreviousActions: 50,
    defaultAgentId: '',
    // 面板语言。auto = 按 ?lang= / Accept-Language 协商（默认）；显式 en/zh
    // 则忽略浏览器偏好，面板右上角的切换控件写入的就是这个键。
    panelLocale: 'auto',
    runtimeHooks: {
      // Opt-in. The plugin probes NODE_OPTIONS at boot; when the runtime hook
      // is not preloaded, the bootstrap pipeline disables this flag. Users who
      // want process/network coverage must set NODE_OPTIONS themselves (the
      // plugin no longer mutates the host entrypoint).
      enabled: false,
      networkEnabled: true,
      logPath: path.join(homedir(), '.openclaw', 'security-events-runtime.jsonl'),
      replayOnFirstRun: false,
      firstRunLookbackBytes: 0,
      maxLogSizeBytes: 50 * 1024 * 1024, // 50 MB
      // 评估队列积压上限：超出后新事件跳过评估、仅落盘。
      maxEvaluationBacklog: 1000,
      // 默认阻断名单唯一数据源是 spl.yaml metadata.flagRegistry
      // .hookBlockedFlags（构建期生成 generated-flag-defaults.ts）。
      blockedFlags: [...GENERATED_HOOK_BLOCKED_FLAGS],
      excludeCommandLines: [],
      excludeNetworkUrls: [],
      // 宿主自有内部 worker 的子进程事件（sqlite 只读子进程等）默认排除：
      // 实测 43 条 process_start 里 26 条属于这一类，占事件文件体积 17%。
      // 需要完整审计时置 false。
      excludeHostInternalProcesses: true,
      // 宿主自身的只读维护探针（lsof / systemctl / busctl / npm root -g /
      // git 工作区查询 …）默认排除：实测 1139 条 process_start 里约 560 条
      // 属于这一类，其中 lsof 一条命令重复 203 次，且 360 条带着
      // self_protection_bypass 误标。排除需要「无 agent 归属」+「命令逐字
      // 命中已知只读探针形态」两道闸门同时成立，带凭据的命令不受影响。
      // 需要完整审计时置 false。
      excludeHostInternalProbeCommands: true,
      // runtime 采集事件的单字段最大长度。1.1.0 之前 runtime hook 的
      // content 原样透传，不受 application.maxContentLength 约束。
      maxContentLength: 2000,
    },
  },
  network: {
    enabled: false,
    llmGateway: { enabled: false },
    mcpMiddleware: { enabled: false },
    dnsLogs: { enabled: false },
    flowLogs: { enabled: false },
  },
  system: {
    // Opt-in. Requires Python + psutil on the host. The bootstrap pipeline
    // probes `python3 -c "import psutil"`; when psutil is missing the layer is
    // disabled and the user sees a warning pointing at the install command.
    enabled: false,
    procfs: {
      enabled: false,
      pythonPath: 'python3',
      scanIntervalMs: 5000,
      snapshotIntervalMs: 0,
      burstScanEnabled: true,
      burstScanIntervalMs: 100,
      burstScanDurationMs: 3000,
      // Default to false to avoid scanning (and potentially killing) processes
      // outside the current OpenClaw tool-call tree. Only set to true after
      // explicit risk assessment and allowlisting.
      burstScanGlobal: false,
      processNames: ['openclaw', 'node', 'python', 'hermes'],
      excludeCommandLines: ['process_monitor.py'],
      collectOpenFiles: false,
      collectConnections: false,
      collectChildren: true,
      collectCpuPercent: false,
      changeDetectionFields: ['cmdline', 'cwd', 'process_status', 'ppid', 'exe_path'],
      memoryRssChangeThresholdBytes: 1024 * 1024, // 1 MB
      // autoKill is opt-in. When enabled, default riskFlags are intentionally
      // narrow to minimize false positives in production: only unmistakable
      // reverse-shell patterns and skill-shipped compiled binaries are killed.
      autoKill: false,
      riskFlags: ['reverse_shell', 'skill_binary_execution'],
      riskThreshold: 1.0,
      protectedPids: [],
      killSignal: 'SIGTERM',
    },
    cgroups: {
      enabled: false,
      scanIntervalMs: 5000,
      burstScanIntervalMs: 200,
      cpuChangeThresholdPercent: 5,
      memoryChangeThresholdPercent: 5,
      ioChangeThresholdBytes: 1024 * 1024,
      anomalyCpuSpikeThresholdPercent: 50,
      anomalyMemoryThresholdPercent: 80,
      fullFieldsInBurstOnly: true,
      heartbeatEnabled: false,
      aggregateWindowSeconds: 60,
    },
  },
  intervention: {
    enabled: true,
    // Default to enforce so the bundled policy (69 rules: self_protection /
    // data_leak_monitoring / intrusion_defense / behavior_guidance /
    // data_desensitization) actually blocks out of the box. Users who want
    // monitoring-only can switch this back to 'audit' from the Control UI's
    // Configuration view (or by editing ~/.openclaw/openclaw.json). The
    // bundled policy file also carries its own `mode: enforce` — both layers
    // now agree, so InterventionEngine takes the first matching block rule.
    mode: 'enforce',
    policyPath: path.join(homedir(), '.openclaw', 'security-policy.yaml'),
    reloadIntervalMs: 30000,
    decisionTimeoutMs: 50,
    // fail_closed: when the rule engine errors or times out, default to block
    // rather than allow. fail_open lets a single flaky rule temporarily disable
    // protection; fail_closed errs on the side
    // of safety. Operators who want permissive fallback can switch to
    // fail_open / fail_open_high_risk_only from the Control UI.
    failStrategy: 'fail_closed',
    reportBlockedEvents: true,
    highRiskFlags: ['reverse_shell', 'download_execute', 'mass_deletion', 'privilege_escalation', 'data_exfiltration', 'token_in_command'],
    guidance: {
      enabled: true,
      templatePaths: [path.join(homedir(), '.openclaw', 'guidance-templates')],
      defaultTemplateId: 'guidance.default',
      budgetThresholds: {
        low: 6,
        medium: 4,
        high: 3,
        critical: 1,
        extreme: 1,
      },
      stateTtlMs: 60 * 60 * 1000, // 1 hour
    },
    degrade: {
      enabled: true,
    },
  },
  assetMonitor: {
    enabled: true,
    scanIntervalMs: 300000, // 5 minutes
    fullSnapshotIntervalMs: 86400000, // 24 hours
    watchPaths: [],
    collectContent: false,
    maxFileSizeBytes: 1024 * 1024, // 1 MB
    statePersistencePath: path.join(homedir(), '.openclaw', 'asset-state.json'),
    sensitiveKeyPatterns: ['token', 'key', 'secret', 'password', 'credential'],
    collectSkillPackage: true,
    collectConfigPackage: true,
    maxPackageBytes: 1024 * 1024, // 1 MB (ZIP size before encoding)
    maxPackageEntryBytes: 2 * 1024 * 1024, // 2 MB per file inside skill ZIPs
    packageEncoding: 'base64',
    skillPaths: [],
    mcpPaths: [],
  },
  bootstrap: {
    // Default-on: write host-side plugin-entry defaults on first boot so the
    // host UI hook policy reflects what this plugin actually subscribes to.
    // Opt out via `bootstrap.entryDefaults: false` for locked-down hosts.
    entryDefaults: true,
  },
};

const collectorSchema: Record<string, Rule> = {
  // ndjsonPath is expanded on the way in; always defaults to
  // ~/.openclaw/security-events.jsonl when the caller does not configure one.
  ndjsonPath: pth,
  maxFileSizeBytes: (v, d) => {
    if (v === undefined) return d;
    const n = Number(v);
    return Number.isFinite(n) ? Math.max(0, Math.min(1073741824, n)) : d;
  },
  // Clamp panel cache size to a sane window (100 .. 50000). Below 100 the
  // Event Stream / Policy Hits tabs become useless; above 50000 the heap
  // cost outweighs the marginal history.
  maxEventsInMemory: (v, d) => {
    if (v === undefined) return d;
    const n = Math.floor(Number(v));
    if (!Number.isFinite(n)) return d;
    return Math.max(100, Math.min(50000, n));
  },
};

function mergeCollectorConfig(input: Record<string, unknown> | undefined) {
  const defaults = DEFAULT_CONFIG.collector;
  return pick(input, defaults as unknown as Record<string, unknown>, collectorSchema) as unknown as SecurityMonitorConfig['collector'];
}

const applicationSchema: Record<string, Rule> = {
  enabled: bool,
  captureUserPrompt: bool,
  captureSystemPrompt: bool,
  captureAgentPlan: bool,
  captureCodeMode: bool,
  captureUserId: bool,
  captureReasoning: bool,
  userIdField: str,
  maxContentLength: (v, d) => {
    if (v === undefined) return d;
    const n = Number(v);
    return Number.isFinite(n) ? Math.max(100, Math.min(100000, n)) : d;
  },
  maxResultPreviewLength: num,
  maxRawParamsLength: num,
  maxCodeContentLength: num,
  sessionTtlMs: (v, d) => {
    if (v === undefined) return d;
    const n = Number(v);
    return Number.isFinite(n) ? Math.max(60000, Math.min(86400000, n)) : d;
  },
  maxPreviousActions: (v, d) => (v !== undefined ? Number(v) : d ?? 50),
  defaultAgentId: str,
  // 手改 openclaw.json 写进未收录的值时回落 auto，不让面板拿到非法语言。
  panelLocale: en(['auto', 'en', 'zh']),
};

function mergeApplicationConfig(input: Record<string, unknown> | undefined) {
  const defaults = DEFAULT_CONFIG.application!;
  const merged = pick(input, defaults as unknown as Record<string, unknown>, applicationSchema);
  return {
    ...merged,
    runtimeHooks: mergeRuntimeHooksConfig(input?.runtimeHooks as Record<string, unknown> | undefined),
  };
}

const runtimeHooksSchema: Record<string, Rule> = {
  enabled: bool,
  networkEnabled: bool,
  logPath: pth,
  replayOnFirstRun: bool,
  firstRunLookbackBytes: (v, d) => (v !== undefined ? Math.max(0, Number(v)) : d),
  maxLogSizeBytes: (v, d) => (v !== undefined ? Math.max(0, Number(v)) : d),
  maxEvaluationBacklog: (v, d) => (v !== undefined ? Math.max(0, Number(v)) : d),
  blockedFlags: arr,
  excludeCommandLines: arr,
  excludeNetworkUrls: arr,
  excludeHostInternalProcesses: bool,
  excludeHostInternalProbeCommands: bool,
  maxContentLength: (v, d) => (v !== undefined ? Math.max(0, Number(v)) : d),
};

function mergeRuntimeHooksConfig(input: Record<string, unknown> | undefined) {
  const defaults = DEFAULT_CONFIG.application!.runtimeHooks!;
  return pick(input, defaults as unknown as Record<string, unknown>, runtimeHooksSchema);
}

const llmGatewaySchema: Record<string, Rule> = {
  enabled: bool,
  listenPort: num,
  upstreamProviders: passthrough,
};
const mcpSchema: Record<string, Rule> = {
  enabled: bool,
  monitoredServers: arr,
};
const dnsLogsSchema: Record<string, Rule> = {
  enabled: bool,
  source: en(['dnstap', 'systemd-resolved', 'dnsmasq']),
};
const flowLogsSchema: Record<string, Rule> = {
  enabled: bool,
  provider: en(['aws', 'azure', 'gcp']),
};

function mergeNetworkConfig(input: Record<string, unknown> | undefined): NetworkLayerConfig {
  const defaults = DEFAULT_CONFIG.network!;
  const enabled = bool(input?.enabled, defaults.enabled) as boolean;
  return {
    enabled,
    llmGateway: pick(input?.llmGateway as Record<string, unknown> | undefined, defaults.llmGateway as unknown as Record<string, unknown>, llmGatewaySchema) as NetworkLayerConfig['llmGateway'],
    mcpMiddleware: pick(input?.mcpMiddleware as Record<string, unknown> | undefined, defaults.mcpMiddleware as unknown as Record<string, unknown>, mcpSchema) as NetworkLayerConfig['mcpMiddleware'],
    dnsLogs: pick(input?.dnsLogs as Record<string, unknown> | undefined, defaults.dnsLogs as unknown as Record<string, unknown>, dnsLogsSchema) as NetworkLayerConfig['dnsLogs'],
    flowLogs: pick(input?.flowLogs as Record<string, unknown> | undefined, defaults.flowLogs as unknown as Record<string, unknown>, flowLogsSchema) as NetworkLayerConfig['flowLogs'],
  };
}

const procfsSchema: Record<string, Rule> = {
  enabled: bool,
  pythonPath: str,
  scanIntervalMs: num,
  snapshotIntervalMs: num,
  burstScanEnabled: bool,
  burstScanIntervalMs: num,
  burstScanDurationMs: num,
  burstScanGlobal: bool,
  processNames: arr,
  excludeCommandLines: arr,
  collectOpenFiles: bool,
  collectConnections: bool,
  collectChildren: bool,
  collectCpuPercent: bool,
  changeDetectionFields: arr,
  memoryRssChangeThresholdBytes: num,
  autoKill: bool,
  riskFlags: arr,
  riskThreshold: num,
  protectedPids: (v, d) => (Array.isArray(v) ? v : d),
  killSignal: (v, d) => (v !== undefined ? v : d),
};

const cgroupsSchema: Record<string, Rule> = {
  enabled: bool,
  scanIntervalMs: num,
  burstScanIntervalMs: num,
  cpuChangeThresholdPercent: num,
  memoryChangeThresholdPercent: num,
  ioChangeThresholdBytes: num,
  anomalyCpuSpikeThresholdPercent: num,
  anomalyMemoryThresholdPercent: num,
  fullFieldsInBurstOnly: bool,
  heartbeatEnabled: bool,
  aggregateWindowSeconds: num,
};

function mergeSystemConfig(input: Record<string, unknown> | undefined): SystemLayerConfig {
  const defaults = DEFAULT_CONFIG.system!;
  return {
    enabled: bool(input?.enabled, defaults.enabled) as boolean,
    procfs: pick(input?.procfs as Record<string, unknown> | undefined, defaults.procfs as unknown as Record<string, unknown>, procfsSchema) as SystemLayerConfig['procfs'],
    cgroups: pick(input?.cgroups as Record<string, unknown> | undefined, defaults.cgroups as unknown as Record<string, unknown>, cgroupsSchema) as SystemLayerConfig['cgroups'],
  };
}

const interventionSchema: Record<string, Rule> = {
  enabled: bool,
  mode: en(['audit', 'enforce']),
  policyPath: pth,
  reloadIntervalMs: (v, d) => {
    if (v === undefined) return d;
    const n = Number(v);
    return Number.isFinite(n) ? Math.max(1000, Math.min(600000, n)) : d;
  },
  decisionTimeoutMs: num,
  failStrategy: en(['fail_open', 'fail_closed', 'fail_open_high_risk_only']),
  reportBlockedEvents: bool,
  highRiskFlags: arr,
};

function validFailStrategy(value: unknown, defaultValue: FailStrategy): FailStrategy {
  if (value === 'fail_open' || value === 'fail_closed' || value === 'fail_open_high_risk_only') {
    return value as FailStrategy;
  }
  return defaultValue;
}

function mergeInterventionConfig(input: Record<string, unknown> | undefined): InterventionConfig {
  const defaults = DEFAULT_CONFIG.intervention!;
  const merged = pick(input, defaults as unknown as Record<string, unknown>, {
    ...interventionSchema,
    // failStrategy needs cross-field validation; override the loose enum rule.
    failStrategy: (v, d) => validFailStrategy(v, d as FailStrategy),
  });
  return {
    ...(merged as unknown as InterventionConfig),
    guidance: mergeGuidanceConfig(input?.guidance as Record<string, unknown> | undefined) as InterventionConfig['guidance'],
    degrade: mergeDegradeConfig(input?.degrade as Record<string, unknown> | undefined) as InterventionConfig['degrade'],
  };
}

const guidanceSchema: Record<string, Rule> = {
  enabled: bool,
  templatePaths: (v, d) => {
    // templatePaths is an array of paths — drop empties, expand each.
    if (!Array.isArray(v) || v.length === 0) return d;
    const expanded = v
      .map((p) => expandPath(typeof p === 'string' ? p : undefined))
      .filter((p): p is string => typeof p === 'string');
    return expanded.length > 0 ? expanded : d;
  },
  defaultTemplateId: str,
  budgetThresholds: passthrough,
  stateTtlMs: num,
};

function mergeGuidanceConfig(input: Record<string, unknown> | undefined) {
  const defaults = DEFAULT_CONFIG.intervention!.guidance!;
  return pick(input, defaults as unknown as Record<string, unknown>, guidanceSchema);
}

const degradeSchema: Record<string, Rule> = {
  enabled: bool,
};

function mergeDegradeConfig(input: Record<string, unknown> | undefined) {
  const defaults = DEFAULT_CONFIG.intervention!.degrade!;
  return pick(input, defaults as unknown as Record<string, unknown>, degradeSchema);
}

const assetMonitorSchema: Record<string, Rule> = {
  enabled: bool,
  scanIntervalMs: (v, d) => {
    if (v === undefined) return d;
    const n = Number(v);
    return Number.isFinite(n) ? Math.max(10000, Math.min(3600000, n)) : d;
  },
  fullSnapshotIntervalMs: num,
  watchPaths: (v, d) => {
    // watchPaths is an array of files/dirs — drop empties, expand each.
    if (!Array.isArray(v) || v.length === 0) return d;
    const expanded = v
      .map((p) => expandPath(typeof p === 'string' ? p : undefined))
      .filter((p): p is string => typeof p === 'string');
    return expanded.length > 0 ? expanded : d;
  },
  collectContent: bool,
  maxFileSizeBytes: num,
  statePersistencePath: pth,
  sensitiveKeyPatterns: arr,
  collectSkillPackage: bool,
  collectConfigPackage: bool,
  maxPackageBytes: num,
  maxPackageEntryBytes: num,
  packageEncoding: en(['base64', 'hex']),
  skillPaths: (v, d) => {
    if (!Array.isArray(v) || v.length === 0) return d;
    const expanded = v
      .map((p) => expandPath(typeof p === 'string' ? p : undefined))
      .filter((p): p is string => typeof p === 'string');
    return expanded.length > 0 ? expanded : d;
  },
  mcpPaths: (v, d) => {
    if (!Array.isArray(v) || v.length === 0) return d;
    const expanded = v
      .map((p) => expandPath(typeof p === 'string' ? p : undefined))
      .filter((p): p is string => typeof p === 'string');
    return expanded.length > 0 ? expanded : d;
  },
};

function mergeAssetMonitorConfig(input: Record<string, unknown> | undefined): AssetMonitorConfig {
  const defaults = DEFAULT_CONFIG.assetMonitor!;
  return pick(input, defaults as unknown as Record<string, unknown>, assetMonitorSchema) as AssetMonitorConfig;
}

const bootstrapSchema: Record<string, Rule> = {
  entryDefaults: bool,
};

function mergeBootstrapConfig(input: Record<string, unknown> | undefined) {
  const defaults = DEFAULT_CONFIG.bootstrap!;
  return pick(input, defaults as unknown as Record<string, unknown>, bootstrapSchema);
}

export function normalizeConfig(input: Record<string, unknown>): SecurityMonitorConfig {
  const collector = mergeCollectorConfig(input.collector as Record<string, unknown> | undefined);
  const application = mergeApplicationConfig(input.application as Record<string, unknown> | undefined);
  const environment = (input.environment as Record<string, unknown>) || {};

  return {
    collector,
    application,
    network: mergeNetworkConfig(input.network as Record<string, unknown> | undefined),
    system: mergeSystemConfig(input.system as Record<string, unknown> | undefined),
    intervention: mergeInterventionConfig(input.intervention as Record<string, unknown> | undefined),
    assetMonitor: mergeAssetMonitorConfig(input.assetMonitor as Record<string, unknown> | undefined),
    environment: {
      hostId: (environment.hostId as string) || getHostId(),
      containerId: (environment.containerId as string) || getContainerId(),
      podName: (environment.podName as string) || getPodName(),
      namespace: (environment.namespace as string) || getNamespace(),
    },
    bootstrap: mergeBootstrapConfig(input.bootstrap as Record<string, unknown> | undefined),
  };
}