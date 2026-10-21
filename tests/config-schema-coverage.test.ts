import { describe, it, expect } from "vitest";
import { DEFAULT_CONFIG } from "../src/config.js";
import { CONFIG_SCHEMA } from "../index.js";

/**
 * Config 面板防脱节（验收硬项）。
 *
 * DEFAULT_CONFIG（src/config.ts）的每个叶子都必须满足其一：
 *   1. CONFIG_SCHEMA（index.ts）有对应条目 —— 面板可编辑、保存可校验；
 *   2. 在下方 JSON_ONLY_KEYS 白名单内 —— 有意不进 UI，手改 openclaw.json 仍生效。
 *
 * 新增 DEFAULT_CONFIG 叶子时：要么补 CONFIG_SCHEMA 条目，要么在白名单登记并
 * 注明理由；本测试禁止用源码文字匹配，只校验两条真实数据结构的映射关系。
 */

// 键 → 留在 JSON-only 的理由。分区注释说明该组不进 UI 的共同原因。
const JSON_ONLY_KEYS: Record<string, string> = {
  // ── application：截断 / 窗口类调优阈值，面板暴露只会诱导乱调 ──
  "application.maxResultPreviewLength": "结果预览截断阈值（调优参数）",
  "application.maxRawParamsLength": "raw_params 截断阈值（调优参数）",
  "application.maxCodeContentLength": "code_content 截断阈值（调优参数）",
  "application.maxPreviousActions": "previous_actions 历史窗口（调优参数）",
  "application.defaultAgentId": "默认 agent 归因回退值，仅特殊宿主需要（高级场景）",
  // ── application.runtimeHooks：事件落盘路径与 hook 行为细调，误配直接断流 ──
  "application.runtimeHooks.logPath": "runtime 事件落盘路径（路径类配置， JSON-only）",
  "application.runtimeHooks.replayOnFirstRun": "首次运行回放开关（排障场景专用）",
  "application.runtimeHooks.firstRunLookbackBytes": "回放回溯字节数（排障场景专用）",
  "application.runtimeHooks.maxLogSizeBytes": "runtime 日志轮转上限（调优参数）",
  "application.runtimeHooks.maxEvaluationBacklog": "评估队列积压上限（调优参数）",
  "application.runtimeHooks.blockedFlags": "拦截 flag 列表（策略数组，随策略文件演进）",
  "application.runtimeHooks.excludeCommandLines": "排除命令行模式（正则数组，误配漏采集）",
  "application.runtimeHooks.excludeNetworkUrls": "排除 URL 模式（正则数组，误配漏采集）",
  // ── network：整层未实现占位（network.enabled 不进 UI；其余子项亦为占位），
  //    网络拦截请走 Runtime Hooks ──
  "network.enabled": "网络层总开关未实现（占位，未来功能；手改 JSON 仍触发 dangerous 警告）",
  "network.llmGateway.enabled": "LLM 网关未实现（占位，未来功能）",
  "network.mcpMiddleware.enabled": "MCP 中间件未实现（占位，未来功能）",
  "network.dnsLogs.enabled": "DNS 日志未实现（占位，未来功能）",
  "network.flowLogs.enabled": "流日志未实现（占位，未来功能）",
  // ── system.procfs：采集细项 / 阈值，除 enabled/pythonPath/scanIntervalMs 外的
  //    开关均为开销或杀伤相关的调优项 ──
  "system.procfs.snapshotIntervalMs": "进程快照节流间隔（调优参数）",
  "system.procfs.burstScanEnabled": "突发扫描开关（调优参数）",
  "system.procfs.burstScanIntervalMs": "突发扫描间隔（调优参数）",
  "system.procfs.burstScanDurationMs": "突发扫描时长（调优参数）",
  "system.procfs.burstScanGlobal": "全局进程扫描，高危（DEFAULT_CONFIG 注释要求风险评估后仅手工开启）",
  "system.procfs.processNames": "进程名匹配列表（数组，误配漏采集）",
  "system.procfs.excludeCommandLines": "排除命令行模式（数组，误配漏采集）",
  "system.procfs.collectOpenFiles": "采集打开文件，高开销（调优参数）",
  "system.procfs.collectConnections": "采集网络连接，高开销（调优参数）",
  "system.procfs.collectChildren": "采集子进程树，开销相关（调优参数）",
  "system.procfs.collectCpuPercent": "采集 CPU 百分比，高开销（调优参数）",
  "system.procfs.changeDetectionFields": "变化检测字段集（数组，误配漏告警）",
  "system.procfs.memoryRssChangeThresholdBytes": "RSS 变化阈值（调优参数）",
  "system.procfs.autoKill": "进程杀伤开关，高危（JSON-only，需风险评估）",
  "system.procfs.riskFlags": "autoKill 配套 risk flag 列表（JSON-only，策略数组）",
  "system.procfs.riskThreshold": "risk 评分阈值（调优参数）",
  "system.procfs.protectedPids": "保护 PID 列表（数组，运维专用）",
  "system.procfs.killSignal": "杀伤信号选择（运维专用）",
  // ── system.cgroups：刚暴露 cgroups.enabled，指标层阈值均留 JSON ──
  "system.cgroups.scanIntervalMs": "cgroup 扫描间隔（调优参数）",
  "system.cgroups.burstScanIntervalMs": "cgroup 突发扫描间隔（调优参数）",
  "system.cgroups.cpuChangeThresholdPercent": "CPU 变化阈值（调优参数）",
  "system.cgroups.memoryChangeThresholdPercent": "内存变化阈值（调优参数）",
  "system.cgroups.ioChangeThresholdBytes": "IO 变化阈值（调优参数）",
  "system.cgroups.anomalyCpuSpikeThresholdPercent": "CPU 尖刺异常阈值（调优参数）",
  "system.cgroups.anomalyMemoryThresholdPercent": "内存异常阈值（调优参数）",
  "system.cgroups.fullFieldsInBurstOnly": "突发期全字段开关（调优参数）",
  "system.cgroups.heartbeatEnabled": "cgroup 心跳开关（调优参数）",
  "system.cgroups.aggregateWindowSeconds": "心跳聚合窗口（调优参数）",
  // ── intervention：策略数组 / 引导引擎细项 ──
  "intervention.highRiskFlags": "高危 flag 列表（策略数组，随策略文件演进）",
  "intervention.guidance.templatePaths": "引导模板路径数组（路径类配置）",
  "intervention.guidance.defaultTemplateId": "默认引导模板 ID（模板运维专用）",
  "intervention.guidance.budgetThresholds": "引导预算阈值对象（调优参数）",
  "intervention.guidance.stateTtlMs": "引导状态 TTL（调优参数）",
  "intervention.degrade.enabled": "degrade 能力开关（策略语义，JSON-only）",
  // ── assetMonitor：路径数组 / 打包阈值，误配直接影响采集面 ──
  "assetMonitor.fullSnapshotIntervalMs": "全量快照间隔（调优参数）",
  "assetMonitor.watchPaths": "监听路径数组（路径类配置，面板不适合编辑列表）",
  "assetMonitor.maxFileSizeBytes": "单文件采集上限（调优参数，超限文件按 truncated 跳过）",
  "assetMonitor.statePersistencePath": "采集状态文件路径（路径类配置）",
  "assetMonitor.sensitiveKeyPatterns": "敏感键模式数组（误配泄露或漏混淆）",
  "assetMonitor.maxPackageBytes": "ZIP 包大小上限（调优参数）",
  "assetMonitor.maxPackageEntryBytes": "ZIP 单文件上限（调优参数）",
  "assetMonitor.packageEncoding": "包编码枚举 base64/hex（运维专用）",
  "assetMonitor.skillPaths": "skill 根路径数组（路径类配置）",
  "assetMonitor.mcpPaths": "MCP 路径数组（路径类配置）",
};

/** 递归展开 DEFAULT_CONFIG 的全部叶子路径（数组按叶子计，不展开元素）。 */
function leafPaths(value: unknown, prefix: string, out: string[]): string[] {
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      leafPaths(v, prefix ? `${prefix}.${k}` : k, out);
    }
    return out;
  }
  out.push(prefix);
  return out;
}

/** 按点号路径读取嵌套值（schema section+key → DEFAULT_CONFIG 结构映射）。 */
function readPath(root: unknown, dotPath: string): unknown {
  let cur = root;
  for (const seg of dotPath.split(".")) {
    if (cur === null || typeof cur !== "object" || Array.isArray(cur)) return undefined;
    cur = (cur as Record<string, unknown>)[seg];
  }
  return cur;
}

describe("CONFIG_SCHEMA ↔ DEFAULT_CONFIG 防脱节", () => {
  const schemaPaths = new Set(CONFIG_SCHEMA.map((f) => `${f.section}.${f.key}`));
  const leaves = leafPaths(DEFAULT_CONFIG, "", []);
  // 白名单按前缀覆盖整棵子树（如 guidance.budgetThresholds 下的全部阈值叶子）。
  const whitelisted = (p: string): boolean =>
    p in JSON_ONLY_KEYS || Object.keys(JSON_ONLY_KEYS).some((k) => p.startsWith(k + "."));

  it("DEFAULT_CONFIG 非空且每个叶子都在 schema 或白名单内", () => {
    expect(leaves.length).toBeGreaterThan(30);
    const missing = leaves.filter((p) => !schemaPaths.has(p) && !whitelisted(p));
    expect(missing).toEqual([]);
  });

  it("白名单无冗余：白名单键不应出现在 schema（出现即应改从白名单移除）", () => {
    const redundant = Object.keys(JSON_ONLY_KEYS).filter((p) => schemaPaths.has(p));
    expect(redundant).toEqual([]);
  });

  it("schema 每个条目都对应 DEFAULT_CONFIG 的真实路径（防拼写漂移）", () => {
    const dangling = [...schemaPaths].filter((p) => readPath(DEFAULT_CONFIG, p) === undefined);
    expect(dangling).toEqual([]);
  });

  it("schema 条目类型与 DEFAULT_CONFIG 默认值类型一致", () => {
    const mismatches: string[] = [];
    for (const f of CONFIG_SCHEMA) {
      const dv = readPath(DEFAULT_CONFIG, `${f.section}.${f.key}`);
      if (dv === undefined || dv === null) continue;
      const t = typeof dv;
      const want =
        f.type === "bool" ? "boolean"
        : f.type === "number" ? "number"
        : "string"; // string / enum
      if (t !== want) mismatches.push(`${f.section}.${f.key}: schema=${f.type} default=${t}`);
    }
    expect(mismatches).toEqual([]);
  });

  it("hidden 字段仍保留服务端校验能力（min/max/bounds 不丢失）", () => {
    const hidden = CONFIG_SCHEMA.filter((f) => f.hidden);
    expect(hidden.map((f) => `${f.section}.${f.key}`)).toEqual(
      expect.arrayContaining([
        "collector.maxEventsInMemory",
        "application.sessionTtlMs",
        "application.maxContentLength",
        "intervention.reloadIntervalMs",
        "intervention.decisionTimeoutMs",
        "assetMonitor.scanIntervalMs",
      ])
    );
  });
});
