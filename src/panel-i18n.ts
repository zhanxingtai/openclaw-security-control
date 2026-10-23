/**
 * 面板文案词典。
 *
 * 面板此前把中文直接写死在 HTML / JS 里，`<html lang="en">` 名不副实，且存在
 * 同行中英拼接（`Last updated: … (paused — Config 有未保存改动)`）。本模块把
 * 面板的每一句可见文案收敛成一份平铺词典：默认 `en`，`?lang=zh` 或
 * `Accept-Language` 命中中文时用 `zh`。
 *
 * 三条不变量（tests/panel-i18n.test.ts 逐条钉住）：
 *   1. 两种 locale 的 key 集合完全相等，且没有空值——由 `Record<DictKey, string>`
 *      这一行类型在编译期强制，新增 en 键漏写 zh 会直接 tsc 失败。
 *   2. `en` 侧全词典零 CJK，保证英文面板在剥离 <script>/<style> 后也是纯英文。
 *   3. 词典未收录的值（后端新增 decision / severity / layer）回落到原始标识符，
 *      见 `RAW_FALLBACK_PREFIXES`——不得显示 `decision.degrade`，也不得显示空白。
 *
 * 词典按 `section.key` 索引 Config 页文案（`cfg.label.<section>.<key>` 等），
 * CONFIG_SCHEMA 里存的是这些键而非文案本身，避免同一句话在两处各存一份后漂移。
 */

/** 支持的 locale。白名单只有 en / zh，其余语言一律回落 en。 */
export const LOCALES = ["en", "zh"] as const;
export type Locale = (typeof LOCALES)[number];

/** 写入 `<html lang>` 的值。与实际渲染语言一致（验收硬项）。 */
export const HTML_LANG: Record<Locale, string> = { en: "en", zh: "zh-CN" };

/**
 * 未命中词典时的回落策略：这些命名空间的 key 后缀本身就是界面上要显示的
 * 标识符（decision=block、sev=high、layer=system、sec=assetMonitor…），剥掉前缀
 * 即可。用于后端新增枚举值 / 配置分组时的前向兼容——面板必须显示 `degrade`
 * 原文，而不是词典键或空白。
 */
export const RAW_FALLBACK_PREFIXES = ["decision.", "sev.", "layer.", "capsule.", "sec."] as const;

// ── en 词典（key 集合的唯一定义源）────────────────────────────────────
const EN = {
  // 文档骨架
  "header.subtitle": "OpenClaw {version} · auto-refresh 30s",
  "spinner.loading": "Loading...",

  // 标签页
  "tab.metrics": "Metrics",
  "tab.events": "Event Stream",
  "tab.blocks": "Policy Hits",
  "tab.config": "Config",

  // 指标卡
  "metric.totalEvents": "Total Events",
  "metric.last24h": "Last 24h",
  "metric.blocked": "Blocked",
  "metric.threatEvents": "Threat Events",
  "metric.byLayer": "By Layer",
  "metric.noData": "No data",

  // 表头
  "th.time": "Time",
  "th.type": "Type",
  "th.layer": "Layer",
  "th.severity": "Severity",
  "th.agent": "Agent",
  "th.toolSession": "Tool/Session",
  "th.status": "Status",
  "th.tool": "Tool",
  "th.decision": "Decision",
  "th.policy": "Policy",
  "th.reason": "Reason",

  // 分页
  "pager.loadMore": "Load more",
  "pager.endOfResults": "end of results",
  "pager.showing": "Showing {shown} of {total}{mark} {unit}",
  // Unit nouns are dictionary entries, not identifiers: the pager passes the
  // wire value ("events" / "hits") and pagerFooter() resolves it through T(),
  // so both locales keep the same {unit} placeholder.
  "pager.unit.events": "events",
  "pager.unit.hits": "hits",

  // 事件详情
  "jsonPane.title": "Event JSON",
  "detail.paused":
    "⏸ An event detail row is expanded, auto-refresh is paused (collapse it to resume)",

  // 复制按钮（事件 JSON 内联 + Config 的 Copy JSON 共用）
  "copy.idle": "Copy JSON",
  "copy.ok": "Copied to clipboard.",
  "copy.fail": "Copy failed.",
  "copy.configCopied": "Copied",
  "copy.configFailed": "Copy failed",
  "copy.configCopiedFallback": "Copied (redacted view)",

  // 事件类型工具条
  "events.allTypes": "All event types",
  "events.since": "since (minutes ago)",
  "events.apply": "Apply",
  "events.limit": "limit 50 per page",
  "events.empty": "No events yet",
  "events.truncated":
    "⚠ Only the most recent in-memory events are shown — the on-disk log exceeds the cache cap (older history is pruned from the search). Stats on the Metrics tab continue to reflect the full log.",

  // 徽标 / 筛选胶囊（仅 zh 中文化，en 保持原标识符）
  "decision.block": "block",
  "decision.warn": "warn",
  "decision.modify": "modify",
  "decision.audit": "audit",
  "sev.critical": "critical",
  "sev.extreme": "extreme",
  "sev.high": "high",
  "sev.medium": "medium",
  "sev.low": "low",
  "layer.application": "application",
  "layer.system": "system",
  "layer.asset": "asset",
  "capsule.all": "all",
  "capsule.block": "block",
  "capsule.warn": "warn",
  "capsule.modify": "modify",
  "capsule.audit": "audit",

  // Config 分组标题
  "sec.collector": "Collector",
  "sec.application": "Application",
  "sec.network": "Network",
  "sec.system": "System",
  "sec.intervention": "Intervention",
  "sec.assetMonitor": "Asset Monitor",
  "sec.bootstrap": "Bootstrap",

  // Config 工具条 / 表单
  "config.noConfig": "No config",
  "config.sourceHint":
    "Edit and click Save; takes effect after a gateway restart. Source: plugins.entries[id].config (DEFAULT_CONFIG × user openclaw.json)",
  "config.reset": "Discard changes",
  "config.resetTitle":
    "Drop local edits and reload the current config from the server (defaults are not restored)",
  "config.save": "Save",
  "config.on": "on",
  "config.off": "off",
  "config.dangerMark": "⚠ danger",
  "config.advanced": "Advanced ({n} tuning parameters, safe to leave alone) ▾",
  "config.itemCount": "({n} fields)",
  "config.depHint": "ⓘ Enable {deps} first",
  "config.depJoiner": " and ",
  "config.dirty": "● Unsaved changes, auto-refresh is paused (save or discard to resume)",

  // 危险确认弹窗
  "danger.title": "⚠ Confirm dangerous change",
  "danger.intro": "The following changes affect critical settings. Please confirm before saving:",
  "danger.confirmLabel": "I understand the impact of these changes and still want to save",
  "danger.cancel": "Cancel",
  "danger.ok": "Confirm and save",

  // 保存流程
  "save.saving": "Saving...",
  "save.saved": "Saved ✓",
  "save.noChanges": "No changes detected",
  "save.unknownError": "unknown error",
  "save.needsConfirm": "Needs confirmation: ",
  "save.failed": "Save failed: ",
  "save.rpcFailed": "RPC failed: ",

  // 保存后横幅
  "banner.savedTitle": "✓ Config written to disk",
  "banner.backup": "Backup: {path}",
  "banner.none": "none",
  "banner.restart": "⚠ Takes effect after a gateway restart",
  "banner.bootstrapTitle": "⚠ These items will be turned off automatically after a gateway restart",
  "banner.bootstrapReason":
    "Reason: the host environment does not meet the prerequisites (e.g. NODE_OPTIONS does not reference the runtime hook / Python lacks psutil)",
  "banner.bootstrapDiagLead": "Full diagnostics: the bootstrap complete line in the host OpenClaw log ",
  "banner.bootstrapDiagTail": " (for container deployments use <code>docker logs &lt;container&gt;</code>)",
  "banner.warningsTitle": "⚠ Config saved — please note the following",

  // 刷新状态行
  "refresh.updated": "Last updated: {time}",
  "refresh.pausedConfig": "(paused — Config has unsaved changes)",
  "refresh.pausedDetail": "(paused — close the expanded row to resume auto-refresh)",

  // 申诉标注
  "appeal.defaultHint":
    "This block can be reviewed with an administrator and the policy adjusted (see the event's intervention.remediation_hint)",

  // 持久状态条
  "status.hookNotLoaded":
    "⚠ Runtime hook is not active: the host NODE_OPTIONS does not preload the security hook, so runtime process/network protection is currently off (this is a silent downgrade, not an explicit opt-out). See application.runtimeHooks.enabled on the Config tab.",
  // 带路径变体：这条警告最常见的成因就是 NODE_OPTIONS 指了一条不存在的路径，
  // 而路径必须现读现算（容器里的 home 与宿主机 home 不是同一个），因此由
  // 后端 security.status 现算后经 {hookPath} 下发。拿不到路径时回落到上面
  // 那条无占位符的文案，避免面板把 {hookPath} 原样印出来。
  "status.hookNotLoadedWithPath":
    "⚠ Runtime hook is not active: the host NODE_OPTIONS does not preload the security hook, so runtime process/network protection is currently off (this is a silent downgrade, not an explicit opt-out).\nNODE_OPTIONS='--require {hookPath}'",

  // Metrics 页脚 / 完整面板按钮 / toast
  "footer.visitSite": "Visit Site",
  "footer.followWeChat": "Follow Us on WeChat",
  "fullView.title": "Open in new tab",
  "fullView.label": "↗ Full Panel",
  // 语言切换控件。语言名本身（EN / 中文）是 endonym，两种界面下完全一致、
  // 不进词典——只有控件的可访问名随界面语言变化。
  "lang.group": "Switch panel language",
  // 点了之后到真的刷新之间有半秒到几秒，按钮上得说清正在做什么。写成
  // "Saved" 会让人以为完事了、然后干等一个不会自己变的页面。
  "lang.switching": "Switching...",
  "toast.copied": "Link copied — paste it into a new tab",
  "toast.cannotOpen": "Could not open or copy automatically; please visit {url} manually",

  // 二维码弹窗 / noscript
  "qr.close": "Close",
  "qr.alt": "WeChat official account QR code",
  "qr.note": "Scan with WeChat to follow the official account",
  "noscript.lead":
    "The OpenClaw 9.4 Tab iframe does not run inline scripts, so the panel cannot render in this view. Please ",
  "noscript.link": "👉 open the full panel in a new tab",
  "noscript.tail": ".",

  "misc.unknownTab": "Unknown tab",

  // ── Config 字段文案（按 section.key 索引，CONFIG_SCHEMA 里存的就是这些键）──
  "cfg.label.collector.ndjsonPath": "Local NDJSON path",
  "cfg.label.collector.maxFileSizeBytes": "NDJSON file size cap (bytes)",
  "cfg.label.collector.maxEventsInMemory": "In-memory event cap",
  "cfg.label.application.enabled": "Enabled",
  "cfg.label.application.captureUserPrompt": "Capture user prompts",
  "cfg.label.application.captureSystemPrompt": "Capture system prompts",
  "cfg.label.application.captureAgentPlan": "Capture agent plans",
  "cfg.label.application.captureCodeMode": "Capture Code Mode",
  "cfg.label.application.captureReasoning": "Capture reasoning traces",
  "cfg.label.application.captureUserId": "Capture user ID",
  "cfg.label.application.userIdField": "User ID field name",
  "cfg.label.application.panelLocale": "Panel language",
  "cfg.label.application.maxContentLength": "Max length per field",
  "cfg.label.application.sessionTtlMs": "Session cache TTL (ms)",
  "cfg.label.application.runtimeHooks.enabled": "Enable Runtime Hooks",
  "cfg.label.application.runtimeHooks.networkEnabled": "Runtime Hooks · Enable network interception",
  "cfg.label.system.enabled": "Enabled",
  "cfg.label.system.procfs.enabled": "procfs collection",
  "cfg.label.system.cgroups.enabled": "cgroups metrics",
  "cfg.label.system.procfs.pythonPath": "Python path",
  "cfg.label.system.procfs.scanIntervalMs": "Scan interval (ms)",
  "cfg.label.intervention.enabled": "Enabled",
  "cfg.label.intervention.mode": "Mode",
  "cfg.label.intervention.failStrategy": "Failure strategy",
  "cfg.label.intervention.guidance.enabled": "Guided intervention",
  "cfg.label.intervention.reportBlockedEvents": "Report blocked events",
  "cfg.label.intervention.decisionTimeoutMs": "Decision timeout (ms)",
  "cfg.label.intervention.policyPath": "Policy file path",
  "cfg.label.intervention.reloadIntervalMs": "Policy reload interval (ms)",
  "cfg.label.assetMonitor.enabled": "Enabled",
  "cfg.label.assetMonitor.scanIntervalMs": "Scan interval (ms)",
  "cfg.label.assetMonitor.collectContent": "Collect file contents",
  "cfg.label.assetMonitor.collectSkillPackage": "Collect skill packages",
  "cfg.label.assetMonitor.collectConfigPackage": "Collect config packages",
  "cfg.label.bootstrap.entryDefaults": "Seed host defaults on startup",

  "cfg.danger.collector.ndjsonPath":
    "Changing the path creates the file at the new location on next start; the old file is not cleaned up automatically",
  "cfg.danger.collector.maxFileSizeBytes":
    "Lowering it rotates immediately, renaming the current file to .rotated; the sidecar SDK must tail .rotated too or events are lost",
  "cfg.danger.collector.maxEventsInMemory":
    "Lowering it hides older events from Event Stream / Policy Hits; raising it increases the panel's heap usage",
  "cfg.danger.application.userIdField":
    "Audit attribution field; a field name that does not exist empties user_id on every event and breaks compliance traceability",
  "cfg.danger.application.runtimeHooks.enabled":
    "Requires NODE_OPTIONS='--require <hook>' to take effect; without it no data is produced",
  "cfg.danger.system.enabled":
    "Requires python3 + psutil preinstalled on the host, otherwise startup fails and warns repeatedly",
  "cfg.danger.intervention.enabled":
    "Once off, no hook intercepts anything and the agent may run arbitrary tool calls",
  "cfg.danger.intervention.mode": "enforce really blocks; audit only records",
  "cfg.danger.intervention.failStrategy":
    "fail_closed rejects every unmatched operation when a rule times out",
  "cfg.danger.intervention.guidance.enabled":
    "Once off, guidance silently becomes a hard block",
  "cfg.danger.intervention.reportBlockedEvents":
    "Once off, no block record is visible in the panel or audit trail; traceability disappears entirely",
  "cfg.danger.intervention.policyPath":
    "If the path is unreadable or holds no rules, the plugin silently falls back to allow-all and all protection is lost",
  "cfg.danger.assetMonitor.enabled":
    "Once off, agent config / skill / MCP changes are no longer audited",
  "cfg.danger.assetMonitor.collectContent":
    "Uploads agent config file contents (sensitive fields are obfuscated)",
  "cfg.danger.assetMonitor.collectSkillPackage":
    "Increases event size; make sure downstream storage can take it",
  "cfg.danger.assetMonitor.collectConfigPackage":
    "Agent config files are packaged and reported with events (sensitive fields obfuscated)",

  "cfg.help.application.captureCodeMode": [
    "Captures the body of code executed through the code_mode_exec tool call (the event's code_content field).",
    "When off, code_mode events keep only metadata and carry no code content.",
  ].join("\n"),
  "cfg.help.application.captureUserId": [
    "Extracts the user ID from messages / tool metadata using the field named by userIdField, for audit attribution.",
    "When off, events no longer carry user_id.",
  ].join("\n"),
  "cfg.help.application.userIdField": [
    "Field name to read userId from in message events. OpenClaw 9.4 defaults to 'userId';",
    "on hosts that disagree the audit attribution comes out empty.",
  ].join("\n"),
  "cfg.help.application.panelLocale": [
    "auto: follow ?lang=, then Accept-Language, else English.",
    "en / zh: pin the panel to that language regardless of the browser.",
    "The header switcher does NOT write this key — it saves the choice in the",
    "plugin's own panel-state.json (writing this file restarts every plugin).",
    "So this key is the default for machines whose users never touch the switcher;",
    "?lang= in the URL still wins over both.",
  ].join("\n"),
  "cfg.help.application.runtimeHooks.enabled": [
    "Covers executions that never go through an agent tool call (process / network layer).",
    "",
    "Turn this on, then point NODE_OPTIONS at:",
    "",
    "  {preloadTarget}",
    "",
    "  # docker: -e NODE_OPTIONS='--require {preloadTarget}'",
    "  # host:   NODE_OPTIONS='--require {preloadTarget}'",
    "",
    "hook-mounter.js loads the other two and only warns if one is missing.",
    "",
    "⚠ The path must be absolute inside the runtime environment (a container's home depends on the image).",
    "⚠ After installing or upgrading, let the gateway start successfully once before pointing at it: the copy is written by a running gateway, and --require on a missing file stops the process.",
    "⚠ Restarting the gateway alone is not enough — rebuild the container or restart the host process. Verify: the log shows runtimeHookLoaded=true",
    "⚠ Gateway will not start and the log shows \"SyntaxError: Invalid or unexpected token\" pointing at hook-mounter.js → the preload copy is corrupt. Recovery: (1) drop the --require from NODE_OPTIONS and restart (the gateway comes up and the plugin rewrites the copy), (2) point NODE_OPTIONS back at the path above.",
  ].join("\n"),
  "cfg.help.application.runtimeHooks.networkEnabled": [
    "Defaults to true. Runtime Hooks intercept both child_process and fetch; turn this off when you",
    "want process interception only. 'Enable Runtime Hooks' must be on first. The change applies on the",
    "next gateway restart (it also applies when this process already loaded the network hook, so no",
    "container rebuild is needed).",
  ].join("\n"),
  "cfg.help.system.enabled": [
    "⚙ python3 + psutil>=5.9.0 must be preinstalled on the host before enabling.",
    'The plugin runs <pythonPath> -c "import psutil" at startup to probe; on failure this layer turns itself off.',
    "",
    "  # Debian / Ubuntu",
    "  apt-get install -y python3 python3-pip && python3 -m pip install 'psutil>=5.9.0'",
    "",
    "  # Alpine (slimmed-down container image)",
    "  apk add --no-cache python3 py3-pip && python3 -m pip install 'psutil>=5.9.0'",
    "",
    "  # RHEL / Fedora",
    "  dnf install -y python3 python3-pip && python3 -m pip install 'psutil>=5.9.0'",
    "",
    'Change system.procfs.pythonPath when python is not on the default path (default "python3").',
    "⚠ 'openclaw gateway restart' alone does not install a missing psutil; rebuild the image or add the system package.",
  ].join("\n"),
  "cfg.help.system.procfs.enabled": [
    "Read-only psutil process scanning; it kills nothing by default (autoKill is off).",
    "Requires python3 + psutil on the host; when the bootstrap probe finds them missing, this layer turns",
    "itself off and the save is reported with a warning.",
    "Once enabled and the gateway restarted, tool calls that spawn processes produce process_start /",
    "process_change / process_exit / process_snapshot events.",
  ].join("\n"),
  "cfg.help.system.cgroups.enabled": [
    "Read-only cgroup v1/v2 metrics (cpu / memory / blkio / pids); low overhead.",
    "Starts together with the process monitor. Once enabled and restarted it produces",
    "cgroup_snapshot / cgroup_anomaly events;",
    "steady-state heartbeats are governed by cgroups.heartbeatEnabled + cgroups.aggregateWindowSeconds.",
  ].join("\n"),
  "cfg.help.intervention.guidance.enabled": [
    "On a context_adjust rule hit, offer guidance first (adjust the scope / use an alternative operation)",
    "instead of blocking outright. ⚠ Turning this off turns guidance into a hard block",
    "(GUIDANCE_DISABLED), which tightens the policy — assess the false-positive impact before turning it off.",
  ].join("\n"),
  "cfg.help.intervention.reportBlockedEvents": [
    "Whether tool calls blocked by policy (block) are persisted as events. Blocking itself still takes",
    "effect when this is off, but Policy Hits / the event stream no longer show those block records.",
  ].join("\n"),
  "cfg.help.intervention.decisionTimeoutMs":
    "Reserved field: the evaluation core is fully synchronous, so the timeout branch never fires; it will be enabled after the async evaluation refactor.",
  "cfg.help.assetMonitor.collectSkillPackage": [
    "Scans the skill directory and attaches the ZIP package (base64) to asset events for downstream",
    "auditing and scanning; when off, only the file listing and fingerprints are reported.",
  ].join("\n"),
  "cfg.help.assetMonitor.collectConfigPackage": [
    "Packages the agent config files as a ZIP and reports them with events (the package holds the raw",
    "text; sensitive values in the parsed summary are obfuscated); when off, only the parsed summary is kept.",
  ].join("\n"),
} as const;

export type DictKey = keyof typeof EN;

// ── zh 词典（key 集合由类型强制与 en 完全一致）────────────────────────
const ZH: Record<DictKey, string> = {
  // 文档骨架
  "header.subtitle": "OpenClaw {version} · 自动刷新 30 秒",
  "spinner.loading": "加载中…",

  // 标签页
  "tab.metrics": "统计",
  "tab.events": "事件",
  "tab.blocks": "威胁",
  "tab.config": "配置",

  // 指标卡
  "metric.totalEvents": "事件总数",
  "metric.last24h": "近 24 小时",
  "metric.blocked": "已阻断",
  "metric.threatEvents": "威胁事件",
  "metric.byLayer": "按层级",
  "metric.noData": "暂无数据",

  // 表头
  "th.time": "时间",
  "th.type": "类型",
  "th.layer": "层级",
  "th.severity": "严重度",
  "th.agent": "智能体",
  "th.toolSession": "工具 / 会话",
  "th.status": "状态",
  "th.tool": "工具",
  "th.decision": "决策",
  "th.policy": "策略",
  "th.reason": "原因",

  // 分页
  "pager.loadMore": "加载更多",
  "pager.endOfResults": "已到末尾",
  "pager.showing": "已显示 {shown} / {total}{mark} {unit}",
  "pager.unit.events": "条",
  "pager.unit.hits": "次",

  // 事件详情
  "jsonPane.title": "事件 JSON",
  "detail.paused": "⏸ 有展开的事件详情，自动刷新已暂停（收起详情行后恢复）",

  // 复制按钮
  "copy.idle": "复制 JSON",
  "copy.ok": "已复制到剪贴板。",
  "copy.fail": "复制失败。",
  "copy.configCopied": "已复制",
  "copy.configFailed": "复制失败",
  "copy.configCopiedFallback": "已复制（脱敏视图）",

  // 事件类型工具条
  "events.allTypes": "全部事件类型",
  "events.since": "起始时间（分钟前）",
  "events.apply": "应用",
  "events.limit": "每页上限 50",
  "events.empty": "暂无事件",
  "events.truncated":
    "⚠ 仅显示内存中最近的事件——磁盘日志超出缓存上限（更早的历史已从检索中裁剪）。统计页的指标仍反映完整日志。",

  // 徽标 / 筛选胶囊
  "decision.block": "阻断",
  "decision.warn": "警告",
  "decision.modify": "修改",
  "decision.audit": "审计",
  "sev.critical": "严重",
  "sev.extreme": "极高",
  "sev.high": "高",
  "sev.medium": "中",
  "sev.low": "低",
  "layer.application": "应用层",
  "layer.system": "系统层",
  "layer.asset": "资产层",
  "capsule.all": "全部",
  "capsule.block": "阻断",
  "capsule.warn": "警告",
  "capsule.modify": "修改",
  "capsule.audit": "审计",

  // Config 分组标题
  "sec.collector": "采集器",
  "sec.application": "应用层",
  "sec.network": "网络",
  "sec.system": "系统",
  "sec.intervention": "干预",
  "sec.assetMonitor": "资产监控",
  "sec.bootstrap": "启动引导",

  // Config 工具条 / 表单
  "config.noConfig": "暂无配置",
  "config.sourceHint":
    "编辑后点击保存，重启 gateway 后生效。源: plugins.entries[id].config (DEFAULT_CONFIG × 用户 openclaw.json)",
  "config.reset": "撤销更改",
  "config.resetTitle": "丢弃本地编辑，重新从服务器加载当前配置（不会恢复默认值）",
  "config.save": "保存",
  "config.on": "开",
  "config.off": "关",
  "config.dangerMark": "⚠ 危险",
  "config.advanced": "高级（{n} 项调优参数，默认不必改动）▾",
  "config.itemCount": "（{n} 项）",
  "config.depHint": "ⓘ 需先启用 {deps}",
  "config.depJoiner": " 和 ",
  "config.dirty": "● 有未保存改动，自动刷新已暂停（保存或撤销更改后恢复）",

  // 危险确认弹窗
  "danger.title": "⚠ 危险操作确认",
  "danger.intro": "以下变更涉及关键参数，保存前请确认：",
  "danger.confirmLabel": "我已确认上述变更的影响，仍要保存",
  "danger.cancel": "取消",
  "danger.ok": "确认保存",

  // 保存流程
  "save.saving": "保存中...",
  "save.saved": "已保存 ✓",
  "save.noChanges": "没有检测到变更",
  "save.unknownError": "未知错误",
  "save.needsConfirm": "需要确认: ",
  "save.failed": "保存失败: ",
  "save.rpcFailed": "RPC 失败: ",

  // 保存后横幅
  "banner.savedTitle": "✓ 配置已写入磁盘",
  "banner.backup": "备份: {path}",
  "banner.none": "无",
  "banner.restart": "⚠ 需重启 gateway 后生效",
  "banner.bootstrapTitle": "⚠ 重启 gateway 后以下项会被自动关闭",
  "banner.bootstrapReason":
    "原因：宿主环境不满足前置条件（如 NODE_OPTIONS 未引用 runtime hook / Python 缺 psutil）",
  "banner.bootstrapDiagLead": "完整诊断：宿主 OpenClaw 日志中的 bootstrap complete 行",
  "banner.bootstrapDiagTail": "（容器部署用 <code>docker logs &lt;容器名&gt;</code> 查看）",
  "banner.warningsTitle": "⚠ 配置已保存，请注意以下提示",

  // 刷新状态行
  "refresh.updated": "最后更新：{time}",
  "refresh.pausedConfig": "(已暂停 — 配置页有未保存改动)",
  "refresh.pausedDetail": "(已暂停 — 关闭展开行后恢复刷新)",

  // 申诉标注
  "appeal.defaultHint": "该阻断可联系管理员复核并调整策略（见事件 intervention.remediation_hint）",

  // 持久状态条
  "status.hookNotLoaded":
    "⚠ Runtime hook 未生效：宿主 NODE_OPTIONS 未预加载安全 hook，运行时进程/网络防护当前不生效（配置未主动关闭，属静默降级）。详见 Config 页 application.runtimeHooks.enabled 说明。",
  // 带路径变体，路径由后端现算（见 en 侧同名键的注释）。
  "status.hookNotLoadedWithPath":
    "⚠ Runtime hook 未生效：宿主 NODE_OPTIONS 未预加载安全 hook，运行时进程/网络防护当前不生效（配置未主动关闭，属静默降级）。\nNODE_OPTIONS='--require {hookPath}'",

  // Metrics 页脚 / 完整面板按钮 / toast
  "footer.visitSite": "访问官网",
  "footer.followWeChat": "关注公众号",
  "fullView.title": "在新标签页打开",
  "fullView.label": "↗ 完整面板",
  "lang.group": "切换面板语言",
  "lang.switching": "切换中...",
  "toast.copied": "链接已复制，请粘贴到新标签页打开",
  "toast.cannotOpen": "无法自动打开或复制，请手动访问 {url}",

  // 二维码弹窗 / noscript
  "qr.close": "关闭",
  "qr.alt": "微信公众号二维码",
  "qr.note": "微信扫码，关注公众号",
  "noscript.lead": "OpenClaw 9.4 Tab iframe 不执行内联脚本，面板无法在此视图渲染。请",
  "noscript.link": "👉 在新标签页打开完整面板",
  "noscript.tail": "。",

  "misc.unknownTab": "未知标签页",

  // ── Config 字段文案（zh 侧保留原文，只补 en 侧的英文）──
  "cfg.label.collector.ndjsonPath": "本地 NDJSON 路径",
  "cfg.label.collector.maxFileSizeBytes": "NDJSON 文件大小上限 (bytes)",
  "cfg.label.collector.maxEventsInMemory": "面板内存事件数上限",
  "cfg.label.application.enabled": "启用",
  "cfg.label.application.captureUserPrompt": "捕获用户 Prompt",
  "cfg.label.application.captureSystemPrompt": "捕获系统 Prompt",
  "cfg.label.application.captureAgentPlan": "捕获 Agent Plan",
  "cfg.label.application.captureCodeMode": "捕获 Code Mode",
  "cfg.label.application.captureReasoning": "捕获推理过程",
  "cfg.label.application.captureUserId": "捕获用户 ID",
  "cfg.label.application.userIdField": "用户 ID 字段名",
  "cfg.label.application.panelLocale": "面板语言",
  "cfg.label.application.maxContentLength": "单字段最大长度",
  "cfg.label.application.sessionTtlMs": "会话缓存 TTL (ms)",
  "cfg.label.application.runtimeHooks.enabled": "启用 Runtime Hooks",
  "cfg.label.application.runtimeHooks.networkEnabled": "Runtime Hooks · 启用网络拦截",
  "cfg.label.system.enabled": "启用",
  "cfg.label.system.procfs.enabled": "procfs 采集",
  "cfg.label.system.cgroups.enabled": "cgroups 指标",
  "cfg.label.system.procfs.pythonPath": "Python 路径",
  "cfg.label.system.procfs.scanIntervalMs": "扫描间隔 (ms)",
  "cfg.label.intervention.enabled": "启用",
  "cfg.label.intervention.mode": "模式",
  "cfg.label.intervention.failStrategy": "失败策略",
  "cfg.label.intervention.guidance.enabled": "引导式干预",
  "cfg.label.intervention.reportBlockedEvents": "上报被拦截事件",
  "cfg.label.intervention.decisionTimeoutMs": "决策超时 (ms)",
  "cfg.label.intervention.policyPath": "策略文件路径",
  "cfg.label.intervention.reloadIntervalMs": "策略重载间隔 (ms)",
  "cfg.label.assetMonitor.enabled": "启用",
  "cfg.label.assetMonitor.scanIntervalMs": "扫描间隔 (ms)",
  "cfg.label.assetMonitor.collectContent": "收集文件内容",
  "cfg.label.assetMonitor.collectSkillPackage": "收集 Skill 安装包",
  "cfg.label.assetMonitor.collectConfigPackage": "收集配置文件包",
  "cfg.label.bootstrap.entryDefaults": "启动写入 host 默认值",

  "cfg.danger.collector.ndjsonPath": "改路径后下次启动会在新位置创建文件，旧路径文件不会被自动清理",
  "cfg.danger.collector.maxFileSizeBytes":
    "调小后会立刻触发 rotate，把当前文件改名 .rotated；sidecar SDK 必须同时 tail .rotated 才能不丢事件",
  "cfg.danger.collector.maxEventsInMemory":
    "调小会让 Event Stream / Policy Hits 看不到更早的事件；调大增加面板堆内存占用",
  "cfg.danger.application.userIdField":
    "审计归因字段，改成不存在的字段名会让所有事件 user_id 变空，影响合规追溯",
  "cfg.danger.application.runtimeHooks.enabled": "需 NODE_OPTIONS='--require <hook>' 才能生效，否则无数据",
  "cfg.danger.system.enabled": "需主机预装 python3 + psutil，否则启动失败并频繁告警",
  "cfg.danger.intervention.enabled": "关闭后所有 hook 不再拦截，agent 可执行任意工具调用",
  "cfg.danger.intervention.mode": "enforce 会真实拦截；audit 仅记录不拦截",
  "cfg.danger.intervention.failStrategy": "fail_closed 在规则超时时会拒绝所有未匹配操作",
  "cfg.danger.intervention.guidance.enabled": "关闭后引导变直接拦截，行为静默切换",
  "cfg.danger.intervention.reportBlockedEvents":
    "关闭后无法在面板/审计中查看任何拦截记录，审计追溯完全消失",
  "cfg.danger.intervention.policyPath":
    "若路径不可读或无规则文件，插件会静默回退到 allow-all，所有防护失效",
  "cfg.danger.assetMonitor.enabled": "关闭后 agent 配置 / skill / MCP 变更不再审计",
  "cfg.danger.assetMonitor.collectContent": "会上传 agent 配置文件内容（敏感字段已混淆）",
  "cfg.danger.assetMonitor.collectSkillPackage": "开启会增加事件体积，请确认下游存储可接受",
  "cfg.danger.assetMonitor.collectConfigPackage": "开启后 agent 配置文件原文会打包随事件上报（敏感字段已混淆）",

  "cfg.help.application.captureCodeMode":
    "捕获 code_mode_exec 工具调用的代码正文（事件 code_content 字段）；关闭后 code_mode 事件只保留元数据，不含代码内容。",
  "cfg.help.application.captureUserId":
    "按 userIdField 指定的字段名从消息 / 工具元数据提取用户 ID，用于审计归因；关闭后事件不再携带 user_id。",
  "cfg.help.application.userIdField":
    "从消息事件中取 userId 的字段名。OpenClaw 9.4 默认 'userId'；其他宿主若不一致会导致审计归因为空。",
  "cfg.help.application.panelLocale": [
    "auto：依次按 ?lang=、Accept-Language 协商，都没有则英文。",
    "en / zh：无视浏览器偏好，把面板钉死为该语言。",
    "面板右上角的切换控件写的不是这个键：它把选择存在插件自己的",
    "panel-state.json 里（写宿主 openclaw.json 会让 gateway 重载全部插件，",
    "一次语言切换要等 8 秒以上）。所以这个键是“没人碰过开关的机器”的默认值；",
    "URL 里的 ?lang= 仍然优先于两者。",
  ].join("\n"),
  "cfg.help.application.runtimeHooks.enabled": [
    "覆盖不经工具调用的执行（进程层 / 网络层）。",
    "",
    "打开本开关，然后把 NODE_OPTIONS 指向：",
    "",
    "  {preloadTarget}",
    "",
    "  # docker: -e NODE_OPTIONS='--require {preloadTarget}'",
    "  # 宿主机: NODE_OPTIONS='--require {preloadTarget}'",
    "",
    "hook-mounter.js 会加载另外两个，缺文件只告警。",
    "",
    "⚠ 路径须为运行环境内的绝对路径（容器内 home 取决于镜像）。",
    "⚠ 装/升级后先让 gateway 成功启动一次再指过去：副本由运行中的 gateway 写出，--require 一个不存在的文件会直接停掉进程。",
    "⚠ 仅重启 gateway 不生效，须重建容器 / 重启宿主进程。验证：日志出现 runtimeHookLoaded=true",
    "⚠ gateway 起不来、日志报 \"SyntaxError: Invalid or unexpected token\" 且指向 hook-mounter.js → 预加载副本坏了。恢复：① 先把 NODE_OPTIONS 里的 --require 去掉再重启（gateway 即可起来，插件会把副本重写好），② 再把 NODE_OPTIONS 指回上面的路径。",
  ].join("\n"),
  "cfg.help.application.runtimeHooks.networkEnabled":
    "默认 true。Runtime Hooks 同时拦截 child_process + fetch；只想要进程拦截、不想要网络拦截时关闭。必须先启用「启用 Runtime Hooks」。关闭/开启在 gateway 重启后生效（本进程已加载 network hook 的场景同样生效，无需重建容器）。",
  "cfg.help.system.enabled": [
    "⚙ 启用前需主机预装 python3 + psutil>=5.9.0。",
    'plugin 启动时执行 <pythonPath> -c "import psutil" 探测，失败则自动关闭本层。',
    "",
    "  # Debian / Ubuntu",
    "  apt-get install -y python3 python3-pip && python3 -m pip install 'psutil>=5.9.0'",
    "",
    "  # Alpine（容器精简镜像）",
    "  apk add --no-cache python3 py3-pip && python3 -m pip install 'psutil>=5.9.0'",
    "",
    "  # RHEL / Fedora",
    "  dnf install -y python3 python3-pip && python3 -m pip install 'psutil>=5.9.0'",
    "",
    'python 路径非默认时改 system.procfs.pythonPath（默认 "python3"）。',
    "⚠ 仅 openclaw gateway restart 不补 psutil 缺失，须重建镜像或装系统包。",
  ].join("\n"),
  "cfg.help.system.procfs.enabled": [
    "只读 psutil 进程扫描，默认不做任何杀伤（autoKill 默认关闭）。",
    "需主机 python3 + psutil；bootstrap 探测缺失时会自动关闭本层并在保存时提示。",
    "开启并重启 gateway 后，绑定的工具调用进程树会产生 process_start / ",
    "process_change / process_exit / process_snapshot 事件。",
  ].join("\n"),
  "cfg.help.system.cgroups.enabled": [
    "只读 cgroup v1/v2 指标（cpu / memory / blkio / pids），低开销。",
    "随 process monitor 一同启动，开启并重启后产生 cgroup_snapshot / cgroup_anomaly 事件；",
    "稳态心跳由 cgroups.heartbeatEnabled + cgroups.aggregateWindowSeconds 控制。",
  ].join("\n"),
  "cfg.help.intervention.guidance.enabled":
    "命中 context_adjust 规则时先给出引导建议（调整范围 / 替代操作），而不是直接阻断。⚠ 关闭 = 引导变直接拦截（GUIDANCE_DISABLED），属策略收紧，请评估误拦影响后再关。",
  "cfg.help.intervention.reportBlockedEvents":
    "被策略拦截（block）的工具调用是否落盘为事件。关闭后拦截本身仍生效，但面板 Policy Hits / 事件流不再显示这些拦截记录。",
  "cfg.help.intervention.decisionTimeoutMs":
    "保留字段：评估核心全同步，超时分支不生效；待后续异步评估重构后启用。",
  "cfg.help.assetMonitor.collectSkillPackage":
    "扫描 skill 目录并随 asset 事件附带 ZIP 包（base64），供下游审计与扫描；关闭后仅上报文件清单与指纹。",
  "cfg.help.assetMonitor.collectConfigPackage":
    "将 agent 配置文件打包为 ZIP 随事件上报（包内为原文，解析摘要中的敏感值已混淆）；关闭后仅保留解析摘要。",
};

// ── 对外接口 ─────────────────────────────────────────────────────────

export const PANEL_DICT: Record<Locale, Record<DictKey, string>> = { en: EN, zh: ZH };

/**
 * 词典未收录时的回落：枚举类命名空间剥掉前缀交出原始标识符，其余交出键本身。
 * 与面板 `<script>` 里的 `T()` 是同一套规则的两份实现（脚本跑在浏览器里，
 * import 不到本模块），tests/panel-i18n.test.ts 对全部键做逐键比对防止漂移。
 */
function rawFallback(key: string): string {
  for (const prefix of RAW_FALLBACK_PREFIXES) {
    if (key.startsWith(prefix)) return key.slice(prefix.length);
  }
  return key;
}

/** 服务端查表：用于写进面板模板静态 HTML 的那部分文案（标签页、noscript…）。 */
export function translate(locale: Locale, key: string, vars?: Record<string, unknown>): string {
  const raw: unknown = PANEL_DICT[locale][key as DictKey];
  let s = typeof raw === "string" && raw !== "" ? raw : rawFallback(key);
  if (!vars) return s;
  for (const name of Object.keys(vars)) s = s.split("{" + name + "}").join(String(vars[name]));
  return s;
}

/**
 * 把词典序列化成可直接内联进面板 `<script>` 的字面量。
 *
 * 只下发当前 locale 的词典（而非两套全量）：en 面板因此连 `<script>` 内部都不含
 * 一个中文字符，"零 CJK" 从一条需要豁免的验收口径升级为整页不变量。
 *
 * 序列化时把每个 `<` 转成它的 Unicode 转义：词典值里出现 `</script>` 会让 HTML 解析器提前
 * 终止脚本块，之后的内容会被当成正文渲染。反引号与 `${` 无需处理——本模块是独立
 * 源文件，index.ts 那边只有 `${serializeDictionary(...)}` 一段源码，运行时产物里
 * 的反引号不构成模板字符串终止（真正会炸的是直接写在 index.ts 面板模板里的字面量，
 * 那些必须一律改走词典）。
 */
export function serializeDictionary(locale: Locale): string {
  return JSON.stringify(PANEL_DICT[locale]).replace(/</g, "\\u003c");
}

/** 语言标签 → 受支持 locale。`zh-*` / `en-*` 折叠到白名单，其余不支持。 */
function normalizeTag(tag: string): Locale | undefined {
  const lower = tag.trim().toLowerCase();
  if (lower.startsWith("zh")) return "zh";
  if (lower.startsWith("en")) return "en";
  return undefined;
}

function readQueryParam(requestUrl: string | undefined, name: string): string | undefined {
  if (!requestUrl) return undefined;
  const q = requestUrl.indexOf("?");
  if (q < 0) return undefined;
  for (const part of requestUrl.slice(q + 1).split("&")) {
    const eq = part.indexOf("=");
    const rawName = eq < 0 ? part : part.slice(0, eq);
    if (decodeURIComponent(rawName) !== name) continue;
    return eq < 0 ? "" : decodeURIComponent(part.slice(eq + 1).replace(/\+/g, " "));
  }
  return undefined;
}

/**
 * 面板语言的持久化取值。`auto` 交回协商，显式 en/zh 则无视浏览器偏好把面板
 * 钉死。两个落盘处共用这一组取值：
 *   · `panel-state.json` 的 `panelLocale` —— 面板右上角切换控件写的（见
 *     index.ts 的 writePanelStateLocale：不写宿主配置，免得写一次就把整个插件
 *     栈换一遍血、一次切换要等 8 秒）；
 *   · 配置键 `application.panelLocale` —— 留给想给某台机器钉死语言的人，作为
 *     开关还没按过时（两边都是 auto）的默认值。
 */
export const PANEL_LOCALE_PREFERENCES = ["auto", "en", "zh"] as const;
export type PanelLocalePreference = (typeof PANEL_LOCALE_PREFERENCES)[number];

/** 把配置里的任意值收敛成合法偏好；未收录的值（含 undefined）一律当 auto。 */
export function normalizePanelLocalePreference(value: unknown): PanelLocalePreference {
  return typeof value === "string" && (PANEL_LOCALE_PREFERENCES as readonly string[]).includes(value)
    ? (value as PanelLocalePreference)
    : "auto";
}

/**
 * 解析面板 locale：查询参数 → 已保存的偏好 → Accept-Language → 默认 en。
 *
 * `?lang=` 一旦出现就独占决定权，**包括它给的是不支持的值**：此时直接回落 en
 * 而不是继续看 Accept-Language。否则一次显式的 `?lang=fr` 会被浏览器里残留的
 * `Accept-Language: zh` 悄悄救回来，行为反直觉。验收要求的「`?lang=fr` 得到英文
 * 面板」在两种实现下都成立，这里选语义更直的一种。
 *
 * savedPreference 是**已经合成过的一个**偏好值，不是两处落盘原样塞进来：
 * 合成发生在 index.ts 的 readSavedPanelLocale（开关的 panel-state.json 优先于
 * 配置键 application.panelLocale），本函数只负责"一个已保存的偏好 vs 浏览器"。
 * 它排在 Accept-Language 之前：它代表用户在本面板上的一次显式选择，比浏览器
 * 级别的语言偏好更具体。`auto` 不参与决策，等价于未设置。
 *
 * Accept-Language 按声明顺序扫描（浏览器本就按 q 降序发），跳过 `q=0`（显式
 * 不可接受）的条目。不做 q 值排序：q 乱序的 header 属病态输入，而排序会让本函数
 * 对同一个 header 的解析依赖全表扫描。
 */
export function parseLocale(
  requestUrl: string | undefined,
  acceptLanguage: string | undefined,
  savedPreference?: unknown,
): Locale {
  const explicit = readQueryParam(requestUrl, "lang");
  if (explicit !== undefined) return normalizeTag(explicit) ?? "en";

  const pinned = normalizePanelLocalePreference(savedPreference);
  if (pinned !== "auto") return pinned;

  for (const entry of (acceptLanguage ?? "").split(",")) {
    const [tag, ...params] = entry.split(";");
    const rejected = params.some((p) => {
      const t = p.trim().toLowerCase();
      return t.startsWith("q=") && Number.parseFloat(t.slice(2)) === 0;
    });
    if (rejected) continue;
    const hit = normalizeTag(tag ?? "");
    if (hit) return hit;
  }
  return "en";
}