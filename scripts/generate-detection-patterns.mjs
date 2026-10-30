/* node scripts/generate-detection-patterns.mjs；shebang 删去以兼容 vitest dynamic import（node:vm 不接受 shebang 行）。 */
/**
 * OpenClaw Security Monitor - 检测模式产物生成器
 *
 * policies/security-policy.spl.yaml 是 runtime hook / process monitor /
 * SelfProtection 三层检测模式与三套默认处置名单的唯一数据源。本脚本在
 * 构建期（scripts/build.js 调用）收集并校验后生成四个产物：
 *
 *   - hooks/generated-patterns.json
 *       { flags: { <flag>: [{ pattern, flags?, input? }] }, blockedFlags }
 *   - monitor/generated-patterns.json
 *       { patterns: [{ flag, pattern, flags? }], autoKillFlags }
 *   - policies/generated/self-protection-patterns.generated.json
 *       x-openclaw-selfProtection 区原样结构化 { flags, groups, structural }
 *   - src/intervention/generated-flag-defaults.ts
 *       三套默认处置名单（hookBlockedFlags / monitorAutoKillFlags /
 *       engineHighRiskFlags），供 types.ts / store.ts / config.ts 引用
 *
 * 生成期校验（任一失败即非零退出，构建失败）：
 *   - flag 名 ⊆ 治理字典 enum（字典源在兄弟仓库 project_standards，跨仓库
 *     路径不可靠：源存在则刷新 vendor 副本 policies/risk-flags.json 并基于
 *     其校验；源不存在则 WARN 并沿用现有 vendor 副本）。
 *   - 所有 pattern 经 JS `new RegExp` 试编译；并经 python `re.compile`
 *     试编译（python 不可用时 WARN 跳过而非失败——构建环境可能无 python）。
 *   - 分层字段子集 lint：禁 `(?i` 内联标志（用条目/规则级 flags 字段）、
 *     禁 `(?<`（lookbehind/命名组）、禁 `\p{`（unicode 属性类）。
 *
 * 用法：
 *   node scripts/generate-detection-patterns.mjs          # 生成（漂移时覆盖）
 *   node scripts/generate-detection-patterns.mjs --check  # 只校验漂移，不写盘
 */

import { spawnSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import * as yaml from 'js-yaml';

const __filename = fileURLToPath(import.meta.url);
const ROOT = path.resolve(path.dirname(__filename), '..');

export const PATHS = {
  policy: path.join(ROOT, 'policies', 'security-policy.spl.yaml'),
  dictSource: path.resolve(ROOT, '..', 'project_standards', 'governance', 'dicts', 'risk-flags.json'),
  dictVendor: path.join(ROOT, 'policies', 'risk-flags.json'),
  hookOut: path.join(ROOT, 'hooks', 'generated-patterns.json'),
  monitorOut: path.join(ROOT, 'monitor', 'generated-patterns.json'),
  selfProtectionOut: path.join(ROOT, 'policies', 'generated', 'self-protection-patterns.generated.json'),
  flagDefaultsOut: path.join(ROOT, 'src', 'intervention', 'generated-flag-defaults.ts'),
};

const VALID_FLAGS = /^[ims]*$/;

/**
 * 当前分支允许纳入 vendor 字典的 flag `since` 上限。
 *
 * vendor 字典源按跨分支推进，会持续加入新 flag（如
 * semantic_token_diff / semantic_repl_allowlist_bypass / 等）。本分支
 * （目标版本 1.0.0）只接受
 * `since <= BRANCH_MAX_FLAG_SINCE` 的 flag，超过的主动过滤。
 *
 * 历史上曾因 vendor 同步把这些 flag 误带入发布分支而回退；
 * 此处用 semver 上限在 vendor 同步时主动过滤，避免每次跑构建都要手动
 * `git checkout HEAD -- policies/risk-flags.json`。
 *
 * 注意：阈值**不**从 package.json version 读（package.json 反映的是
 * 已发布的最近版本，不是本分支目标）。切换发布目标时改这里：
 *   - 目标 1.0.0 → "1.0.0"
 *   - 目标 1.1.0 → "1.1.0"
 */
const BRANCH_MAX_FLAG_SINCE = '1.0.0';

/** 简单 semver tuple 比较（仅够区分 0.9.7 / 1.0.0 / 1.1.0 类里程碑）。 */
function compareSemver(a, b) {
  const pa = String(a).split('.').map((n) => Number.parseInt(n, 10) || 0);
  const pb = String(b).split('.').map((n) => Number.parseInt(n, 10) || 0);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const na = pa[i] ?? 0;
    const nb = pb[i] ?? 0;
    if (na !== nb) return na - nb;
  }
  return 0;
}

/**
 * 字典源 → vendor 副本前按 `since` 过滤。返回
 * `{ dict, dropped }`：dict 是新对象（不 mutate 入参），dropped 是被
 * 过滤掉的 flag 名列表。过滤掉的 flag 同时从 registry 和 enum 列表
 * 移除，确保后续 validateFlagNames 不会因为源里有本分支不该用的 flag
 * 而失败。
 */
function filterDictForBranch(dict, maxSince) {
  if (!dict || typeof dict !== 'object') return { dict, dropped: [] };
  const registry = Array.isArray(dict.registry) ? dict.registry : [];
  const kept = [];
  const dropped = [];
  for (const entry of registry) {
    if (!entry || typeof entry.name !== 'string') {
      kept.push(entry);
      continue;
    }
    if (typeof entry.since === 'string' && compareSemver(entry.since, maxSince) > 0) {
      dropped.push(entry.name);
      continue;
    }
    kept.push(entry);
  }
  const enumArr = dict?.definitions?.flag_name?.enum;
  let filteredEnum;
  if (Array.isArray(enumArr)) {
    const droppedSet = new Set(dropped);
    filteredEnum = enumArr.filter((n) => !droppedSet.has(n));
  }
  return {
    dict: {
      ...dict,
      registry: kept,
      definitions: filteredEnum
        ? { ...(dict.definitions || {}), flag_name: { ...(dict.definitions?.flag_name || {}), enum: filteredEnum } }
        : dict.definitions,
    },
    dropped,
  };
}

export class GenerateError extends Error {}

function fail(message) {
  throw new GenerateError(message);
}

// 字典 vendor 同步与加载

/**
 * 刷新 vendor 字典副本（源存在时）并返回 { enum, deprecated, source }。
 * 源不存在时 WARN 并沿用现有 vendor 副本；两者都没有则失败。
 */
export function syncDict(paths = PATHS, warn = console.warn) {
  if (fs.existsSync(paths.dictSource)) {
    const { dict: filtered, dropped } = filterDictForBranch(JSON.parse(fs.readFileSync(paths.dictSource, 'utf8')), BRANCH_MAX_FLAG_SINCE);
    const filteredText = JSON.stringify(filtered, null, 2) + '\n';
    const prev = fs.existsSync(paths.dictVendor) ? fs.readFileSync(paths.dictVendor, 'utf8') : null;
    if (prev !== filteredText) {
      fs.writeFileSync(paths.dictVendor, filteredText);
      if (dropped.length > 0) {
        warn(
          `[generate-detection-patterns] refreshed vendor dict copy: ${path.relative(ROOT, paths.dictVendor)} ` +
            `(filtered ${dropped.length} flag(s) with since > ${BRANCH_MAX_FLAG_SINCE}: ${dropped.join(', ')})`
        );
      } else {
        warn(`[generate-detection-patterns] refreshed vendor dict copy: ${path.relative(ROOT, paths.dictVendor)}`);
      }
    }
  } else if (fs.existsSync(paths.dictVendor)) {
    warn(
      `[generate-detection-patterns] WARN: dict source ${paths.dictSource} not found; ` +
        'using existing vendor copy policies/risk-flags.json'
    );
  } else {
    fail(`risk flag dictionary unavailable: neither ${paths.dictSource} nor vendor copy ${paths.dictVendor} exists`);
  }
  const dict = JSON.parse(fs.readFileSync(paths.dictVendor, 'utf8'));
  const enumList = dict?.definitions?.flag_name?.enum;
  if (!Array.isArray(enumList) || enumList.length === 0) {
    fail('risk-flags.json missing definitions.flag_name.enum');
  }
  const deprecated = new Map();
  for (const entry of dict.registry || []) {
    if (entry && typeof entry.name === 'string' && entry.deprecated) {
      deprecated.set(entry.name, entry.deprecated);
    }
  }
  return { enum: new Set(enumList), deprecated, vendorPath: paths.dictVendor };
}

// 收集：顶层区段 + 规则级 hookPatterns / monitorPatterns 合并

function normalizeLayeredEntry(item, defaultFlags, where) {
  if (typeof item === 'string') {
    return defaultFlags ? { pattern: item, flags: defaultFlags } : { pattern: item };
  }
  if (item && typeof item === 'object' && !Array.isArray(item)) {
    if (typeof item.pattern !== 'string' || item.pattern.length === 0) {
      fail(`${where}: layered pattern entry missing non-empty "pattern" string`);
    }
    const entry = { pattern: item.pattern };
    const flags = item.flags !== undefined ? item.flags : defaultFlags;
    if (flags !== undefined) entry.flags = flags;
    if (item.input !== undefined) {
      if (item.input !== 'lowercased' && item.input !== 'raw') {
        fail(`${where}: invalid input ${JSON.stringify(item.input)} (allowed: lowercased|raw)`);
      }
      entry.input = item.input;
    }
    return entry;
  }
  fail(`${where}: unsupported layered pattern entry ${JSON.stringify(item)}`);
}

function mergeLayeredMap(target, source, defaultFlags, where) {
  if (source === undefined || source === null) return;
  if (typeof source !== 'object' || Array.isArray(source)) {
    fail(`${where}: expected a flag → patterns map`);
  }
  for (const [flag, list] of Object.entries(source)) {
    if (!Array.isArray(list) || list.length === 0) {
      fail(`${where}.${flag}: expected a non-empty array of patterns`);
    }
    const entries = list.map((item, i) => normalizeLayeredEntry(item, defaultFlags, `${where}.${flag}[${i}]`));
    target[flag] = [...(target[flag] || []), ...entries];
  }
}

function normalizeSelfProtection(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    fail('top-level x-openclaw-selfProtection: expected { flags?, groups, structural }');
  }
  const flags = raw.flags === undefined ? undefined : raw.flags;
  if (flags !== undefined && (typeof flags !== 'string' || !VALID_FLAGS.test(flags))) {
    fail(`x-openclaw-selfProtection.flags: invalid regex flags ${JSON.stringify(flags)} (allowed: i/m/s)`);
  }
  const groups = {};
  if (!raw.groups || typeof raw.groups !== 'object' || Array.isArray(raw.groups)) {
    fail('x-openclaw-selfProtection.groups: expected a group name → patterns map');
  }
  for (const [name, list] of Object.entries(raw.groups)) {
    if (!Array.isArray(list) || list.length === 0 || list.some((p) => typeof p !== 'string' || p.length === 0)) {
      fail(`x-openclaw-selfProtection.groups.${name}: expected a non-empty array of pattern strings`);
    }
    groups[name] = list;
  }
  const structural = {};
  if (!raw.structural || typeof raw.structural !== 'object' || Array.isArray(raw.structural)) {
    fail('x-openclaw-selfProtection.structural: expected a name → pattern map');
  }
  for (const [name, pattern] of Object.entries(raw.structural)) {
    if (typeof pattern !== 'string' || pattern.length === 0) {
      fail(`x-openclaw-selfProtection.structural.${name}: expected a non-empty pattern string`);
    }
    structural[name] = pattern;
  }
  return { ...(flags !== undefined ? { flags } : {}), groups, structural };
}

function normalizeFlagRegistry(raw, warn = console.warn) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    fail('metadata.flagRegistry: expected an object with the three default flag lists');
  }
  const out = {};
  for (const key of ['hookBlockedFlags', 'monitorAutoKillFlags', 'engineHighRiskFlags']) {
    const list = raw[key];
    if (!Array.isArray(list)) {
      fail(`metadata.flagRegistry.${key}: expected an array of flag names (use [] if the corresponding layer is intentionally disabled)`);
    }
    if (list.some((f) => typeof f !== 'string' || f.length === 0)) {
      fail(`metadata.flagRegistry.${key}: contains non-string or empty flag name`);
    }
    // 唯一数据源原则要求三套名单都必须声明（数组
    // 形态），但允许单侧为 [] 表示对应层未部署。仅在为空时 WARN，构建不阻断。
    // 注：hookBlockedFlags 的空数组不在此处 WARN——validateHookBlockedByEngine
    // 阶段会 fail-loud，避免与本处 "层未部署可显式留空" 的语义混淆。
    if (list.length === 0 && key !== 'hookBlockedFlags') {
      warn(`[generate-detection-patterns] WARN: metadata.flagRegistry.${key} is empty（单侧层未部署时可显式留空，但确保 audit 文档同步说明）`);
    }
    out[key] = list;
  }
  return out;
}

/**
 * hookBlockPatterns 归一化：条目 { pattern, reason?, input? }。
 * 同步阻断点不走 flag 名（治理字典源已冻结，新 flag 名走不通），
 * 只能走「不占 flag 名」的模式集（见 yaml 注释）。
 */
function normalizeBlockPatterns(raw) {
  if (raw === undefined || raw === null) return [];
  if (!Array.isArray(raw)) {
    fail('hookBlockPatterns: expected an array of { pattern, reason?, input? } entries');
  }
  return raw.map((item, i) => {
    const where = `hookBlockPatterns[${i}]`;
    if (typeof item === 'string') return { pattern: item };
    if (!item || typeof item !== 'object' || Array.isArray(item)) {
      fail(`${where}: expected a string or { pattern, reason?, input? } object`);
    }
    if (typeof item.pattern !== 'string' || item.pattern.length === 0) {
      fail(`${where}: missing non-empty "pattern" string`);
    }
    const entry = { pattern: item.pattern };
    if (item.reason !== undefined) {
      if (typeof item.reason !== 'string' || item.reason.length === 0) {
        fail(`${where}: invalid "reason" (expected a non-empty string)`);
      }
      entry.reason = item.reason;
    }
    if (item.input !== undefined) {
      if (item.input !== 'lowercased' && item.input !== 'raw') {
        fail(`${where}: invalid input ${JSON.stringify(item.input)} (allowed: lowercased|raw)`);
      }
      entry.input = item.input;
    }
    return entry;
  });
}

/**
 * 从解析后的策略对象收集全部待分发内容。顶层区段与规则级
 * hookPatterns/monitorPatterns（条目 flags 缺省继承规则级 flags）合并。
 */
export function collectFromPolicy(policy, warn = console.warn) {
  if (!policy || typeof policy !== 'object' || Array.isArray(policy)) {
    fail('policy file must be an object');
  }
  const hookFlags = {};
  const monitorFlags = {};
  mergeLayeredMap(hookFlags, policy.hookPatterns, undefined, 'hookPatterns');
  mergeLayeredMap(monitorFlags, policy.monitorPatterns, undefined, 'monitorPatterns');
  for (const [i, rule] of (policy.rules || []).entries()) {
    if (!rule || typeof rule !== 'object') continue;
    const ruleId = typeof rule.id === 'string' ? rule.id : `rule-${i}`;
    const ruleFlags = typeof rule.flags === 'string' ? rule.flags : undefined;
    if (ruleFlags !== undefined && !VALID_FLAGS.test(ruleFlags)) {
      fail(`rule ${ruleId} flags: invalid regex flags ${JSON.stringify(ruleFlags)} (allowed: i/m/s)`);
    }
    mergeLayeredMap(hookFlags, rule.hookPatterns, ruleFlags, `rule ${ruleId} hookPatterns`);
    mergeLayeredMap(monitorFlags, rule.monitorPatterns, ruleFlags, `rule ${ruleId} monitorPatterns`);
  }
  return {
    hookFlags,
    monitorFlags,
    // 运行时 hook 的同步阻断模式集（不占 flag 名）。
    blockPatterns: normalizeBlockPatterns(policy.hookBlockPatterns),
    // 项目扩展区段统一为 x- 前缀
    // （与 PolicyFile 类型声明 + SPLRuleLoader 读取保持一致）。
    selfProtection: normalizeSelfProtection(policy['x-openclaw-selfProtection']),
    flagRegistry: normalizeFlagRegistry(policy.metadata?.flagRegistry, warn),
  };
}

// 校验：flag 字典子集 / 子集 lint / 双侧编译

/** 分层字段子集 lint：内联 (?i 标志、(?< 与 \p{ 均属 JS/Python 非公共子集。 */
export function lintPatternSubset(pattern, where) {
  if (pattern.includes('(?i')) {
    fail(`${where}: inline "(?i" flag syntax is forbidden in layered patterns; use the entry/rule "flags" field instead: ${pattern}`);
  }
  if (pattern.includes('(?<')) {
    fail(`${where}: "(?<" (lookbehind / named group) is outside the JS/Python common subset: ${pattern}`);
  }
  if (pattern.includes('\\p{')) {
    fail(`${where}: "\\p{" unicode property classes are outside the JS/Python common subset: ${pattern}`);
  }
}

function validateFlagsField(flags, where) {
  if (flags !== undefined && (typeof flags !== 'string' || !VALID_FLAGS.test(flags))) {
    fail(`${where}: invalid regex flags ${JSON.stringify(flags)} (allowed: i/m/s)`);
  }
}

/** 校验单条分层条目：flags 合法性 + lint + JS 试编译。 */
export function validateLayeredEntry(entry, where) {
  validateFlagsField(entry.flags, where);
  lintPatternSubset(entry.pattern, where);
  try {
    new RegExp(entry.pattern, entry.flags || '');
  } catch (err) {
    fail(`${where}: pattern does not compile in JS: ${entry.pattern} (${err.message})`);
  }
}

function validateFlagNames(names, dictEnum, deprecated, where, warn) {
  for (const name of names) {
    if (!dictEnum.has(name)) {
      fail(`${where}: flag "${name}" is not in the risk-flags.json dictionary enum`);
    }
    if (deprecated.has(name)) {
      warn(`[generate-detection-patterns] WARN: ${where}: flag "${name}" is deprecated since ${deprecated.get(name)} in the dictionary`);
    }
  }
}

/** python re.compile 双侧校验；python 不可用时 WARN 跳过（返回 false）。 */
export function pythonCompileCheck(entries, warn = console.warn) {
  const payload = JSON.stringify(
    entries.map((e) => ({ where: e.where, pattern: e.pattern, flags: e.flags || '' }))
  );
  const script =
    'import json,re,sys\n' +
    'items=json.load(sys.stdin)\n' +
    'fmap={"i":re.IGNORECASE,"m":re.MULTILINE,"s":re.DOTALL}\n' +
    'bad=[]\n' +
    'for it in items:\n' +
    '    f=0\n' +
    '    for ch in it["flags"]: f|=fmap[ch]\n' +
    '    try: re.compile(it["pattern"],f)\n' +
    '    except Exception as ex: bad.append((it["where"],it["pattern"],str(ex)))\n' +
    'for w,p,m in bad: print(w+"\\t"+p+"\\t"+m)\n' +
    'sys.exit(1 if bad else 0)\n';
  for (const cmd of ['python', 'python3']) {
    const probe = spawnSync(cmd, ['--version'], { stdio: 'ignore' });
    if (probe.error || probe.status !== 0) continue;
    const res = spawnSync(cmd, ['-c', script], { input: payload, encoding: 'utf8' });
    if (res.error) continue;
    if (res.status !== 0) {
      const lines = (res.stdout || '').trim().split('\n').filter(Boolean);
      fail(`python re.compile rejected ${lines.length} pattern(s):\n${lines.join('\n')}`);
    }
    return true;
  }
  warn('[generate-detection-patterns] WARN: python not available on this build host; skipping re.compile cross-check');
  return false;
}

// 产物渲染

export function renderHookArtifact(collected) {
  return {
    flags: collected.hookFlags,
    blockedFlags: collected.flagRegistry.hookBlockedFlags,
    // 运行时 hook 的同步阻断模式集（不占 flag 名）。缺失时 runtime.js 走
    // 内置兜底表——**两侧必须一致**，由 hooks/runtime.test.ts 的
    // 「兜底 vs 产物 一致性」用例守住。
    blockPatterns: collected.blockPatterns,
  };
}

export function renderMonitorArtifact(collected) {
  const patterns = [];
  for (const [flag, entries] of Object.entries(collected.monitorFlags)) {
    for (const entry of entries) {
      patterns.push(entry.flags ? { flag, pattern: entry.pattern, flags: entry.flags } : { flag, pattern: entry.pattern });
    }
  }
  return {
    patterns,
    autoKillFlags: collected.flagRegistry.monitorAutoKillFlags,
  };
}

export function renderSelfProtectionArtifact(collected) {
  return collected.selfProtection;
}

export function renderFlagDefaultsTs(collected) {
  const renderArray = (name, list) =>
    `export const ${name}: readonly string[] = [\n${list.map((f) => `  '${f}',`).join('\n')}\n];`;
  return (
    `// GENERATED FILE — 由 scripts/generate-detection-patterns.mjs 从\n` +
    `// policies/security-policy.spl.yaml 的 metadata.flagRegistry 生成（单源化产物）。\n` +
    `// 请勿手改；改动源请编辑 spl.yaml 后执行 npm run build:prod。\n` +
    `//\n` +
    `// 三套默认处置名单：\n` +
    `//   - GENERATED_HOOK_BLOCKED_FLAGS     → runtime hook 本地阻断（hooks/runtime.js\n` +
    `//     DEFAULT_BLOCKED_FLAGS 与 store.ts OPENCLAW_RUNTIME_BLOCKED_FLAGS 默认值）\n` +
    `//   - GENERATED_MONITOR_AUTOKILL_FLAGS → process monitor autokill 默认名单\n` +
    `//    （monitor/process_monitor.py DEFAULT_CONFIG.riskFlags）\n` +
    `//   - GENERATED_ENGINE_HIGH_RISK_FLAGS → 引擎 fail_open_high_risk_only 高危回退\n` +
    `//    （本目录 types.ts DEFAULT_HIGH_RISK_FLAGS）\n` +
    `\n` +
    `${renderArray('GENERATED_HOOK_BLOCKED_FLAGS', collected.flagRegistry.hookBlockedFlags)}\n` +
    `\n` +
    `${renderArray('GENERATED_MONITOR_AUTOKILL_FLAGS', collected.flagRegistry.monitorAutoKillFlags)}\n` +
    `\n` +
    `${renderArray('GENERATED_ENGINE_HIGH_RISK_FLAGS', collected.flagRegistry.engineHighRiskFlags)}\n`
  );
}

// 主流程

export function generateArtifacts(policy, dict, warn = console.warn) {
  const collected = collectFromPolicy(policy, warn);

  // flag 名 ⊆ 字典 enum（pattern 映射键 + 三套名单）。
  validateFlagNames(Object.keys(collected.hookFlags), dict.enum, dict.deprecated, 'hookPatterns', warn);
  validateFlagNames(Object.keys(collected.monitorFlags), dict.enum, dict.deprecated, 'monitorPatterns', warn);
  validateFlagNames(collected.flagRegistry.hookBlockedFlags, dict.enum, dict.deprecated, 'flagRegistry.hookBlockedFlags', warn);
  validateFlagNames(collected.flagRegistry.monitorAutoKillFlags, dict.enum, dict.deprecated, 'flagRegistry.monitorAutoKillFlags', warn);
  validateFlagNames(collected.flagRegistry.engineHighRiskFlags, dict.enum, dict.deprecated, 'flagRegistry.engineHighRiskFlags', warn);

  // 条目级校验 + JS 试编译。
  const pythonCandidates = [];
  for (const [flag, entries] of Object.entries(collected.hookFlags)) {
    for (const [i, entry] of entries.entries()) {
      const where = `hookPatterns.${flag}[${i}]`;
      validateLayeredEntry(entry, where);
      pythonCandidates.push({ where, pattern: entry.pattern, flags: entry.flags });
    }
  }
  for (const [flag, entries] of Object.entries(collected.monitorFlags)) {
    for (const [i, entry] of entries.entries()) {
      const where = `monitorPatterns.${flag}[${i}]`;
      validateLayeredEntry(entry, where);
      pythonCandidates.push({ where, pattern: entry.pattern, flags: entry.flags });
    }
  }
  // hookBlockPatterns：同步阻断模式集（不占 flag 名）——同样要过 JS 试编译与
  // python re.compile 双侧校验（阻断面比打标面更敏感，绝不能有方言差异）。
  for (const [i, entry] of collected.blockPatterns.entries()) {
    const where = `hookBlockPatterns[${i}]`;
    validateLayeredEntry(entry, where);
    pythonCandidates.push({ where, pattern: entry.pattern, flags: entry.flags });
  }
  const spFlags = collected.selfProtection.flags;
  validateFlagsField(spFlags, 'x-openclaw-selfProtection.flags');
  for (const [group, list] of Object.entries(collected.selfProtection.groups)) {
    for (const [i, pattern] of list.entries()) {
      const where = `x-openclaw-selfProtection.groups.${group}[${i}]`;
      validateLayeredEntry({ pattern, flags: spFlags }, where);
      pythonCandidates.push({ where, pattern, flags: spFlags });
    }
  }
  for (const [name, pattern] of Object.entries(collected.selfProtection.structural)) {
    const where = `x-openclaw-selfProtection.structural.${name}`;
    validateLayeredEntry({ pattern, flags: spFlags }, where);
    pythonCandidates.push({ where, pattern, flags: spFlags });
  }

  pythonCompileCheck(pythonCandidates, warn);

  // 跨校验：flagRegistry.hookBlockedFlags ⊆ 引擎 block 规则意图。
  // 即每个"hook 运行时阻断"的 flag 必须在 shipped 策略中存在至少一条
  // decision: block 且通过 riskFlagsAny/riskFlagsAll 消费该 flag 的规则——
  // 否则 hook 阻断后引擎层无消费路径，事件流只产审计无策略响应，构建期阻断。
  const consumedFlags = validateHookBlockedByEngine(
    collected.flagRegistry.hookBlockedFlags,
    policy.rules,
    warn
  );

  // monitorAutoKillFlags ⊆ monitorPatterns 键集（autokill
  // 必须有可触发的 monitor pattern）；engineHighRiskFlags 覆盖消费集合的
  // 检查以 WARN 形式给出（fail-open 兜底允许"暂无对应策略"语义）。
  validateMonitorAutoKillInMonitorPatterns(
    collected.flagRegistry.monitorAutoKillFlags,
    collected.monitorFlags,
    warn
  );
  warnEngineHighRiskCoverage(
    collected.flagRegistry.engineHighRiskFlags,
    consumedFlags,
    warn
  );

  return {
    hook: renderHookArtifact(collected),
    monitor: renderMonitorArtifact(collected),
    selfProtection: renderSelfProtectionArtifact(collected),
    flagDefaultsTs: renderFlagDefaultsTs(collected),
  };
}

/**
 * 校验 hookBlockedFlags 中每个 flag 至少被一条 engine block 规则消费。
 * 消费定义：规则 action.decision === 'block' 且 match.riskFlagsAny/All 包含该 flag。
 * 未消费的 flag 报错（构建失败）：运行时 hook 会阻断但引擎策略层无对应 block 规则，
 * 阻断事件不进入决策流。monitorAutoKillFlags / engineHighRiskFlags 不在此校验内：
 * 前者作用于 python 端 sysmon 子进程 kill，不在策略层；后者是 fail-open 高危回退的
 * 默认面表，允许"暂无对应策略但兜底"。hookBlockedFlags 是阻断+硬阻断语义，
 * 缺消费路径会形成"阻断但无规则响应"的死水印，必须在构建期捕获。
 */
export function validateHookBlockedByEngine(hookBlockedFlags, rules, warn) {
  if (!Array.isArray(hookBlockedFlags)) {
    fail('validateHookBlockedByEngine: hookBlockedFlags must be an array');
  }
  // 空数组不可静默通过——运行期 runtime.js 会 fallback 到
  // 旧 FALLBACK_BLOCKED_FLAGS 形成静默降级，构造期必须 fail-loud。
  // （注意：与 "monitorAutoKillFlags/engineHighRiskFlags 可留空"
  // 不冲突——hook 是永远在线的 JS runtime hook，hookBlockedFlags 是阻断
  // 路径必填；monitor/engine 可选择性关闭。）
  if (hookBlockedFlags.length === 0) {
    fail(
      'flagRegistry.hookBlockedFlags 是空数组：构建期不得静默通过，' +
      '运行期 runtime.js 会 fallback 到旧 FALLBACK_BLOCKED_FLAGS 形成静默降级。' +
      '请补至少一条 hook 阻断的 flag（hookBlockedFlags ⊆ 引擎 block 规则意图）。'
    );
  }
  if (!Array.isArray(rules)) {
    fail('validateHookBlockedByEngine: rules must be an array');
  }
  // 收集引擎层 block 规则消费的 flag 集合（riskFlagsAny ∪ riskFlagsAll，按 block 决策过滤）。
  const consumedFlags = new Set();
  for (const rule of rules) {
    if (!rule || typeof rule !== 'object') continue;
    const decision = rule.action?.decision;
    if (decision !== 'block') continue;
    const match = rule.match || {};
    const any = Array.isArray(match.riskFlagsAny) ? match.riskFlagsAny : [];
    const all = Array.isArray(match.riskFlagsAll) ? match.riskFlagsAll : [];
    for (const f of [...any, ...all]) {
      if (typeof f === 'string' && f.length > 0) consumedFlags.add(f);
    }
  }
  const orphans = hookBlockedFlags.filter((f) => !consumedFlags.has(f));
  if (orphans.length > 0) {
    fail(
      `flagRegistry.hookBlockedFlags 中以下 flag 无引擎 block 规则消费（hook 会阻断但 ` +
        `引擎层无对应策略响应）：\n  ${orphans.join('\n  ')}\n` +
        `请补一条 decision: block 且 match.riskFlagsAny/All 包含该 flag 的规则，或从 ` +
        `hookBlockedFlags 移除。`
    );
  }
  return consumedFlags;
}

/**
 * 生成期校验 monitorAutoKillFlags ⊆ monitorPatterns 键集。
 * autokill 语义要求 monitor 层能识别该 flag；缺 monitorPatterns 条目
 * 等于 autokill 永不触发，构建期阻断。
 *
 * monitorAutoKillFlags 为空数组时跳过（允许层未部署）。
 */
export function validateMonitorAutoKillInMonitorPatterns(monitorAutoKillFlags, monitorFlags, warn) {
  if (!Array.isArray(monitorAutoKillFlags)) {
    fail('validateMonitorAutoKillInMonitorPatterns: monitorAutoKillFlags must be an array');
  }
  if (monitorAutoKillFlags.length === 0) return; // 层未部署可显式留空
  if (!monitorFlags || typeof monitorFlags !== 'object' || Array.isArray(monitorFlags)) {
    fail('validateMonitorAutoKillInMonitorPatterns: monitorFlags must be an object');
  }
  const monitorFlagKeys = new Set(Object.keys(monitorFlags));
  const orphans = monitorAutoKillFlags.filter((f) => !monitorFlagKeys.has(f));
  if (orphans.length > 0) {
    fail(
      `flagRegistry.monitorAutoKillFlags 中以下 flag 无对应 monitorPatterns 条目（autokill 永不触发）：\n` +
        `  ${orphans.join('\n  ')}\n` +
        `请补顶层 monitorPatterns.<flag> 或规则级 monitorPatterns.<flag> 条目，或从 monitorAutoKillFlags 移除。`
    );
  }
}

/**
 * engineHighRiskFlags 是 fail-open 高危回退名单，应至少
 * 覆盖引擎层消费的 flag 集合（防止某条新 block 规则用了新 flag 但未同步
 * 加入 engineHighRiskFlags，回退时漏判）。非阻断（warn only）——允许
 * "暂无对应策略但兜底" 是该名单的设计初衷，因此缺项仅提示。
 */
export function warnEngineHighRiskCoverage(engineHighRiskFlags, consumedFlags, warn) {
  if (!Array.isArray(engineHighRiskFlags)) {
    fail('warnEngineHighRiskCoverage: engineHighRiskFlags must be an array');
  }
  if (engineHighRiskFlags.length === 0) return; // 层未部署可显式留空
  if (!(consumedFlags instanceof Set)) {
    fail('warnEngineHighRiskCoverage: consumedFlags must be a Set');
  }
  const covered = new Set(engineHighRiskFlags);
  const uncovered = [...consumedFlags].filter((f) => !covered.has(f));
  if (uncovered.length > 0) {
    warn(
      `[generate-detection-patterns] WARN: engineHighRiskFlags 未覆盖以下被 block 规则消费的 flag：` +
        `fail-open 高危回退将漏判这些 flag：\n  ${uncovered.join('\n  ')}\n` +
        `请补入 engineHighRiskFlags 或显式说明豁免理由。`
    );
  }
}

function renderAll(paths = PATHS, warn = console.warn) {
  const dict = syncDict(paths, warn);
  const policy = yaml.load(fs.readFileSync(paths.policy, 'utf8'), { schema: yaml.JSON_SCHEMA });
  const artifacts = generateArtifacts(policy, dict, warn);
  return {
    [paths.hookOut]: JSON.stringify(artifacts.hook, null, 2) + '\n',
    [paths.monitorOut]: JSON.stringify(artifacts.monitor, null, 2) + '\n',
    [paths.selfProtectionOut]: JSON.stringify(artifacts.selfProtection, null, 2) + '\n',
    [paths.flagDefaultsOut]: artifacts.flagDefaultsTs,
  };
}

export function main(argv = process.argv.slice(2)) {
  const check = argv.includes('--check');
  const rendered = renderAll();
  let drifted = 0;
  for (const [file, content] of Object.entries(rendered)) {
    const prev = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : null;
    if (prev === content) continue;
    drifted += 1;
    if (check) {
      console.error(`[generate-detection-patterns] DRIFT: ${path.relative(ROOT, file)} is stale (run npm run build:prod)`);
    } else {
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.writeFileSync(file, content);
      console.log(`[generate-detection-patterns] wrote ${path.relative(ROOT, file)}`);
    }
  }
  if (check && drifted > 0) {
    throw new GenerateError(`${drifted} generated artifact(s) drifted from policies/security-policy.spl.yaml`);
  }
  if (!check && drifted === 0) {
    console.log('[generate-detection-patterns] all artifacts up to date');
  }
}

const invokedAsScript = process.argv[1] && path.resolve(process.argv[1]) === __filename;
if (invokedAsScript) {
  try {
    main();
  } catch (err) {
    console.error(`[generate-detection-patterns] FAILED: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  }
}
