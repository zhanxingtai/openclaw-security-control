#!/usr/bin/env node
// scripts/verify-fp-risk.mjs
// FP 风险评分脚本 — openclaw shipped 策略的 8 维度启发式检测。
//
// 维度加分（1-8 项命中各 +1~2）：无 paramsNotRegex 白名单 / Tier-2 路径
// （.env/.npmrc/...）/ 用户路径（/tmp//home//root/）/ 常见命令（curl/ssh/...）/
// 配置文件（.bashrc/...）/ 自启动配置（autostart/systemd/crontab）/ 包安装 /
// testCases 正例 < 2。
//
// 分档：🔴 ≥ 5（必须降 warn / 加白名单）/ 🟠 3-4（评审豁免）/ 🟢 ≤ 2（保留 block）。
//
// 用法：默认自测 / --repo=<path> / --strict / --strict --threshold=6（CI 当前形态）/
// --json / --threshold=<n>。
// Exit code: 0 ≤ threshold；1 🔴 > threshold + --strict（CI 阻断）；2 参数错误。
//
// 阈值说明：默认 threshold=5，对应"🔴 ≥ 5 = 必须降 warn"；--strict 下
// 🔴 超阈值即 CI 阻断（exit 1）。

import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '..');

// ---------- 参数解析 ----------
const args = process.argv.slice(2);
const opts = {
  strict: args.includes('--strict'),
  json: args.includes('--json'),
  repoPath: null,
  threshold: 5,
};
for (const arg of args) {
  if (arg.startsWith('--repo=')) opts.repoPath = arg.slice('--repo='.length);
  if (arg.startsWith('--threshold=')) {
    const v = Number(arg.slice('--threshold='.length));
    if (!Number.isFinite(v) || v < 0) {
      console.error(`FAIL: --threshold 须为非负整数：${arg}`);
      process.exit(2);
    }
    opts.threshold = v;
  }
}

// ---------- 路径默认值 ----------
const REPO_DEFAULT = path.join(rootDir, 'policies', 'security-policy.spl.yaml');
const repoPath = opts.repoPath || REPO_DEFAULT;
if (!fs.existsSync(repoPath)) {
  console.error(`FAIL: 策略文件不存在: ${repoPath}`);
  process.exit(2);
}

// ---------- YAML 解析 ----------
const require = createRequire(import.meta.url);
const yamlModule = (() => {
  try {
    return require('js-yaml');
  } catch {
    return require(path.join(rootDir, 'install', 'application', 'node_modules', 'js-yaml'));
  }
})();

function loadPolicy(p) {
  const text = fs.readFileSync(p, 'utf-8');
  const parsed = yamlModule.load(text);
  if (!parsed || typeof parsed !== 'object') {
    throw new Error(`策略文件 ${p} 解析失败：非对象`);
  }
  if (!Array.isArray(parsed.rules)) {
    throw new Error(`策略文件 ${p} 解析失败：rules 字段不是数组`);
  }
  return parsed;
}

const policy = loadPolicy(repoPath);

// ---------- 评分维度 ----------
const DIMENSIONS = [
  {
    name: 'no-paramsNotRegex',
    label: '无 paramsNotRegex 白名单',
    weight: 2,
    test: (r) => r.action?.decision === 'block' && !hasAnyParamsNotRegex(r),
  },
  {
    name: 'tier2-path',
    label: '命中 Tier-2 路径（.env/.npmrc/.pypirc 等凭据/配置）',
    weight: 2,
    test: (r) => /(?:\.env|\.npmrc|\.pypirc|authorized_keys|known_hosts|\.aws|\.docker|\.netrc|git-credentials)/.test(concatMatch(r)),
  },
  {
    name: 'user-path',
    label: '命中用户路径（/tmp//home//root/）',
    weight: 1,
    test: (r) => /\/(?:tmp|home|root)\b/.test(concatMatch(r)),
  },
  {
    name: 'common-cmd',
    label: '命中常见命令（curl/wget/ssh/npm install/pip install）',
    weight: 1,
    test: (r) => /\b(?:curl|wget|ssh|npm install|pip install)\b/.test(concatMatch(r)),
  },
  {
    name: 'config-file',
    label: '命中配置文件（.bashrc/.zshrc/.profile）',
    weight: 1,
    test: (r) => /\.(?:bashrc|zshrc|profile|bash_profile|bash_login)\b/.test(concatMatch(r)),
  },
  {
    name: 'autostart',
    label: '命中自启动配置（autostart/systemd/crontab）',
    weight: 1,
    test: (r) => /(?:\.config\/systemd|\.config\/autostart|crontab|\/etc\/(?:cron|systemd)|systemctl\s+--user\s+(?:enable|start|disable|mask|preset))/.test(concatMatch(r)),
  },
  {
    name: 'pkg-install',
    label: '命中包安装命令',
    weight: 1,
    test: (r) => /\b(?:pip|npm|yarn|pnpm|apt|apk|yum|dnf)\s+(?:install|add)\b/.test(concatMatch(r)),
  },
  {
    name: 'few-positives',
    label: 'testCases 正例 < 2 条',
    weight: 1,
    test: (r) => countPositives(r) < 2,
  },
];

// ---------- 工具函数 ----------
function hasAnyParamsNotRegex(rule) {
  const m = rule.match || {};
  // paramsNotRegex 在 shipped 策略里以分维度的 object 形式出现（{path: [...], command: [...]}），
  // 也兼容 array 形态。只要任一维度下有 ≥1 条正则即视为"已加白名单"。
  const v = m.paramsNotRegex;
  if (Array.isArray(v)) return v.length > 0;
  if (v && typeof v === 'object') {
    return Object.values(v).some((dim) => Array.isArray(dim) && dim.length > 0);
  }
  return false;
}

function concatMatch(rule) {
  // 把 paramsRegex / paramsNotRegex / actionType 等所有匹配相关字段拼成单字符串用于正则检索
  const m = rule.match || {};
  const parts = [];
  const collect = (v) => {
    if (Array.isArray(v)) v.forEach(collect);
    else if (typeof v === 'string') parts.push(v);
    else if (v && typeof v === 'object') {
      for (const key of Object.keys(v)) collect(v[key]);
    }
  };
  collect(m);
  if (Array.isArray(rule.actionType)) parts.push(rule.actionType.join(' '));
  return parts.join('\n');
}

function countPositives(rule) {
  // 正例 = expectedDecision 与规则 decision 一致
  const decision = rule.action?.decision;
  if (!decision) return 0;
  return (rule.testCases || []).filter((tc) => tc.expectedDecision === decision).length;
}

function bucket(score) {
  if (score >= 5) return 'red';
  if (score >= 3) return 'orange';
  return 'green';
}

function bucketIcon(b) {
  return { red: '🔴', orange: '🟠', green: '🟢' }[b] || '⚪';
}

// ---------- 评分 ----------
const findings = [];
for (const rule of policy.rules) {
  if (rule.enabled === false) continue; // 占位规则豁免
  if (rule.action?.decision !== 'block') continue; // 仅评估 block 规则
  const dims = [];
  let score = 0;
  for (const dim of DIMENSIONS) {
    if (dim.test(rule)) {
      dims.push({ name: dim.name, label: dim.label, weight: dim.weight });
      score += dim.weight;
    }
  }
  findings.push({
    id: rule.id,
    severity: rule.severity || 'unknown',
    priority: rule.priority ?? 'unset',
    blockCode: rule.action?.blockCode || '(none)',
    score,
    bucket: bucket(score),
    dimensions: dims,
  });
}

// 按 score 降序，score 同则按 id 升序
findings.sort((a, b) => b.score - a.score || a.id.localeCompare(b.id));

const redCount = findings.filter((f) => f.bucket === 'red').length;
const orangeCount = findings.filter((f) => f.bucket === 'orange').length;
const greenCount = findings.filter((f) => f.bucket === 'green').length;

// ---------- 输出 ----------
if (opts.json) {
  const report = {
    repoPath,
    threshold: opts.threshold,
    summary: {
      total: findings.length,
      red: redCount,
      orange: orangeCount,
      green: greenCount,
    },
    findings,
  };
  console.log(JSON.stringify(report, null, 2));
} else {
  console.log(`=== FP 风险评分报告（6 维度启发式） ===`);
  console.log(`策略文件: ${repoPath}`);
  console.log(`🔴 阈值: ${opts.threshold}（≥${opts.threshold} 即视为 🔴）`);
  console.log(`规则总数（仅 block）: ${findings.length}`);
  console.log(`分布: ${redCount} 🔴 / ${orangeCount} 🟠 / ${greenCount} 🟢\n`);

  console.log(`--- 🔴 高 FP 风险（score ≥ ${opts.threshold}）---`);
  const reds = findings.filter((f) => f.bucket === 'red');
  if (reds.length === 0) {
    console.log('(无)');
  } else {
    for (const f of reds) {
      console.log(`${bucketIcon(f.bucket)} ${f.id}  score=${f.score}  severity=${f.severity}  priority=${f.priority}`);
      for (const d of f.dimensions) {
        console.log(`     +${d.weight} ${d.label}`);
      }
    }
  }

  console.log(`\n--- 🟠 中 FP 风险（score ${opts.threshold >= 4 ? '3' : '3-4'}）---`);
  const oranges = findings.filter((f) => f.bucket === 'orange');
  if (oranges.length === 0) {
    console.log('(无)');
  } else {
    for (const f of oranges) {
      console.log(`${bucketIcon(f.bucket)} ${f.id}  score=${f.score}  severity=${f.severity}`);
    }
  }

  console.log(`\n--- 🟢 低 FP 风险（score ≤ 2）---`);
  console.log(`(共 ${greenCount} 条，已收敛或天然窄口径)`);
}

if (opts.strict && redCount > opts.threshold) {
  console.error(`\nFAIL: 🔴 ${redCount} > threshold ${opts.threshold}（--strict CI 阻断）`);
  process.exit(1);
}