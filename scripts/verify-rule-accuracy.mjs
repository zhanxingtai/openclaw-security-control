#!/usr/bin/env node
// scripts/verify-rule-accuracy.mjs
// shipped testCases 真实评估（per-rule precision/recall/F1/FP 率），audit 模式跑真引擎
// 与 verify-fp-risk.mjs（静态启发式）互补
//
// 阈值分档（FP 率）：
//   🔴 ≥ threshold（默认 0.5）— 必须收窄
//   🟠 0.3–threshold
//   🟢 < 0.3
//
// 用法：
//   node scripts/verify-rule-accuracy.mjs                          # 文本报告
//   node scripts/verify-rule-accuracy.mjs --json                    # JSON
//   node scripts/verify-rule-accuracy.mjs --strict --threshold=0.3 # CI 形态
//   node scripts/verify-rule-accuracy.mjs --repo=<path>             # 其他策略
//
// Exit: 0 通过 / 1 strict 失败 / 2 参数错误
// 依赖：dist/ 下的 InterventionEngineImpl，缺失先 `npm run build`

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { fileURLToPath, pathToFileURL } from 'url';
import { spawnSync } from 'child_process';
import { createRequire } from 'module';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '..');

// ---------- 参数解析 ----------
const args = process.argv.slice(2);
const opts = {
  strict: args.includes('--strict'),
  json: args.includes('--json'),
  repoPath: null,
  // FP 率 ≥ threshold 视为 🔴；默认 0.5（"半数负例被误伤"门槛）
  threshold: 0.5,
};
for (const arg of args) {
  if (arg.startsWith('--repo=')) opts.repoPath = arg.slice('--repo='.length);
  if (arg.startsWith('--threshold=')) {
    const v = Number(arg.slice('--threshold='.length));
    if (!Number.isFinite(v) || v < 0 || v > 1) {
      console.error(`FAIL: --threshold 须为 [0,1] 浮点: ${arg}`);
      process.exit(2);
    }
    opts.threshold = v;
  }
}

const REPO_DEFAULT = path.join(rootDir, 'policies', 'security-policy.spl.yaml');
const repoPath = opts.repoPath || REPO_DEFAULT;
if (!fs.existsSync(repoPath)) {
  console.error(`FAIL: 策略文件不存在: ${repoPath}`);
  process.exit(2);
}

// ---------- 引擎加载 ----------
const engineEntry = path.join(rootDir, 'dist', 'src', 'intervention', 'InterventionEngine.js');
if (!fs.existsSync(engineEntry)) {
  console.error(`FAIL: dist/${path.basename(engineEntry)} 缺失，请先 \`npm run build\` 生成 dist/`);
  process.exit(2);
}

// 引擎/RuleLoader 内部用 console.log 输出诊断（`[RuleLoader] loaded ...`、
// `[InterventionEngine] rule matched: ...`），每次评估都打。报告 stdout 必须
// 干净：从加载阶段起静音 console.log，--json 模式下仅在最后一刻直接
// process.stdout.write 出 JSON；文本模式恢复 console.log 后再打印报告。
const silentForEngine = opts.json;
const savedLog = console.log;
if (silentForEngine) console.log = () => {};

// 仅加载需要的接口（InterventionContext 类型在 .d.ts，运行时无影响）。
const { InterventionEngineImpl } = await import(pathToFileURL(engineEntry).href);

// ---------- 策略加载（独立 yaml 解析，仅取规则元数据；testCases 通过 engine 走） ----------
const require = createRequire(import.meta.url);
const yamlModule = (() => {
  try {
    return require('js-yaml');
  } catch {
    return require(path.join(rootDir, 'install', 'application', 'node_modules', 'js-yaml'));
  }
})();
function loadPolicy(p) {
  const parsed = yamlModule.load(fs.readFileSync(p, 'utf8'));
  if (!parsed || typeof parsed !== 'object') throw new Error('策略解析失败：非对象');
  if (!Array.isArray(parsed.rules)) throw new Error('策略解析失败：rules 字段不是数组');
  return parsed;
}
const policy = loadPolicy(repoPath);

// RuleLoader 沙箱仅允许 ~/.openclaw 与 os.tmpdir()：复制策略到临时目录加载。
const policyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'verify-rule-accuracy-'));
fs.copyFileSync(repoPath, path.join(policyDir, 'policy.yaml'));
process.on('exit', () => fs.rmSync(policyDir, { recursive: true, force: true }));

// audit 模式不短路：一次评估采集全部命中规则，否则 block 规则命中后
// 短路后续规则看不到，造成误报统计偏差。
const engine = new InterventionEngineImpl({
  mode: 'audit',
  ruleLoader: { policyPath: path.join(policyDir, 'policy.yaml'), reloadIntervalMs: 0 },
  guidance: { enabled: false }, // 测试场景不需要会话级预算干预
});
await engine.initialize();

// ---------- per-rule 跑所有 testCases ----------
// "positive" / "negative" 定义：
//   - 该规则 action.decision = ruleExpected (e.g. 'block')
//   - testCase.expectedDecision === ruleExpected  → 用例是"正例"（希望被命中）
//   - testCase.expectedDecision === 'allow'       → 用例是"负例"（希望被放过）
//   - evaluateSync 返回非 'allow' (即任何被触发的 decision) → 规则视作"触发"
//   - 引擎层最终 decision 与 expectedDecision 是否一致以 engine.evaluateSync 输出为准
//
//   TP：正例 → 引擎实际命中（非 allow）
//   FN：正例 → 引擎实际放过（allow，漏报）
//   FP：负例 → 引擎实际命中（误报）
//   TN：负例 → 引擎实际放过（正确排除）

function isHit(decision) {
  // audit / modify / warn / block / escalate / substitute / context_adjust / degrade 都视作"规则触发"
  return decision && decision !== 'allow';
}

const perRule = [];
for (const rule of policy.rules) {
  if (rule.enabled === false) continue; // 占位 / 示例规则跳过
  const ruleExpected = rule.action?.decision;
  if (!ruleExpected) continue;
  const cases = rule.testCases || [];
  if (cases.length === 0) continue; // 无用例：不参与统计（与 policy-testcases 对齐）

  let tp = 0, fn = 0, fp = 0, tn = 0;
  let positives = 0, negatives = 0;
  let firstFailingCase = null;

  for (let i = 0; i < cases.length; i++) {
    const tc = cases[i];
    const expected = tc.expectedDecision;
    if (expected !== ruleExpected && expected !== 'allow') continue; // 既非正例也非负例 → 不计入
    const ctx = {
      ...(tc.input || {}),
      actionType: tc.input?.actionType || 'tool_call',
      sessionId: `tc:${rule.id}#${i}`,
    };
    const out = engine.evaluateSync(ctx);
    const predicted = out && out.decision;
    const hit = isHit(predicted);

    if (expected === ruleExpected) {
      positives++;
      if (hit) tp++;
      else {
        fn++;
        if (!firstFailingCase) firstFailingCase = { index: i, name: tc.name, expected, predicted, kind: 'FN' };
      }
    } else {
      // expected === 'allow'
      negatives++;
      if (hit) {
        fp++;
        if (!firstFailingCase) firstFailingCase = { index: i, name: tc.name, expected, predicted, kind: 'FP' };
      } else tn++;
    }
  }

  const precision = tp + fp === 0 ? null : tp / (tp + fp);
  const recall = tp + fn === 0 ? null : tp / (tp + fn);
  const f1 = precision == null || recall == null || (precision + recall) === 0
    ? null
    : (2 * precision * recall) / (precision + recall);
  // FP 率：负例里被误伤的比例 → 主要关切指标
  const fpRate = negatives === 0 ? null : fp / negatives;
  const fnRate = positives === 0 ? null : fn / positives;

  perRule.push({
    id: rule.id,
    severity: rule.severity || 'unknown',
    decision: ruleExpected,
    cases: cases.length,
    positives,
    negatives,
    tp, fp, fn, tn,
    precision, recall, f1,
    fpRate, fnRate,
    firstFailingCase,
  });
}

// 按 FP 率倒序（null 排最后，便于一眼看出"FP 率最高的是谁"）
perRule.sort((a, b) => {
  const ap = a.fpRate === null ? -1 : a.fpRate;
  const bp = b.fpRate === null ? -1 : b.fpRate;
  if (bp !== ap) return bp - ap;
  return a.id.localeCompare(b.id);
});

// FP 率分档
function bucket(rate) {
  if (rate == null) return 'untested'; // 无负例 → 无法度量 FP 率，单独桶
  if (rate >= opts.threshold) return 'red';
  if (rate >= 0.3) return 'orange';
  return 'green';
}
const bucketIcon = { red: '🔴', orange: '🟠', green: '🟢', untested: '⚪' };

const counts = { red: 0, orange: 0, green: 0, untested: 0 };
for (const r of perRule) counts[bucket(r.fpRate)]++;

const totals = perRule.reduce(
  (acc, r) => ({
    tp: acc.tp + r.tp, fp: acc.fp + r.fp, fn: acc.fn + r.fn, tn: acc.tn + r.tn,
    positives: acc.positives + r.positives, negatives: acc.negatives + r.negatives,
    cases: acc.cases + r.cases,
  }),
  { tp: 0, fp: 0, fn: 0, tn: 0, positives: 0, negatives: 0, cases: 0 },
);
const overallPrecision = totals.tp + totals.fp === 0 ? null : totals.tp / (totals.tp + totals.fp);
const overallRecall = totals.tp + totals.fn === 0 ? null : totals.tp / (totals.tp + totals.fn);
const overallF1 = overallPrecision == null || overallRecall == null || (overallPrecision + overallRecall) === 0
  ? null : (2 * overallPrecision * overallRecall) / (overallPrecision + overallRecall);
const overallFpRate = totals.negatives === 0 ? null : totals.fp / totals.negatives;

// ---------- 输出 ----------
if (opts.json) {
  const report = {
    repoPath,
    threshold: opts.threshold,
    summary: {
      rules: perRule.length,
      tp: totals.tp, fp: totals.fp, fn: totals.fn, tn: totals.tn,
      precision: overallPrecision, recall: overallRecall, f1: overallF1, fpRate: overallFpRate,
      buckets: counts,
    },
    rules: perRule,
  };
  // JSON 模式：直接 process.stdout.write 写 JSON，绕开静音的 console.log。
  process.stdout.write(JSON.stringify(report, null, 2) + '\n');
} else {
  // 文本模式：恢复 console.log，再打印人读报告
  console.log = savedLog;
  console.log('=== SPL 规则准确率 + 误报率报告（真引擎逐用例评估）===');
  console.log(`策略文件: ${repoPath}`);
  console.log(`FP 率 🔴 阈值: ${opts.threshold}（≥ ${opts.threshold} 视为 🔴）`);
  console.log(`参与评估规则数: ${perRule.length}`);
  console.log(`用例总数: ${totals.cases}（正 ${totals.positives} / 负 ${totals.negatives}）`);
  console.log(`全局: precision=${fmt(overallPrecision)}  recall=${fmt(overallRecall)}  F1=${fmt(overallF1)}  FP 率=${fmt(overallFpRate)}`);
  console.log(`分桶: ${counts.red} 🔴 / ${counts.orange} 🟠 / ${counts.green} 🟢 / ${counts.untested} ⚪\n`);

  console.log(`--- 🔴 极高误报率（FP 率 ≥ ${opts.threshold}）---`);
  printBucket(perRule, 'red', bucketIcon);

  console.log(`\n--- 🟠 较高误报率（FP 率 0.3–${opts.threshold}）---`);
  printBucket(perRule, 'orange', bucketIcon);

  console.log(`\n--- 🟢 低误报率（FP 率 < 0.3）---`);
  printBucket(perRule, 'green', bucketIcon);

  console.log(`\n--- ⚪ 无负例无法度量 FP 率（需要补负例 testCase 才能评估）---`);
  printBucket(perRule, 'untested', bucketIcon);
}

if (opts.strict && counts.red > 0) {
  console.error(`\nFAIL: 🔴 规则 ${counts.red} 条 > 0（FP 率 ≥ ${opts.threshold}，--strict CI 阻断）`);
  process.exit(1);
}

// ---------- helpers ----------
function fmt(v) {
  return v === null || v === undefined ? 'N/A' : v.toFixed(3);
}
function printBucket(rules, key) {
  const items = rules.filter((r) => bucket(r.fpRate) === key);
  if (items.length === 0) { console.log('(无)'); return; }
  for (const r of items) {
    const icon = bucketIcon[key];
    console.log(`${icon} ${r.id}  decision=${r.decision}  severity=${r.severity}  用例 ${r.cases}（正 ${r.positives}/负 ${r.negatives}）`);
    console.log(`     precision=${fmt(r.precision)}  recall=${fmt(r.recall)}  F1=${fmt(r.f1)}  FP 率=${fmt(r.fpRate)}`);
    if (r.firstFailingCase) {
      console.log(`     首条失败用例: #${r.firstFailingCase.index} ${r.firstFailingCase.name || '(无 name)'} → ${r.firstFailingCase.kind}`);
    }
  }
}
