// scripts/_smoke-fp-risk.test.mjs
// Smoke test for scripts/verify-fp-risk.mjs
//
// 运行： node scripts/_smoke-fp-risk.test.mjs
// 或：  npm test -- scripts/_smoke-fp-risk.test.mjs
//
// 验收点：
//   1. 默认自测可运行，输出含 6 大检查维度标签 + summary 行
//   2. --json 模式输出合法 JSON 且 summary 字段完整
//   3. --repo=<不存在路径> 返回 exit 2
//   4. --strict + 默认 threshold（5）下，≤4 🔴 → exit 0
//   5. --strict --threshold=4（CI 形态）exit 0
//   6. block 规则数 = 37（70 shipped - 30 non-block - 2 enabled:false - 1 演示 - 2 已降 warn）

import { execSync } from 'child_process';
import { strict as assert } from 'assert';

const SCRIPT = 'scripts/verify-fp-risk.mjs';
const ROOT = process.cwd();

function runScript(args) {
  try {
    const stdout = execSync(`node ${SCRIPT} ${args}`, { encoding: 'utf-8', cwd: ROOT });
    return { stdout, stderr: '', code: 0 };
  } catch (err) {
    return {
      stdout: err.stdout?.toString() || '',
      stderr: err.stderr?.toString() || '',
      code: err.status ?? 1,
    };
  }
}

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (e) {
    console.error(`  ✗ ${name}\n    ${e.message}`);
    failed++;
  }
}

console.log('=== verify-fp-risk.mjs smoke test ===\n');

// 1. 默认自测
test('默认自测含 summary + 三档分布', () => {
  const { stdout } = runScript('');
  assert.ok(stdout.includes('FP 风险评分报告'), '缺少报告标题');
  assert.ok(stdout.includes('🔴'), '缺少 🔴 标签');
  assert.ok(stdout.includes('🟠'), '缺少 🟠 标签');
  assert.ok(stdout.includes('🟢'), '缺少 🟢 标签');
  assert.ok(stdout.includes('🔴 高 FP 风险'), '缺少高风险节标题');
});

// 2. --json 模式
test('--json 模式输出合法 JSON + summary 字段完整', () => {
  const { stdout } = runScript('--json');
  const report = JSON.parse(stdout);
  assert.ok(report.repoPath, '缺少 repoPath');
  assert.ok(typeof report.threshold === 'number', 'threshold 非数字');
  assert.ok(report.summary, '缺少 summary');
  assert.ok(typeof report.summary.red === 'number', 'summary.red 非数字');
  assert.ok(typeof report.summary.orange === 'number', 'summary.orange 非数字');
  assert.ok(typeof report.summary.green === 'number', 'summary.green 非数字');
  assert.ok(Array.isArray(report.findings), 'findings 非数组');
});

// 3. --repo=<不存在路径> → exit 2
test('--repo=<不存在路径> → exit 2', () => {
  const { code, stderr } = runScript('--repo=/tmp/nonexistent.yaml');
  assert.equal(code, 2, `应 exit 2，实际 ${code}`);
  assert.ok(stderr.includes('策略文件不存在'), 'stderr 应含错误信息');
});

// 4. --strict + 默认 threshold → 4 🔴 ≤ 5 → exit 0
test('--strict 默认 threshold → exit 0（4 🔴 ≤ 5，误报收敛达成）', () => {
  const { code } = runScript('--strict');
  assert.equal(code, 0, `应 exit 0，实际 ${code}`);
});

// 5. --strict --threshold=4 → exit 0（CI 形态）
test('--strict --threshold=4 → exit 0（9→4 收敛后 CI 形态）', () => {
  const { code } = runScript('--strict --threshold=4');
  assert.equal(code, 0, `应 exit 0，实际 ${code}`);
});

// 6. block 规则数 = 37（70 shipped - 30 non-block - 2 enabled:false - 1 演示 - 2 已降 warn）
test('block 规则数 = 37（误报收敛后：70 shipped - 30 non-block - 2 enabled:false - 1 演示 - 2 已降 warn）', () => {
  const { stdout } = runScript('--json');
  const report = JSON.parse(stdout);
  assert.equal(report.summary.total, 37, `block 规则数应为 37，实际 ${report.summary.total}`);
});

// 7. 降 warn 的规则已不在 block 集合
test('#1 block-write-system-backdoor 已降 warn（不应在 block findings 中）', () => {
  const { stdout } = runScript('--json');
  const report = JSON.parse(stdout);
  const ids = report.findings.map((f) => f.id);
  assert.ok(!ids.includes('block-write-system-backdoor'), '降 warn 后不应出现在 block findings');
});

console.log(`\n=== ${passed} passed, ${failed} failed ===`);
if (failed > 0) process.exit(1);