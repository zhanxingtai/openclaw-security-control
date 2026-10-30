#!/usr/bin/env node
/**
 * verify-hook-env-contract.mjs —— hook 环境变量契约门禁
 *
 * 代码里新增的 env 变量文档没写、或文档里写了代码已不读的变量，都会让
 * 运维配出空转变量。本门禁把「代码 ⇄ 手册」口径固化成三条断言，缺一即红：
 *   A · 覆盖：代码里读的每个 `OPENCLAW_*` 变量 ⇒ 文档里必须出现；
 *   B · 不过度：文档里写的每个 `OPENCLAW_*` 变量 ⇒ 代码里必须真的读；
 *   C · 可达：手册必须被 `docs/operations/README.md` 索引（孤儿文档 = 没写）。
 *
 * 口径：只管 `OPENCLAW_*` 前缀（宿主系统变量不纳入）；代码侧扫
 * `process.env.<NAME>` 与 `readHookEnv('<NAME>')` 两种字面量形式；文档侧
 * 只认反引号包裹的变量名（正文散文不会误判，表格里写的会计上）。
 *
 * ⛔ 读不到代码或读不到文档 ⇒ `unavailable`（不是 `pass`）：不可采集 ≠ 通过。
 *
 * 用法：
 *   node scripts/verify-hook-env-contract.mjs           # 文本报告
 *   node scripts/verify-hook-env-contract.mjs --json    # JSON（供 L0 门禁封装）
 *   node scripts/verify-hook-env-contract.mjs --root=<dir>   # 对着夹具仓跑（回归测试用）
 *
 * Exit: 0 通过 / 1 有违反 / 2 环境错误（不可采集）
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const asJson = argv.includes('--json');
// `--root=<dir>`：让回归测试能对着临时夹具仓跑本门禁。
const rootArg = argv.find((a) => a.startsWith('--root='));
const rootDir = rootArg ? path.resolve(rootArg.slice('--root='.length)) : path.resolve(__dirname, '..');

/** 代码侧扫描的目标文件（两个 preload hook）。 */
const HOOK_FILES = ['hooks/runtime.js', 'hooks/network.js'];
/** 手册本体。 */
const DOC_FILE = 'docs/operations/hook-env.md';
/** 手册必须被它索引（否则是孤儿文档）。 */
const INDEX_FILE = 'docs/operations/README.md';

/**
 * 契约只覆盖 OpenClaw 自有前缀。尾部用 `(?![A-Z0-9_])` 收口（而不是
 * `[A-Z0-9_]+`）：否则文档里的通配写法 `OPENCLAW_RUNTIME_*` 和
 * `globalThis.__OPENCLAW_SECURITY_HOOK_ENV__` 都会被截断，误报成
 * 「文档写了代码没读的变量」。
 */
const NAME_RE = /OPENCLAW_[A-Z0-9_]*[A-Z0-9](?![A-Z0-9_])/g;

/** 代码里 env 读取的两种字面量形式。 */
const CODE_PATTERNS = [
  /process\.env\.(OPENCLAW_[A-Z0-9_]+)/g,
  /readHookEnv\(['"](OPENCLAW_[A-Z0-9_]+)['"]\)/g,
];

/**
 * 收集一组名字。
 * @param {string} text
 * @param {RegExp[]} patterns
 * @returns {Set<string>}
 */
function collect(text, patterns) {
  const out = new Set();
  for (const re of patterns) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text)) !== null) {
      if (m[1]) out.add(m[1]);
    }
  }
  return out;
}

/**
 * 文档侧只认**反引号包裹**的变量名。
 * @param {string} text
 * @returns {Set<string>}
 */
function collectDoc(text) {
  const out = new Set();
  const re = /`([^`\n]*)`/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    for (const name of m[1].match(NAME_RE) ?? []) out.add(name);
  }
  return out;
}

/** 读文件；读不到 ⇒ 返回 null（⇒ 不可采集，不是通过）。 */
function readOrNull(rel) {
  const abs = path.join(rootDir, rel);
  try {
    if (!fs.existsSync(abs)) return null;
    return fs.readFileSync(abs, 'utf8');
  } catch {
    return null;
  }
}

// 采集

const codeNames = new Set();
const missingFiles = [];
for (const rel of HOOK_FILES) {
  const text = readOrNull(rel);
  if (text === null) {
    missingFiles.push(rel);
    continue;
  }
  for (const name of collect(text, CODE_PATTERNS)) codeNames.add(name);
}

const docText = readOrNull(DOC_FILE);
const indexText = readOrNull(INDEX_FILE);

// ⛔ 采集不齐 ⇒ 不可采集（≠ 通过）
if (missingFiles.length || docText === null || indexText === null) {
  const reason = [
    missingFiles.length ? `读不到代码文件：${missingFiles.join('、')}` : null,
    docText === null ? `读不到手册：${DOC_FILE}` : null,
    indexText === null ? `读不到索引：${INDEX_FILE}` : null,
  ]
    .filter(Boolean)
    .join('；');
  const payload = { status: 'unavailable', reason, violations: [], summary: {} };
  if (asJson) {
    process.stdout.write(JSON.stringify(payload, null, 2) + '\n');
  } else {
    console.error(`⚪ 不可采集（≠ 通过）：${reason}`);
  }
  process.exit(2);
}

const docNames = collectDoc(docText);

/** A · 文档覆盖：代码读了但文档没写。 */
const undocumented = [...codeNames].filter((n) => !docNames.has(n)).sort();
/** B · 文档不过度：文档写了但代码没读。 */
const phantom = [...docNames].filter((n) => !codeNames.has(n)).sort();
/** C · 文档可达：手册是否被索引。 */
const docIndexed = indexText.includes('hook-env.md');

// 判定

const violations = [];
for (const n of undocumented) {
  violations.push(`代码读取了 \`${n}\` 但 ${DOC_FILE} 未记录 ⇒ 运维不知道它存在`);
}
for (const n of phantom) {
  violations.push(`${DOC_FILE} 记录了 \`${n}\` 但代码里没有读取 ⇒ 配了也空转`);
}
if (!docIndexed) {
  violations.push(`${DOC_FILE} 未被 ${INDEX_FILE} 索引 ⇒ 孤儿文档 = 等于没写`);
}

const status = violations.length ? 'fail' : 'pass';

const payload = {
  status,
  reason: violations.length ? `${violations.length} 项契约违反` : null,
  violations,
  summary: {
    codeVars: codeNames.size,
    docVars: docNames.size,
    undocumented: undocumented.length,
    phantom: phantom.length,
    docIndexed,
    codeVarList: [...codeNames].sort(),
  },
};

if (asJson) {
  process.stdout.write(JSON.stringify(payload, null, 2) + '\n');
} else {
  console.log('=== hook 环境变量契约（代码 ⇄ 手册）===');
  console.log(`代码读取：${codeNames.size} 个 · 手册记录：${docNames.size} 个`);
  if (status === 'pass') {
    console.log('✅ 双向一致（代码读的都有文档 · 文档写的都真在读）· 手册已被索引');
  } else {
    for (const v of violations) console.error(`  ↳ ${v}`);
    console.error(`\nFAIL: ${violations.length} 项契约违反`);
  }
}

process.exit(status === 'pass' ? 0 : 1);
