/**
 * Version single-source-of-truth check.
 *
 * package.json#version 是唯一权威版本；其他副本（openclaw.plugin.json、
 * hooks/package.json、hooks/*.js `// openclaw-hook: vX.Y.Z` 头、
 * src/store.ts `readonly version`）必须与之对齐。scripts/build.js 在编译
 * 前跑此脚本，drift 即 fail；导出纯函数供 vitest 单测覆盖两种路径。
 */
import fs from 'fs';
import path from 'path';

/**
 * @typedef {{ label: string, value: string }} VersionCopy
 * @typedef {{ expected: string, copies: VersionCopy[] }} VersionAudit
 */

/**
 * @param {string} filePath
 * @returns {Record<string, unknown>}
 */
function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

/**
 * @param {string} hookSource
 * @param {string} fileName
 * @returns {VersionCopy}
 */
function hookHeaderVersion(hookSource, fileName) {
  const label = `hooks/${fileName} header tag`;
  let source;
  try {
    source = fs.readFileSync(path.join(hookSource, fileName), 'utf8');
  } catch {
    return { label, value: '(file missing)' };
  }
  const match = source.match(/\/\/ openclaw-hook: v(\d+\.\d+\.\d+)/);
  return { label, value: match ? match[1] : '(tag missing)' };
}

/** Collect every version copy in the tree alongside the expected value.
 * @param {string} rootDir
 * @returns {VersionAudit}
 */
export function collectVersionCopies(rootDir) {
  const pkg = readJson(path.join(rootDir, 'package.json'));
  const expected = typeof pkg.version === 'string' ? pkg.version : '(missing)';

  /** @type {VersionCopy[]} */
  const copies = [
    {
      label: 'openclaw.plugin.json#version',
      value: String(readJson(path.join(rootDir, 'openclaw.plugin.json')).version ?? '(missing)'),
    },
  ];

  // The hooks live at the repo root; fall back to src/hooks when absent.
  const hooksDir = fs.existsSync(path.join(rootDir, 'hooks'))
    ? path.join(rootDir, 'hooks')
    : path.join(rootDir, 'src', 'hooks');
  copies.push(hookHeaderVersion(hooksDir, 'runtime.js'));
  copies.push(hookHeaderVersion(hooksDir, 'network.js'));
  copies.push({
    label: 'hooks/package.json#version',
    value: String(readJson(path.join(hooksDir, 'package.json')).version ?? '(missing)'),
  });

  let storeSource = '';
  try {
    storeSource = fs.readFileSync(path.join(rootDir, 'src', 'store.ts'), 'utf8');
  } catch {
    /* src/store.ts may be absent */
  }
  if (storeSource) {
    const match = storeSource.match(/readonly version = '([^']+)'/);
    copies.push({ label: 'src/store.ts readonly version', value: match ? match[1] : '(missing)' });
  }

  return { expected, copies };
}

/**
 * Throw with the drift locations when any copy disagrees with package.json.
 * Returns the audit when consistent.
 * @param {string} rootDir
 * @returns {VersionAudit}
 */
export function assertVersionConsistency(rootDir) {
  const { expected, copies } = collectVersionCopies(rootDir);
  const drifted = copies.filter((copy) => copy.value !== expected);
  if (drifted.length > 0) {
    const details = drifted
      .map((copy) => `  - ${copy.label}: ${copy.value} (expected ${expected})`)
      .join('\n');
    throw new Error(
      `Version drift detected — package.json (v${expected}) is the single source of truth:\n${details}`
    );
  }
  return { expected, copies };
}
