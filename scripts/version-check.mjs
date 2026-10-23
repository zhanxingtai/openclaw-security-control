/**
 * Version single-source-of-truth check.
 *
 * package.json#version 是唯一权威版本，openclaw.plugin.json#version 是唯一
 * 允许存在的副本（宿主清单契约，OpenClaw 靠它认插件版本）。scripts/build.js
 * 在编译前跑此脚本，两者不等即 fail；导出纯函数供 vitest 单测覆盖两条路径。
 *
 * 为什么只有这一个副本：
 *   - hooks/*.js 里没有任何版本号。它们按内容哈希判定是否需要重装（见
 *     src/initialize.ts readHookFingerprint），改内容自动生效，不需要人工
 *     记得 bump 什么，也不跟踪包版本。
 *   - hooks/package.json#version 无读者（Node 解析只看 name/main/type）。
 *   - 运行时版本（面板副标题、启动日志）由 index.ts resolvePluginVersion()
 *     从 package.json 现读，不缓存。
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
