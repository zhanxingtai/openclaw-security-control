#!/usr/bin/env node
/**
 * Tarball structure verification.
 *
 * Usage:
 *   node scripts/verify-tarball.mjs [path/to/tarball.tgz]
 *
 * Implements the post-build acceptance (9.4 端到端验收):
 *   - tarball 必须能在 OpenClaw 9.4 宿主直接 require
 *   - 根目录含 index.js / openclaw.plugin.json / policies/ / hooks/ / system/
 *   - 不含 src/adapters/ / src/middleware/ / dist/ 旧路径
 *   - 不含 scripts/setup-openclaw.js（插件严格自包含，无 install scripts）
 *   - 打包进去的 openclaw.plugin.json 只含宿主认识的字段（ClawHub 上架校验
 *     对未知顶层字段 / 未知 contracts 键判硬错误），且 package.json 声明的
 *     openclaw.extensions 入口在包里真实存在
 *
 * Exit code: 0 if all checks pass, 1 otherwise.
 */

import { execSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import {
  findUnknownCategories,
  findUnknownContractKeys,
  findUnknownManifestFields,
} from './openclaw-manifest-contract.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '..');
const pkgVersion = JSON.parse(fs.readFileSync(path.join(rootDir, 'package.json'), 'utf8')).version;
const defaultTarball = path.join(rootDir, 'install', `sst-security-control-openclaw-${pkgVersion}.tgz`);
const tarballPath = process.argv[2] || defaultTarball;

// Git Bash tar treats "E:/..." as a remote host. Convert Windows drive paths
// to POSIX ("/e/...") before handing them to the tar CLI. No-op on Linux.
const toTarPath = (p) => {
  const resolved = path.resolve(p);
  return /^[A-Za-z]:[\\/]/.test(resolved)
    ? '/' + resolved[0].toLowerCase() + resolved.slice(2).replace(/\\/g, '/')
    : resolved;
};
const tarPath = toTarPath(tarballPath);

if (!fs.existsSync(tarballPath)) {
  console.error(`[verify-tarball] not found: ${tarballPath}`);
  console.error(`[verify-tarball] run \`npm run build:prod\` first.`);
  process.exit(1);
}

// Entries the 9.4 host loader expects at the package root.
const REQUIRED = [
  'package/index.js',
  'package/openclaw.plugin.json',
  'package/policies/',
  'package/hooks/',
  'package/system/',
  'package/README.md',
  // 中文版 README 随包分发。没有这条断言，某天 copyFile 被漏掉时 CI 不会报错，
  // 中文用户会在 tgz 里找不到 README.zh.md。
  'package/README.zh.md',
];

// Entries that must not appear in the install bundle.
const FORBIDDEN = [
  'package/src/adapters/',
  'package/src/middleware/',
  'package/application/src/adapters/',
  'package/application/src/middleware/',
  'package/dist/',
  'package/src/auth/',
  'package/application/src/auth/',
  'package/src/collectors/NodeActivityReporter.js',
  'package/src/collectors/EventCollector.js',
  'package/hookRegistry.js',
  'package/src/hookRegistry.js',
  'package/src/pluginContext.js',
  // 遗留布局：hook 副本出现在包根。1.0.x 让 NODE_OPTIONS 指向包根的 runtime.js，
  // 而那个文件是插件每次启动拷进**安装目录**的，不在包清单内 —— 宿主安装器
  // 因此每次装/升级都提示删除它，而删掉又让 --require 找不到文件、gateway
  // 起不来（插件也无从重建）。hook 只能出现在 package/hooks/ 下。
  // 文件名单的"必含"侧由 scripts/build.js 的 REQUIRED_HOOK_FILES 拥有。
  'package/hook-mounter.js',
  'package/runtime.js',
  'package/network.js',
];

let exitCode = 0;
const failures = [];

try {
  const listing = execSync(`tar -tzf "${tarPath}"`, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] })
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .sort();

  const present = (entry) => listing.some((line) => line === entry || line.startsWith(entry));
  const isDir = (entry) => listing.some((line) => line === entry);

  console.log('[verify-tarball] required entries:');
  for (const entry of REQUIRED) {
    const ok = isDir(entry) || present(entry);
    console.log(`  ${ok ? '✓' : '✗'} ${entry}`);
    if (!ok) failures.push(`missing required: ${entry}`);
  }

  console.log('[verify-tarball] forbidden entries:');
  for (const entry of FORBIDDEN) {
    const bad = isDir(entry) || present(entry);
    console.log(`  ${bad ? '✗' : '✓'} ${entry} (must NOT exist)`);
    if (bad) failures.push(`forbidden entry present: ${entry}`);
  }

  // The shipped manifest must only carry fields the host knows.
  // ClawHub's publish validation rejects unknown top-level fields
  // (manifest-unknown-fields) and unknown contracts keys
  // (manifest-unknown-contracts) as hard errors, so the tarball is checked
  // here — the artifact the user actually uploads, not just the repo copy.
  const manifest = JSON.parse(
    execSync(`tar -xOzf "${tarPath}" package/openclaw.plugin.json`, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] })
  );
  const unknownFields = findUnknownManifestFields(manifest);
  const fieldsOk = unknownFields.length === 0;
  console.log(`[verify-tarball] manifest fields: ${fieldsOk ? '✓' : '✗'}${fieldsOk ? '' : ` unknown=${JSON.stringify(unknownFields)}`}`);
  if (!fieldsOk) failures.push(`manifest declares unknown top-level fields: ${JSON.stringify(unknownFields)}`);

  const unknownContracts = findUnknownContractKeys(manifest);
  const contractsOk = unknownContracts.length === 0;
  console.log(`[verify-tarball] manifest contracts keys: ${contractsOk ? '✓' : '✗'}${contractsOk ? '' : ` unknown=${JSON.stringify(unknownContracts)}`}`);
  if (!contractsOk) failures.push(`manifest.contracts declares unknown keys: ${JSON.stringify(unknownContracts)}`);

  const unknownCategories = findUnknownCategories(manifest);
  const categoriesOk = unknownCategories.length === 0;
  console.log(`[verify-tarball] manifest categories: ${categoriesOk ? '✓' : '✗'}${categoriesOk ? '' : ` unknown=${JSON.stringify(unknownCategories)}`}`);
  if (!categoriesOk) failures.push(`manifest.categories has unknown slugs: ${JSON.stringify(unknownCategories)}`);

  // The host resolves the plugin entry from package.json#openclaw.extensions,
  // not from the manifest — the manifest has no main/entry field to read.
  // Every declared extension must exist in the tarball, otherwise the host
  // resolves to a missing file and the plugin silently never loads.
  const shippedPkg = JSON.parse(
    execSync(`tar -xOzf "${tarPath}" package/package.json`, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] })
  );
  const extensions = Array.isArray(shippedPkg.openclaw?.extensions) ? shippedPkg.openclaw.extensions : [];
  const missingExtensions = extensions.filter(
    (entry) => !present(`package/${String(entry).replace(/^\.\//, '')}`)
  );
  const extensionsOk = extensions.length > 0 && missingExtensions.length === 0;
  console.log(`[verify-tarball] openclaw.extensions: ${extensionsOk ? '✓' : '✗'} ${JSON.stringify(extensions)}`);
  if (!extensionsOk) failures.push(`openclaw.extensions missing from tarball: ${JSON.stringify(missingExtensions)}`);
} catch (err) {
  console.error(`[verify-tarball] failed: ${err.message}`);
  exitCode = 1;
}

if (failures.length > 0) {
  console.error(`\n[verify-tarball] ${failures.length} failure(s):`);
  for (const f of failures) console.error(`  - ${f}`);
  exitCode = 1;
} else {
  console.log('\n[verify-tarball] all checks passed');
}
process.exit(exitCode);
