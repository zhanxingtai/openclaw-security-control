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
 *
 * Exit code: 0 if all checks pass, 1 otherwise.
 */

import { execSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';

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

  // openclaw.plugin.json must declare entry = index.js so the 9.4 host loader
  // resolves to package/index.js (the tarball-stripped re-export).
  const manifest = JSON.parse(
    execSync(`tar -xOzf "${tarPath}" package/openclaw.plugin.json`, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] })
  );
  const entryOk = manifest.main === 'index.js' && manifest.entry === 'index.js';
  console.log(`[verify-tarball] manifest entry: ${entryOk ? '✓' : '✗'} main=${manifest.main} entry=${manifest.entry}`);
  if (!entryOk) failures.push(`manifest entry mismatch: ${JSON.stringify({ main: manifest.main, entry: manifest.entry })}`);

  // Contracts must list the 11 typed hooks plus the legacy
  // 5-family hook fallback for older hosts.
  const expectedHooks = [
    'before_agent_run', 'agent_end', 'before_tool_call', 'after_tool_call',
    'before_message_write', 'session_start', 'session_end',
    'subagent_spawned', 'subagent_progress', 'subagent_ended', 'cron_changed',
  ];
  const declaredHooks = manifest.contracts?.hooks ?? [];
  const hooksOk = expectedHooks.every((h) => declaredHooks.includes(h)) && declaredHooks.length === expectedHooks.length;
  console.log(`[verify-tarball] contracts.hooks: ${hooksOk ? '✓' : '✗'} (${declaredHooks.length} declared, expected ${expectedHooks.length})`);
  if (!hooksOk) failures.push(`hooks mismatch: declared=${JSON.stringify(declaredHooks)} expected=${JSON.stringify(expectedHooks)}`);

  // httpRoutes must include the panel route (Security Tab iframe surface).
  const expectedRoutes = [
    '/openclaw-security-monitor/events.ndjson',
    '/openclaw-security-monitor/panel',
  ];
  const routesOk = expectedRoutes.every((r) => (manifest.contracts?.httpRoutes ?? []).includes(r));
  console.log(`[verify-tarball] contracts.httpRoutes: ${routesOk ? '✓' : '✗'}`);
  if (!routesOk) failures.push(`httpRoutes mismatch: ${JSON.stringify(manifest.contracts?.httpRoutes)}`);

  // gatewayMethods must include the 10 RPCs the Control UI calls.
  const expectedRpcs = [
    'security.evaluate', 'security.status', 'security.events.list',
    'security.events.stats', 'security.assets.list', 'security.policy.hits',
    'security.metrics', 'security.config.get', 'security.config.diff',
    'security.config.save',
  ];
  const rpcsOk = expectedRpcs.every((m) => (manifest.contracts?.gatewayMethods ?? []).includes(m));
  console.log(`[verify-tarball] contracts.gatewayMethods: ${rpcsOk ? '✓' : '✗'}`);
  if (!rpcsOk) failures.push(`gatewayMethods mismatch: ${JSON.stringify(manifest.contracts?.gatewayMethods)}`);
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
