#!/usr/bin/env node
/**
 * dedupe-security-events.mjs —— 存量事件文件的可选修复路径
 *
 * 按 `event_id` 把 NDJSON 事件文件里的重复行去掉（保留每个 id 的第一份）。
 * 默认 dry-run：不带 `--apply` 只报告不改文件。真正落盘时先备份为
 * `<path>.bak`，再写 `<path>.tmp` 后 `rename` 覆盖，中途失败不留半截文件。
 * 没有 `event_id` / 解析不了的行绝不删（无从判重 ⇒ 不猜）。
 *
 * 用法：
 *   node scripts/dedupe-security-events.mjs <文件...>                # 干跑（报告）
 *   node scripts/dedupe-security-events.mjs <文件...> --apply        # 真改（先备份）
 *   node scripts/dedupe-security-events.mjs <文件...> --apply --keep-conflicts
 *   node scripts/dedupe-security-events.mjs <文件...> --no-backup
 *
 * 退出码：0 = 成功；1 = 出错（文件读不了 / 写不了）。
 */

import { readFileSync, writeFileSync, copyFileSync, renameSync, statSync, unlinkSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { dedupeEventLines } from './lib/dedupe-events.mjs';

const argv = process.argv.slice(2);
const apply = argv.includes('--apply');
const keepConflicts = argv.includes('--keep-conflicts');
const noBackup = argv.includes('--no-backup');
const paths = argv.filter((a) => !a.startsWith('--'));

if (paths.length === 0) {
  console.error('用法：node scripts/dedupe-security-events.mjs <文件...> [--apply] [--keep-conflicts] [--no-backup]');
  process.exit(1);
}

if (!apply) {
  console.log('🔍 干跑模式（不改文件）—— 确认无误后加 --apply 真正执行。\n');
}

let failed = false;

for (const path of paths) {
  let raw;
  try {
    statSync(path);
    raw = readFileSync(path, 'utf8');
  } catch (err) {
    console.error(`❌ 读不了 ${path}：${err instanceof Error ? err.message : String(err)}`);
    failed = true;
    continue;
  }

  const lines = raw.split('\n');
  // 去掉文件末尾的空段，同时保留"最后一行没有换行"的信息
  const trailingNewline = raw.endsWith('\n');
  if (trailingNewline) lines.pop();

  const result = dedupeEventLines(lines, { keepConflicts });

  const before = lines.filter((l) => l.trim()).length;
  const after = result.kept.length;

  console.log(`📄 ${path}`);
  console.log(`   行数：${before} → ${after}（去掉 ${before - after} 行）`);
  console.log(`   · 完全重复（同 id + 同内容）：${result.duplicates}`);
  console.log(`   · 同 id 不同内容（冲突）：${result.conflicts}`);
  if (result.conflicts > 0) {
    console.log(
      keepConflicts
        ? '     ⤷ 已按 --keep-conflicts 保留（冲突行留在文件里）'
        : '     ⤷ 已按 sink 口径丢弃后来者（要保留请加 --keep-conflicts）',
    );
  }
  console.log(`   · 没有 event_id（保留）：${result.withoutId}`);
  console.log(`   · 解析失败（保留）：${result.unparsable}`);

  if (before === after) {
    console.log('   ✅ 无重复，无需处理\n');
    continue;
  }

  if (!apply) {
    console.log('   （干跑：未改文件）\n');
    continue;
  }

  const content = result.kept.join('\n') + (trailingNewline ? '\n' : '');
  const tmp = `${path}.dedupe-tmp`;
  const bak = `${path}.bak`;
  try {
    writeFileSync(tmp, content, { encoding: 'utf8', mode: 0o600 });
    if (!noBackup) {
      copyFileSync(path, bak);
      console.log(`   💾 备份：${bak}`);
    }
    renameSync(tmp, path);
    console.log(`   ✅ 已重写：${path}\n`);
  } catch (err) {
    failed = true;
    console.error(`   ❌ 写入失败：${err instanceof Error ? err.message : String(err)}`);
    try { unlinkSync(tmp); } catch { /* 临时文件可能没建起来 */ }
    console.error('');
  }
}

if (failed) {
  console.error('[dedupe-security-events] 有文件处理失败。');
  process.exit(1);
}
