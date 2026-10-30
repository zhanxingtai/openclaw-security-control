/**
 * 存量修复脚本（scripts/dedupe-security-events.mjs）的门禁：脚本会改用户的审计文件，
 * 必须破坏性验证两条不可逆红线：① 默认干跑不改文件；② 没有 event_id /
 * 解析不了的行绝不删。
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { dedupeEventLines, canonicalFingerprint } from '../../scripts/lib/dedupe-events.mjs';

const SCRIPT = resolve(process.cwd(), 'scripts/dedupe-security-events.mjs');

let dir: string;
let ndjson: string;

function evt(id: string | undefined, extra: Record<string, unknown> = {}): string {
  const obj: Record<string, unknown> = {
    ...(id ? { event_id: id } : {}),
    event_type: 'test_emit',
    ts: 1,
    ...extra,
  };
  return JSON.stringify(obj);
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'dedupe-events-'));
  ndjson = join(dir, 'security-events.jsonl');
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function run(args: string[]): string {
  return execFileSync('node', [SCRIPT, ...args], { encoding: 'utf8' });
}

describe('去重逻辑（纯函数）', () => {
  it('同 id + 同内容 ⇒ 只留第一份', () => {
    const result = dedupeEventLines([evt('a'), evt('a'), evt('a')]);
    expect(result.kept.length).toBe(1);
    expect(result.duplicates).toBe(3 - 1);
  });

  it('不同 id ⇒ 都保留', () => {
    const result = dedupeEventLines([evt('a'), evt('b')]);
    expect(result.kept.length).toBe(2);
    expect(result.duplicates).toBe(0);
  });

  it('没有 event_id 的行 ⇒ 一条都不删', () => {
    const result = dedupeEventLines([evt(undefined), evt(undefined), evt(undefined)]);
    expect(result.kept.length).toBe(3);
    expect(result.withoutId).toBe(3);
  });

  it('解析不了的行 ⇒ 一条都不删', () => {
    const result = dedupeEventLines(['{not json', evt('a'), 'garbage']);
    expect(result.kept.length).toBe(3);
    expect(result.unparsable).toBe(2);
  });

  it('同 id + 不同内容 ⇒ 算冲突，默认丢后来者', () => {
    const result = dedupeEventLines([evt('a', { x: 1 }), evt('a', { x: 2 })]);
    expect(result.kept.length).toBe(1);
    expect(result.conflicts).toBe(1);
    expect(JSON.parse(result.kept[0]).x).toBe(1);
  });

  it('同 id + 不同内容 ⇒ --keep-conflicts 时保留后来者', () => {
    const result = dedupeEventLines([evt('a', { x: 1 }), evt('a', { x: 2 })], { keepConflicts: true });
    expect(result.kept.length).toBe(2);
    expect(result.conflicts).toBe(1);
    expect(result.keptConflicts).toEqual(['a']);
  });

  it('key 顺序不同但内容相同 ⇒ 判为重复（规范化指纹）', () => {
    const a = { event_id: 'x', p: 1, q: 2 };
    const b = { q: 2, p: 1, event_id: 'x' };
    expect(canonicalFingerprint(a)).toBe(canonicalFingerprint(b));
    const result = dedupeEventLines([JSON.stringify(a), JSON.stringify(b)]);
    expect(result.kept.length).toBe(1);
    expect(result.conflicts).toBe(0);
  });
});

describe('修复脚本（CLI · 破坏性验证）', () => {
  it('默认干跑 ⇒ 文件一个字节都不动', () => {
    const original = [evt('a'), evt('a'), evt('b')].join('\n') + '\n';
    writeFileSync(ndjson, original, 'utf8');
    const out = run([ndjson]);
    expect(out).toContain('干跑');
    expect(readFileSync(ndjson, 'utf8')).toBe(original);
    expect(existsSync(`${ndjson}.bak`)).toBe(false);
  });

  it('--apply ⇒ 重复行被去掉，且留有备份', () => {
    writeFileSync(ndjson, [evt('a'), evt('a'), evt('b')].join('\n') + '\n', 'utf8');
    run([ndjson, '--apply']);
    const lines = readFileSync(ndjson, 'utf8').split('\n').filter((l) => l.trim());
    expect(lines.length).toBe(2);
    expect(existsSync(`${ndjson}.bak`)).toBe(true);
    const backup = readFileSync(`${ndjson}.bak`, 'utf8').split('\n').filter((l) => l.trim());
    expect(backup.length).toBe(3);
  });

  it('--apply ⇒ 没有 event_id 的行一条都不删', () => {
    writeFileSync(ndjson, [evt(undefined), evt(undefined), evt('a'), evt('a')].join('\n') + '\n', 'utf8');
    run([ndjson, '--apply']);
    const lines = readFileSync(ndjson, 'utf8').split('\n').filter((l) => l.trim());
    expect(lines.length).toBe(3);
  });

  it('--apply ⇒ 保留文件末尾换行的形态（NDJSON framing 不被破坏）', () => {
    writeFileSync(ndjson, [evt('a'), evt('a')].join('\n') + '\n', 'utf8');
    run([ndjson, '--apply']);
    expect(readFileSync(ndjson, 'utf8').endsWith('\n')).toBe(true);
  });

  it('文件不存在 ⇒ 报错退出（不静默成功）', () => {
    let failed = false;
    try {
      run([join(dir, 'nope.jsonl'), '--apply']);
    } catch (err) {
      failed = true;
      expect((err as { status?: number }).status).toBe(1);
    }
    expect(failed).toBe(true);
  });
});
